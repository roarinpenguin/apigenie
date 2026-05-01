"""Custom Listeners — backbone, dispatcher, and response builder.

Lets an admin user define a runtime-configurable HTTP endpoint that behaves
like a real SaaS log API so a hand-rolled Observo SCol Lua source can poll it
and exercise its decoder / pagination / auth / retry logic without standing
up the upstream platform.

Design doc: docs/CUSTOM_LISTENERS.md

Responsibilities
================
* Persistent listener configs at        ./data/listeners/<id>.json
* Persistent hit log (line-buffered) at ./data/listeners/<id>.hits.jsonl with
  size-capped rotation, plus an in-memory ring buffer of the last N hits per
  listener for the live trace pane
* Validation of incoming requests (auth, rate-limit, chaos)
* Response building for the two data-source kinds:
    - synthetic — generators under ``sources.synthetic`` (endpoint / identity /
      cloud / network), seeded for determinism, encoded per the listener's
      codec (json / ndjson / syslog) with optional pagination (cursor / page /
      since)
    - replay   — uploaded files served through ``replay.py`` with time-shift
      semantics (anchor_mode = now | offset | fixed), preserving the original
      spread between records

The module is single-process (matches the rest of apigenie which runs with
``--workers 1``). All in-memory state is keyed by listener id.
"""

from __future__ import annotations

import collections
import json
import logging
import os
import re
import threading
import time
from base64 import b64decode
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

logger = logging.getLogger(__name__)

# ── Storage location ─────────────────────────────────────────────────────────
# /var/lib/apigenie is the volume already mounted from ./data on the host
# (see docker-compose.yaml). Listener configs and the on-disk hit log live
# alongside the existing admin_pass file.
_DATA_DIR = Path(os.environ.get("APIGENIE_DATA_DIR", "/var/lib/apigenie"))
LISTENER_DIR = _DATA_DIR / "listeners"

# ── Bounded structures ───────────────────────────────────────────────────────
HITS_MEM_CAP = int(os.environ.get("APIGENIE_LISTENER_HITS_CAP", "200"))
HITS_DISK_CAP = int(os.environ.get("APIGENIE_LISTENER_HITS_DISK_CAP", "5000"))

# ── Validation ───────────────────────────────────────────────────────────────
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,30}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./{}:]*$")  # tolerant; no query string

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}
ALLOWED_CODECS_V1 = {"json", "ndjson", "syslog"}            # see docs §10
ALLOWED_AUTH_KINDS = {"none", "basic", "bearer", "oauth2_cc", "x_api_key"}

# Tokens minted by ApiGenie's existing /oauth2/v1/token endpoint. Listeners
# that declare auth.kind == "oauth2_cc" accept any of these (re-using the
# global token endpoint per docs/CUSTOM_LISTENERS.md §6).
_OAUTH2_VALID_TOKENS = frozenset({
    "apigenie-fake-oauth-access-token",
    "apigenie-valid-token-001",
    "apigenie-valid-token-002",
    "apigenie-valid-token-003",
})


# ── Dataclasses (plain dicts under the hood for JSON round-tripping) ─────────

@dataclass
class AuthSpec:
    kind: Literal["none", "basic", "bearer", "oauth2_cc", "x_api_key"] = "none"
    # bearer:
    token: str | None = None
    header: str = "Authorization"
    prefix: str = "Bearer "
    # basic:
    username: str | None = None
    password: str | None = None
    # x_api_key:
    api_key_header: str = "X-Api-Key"
    api_key: str | None = None


@dataclass
class PaginationSpec:
    kind: Literal["cursor", "since", "page"] = "cursor"
    page_size: int = 100
    total_pages: int = 5


@dataclass
class RateLimitSpec:
    # "every Nth request returns 429" — simplest model for v1.
    every_n: int = 0          # 0 = disabled


@dataclass
class ChaosSpec:
    # "every Nth request returns this status" — for collector retry testing.
    every_n: int = 0          # 0 = disabled
    status: int = 503


@dataclass
class SyntheticTopicSpec:
    topic: Literal["endpoint", "identity", "cloud", "network"] = "endpoint"
    rate_per_request: int = 100
    seed: int | None = None


@dataclass
class ReplayFileSpec:
    file_id: str = ""
    format: Literal["json", "jsonl", "csv", "syslog", "cef"] = "jsonl"
    timestamp_field: str = "timestamp"
    anchor_mode: Literal["now", "offset", "fixed"] = "now"
    anchor_offset_seconds: int = 0
    anchor_fixed_iso: str | None = None
    preserve_spread: bool = True


@dataclass
class Listener:
    id: str
    name: str
    path: str
    method: str = "GET"
    codec: str = "json"
    enabled: bool = True
    auth: AuthSpec = field(default_factory=AuthSpec)
    pagination: PaginationSpec | None = None
    rate_limit: RateLimitSpec | None = None
    chaos: ChaosSpec | None = None
    # Exactly one of these is populated. Encoded as a tagged dict on disk.
    synthetic: SyntheticTopicSpec | None = None
    replay: ReplayFileSpec | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    # ── (de)serialisation ────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Listener":
        def _sub(cls, key):
            v = d.get(key)
            return cls(**v) if isinstance(v, dict) else None

        return Listener(
            id=d["id"],
            name=d.get("name", d["id"]),
            path=d["path"],
            method=d.get("method", "GET"),
            codec=d.get("codec", "json"),
            enabled=d.get("enabled", True),
            auth=AuthSpec(**(d.get("auth") or {})),
            pagination=_sub(PaginationSpec, "pagination"),
            rate_limit=_sub(RateLimitSpec, "rate_limit"),
            chaos=_sub(ChaosSpec, "chaos"),
            synthetic=_sub(SyntheticTopicSpec, "synthetic"),
            replay=_sub(ReplayFileSpec, "replay"),
            created_at=d.get("created_at") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )


# ── Validation ───────────────────────────────────────────────────────────────

def validate_listener_payload(d: dict[str, Any]) -> tuple[bool, str]:
    """Return (ok, error_message). Used by the admin CRUD endpoints."""
    try:
        lid = d.get("id", "")
        if not isinstance(lid, str) or not _ID_RE.match(lid):
            return False, "id must match [a-z0-9][a-z0-9_-]{1,30}"
        path = d.get("path", "")
        if not isinstance(path, str) or not _PATH_RE.match(path):
            return False, "path must start with / and contain only [A-Za-z0-9_-./{}:]"
        method = d.get("method", "GET").upper()
        if method not in ALLOWED_METHODS:
            return False, f"method must be one of {sorted(ALLOWED_METHODS)}"
        codec = d.get("codec", "json")
        if codec not in ALLOWED_CODECS_V1:
            return False, f"codec must be one of {sorted(ALLOWED_CODECS_V1)} (v1 set; see docs §10)"
        auth = d.get("auth") or {}
        akind = auth.get("kind", "none")
        if akind not in ALLOWED_AUTH_KINDS:
            return False, f"auth.kind must be one of {sorted(ALLOWED_AUTH_KINDS)}"
        if akind == "basic" and not (auth.get("username") and auth.get("password")):
            return False, "auth.kind=basic requires username and password"
        if akind == "bearer" and not auth.get("token"):
            return False, "auth.kind=bearer requires token"
        if akind == "x_api_key" and not auth.get("api_key"):
            return False, "auth.kind=x_api_key requires api_key"
        # Exactly one of synthetic / replay
        has_syn = isinstance(d.get("synthetic"), dict)
        has_rep = isinstance(d.get("replay"), dict)
        if has_syn == has_rep:
            return False, "exactly one of 'synthetic' or 'replay' must be set"
        if has_syn:
            topic = d["synthetic"].get("topic", "")
            if topic not in {"endpoint", "identity", "cloud", "network"}:
                return False, "synthetic.topic must be endpoint|identity|cloud|network"
        return True, ""
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"malformed payload: {exc}"


# ── Persistence ──────────────────────────────────────────────────────────────

LISTENERS: dict[str, Listener] = {}
LISTENER_HITS: dict[str, collections.deque] = {}
_HIT_LOCK = threading.Lock()
# Per-listener counters used by rate_limit/chaos "every Nth" logic.
_REQ_COUNTERS: dict[str, int] = collections.defaultdict(int)
# Per-listener counter to throttle disk-rotation stat() calls.
_ROTATE_COUNTERS: dict[str, int] = collections.defaultdict(int)


def _config_path(lid: str) -> Path:
    return LISTENER_DIR / f"{lid}.json"


def _hits_path(lid: str) -> Path:
    return LISTENER_DIR / f"{lid}.hits.jsonl"


def load_all() -> None:
    """Load every <id>.json file into memory. Idempotent — safe at app start.

    Hits are *not* fully loaded; only the tail (up to HITS_MEM_CAP entries) is
    pulled into the in-memory ring so the live trace pane shows recent history
    after a restart.
    """
    LISTENER_DIR.mkdir(parents=True, exist_ok=True)
    LISTENERS.clear()
    LISTENER_HITS.clear()
    for cfg in sorted(LISTENER_DIR.glob("*.json")):
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            listener = Listener.from_dict(data)
            LISTENERS[listener.id] = listener
            LISTENER_HITS[listener.id] = collections.deque(maxlen=HITS_MEM_CAP)
            _hydrate_recent_hits(listener.id)
        except Exception as exc:
            logger.warning(f"Failed to load listener config {cfg}: {exc}")
    logger.info(f"Loaded {len(LISTENERS)} listener config(s) from {LISTENER_DIR}")


def _hydrate_recent_hits(lid: str) -> None:
    p = _hits_path(lid)
    if not p.exists():
        return
    try:
        # Pull the last HITS_MEM_CAP lines without reading the whole file.
        with p.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            chunk = min(size, 256 * 1024)  # 256 KiB tail is plenty for 200 lines
            fh.seek(size - chunk, os.SEEK_SET)
            tail = fh.read().decode("utf-8", errors="replace")
        lines = tail.splitlines()[-HITS_MEM_CAP:]
        for ln in lines:
            if not ln.strip():
                continue
            try:
                LISTENER_HITS[lid].append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    except OSError as exc:
        logger.warning(f"Could not hydrate hits for {lid}: {exc}")


def save(listener: Listener) -> None:
    LISTENER_DIR.mkdir(parents=True, exist_ok=True)
    p = _config_path(listener.id)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(listener.to_dict(), indent=2), encoding="utf-8")
    tmp.replace(p)
    LISTENERS[listener.id] = listener
    LISTENER_HITS.setdefault(listener.id, collections.deque(maxlen=HITS_MEM_CAP))


def delete(lid: str) -> bool:
    listener = LISTENERS.pop(lid, None)
    LISTENER_HITS.pop(lid, None)
    _REQ_COUNTERS.pop(lid, None)
    p = _config_path(lid)
    h = _hits_path(lid)
    removed = False
    for f in (p, h):
        try:
            f.unlink(missing_ok=True)
            removed = True
        except OSError as exc:
            logger.warning(f"Could not delete {f}: {exc}")
    return listener is not None or removed


def clear_hits(lid: str) -> None:
    LISTENER_HITS.get(lid, collections.deque()).clear()
    try:
        _hits_path(lid).unlink(missing_ok=True)
    except OSError:
        pass


# ── Hit recorder ─────────────────────────────────────────────────────────────

def _sanitise_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    sensitive = {"authorization", "cookie", "x-apikeys", "x-api-key"}
    return {k: ("***" if k.lower() in sensitive else v) for k, v in dict(headers).items()}


def record_hit(lid: str, entry: dict[str, Any]) -> None:
    """Append to the in-memory ring AND the on-disk JSONL. Disk writes are
    line-buffered so a crash loses at most the most recent hit. The disk
    file is rotated when it exceeds HITS_DISK_CAP lines: we read the tail,
    truncate, and rewrite the most recent HITS_DISK_CAP // 2 lines so we
    don't rotate every single insert.
    """
    with _HIT_LOCK:
        ring = LISTENER_HITS.setdefault(lid, collections.deque(maxlen=HITS_MEM_CAP))
        ring.appendleft(entry)
        _ROTATE_COUNTERS[lid] += 1
        try:
            p = _hits_path(lid)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            # Check rotation every 50 writes to avoid stat'ing on every hit.
            if _ROTATE_COUNTERS[lid] % 50 == 0:
                _maybe_rotate_disk(p)
        except OSError as exc:
            logger.warning(f"Could not append hit for {lid}: {exc}")


def _maybe_rotate_disk(p: Path) -> None:
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        if len(lines) <= HITS_DISK_CAP:
            return
        keep = lines[-(HITS_DISK_CAP // 2):]
        tmp = p.with_suffix(".jsonl.tmp")
        tmp.write_text("".join(keep), encoding="utf-8")
        tmp.replace(p)
        logger.info(f"Rotated {p.name}: kept last {len(keep)} lines")
    except OSError as exc:
        logger.warning(f"Hit rotation failed for {p}: {exc}")


# ── Auth dispatcher ──────────────────────────────────────────────────────────

def check_auth(spec: AuthSpec, headers: dict[str, str]) -> tuple[bool, str]:
    """Return (ok, identity_label). identity_label is a short string for the
    live trace pane ("anon", "user:bob", "key:apigenie-…", …)."""
    # Normalise header keys to lowercase for case-insensitive lookup.
    h = {k.lower(): v for k, v in headers.items()}

    if spec.kind == "none":
        return True, "anon"

    if spec.kind == "basic":
        v = h.get("authorization", "")
        if not v.lower().startswith("basic "):
            return False, "no-basic"
        try:
            decoded = b64decode(v[6:]).decode("utf-8", errors="replace")
            user, _, pwd = decoded.partition(":")
        except Exception:
            return False, "bad-basic"
        if user == (spec.username or "") and pwd == (spec.password or ""):
            return True, f"user:{user}"
        return False, "basic-mismatch"

    if spec.kind == "bearer":
        hdr = (spec.header or "Authorization").lower()
        v = h.get(hdr, "")
        prefix = spec.prefix or ""
        if prefix and v.startswith(prefix):
            tok = v[len(prefix):].strip()
        else:
            tok = v.strip()
        if tok and tok == (spec.token or ""):
            return True, f"bearer:{tok[:8]}…"
        return False, "bearer-mismatch"

    if spec.kind == "oauth2_cc":
        v = h.get("authorization", "")
        if not v.lower().startswith("bearer "):
            return False, "no-oauth-bearer"
        tok = v[7:].strip()
        if tok in _OAUTH2_VALID_TOKENS:
            return True, f"oauth2:{tok[:12]}…"
        return False, "oauth2-mismatch"

    if spec.kind == "x_api_key":
        hdr = (spec.api_key_header or "X-Api-Key").lower()
        v = h.get(hdr, "").strip()
        if v and v == (spec.api_key or ""):
            return True, f"key:{v[:8]}…"
        return False, "apikey-mismatch"

    return False, "unknown-auth"


# ── Rate-limit + chaos ───────────────────────────────────────────────────────

def maybe_inject_status(listener: Listener) -> int | None:
    """Return an injected status code (429 or chaos.status), else None.
    Increments the per-listener request counter as a side-effect."""
    _REQ_COUNTERS[listener.id] += 1
    n = _REQ_COUNTERS[listener.id]
    rl = listener.rate_limit
    if rl and rl.every_n > 0 and n % rl.every_n == 0:
        return 429
    ch = listener.chaos
    if ch and ch.every_n > 0 and n % ch.every_n == 0:
        return ch.status
    return None


# ── Response builder (Phase 2) ───────────────────────────────────────────────
# Synthetic generators live under sources.synthetic. Replay (Phase 4) will plug
# in here with an alternate code path.

def build_response(
    listener: Listener,
    query_params: dict[str, str],
) -> tuple[dict[str, Any] | str, str, dict[str, str]]:
    """Build the response body, content-type, and any extra HTTP headers.

    The function is **state-less** with respect to pagination: the cursor /
    page index is read straight from ``query_params``, so concurrent collectors
    polling the same listener don't fight over a shared cursor counter. The
    cursor / page identifier is opaque ("page-2", "page-3", ...).

    Returns
    -------
    (body, content_type, extra_headers)
        ``body`` is a ``dict`` for codec=json, otherwise an already-encoded
        ``str``. ``extra_headers`` is empty unless cursor-pagination is in use,
        in which case ``X-Next-Cursor`` (or ``Link: <…>; rel="next"``) is set.
    """
    # ── Replay (Phase 4) ────────────────────────────────────────────────
    if listener.replay is not None:
        return _replay_response(listener, query_params)

    # ── Synthetic ───────────────────────────────────────────────────────
    if listener.synthetic is None:
        return ({"error": "no_data_source"}, "application/json", {})

    # Lazy import so a (hypothetical) load-time failure in a topic module
    # doesn't stop the listener backbone from booting.
    from sources.synthetic import TOPICS

    topic = listener.synthetic.topic
    fn = TOPICS.get(topic)
    if fn is None:
        return ({"error": f"unknown_topic:{topic}"}, "application/json", {})

    n = max(1, int(listener.synthetic.rate_per_request or 100))
    seed = listener.synthetic.seed

    # Pagination state (state-less — derived purely from request params).
    page_idx, has_more, pag_meta, extra_headers = _resolve_pagination(
        listener.pagination, query_params
    )
    if not has_more:
        # Past the configured page count — return an empty page so the
        # collector knows to stop.
        records: list[dict] = []
    else:
        # If a seed is set, derive a per-page seed so successive pages don't
        # return the same records.
        per_page_seed = (seed + page_idx) if seed is not None else None
        records = fn(n, seed=per_page_seed)

    return _encode(listener.codec, records, listener, pag_meta, extra_headers)


# ── Replay branch ────────────────────────────────────────────────────────────
# Defaults for an *unpaginated* replay listener: cap at this many records per
# call so a 100 MB file doesn't try to inline-encode into one response.
_REPLAY_DEFAULT_LIMIT = 1000


def _replay_response(
    listener: Listener,
    query_params: dict[str, str],
) -> tuple[dict[str, Any] | str, str, dict[str, str]]:
    """Stream a replay file with time-shift, sliced for the current page.

    Returns the same ``(body, content_type, extra_headers)`` shape as
    ``build_response``. Uses the existing pagination machinery; total_pages
    is *derived* from the file's ``line_count`` rather than the listener's
    static spec (which is meaningful for synthetic only).
    """
    # Lazy import so a missing replay.py at boot doesn't break the listener
    # backbone (defensive symmetry with the synthetic branch).
    from replay import StreamSpec, get_replay, stream as replay_stream

    rspec = listener.replay
    assert rspec is not None  # narrowed by build_response

    meta = get_replay(rspec.file_id)
    if meta is None:
        return (
            {"error": "replay_file_missing",
             "note": "The uploaded blob this listener pointed at has been deleted.",
             "listener_id": listener.id,
             "file_id": rspec.file_id},
            "application/json",
            {},
        )

    # Effective pagination spec: if the listener has its own pagination
    # config, honour kind+page_size but override total_pages so we stop at
    # the actual end of the file. If the listener has no pagination, return
    # up to _REPLAY_DEFAULT_LIMIT records in one shot.
    if listener.pagination is not None:
        eff = PaginationSpec(
            kind=listener.pagination.kind,
            page_size=max(1, listener.pagination.page_size or 100),
            total_pages=max(1, (meta.line_count + listener.pagination.page_size - 1) // listener.pagination.page_size or 1),
        )
        page_idx, has_more, pag_meta, extra_headers = _resolve_pagination(eff, query_params)
        page_size = eff.page_size
    else:
        page_idx, has_more, pag_meta, extra_headers = 0, True, {}, {}
        page_size = _REPLAY_DEFAULT_LIMIT

    if not has_more:
        return _encode_replay(listener, [], pag_meta, extra_headers, meta)

    # Slice the stream lazily without buffering the whole file: skip
    # ``page_idx * page_size`` records, take the next ``page_size``.
    skip = page_idx * page_size
    stream_spec = StreamSpec(
        file_id=rspec.file_id,
        format=meta.format,
        timestamp_field=rspec.timestamp_field or meta.timestamp_field,
        anchor_mode=rspec.anchor_mode,
        anchor_offset_seconds=rspec.anchor_offset_seconds,
        anchor_fixed_iso=rspec.anchor_fixed_iso,
        preserve_spread=rspec.preserve_spread,
    )

    out: list[dict] = []
    for i, rec in enumerate(replay_stream(stream_spec)):
        if i < skip:
            continue
        if len(out) >= page_size:
            break
        out.append(rec)

    return _encode_replay(listener, out, pag_meta, extra_headers, meta)


def _encode_replay(
    listener: Listener,
    records: list[dict],
    pag_meta: dict[str, Any],
    extra_headers: dict[str, str],
    meta: Any,  # ReplayMeta from replay.py — kept Any to avoid a hard import here
) -> tuple[dict[str, Any] | str, str, dict[str, str]]:
    """Same encoding contract as ``_encode``, but the syslog tag is the
    replay file's stem (e.g. ``edr-export``) rather than a synthetic topic."""
    codec = listener.codec
    if codec == "ndjson":
        body = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records)
        return body, "application/x-ndjson", extra_headers

    if codec == "syslog":
        host = "apigenie"
        tag = (meta.filename.rsplit(".", 1)[0] if getattr(meta, "filename", None) else "replay") or "replay"
        ts_now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        out_lines: list[str] = []
        for r in records:
            kvs = " ".join(f"{k}={_syslog_val(v)}" for k, v in _flatten(r).items())
            out_lines.append(f"<134>{ts_now} {host} {tag}[{listener.id}]: {kvs}")
        body = "\n".join(out_lines) + ("\n" if out_lines else "")
        return body, "text/plain; charset=utf-8", extra_headers

    body_dict: dict[str, Any] = {"records": records, "count": len(records)}
    body_dict.update(pag_meta)
    return body_dict, "application/json", extra_headers


def _resolve_pagination(
    spec: PaginationSpec | None,
    qp: dict[str, str],
) -> tuple[int, bool, dict[str, Any], dict[str, str]]:
    """Return (page_idx, has_more, pagination_meta_for_body, extra_headers).

    page_idx is 0-based for internal use; pagination_meta_for_body and
    extra_headers carry the user-visible cursor/page link for the *next*
    call (or are empty when no more pages remain or pagination is disabled).
    """
    if spec is None or spec.kind not in ("cursor", "since", "page"):
        return 0, True, {}, {}

    total = max(1, spec.total_pages)

    if spec.kind == "cursor":
        cur = qp.get("cursor") or ""
        if cur == "":
            page_idx = 0
        elif cur.startswith("page-"):
            try:
                page_idx = int(cur.split("-", 1)[1])
            except ValueError:
                page_idx = 0
        else:
            page_idx = 0
        if page_idx >= total:
            return page_idx, False, {}, {}
        next_cur = f"page-{page_idx + 1}"
        last = (page_idx + 1) >= total
        meta = {} if last else {"next_cursor": next_cur}
        headers = {} if last else {"X-Next-Cursor": next_cur}
        return page_idx, True, meta, headers

    if spec.kind == "page":
        try:
            page_idx = max(0, int(qp.get("page", "0")))
        except ValueError:
            page_idx = 0
        if page_idx >= total:
            return page_idx, False, {}, {}
        next_p = page_idx + 1
        last = next_p >= total
        meta = {"page": page_idx, "page_size": spec.page_size}
        if not last:
            meta["next_page"] = next_p
        return page_idx, True, meta, {}

    # "since" — clients pass ?since=<iso8601>; we always return fresh records
    # and reflect a watermark for the next call. No "end" semantics: it's an
    # open-ended live stream.
    since = qp.get("since", "")
    next_since = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return 0, True, {"since": since, "next_since": next_since}, {}


def _encode(
    codec: str,
    records: list[dict],
    listener: Listener,
    pag_meta: dict[str, Any],
    extra_headers: dict[str, str],
) -> tuple[dict[str, Any] | str, str, dict[str, str]]:
    """Serialise records per the listener's codec."""
    if codec == "ndjson":
        body = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records)
        return body, "application/x-ndjson", extra_headers

    if codec == "syslog":
        # RFC 3164-shaped one line per record. Pri 134 = facility 16 (local0)
        # + severity 6 (info). Hostname always "apigenie"; tag is "<topic>".
        topic = listener.synthetic.topic if listener.synthetic else "listener"
        host = "apigenie"
        ts_now = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        out_lines: list[str] = []
        for r in records:
            kvs = " ".join(f"{k}={_syslog_val(v)}" for k, v in _flatten(r).items())
            out_lines.append(f"<134>{ts_now} {host} {topic}[{listener.id}]: {kvs}")
        body = "\n".join(out_lines) + ("\n" if out_lines else "")
        return body, "text/plain; charset=utf-8", extra_headers

    # Default: JSON object with records + pagination metadata.
    body_dict: dict[str, Any] = {"records": records, "count": len(records)}
    body_dict.update(pag_meta)
    return body_dict, "application/json", extra_headers


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to dotted keys (one level) for syslog key=val output.
    Lists are JSON-stringified inline."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


def _syslog_val(v: Any) -> str:
    if isinstance(v, (list, tuple)):
        return json.dumps(v, separators=(",", ":"))
    s = str(v)
    if any(c.isspace() for c in s) or "=" in s:
        return '"' + s.replace('"', '\\"') + '"'
    return s


# ── Hit construction helper (called by the dispatcher) ───────────────────────

def make_hit(*, ts: str, method: str, path: str, query: str, client: str,
             status: int, identity: str, headers: dict[str, str],
             body: str, duration_ms: int) -> dict[str, Any]:
    return {
        "ts": ts,
        "method": method,
        "path": path,
        "query": query,
        "client": client,
        "status": status,
        "identity": identity,
        "duration_ms": duration_ms,
        "req_headers": _sanitise_headers(headers.items()),
        "req_body": body[:2000],
    }


# Initialise on import so admin endpoints can list configs immediately.
load_all()
