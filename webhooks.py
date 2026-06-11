"""Webhook composer — outbound HTTP request builder + sender.

Stores per-user webhooks (URL + method + auth + headers + query + templated
body) and ships them via httpx with full visibility into the request that
went out and the response that came back. Designed for the same audience
and isolation model as Log Profiles and Alert Push: per-user CRUD with
private/public visibility, admin-bypass on RBAC, owner_id + visibility on
every object.

Template variable surface (resolved via ``render(template, ctx)``):

  {{profile.user.<field>}}         one randomly picked user from bound profile
  {{profile.machine.<field>}}      one randomly picked machine
  {{profile.c2.<field>}}           one randomly picked C2 server
  {{profile.malware.<field>}}      one randomly picked malware sample
  {{profile.mail_sender.<field>}}  one randomly picked mail sender
  {{custom.<key>}}                 per-send custom variable (modal pane)
  {{now}}                          ISO-8601 UTC timestamp
  {{epoch}}                        Unix epoch seconds
  {{epoch_ms}}                     Unix epoch milliseconds
  {{uuid}}                         random UUID4
  {{env.<KEY>}}                    allowlisted env vars (see ``ENV_ALLOWLIST``)

Missing variables render as ``{{?<original>}}`` markers so authors see the
gap explicitly rather than getting a silent empty string.

Security guardrails enforced by ``send_webhook``:

  - Egress allowlist: by default rejects RFC1918 / link-local / loopback /
    IMDS targets. Override via ``APIGENIE_WEBHOOK_ALLOWED_HOSTS`` (CIDRs
    and/or hostnames, comma-separated).
  - Sensitive header redaction in the "effective request" view (last 4
    chars only): Authorization, X-Api-Key, Cookie, Proxy-Authorization.
  - Response body cap: 64 KiB.
  - Hard timeout: 10 s.

The module does **not** know about FastAPI / RBAC — the admin.py routes
do the auth and ownership checks and call the pure functions here.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import random
import re
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse, urlencode

log = logging.getLogger(__name__)

# ── Storage layout ────────────────────────────────────────────────────────────
DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
WEBHOOKS_DIR = DATA_ROOT / "webhooks"
# Site-wide settings (currently just the SSRF allowlist). Kept next to the
# webhook objects so a single `webhooks/` tarball captures everything an
# operator needs to back up or migrate.
SETTINGS_PATH = DATA_ROOT / "webhook_settings.json"

_lock = threading.Lock()

# ── Constants & guardrails ────────────────────────────────────────────────────
RESPONSE_BODY_CAP = 64 * 1024        # 64 KiB
HARD_TIMEOUT_SECS = 10.0
SENSITIVE_HEADERS = {"authorization", "x-api-key", "cookie",
                     "proxy-authorization", "x-auth-token"}

# Env vars exposed to the renderer. Anything outside this list resolves to
# the {{?env.X}} miss marker, even if the env var exists in the process.
ENV_ALLOWLIST: tuple[str, ...] = (
    "APIGENIE_DOMAIN",
    "APIGENIE_VERSION",
    "APIGENIE_DEPLOYMENT",
)

ALLOWED_METHODS: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
ALLOWED_AUTH_TYPES: tuple[str, ...] = ("none", "basic", "bearer", "custom")
ALLOWED_BODY_FORMATS: tuple[str, ...] = ("json", "form", "raw")

# Regex for {{path.segments}} — restricted to identifier characters + dots so
# we can't be tricked into matching e.g. {{ { } }} or shell-injection shapes.
_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.\-]*)\s*\}\}")


# ── Storage helpers ──────────────────────────────────────────────────────────
def _ensure_dir() -> None:
    WEBHOOKS_DIR.mkdir(parents=True, exist_ok=True)


def _path(wid: str) -> Path:
    return WEBHOOKS_DIR / f"{wid}.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return f"wh-{uuid.uuid4().hex[:12]}"


# ── Validation ───────────────────────────────────────────────────────────────
def _validate_payload(data: dict[str, Any]) -> str | None:
    """Return an error message if the payload is invalid, else None."""
    url = (data.get("url") or "").strip()
    if not url:
        return "url is required"
    if not (url.startswith("http://") or url.startswith("https://")):
        return "url must start with http:// or https://"
    method = (data.get("method") or "POST").upper()
    if method not in ALLOWED_METHODS:
        return f"method must be one of {ALLOWED_METHODS}"
    auth = data.get("auth") or {}
    if auth and auth.get("type") not in ALLOWED_AUTH_TYPES:
        return f"auth.type must be one of {ALLOWED_AUTH_TYPES}"
    body_format = (data.get("body_format") or "json").lower()
    if body_format not in ALLOWED_BODY_FORMATS:
        return f"body_format must be one of {ALLOWED_BODY_FORMATS}"
    for label, items in (("headers", data.get("headers") or []),
                         ("query",   data.get("query")   or [])):
        if not isinstance(items, list):
            return f"{label} must be a list of {{key, value}} objects"
        for kv in items:
            if not isinstance(kv, dict) or "key" not in kv:
                return f"{label} entries need a 'key' field"
    return None


def _normalise(data: dict[str, Any]) -> dict[str, Any]:
    """Coerce common shape variations and apply defaults."""
    return {
        "name":          (data.get("name") or "Untitled webhook").strip(),
        "description":   (data.get("description") or "").strip(),
        "url":           (data.get("url") or "").strip(),
        "method":        (data.get("method") or "POST").upper(),
        "auth":          data.get("auth") or {"type": "none"},
        "headers":       list(data.get("headers") or []),
        "query":         list(data.get("query") or []),
        "body_template": data.get("body_template") or "",
        "body_format":   (data.get("body_format") or "json").lower(),
        "profile_id":    data.get("profile_id") or None,
    }


# ── CRUD ─────────────────────────────────────────────────────────────────────
def create_webhook(data: dict[str, Any]) -> dict[str, Any]:
    """Create a webhook. ``data`` already carries owner_id + visibility.

    Returns the saved dict (with id, created_at, updated_at filled in).
    Raises ValueError on validation failure.
    """
    err = _validate_payload(data)
    if err:
        raise ValueError(err)
    _ensure_dir()
    wid = _new_id()
    now = _now_iso()
    wh = {
        "id":         wid,
        "owner_id":   data.get("owner_id"),
        "visibility": data.get("visibility") or "private",
        **_normalise(data),
        "created_at": now,
        "updated_at": now,
    }
    with _lock:
        _path(wid).write_text(json.dumps(wh, indent=2))
    return wh


def get_webhook(wid: str) -> dict[str, Any] | None:
    p = _path(wid)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("webhook %s: corrupt file: %s", wid, exc)
        return None


def update_webhook(wid: str, data: dict[str, Any]) -> dict[str, Any] | None:
    with _lock:
        existing = get_webhook(wid)
        if existing is None:
            return None
        # Allow partial updates — only validate fields that are actually present.
        merged = dict(existing)
        for key in ("name", "description", "url", "method", "auth", "headers",
                    "query", "body_template", "body_format", "profile_id",
                    "visibility"):
            if key in data:
                merged[key] = data[key]
        err = _validate_payload(merged)
        if err:
            raise ValueError(err)
        merged.update(_normalise(merged))
        merged["updated_at"] = _now_iso()
        _path(wid).write_text(json.dumps(merged, indent=2))
        return merged


def delete_webhook(wid: str) -> bool:
    p = _path(wid)
    if not p.is_file():
        return False
    with _lock:
        try:
            p.unlink()
        except OSError as exc:
            log.warning("webhook %s: delete failed: %s", wid, exc)
            return False
    return True


def list_webhooks() -> list[dict[str, Any]]:
    _ensure_dir()
    out: list[dict[str, Any]] = []
    for p in sorted(WEBHOOKS_DIR.glob("wh-*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("webhook list: skipping %s: %s", p.name, exc)
    return out


def clone_webhook(wid: str, *, owner_id: str | None,
                  new_name: str | None = None) -> dict[str, Any] | None:
    src = get_webhook(wid)
    if src is None:
        return None
    new = {
        **src,
        "owner_id":   owner_id,
        "visibility": "private",
        "name":       new_name or _clone_name(src.get("name") or "Untitled"),
    }
    new.pop("id", None)
    new.pop("created_at", None)
    new.pop("updated_at", None)
    return create_webhook(new)


def _clone_name(name: str) -> str:
    base = (name or "Untitled").strip()
    return base if base.endswith("(copy)") else f"{base} (copy)"


# ── Renderer ─────────────────────────────────────────────────────────────────
class RenderContext:
    """Bag of values the renderer pulls from. Built once per render pass.

    Why a class and not a dict: we want lazy + deterministic picks for the
    ``profile.<pool>.<field>`` family, so the *same* user object backs every
    ``{{profile.user.*}}`` lookup within a single render. The first lookup
    materialises a random pick; subsequent lookups reuse it.
    """

    _POOLS: dict[str, str] = {
        "user":         "users",
        "machine":      "machines",
        "c2":           "c2_servers",
        "malware":      "malware",
        "mail_sender":  "mail_senders",
    }

    def __init__(self, profile: dict[str, Any] | None,
                 custom: dict[str, Any] | None = None,
                 *, rng: random.Random | None = None) -> None:
        self.profile = profile or {}
        self.custom = custom or {}
        self._rng = rng or random.Random()
        self._picks: dict[str, dict[str, Any]] = {}
        self._epoch = time.time()
        self._uuid_cache: str | None = None

    def pick(self, pool_key: str) -> dict[str, Any] | None:
        """Return the chosen object for ``profile.<pool_key>.*`` lookups."""
        if pool_key in self._picks:
            return self._picks[pool_key]
        profile_key = self._POOLS.get(pool_key)
        if not profile_key:
            return None
        pool = self.profile.get(profile_key) or []
        if not pool:
            return None
        chosen = self._rng.choice(pool)
        self._picks[pool_key] = chosen
        return chosen

    def get(self, var: str) -> str | None:
        """Resolve a single ``foo.bar.baz`` path. Returns None on miss."""
        parts = var.split(".")
        if not parts:
            return None
        head = parts[0]

        if head == "profile":
            if len(parts) < 3:
                return None
            pool_key = parts[1]
            field = ".".join(parts[2:])
            obj = self.pick(pool_key)
            if obj is None:
                return None
            return _deep_get(obj, field)

        if head == "custom":
            if len(parts) < 2:
                return None
            val = _deep_get(self.custom, ".".join(parts[1:]))
            return val

        if head == "env":
            if len(parts) != 2:
                return None
            key = parts[1]
            if key not in ENV_ALLOWLIST:
                return None
            val = os.environ.get(key)
            return val if val is not None else None

        # Singletons ------------------------------------------------------
        if head == "now" and len(parts) == 1:
            return datetime.fromtimestamp(self._epoch, tz=timezone.utc).isoformat(timespec="seconds")
        if head == "epoch" and len(parts) == 1:
            return str(int(self._epoch))
        if head == "epoch_ms" and len(parts) == 1:
            return str(int(self._epoch * 1000))
        if head == "uuid" and len(parts) == 1:
            if self._uuid_cache is None:
                self._uuid_cache = str(uuid.uuid4())
            return self._uuid_cache
        return None


def _deep_get(obj: Any, dotted: str) -> str | None:
    """Walk ``obj`` along a dotted path. Returns the value cast to str."""
    cur: Any = obj
    for part in dotted.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        else:
            return None
    if cur is None:
        return None
    if isinstance(cur, (dict, list)):
        # Compact JSON serialisation for nested structures (consistent shape
        # whether the field happens to be scalar or composite).
        return json.dumps(cur, separators=(",", ":"))
    return str(cur)


def render(template: str, ctx: RenderContext) -> str:
    """Substitute ``{{vars}}`` in ``template`` using ``ctx``.

    Unknown variables become ``{{?<original>}}`` markers so authors see the
    gap rather than getting a silent empty string.
    """
    if not template:
        return ""

    def _sub(m: re.Match) -> str:
        name = m.group(1)
        val = ctx.get(name)
        if val is None:
            return "{{?" + name + "}}"
        return val
    return _VAR_RE.sub(_sub, template)


# ── Egress allowlist (SSRF guard) ────────────────────────────────────────────
_BLOCKED_NETS: tuple[ipaddress._BaseNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _parse_allowlist(raw: str) -> tuple[list[ipaddress._BaseNetwork], list[str]]:
    nets: list[ipaddress._BaseNetwork] = []
    hosts: list[str] = []
    for tok in (t.strip() for t in raw.split(",")):
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            hosts.append(tok.lower())
    return nets, hosts


# ── Settings (persisted; admin-editable from the UI) ─────────────────────────
# Hostname syntax restricted to RFC 1123 label rules — keeps log-of-shame
# entries like "rm -rf /" out of the persisted file.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def load_settings() -> dict[str, Any]:
    """Return persisted webhook settings. Shape:

    .. code-block:: python

        {"allowed_hosts": ["192.168.0.0/16", "collector.lab"]}

    Missing file → empty defaults. Malformed file → empty defaults plus a
    log warning, never an exception, so a corrupt settings file can't lock
    operators out of the admin UI.
    """
    if not SETTINGS_PATH.exists():
        return {"allowed_hosts": []}
    try:
        data = json.loads(SETTINGS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("webhook_settings.json unreadable (%s); falling back to defaults", exc)
        return {"allowed_hosts": []}
    if not isinstance(data, dict):
        return {"allowed_hosts": []}
    hosts = data.get("allowed_hosts") or []
    if not isinstance(hosts, list):
        hosts = []
    return {"allowed_hosts": [str(h).strip() for h in hosts if str(h).strip()]}


def validate_allowlist_entries(entries: Iterable[str]) -> tuple[list[str], list[str]]:
    """Return ``(accepted, rejected)``. ``accepted`` is the normalised list
    (CIDRs as their canonical form, hostnames lower-cased). ``rejected``
    carries human-readable reasons for the UI.
    """
    accepted: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for raw in entries:
        tok = (raw or "").strip()
        if not tok:
            continue
        # CIDR / IP first — covers IPv4 + IPv6, single addr or network.
        try:
            net = ipaddress.ip_network(tok, strict=False)
            canon = str(net)
        except ValueError:
            # Hostname fallback.
            if _HOSTNAME_RE.match(tok):
                canon = tok.lower()
            else:
                rejected.append(f"{tok!r}: not a valid CIDR or hostname")
                continue
        if canon in seen:
            continue
        seen.add(canon)
        accepted.append(canon)
    return accepted, rejected


def save_settings(payload: dict[str, Any]) -> dict[str, Any]:
    """Atomically persist webhook settings. Raises ``ValueError`` if the
    payload contains entries that fail validation, so the caller (REST
    handler) can return a 400 with the offending entries.
    """
    if not isinstance(payload, dict):
        raise ValueError("settings payload must be an object")
    raw = payload.get("allowed_hosts") or []
    if not isinstance(raw, list):
        raise ValueError("allowed_hosts must be a list of strings")
    accepted, rejected = validate_allowlist_entries(str(e) for e in raw)
    if rejected:
        raise ValueError("; ".join(rejected))
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps({"allowed_hosts": accepted},
                              indent=2, sort_keys=True))
    tmp.replace(SETTINGS_PATH)
    return {"allowed_hosts": accepted}


def _load_effective_allow_lists() -> tuple[
        list[ipaddress._BaseNetwork], list[str],
        list[ipaddress._BaseNetwork], list[str]]:
    """Merge env-var + persisted settings sources for the SSRF guard.

    Returns ``(env_nets, env_hosts, all_nets, all_hosts)`` so callers that
    need to differentiate the two sources (e.g. the UI's "read-only" badge)
    can do so without re-parsing.
    """
    env_raw = os.environ.get("APIGENIE_WEBHOOK_ALLOWED_HOSTS", "")
    env_nets, env_hosts = _parse_allowlist(env_raw)
    persisted = load_settings().get("allowed_hosts", [])
    persisted_nets, persisted_hosts = _parse_allowlist(",".join(persisted))
    all_nets = env_nets + persisted_nets
    all_hosts = env_hosts + persisted_hosts
    return env_nets, env_hosts, all_nets, all_hosts


def _resolve_host(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve ``host`` to a list of addresses. Empty list on resolution failure."""
    out: list[ipaddress._BaseAddress] = []
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return out
    for info in infos:
        addr = info[4][0]
        try:
            out.append(ipaddress.ip_address(addr))
        except ValueError:
            pass
    return out


def _is_url_allowed(url: str) -> tuple[bool, str]:
    """Return (allowed, reason). ``reason`` is empty on success, human-readable
    on rejection so the UI can surface what went wrong.

    Resolution order:
      1. Parse host. Reject if absent.
      2. Build user allowlist from APIGENIE_WEBHOOK_ALLOWED_HOSTS.
      3. If hostname is in the allowlist's host literals — allow.
      4. Resolve to addresses. If any address falls in a blocked network and
         is NOT covered by an allowlist CIDR — reject.
      5. Otherwise — allow.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip()
    if not host:
        return False, "URL has no host"

    _, _, allow_nets, allow_hosts = _load_effective_allow_lists()

    if host.lower() in allow_hosts:
        return True, ""

    addrs = _resolve_host(host)
    if not addrs:
        # We can't tell if it's safe — be cautious but not draconian: allow
        # only if the bare hostname is in the allowlist (handled above) or
        # if no addresses came back at all because the host is a literal IP.
        try:
            addrs = [ipaddress.ip_address(host)]
        except ValueError:
            return False, f"could not resolve {host!r}"

    for addr in addrs:
        # If any allowlist CIDR covers this address, accept.
        if any(addr in net for net in allow_nets):
            continue
        # Otherwise reject if it's in a blocked network.
        if any(addr in net for net in _BLOCKED_NETS):
            return False, (
                f"refusing private/loopback/link-local target {addr} "
                f"(allow it under Settings → Webhook egress allowlist, or "
                f"via APIGENIE_WEBHOOK_ALLOWED_HOSTS)"
            )
    return True, ""


# ── Build & send ─────────────────────────────────────────────────────────────
def _redact_header(name: str, value: str) -> str:
    if not value:
        return value
    if name.lower() not in SENSITIVE_HEADERS:
        return value
    # Keep last 4 chars to help debugging without exposing the secret.
    tail = value[-4:] if len(value) > 4 else "?"
    return f"<redacted:****{tail}>"


def _build_headers(wh: dict[str, Any], ctx: RenderContext) -> dict[str, str]:
    out: dict[str, str] = {}
    for kv in wh.get("headers") or []:
        k = render(kv.get("key", ""), ctx).strip()
        if not k:
            continue
        out[k] = render(kv.get("value", ""), ctx)
    auth = wh.get("auth") or {}
    t = (auth.get("type") or "none").lower()
    if t == "basic":
        import base64
        u = render(auth.get("username", "") or "", ctx)
        p = render(auth.get("password", "") or "", ctx)
        token = base64.b64encode(f"{u}:{p}".encode()).decode()
        out["Authorization"] = f"Basic {token}"
    elif t == "bearer":
        v = render(auth.get("token_value", "") or "", ctx)
        out["Authorization"] = f"Bearer {v}"
    elif t == "custom":
        prefix = (auth.get("token_prefix") or "").strip()
        v = render(auth.get("token_value", "") or "", ctx)
        out["Authorization"] = f"{prefix} {v}".strip()
    return out


def _build_query(items: Iterable[dict[str, Any]], ctx: RenderContext) -> str:
    pairs: list[tuple[str, str]] = []
    for kv in items or []:
        k = render(kv.get("key", ""), ctx).strip()
        if not k:
            continue
        pairs.append((k, render(kv.get("value", ""), ctx)))
    if not pairs:
        return ""
    return ("?" if "?" not in "" else "&") + urlencode(pairs)


def send_webhook(wh: dict[str, Any],
                 *,
                 profile: dict[str, Any] | None = None,
                 custom_vars: dict[str, Any] | None = None,
                 override_url: str | None = None) -> dict[str, Any]:
    """Render and send a webhook. Returns a result dict.

    Result shape::

        {"status": 200, "elapsed_ms": 123,
         "response_headers": {...}, "response_body": "...",
         "response_truncated": False,
         "effective_request": {"url": "...", "method": "POST",
                               "headers": {...redacted...}, "body": "..."},
         "error": None}

    On guard rejection (SSRF / validation), ``status`` is 0 and ``error``
    carries the human-readable reason.
    """
    import httpx  # lazy — only imported when actually sending

    ctx = RenderContext(profile=profile, custom=custom_vars)

    url = render(override_url or wh.get("url") or "", ctx)
    method = (wh.get("method") or "POST").upper()
    headers = _build_headers(wh, ctx)
    query = _build_query(wh.get("query") or [], ctx)
    if query:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query.lstrip('?').lstrip('&')}"

    body: str | None = None
    if method in ("POST", "PUT", "PATCH"):
        rendered = render(wh.get("body_template") or "", ctx)
        fmt = (wh.get("body_format") or "json").lower()
        if fmt == "json" and rendered.strip():
            # Validate that the rendered template is parseable JSON; surface
            # broken JSON as a clear pre-send error rather than letting the
            # server reject it 20 ms later.
            try:
                parsed = json.loads(rendered)
                rendered = json.dumps(parsed, separators=(",", ":"))
            except json.JSONDecodeError as exc:
                return {
                    "status": 0, "elapsed_ms": 0,
                    "response_headers": {}, "response_body": "",
                    "response_truncated": False,
                    "effective_request": {"url": url, "method": method,
                                          "headers": _redact_dict(headers),
                                          "body": rendered},
                    "error": f"body_template did not render to valid JSON: {exc}",
                }
            headers.setdefault("Content-Type", "application/json")
        elif fmt == "form" and rendered.strip():
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        body = rendered

    # ── Guardrails ────────────────────────────────────────────────────────
    allowed, reason = _is_url_allowed(url)
    if not allowed:
        return {
            "status": 0, "elapsed_ms": 0,
            "response_headers": {}, "response_body": "",
            "response_truncated": False,
            "effective_request": {"url": url, "method": method,
                                  "headers": _redact_dict(headers), "body": body},
            "error": f"egress blocked: {reason}",
        }

    # ── Actual send ───────────────────────────────────────────────────────
    started = time.monotonic()
    try:
        with httpx.Client(timeout=HARD_TIMEOUT_SECS,
                          follow_redirects=False) as client:
            r = client.request(method, url, headers=headers, content=body)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        raw = r.text or ""
        truncated = len(raw) > RESPONSE_BODY_CAP
        body_out = raw[:RESPONSE_BODY_CAP]
        return {
            "status":              r.status_code,
            "elapsed_ms":          elapsed_ms,
            "response_headers":    dict(r.headers),
            "response_body":       body_out,
            "response_truncated":  truncated,
            "effective_request":   {"url": url, "method": method,
                                    "headers": _redact_dict(headers), "body": body},
            "error":               None,
        }
    except httpx.TimeoutException:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "status": 0, "elapsed_ms": elapsed_ms,
            "response_headers": {}, "response_body": "",
            "response_truncated": False,
            "effective_request": {"url": url, "method": method,
                                  "headers": _redact_dict(headers), "body": body},
            "error": f"timeout after {HARD_TIMEOUT_SECS:.0f}s",
        }
    except httpx.HTTPError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "status": 0, "elapsed_ms": elapsed_ms,
            "response_headers": {}, "response_body": "",
            "response_truncated": False,
            "effective_request": {"url": url, "method": method,
                                  "headers": _redact_dict(headers), "body": body},
            "error": f"{type(exc).__name__}: {exc}",
        }


def _redact_dict(headers: dict[str, str]) -> dict[str, str]:
    return {k: _redact_header(k, v) for k, v in (headers or {}).items()}


# ── "Copy as curl" helper ────────────────────────────────────────────────────
def to_curl(effective_request: dict[str, Any]) -> str:
    """Render an "effective request" back into a copy-pastable curl command.

    Sensitive headers are kept *un-redacted* here because the user has
    explicitly asked for a working curl. The UI should make this clear via
    a confirmation step before exposing the string.
    """
    url = effective_request.get("url") or ""
    method = (effective_request.get("method") or "GET").upper()
    headers = effective_request.get("headers") or {}
    body = effective_request.get("body")
    parts = ["curl", "-sS", "-X", method]
    for k, v in headers.items():
        # Restore the real secret from the redacted marker if possible — but
        # callers usually pass the un-redacted dict here.
        parts.append("-H")
        parts.append(_shell_quote(f"{k}: {v}"))
    if body is not None:
        parts.append("--data-binary")
        parts.append(_shell_quote(body))
    parts.append(_shell_quote(url))
    return " ".join(parts)


def _shell_quote(s: str) -> str:
    if s == "":
        return "''"
    if all(c.isalnum() or c in "@%+=:,./-_" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"
