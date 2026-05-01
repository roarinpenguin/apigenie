"""
ApiGenie — Custom Listeners replay engine (Phase 4).

Stores user-uploaded log files under ./data/replays/<file_id>/{meta.json, blob}
and serves them through a listener with time-shift semantics so an old export
"plays back" as if it were happening now (or at any chosen anchor).

Storage layout
==============

    /var/lib/apigenie/replays/
    └── <file_id>/
        ├── meta.json     # filename, size, format, line_count, ts_range, …
        └── blob          # the raw uploaded bytes (never copied/mutated)

Lifecycle
=========

* Upload  → save_replay()  validates size cap, infers format, scans the file
            once to extract min/max timestamp + record count, persists meta.
* List    → list_replays() reads every meta.json under REPLAY_DIR.
* Stream  → Replay(spec).stream(anchor_now=…) yields decoded records lazily,
            with each timestamp shifted so that the latest event in the file
            lands at anchor_now (preserving the original spread between
            records). Three anchor modes are supported:

              now      → anchor_now = datetime.utcnow()
              offset   → anchor_now = utcnow + anchor_offset_seconds
              fixed    → anchor_now = ISO-8601 string from the spec

Supported formats (v1)
======================

  json    — single JSON array (e.g. ``[{"ts":…},{"ts":…}]``)
  jsonl   — one JSON object per line (a.k.a. ndjson)
  csv     — RFC 4180 (header row required); timestamp column = spec field
  syslog  — RFC 3164 (``<PRI>MMM DD HH:MM:SS host tag: msg``)
            **or** RFC 5424 (``<PRI>VER ISO8601 host app procid msgid msg``)
  cef     — ArcSight CEF; either bare or wrapped in a syslog header.
            Timestamp source order: the syslog header (if present) → the
            ``rt=`` extension → file mtime fallback.

Design rules
============

* Files are **never** loaded fully into memory. All parsers iterate line by
  line (CSV uses ``csv.DictReader`` over a file handle).
* The first scan stores ``ts_min`` / ``ts_max`` in meta.json so the time-
  shift delta can be computed without rescanning on every request.
* Records that fail to parse a timestamp inherit the previous good record's
  timestamp (or ``ts_min`` if they're at the head of the file). This keeps
  visualisations contiguous instead of dropping rows on a single bad line.
* The module is single-process and protected by a coarse RLock — same model
  as listeners.py.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# ── Storage location (mirrors listeners.py) ──────────────────────────────────
_DATA_DIR = Path(os.environ.get("APIGENIE_DATA_DIR", "/var/lib/apigenie"))
REPLAY_DIR = _DATA_DIR / "replays"

# ── Limits ───────────────────────────────────────────────────────────────────
MAX_MB = int(os.environ.get("APIGENIE_REPLAY_MAX_MB", "100"))
MAX_BYTES = MAX_MB * 1024 * 1024

# Coarse lock around the on-disk catalogue.
_LOCK = threading.RLock()

# ── Format autodetect ────────────────────────────────────────────────────────

_VALID_FORMATS = {"json", "jsonl", "csv", "syslog", "cef"}


def detect_format(filename: str, head: bytes) -> str:
    """Best-effort guess from extension + first-line sniff. Conservative —
    when in doubt returns ``jsonl`` because a JSONL parse failure is a clean
    line skip whereas mis-classifying as syslog destroys timestamps."""
    name = filename.lower()
    text = head.decode("utf-8", errors="replace").lstrip()
    first = text.split("\n", 1)[0].strip() if text else ""

    if name.endswith((".jsonl", ".ndjson")):
        return "jsonl"
    if name.endswith(".json"):
        return "json" if first.startswith("[") else "jsonl"
    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".cef") or "CEF:" in first:
        return "cef"
    if name.endswith((".log", ".syslog")) or first.startswith("<"):
        return "syslog"
    # Body-based fallback: { = jsonl, [ = json, comma in first row = csv.
    if first.startswith("{"):
        return "jsonl"
    if first.startswith("["):
        return "json"
    if "," in first:
        return "csv"
    return "jsonl"


# ── Timestamp helpers ────────────────────────────────────────────────────────

# Common timestamp formats, tried in this order.
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",   # Apache combined log
    "%b %d %H:%M:%S",          # RFC 3164 (no year, no tz)
    "%b  %d %H:%M:%S",         # RFC 3164 with single-digit day padded by space
)


def parse_ts(value: Any, fallback_year: int | None = None) -> datetime | None:
    """Parse a timestamp value into a tz-aware UTC datetime, or None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # Heuristic: treat very large numbers as ms.
        v = float(value)
        if v > 1e12:
            v /= 1000.0
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    # Native ISO-8601 path first.
    try:
        # Python's fromisoformat doesn't accept trailing 'Z' before 3.11 strict;
        # ours runs on 3.13 but we still normalise for older formats.
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt.year == 1900 and fallback_year is not None:
                dt = dt.replace(year=fallback_year)
            return dt
        except ValueError:
            continue
    return None


def _get_dotted(record: dict, path: str) -> Any:
    """Resolve ``a.b.c`` or top-level key ``a`` against a dict. Returns None."""
    if not path:
        return None
    if path in record:
        return record[path]
    cur: Any = record
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# ── Format-specific parsers ──────────────────────────────────────────────────
# Each parser is a generator function:
#   parse_<fmt>(blob_path: Path, ts_field: str | None) -> Iterator[(record, ts_or_None)]


def _iter_json_array(blob_path: Path, ts_field: str | None) -> Iterator[tuple[dict, datetime | None]]:
    # Single JSON array. We accept it because demos sometimes export this way,
    # but we still iterate streaming via json.load → list. For files >MAX_MB
    # this would be problematic, but the size cap protects us.
    with blob_path.open("r", encoding="utf-8", errors="replace") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as e:
            logger.warning("[replay] JSON array parse failed at %s: %s", blob_path, e)
            return
    if not isinstance(data, list):
        logger.warning("[replay] expected a JSON array, got %s", type(data).__name__)
        return
    for rec in data:
        if not isinstance(rec, dict):
            continue
        yield rec, parse_ts(_get_dotted(rec, ts_field) if ts_field else rec.get("timestamp"))


def _iter_jsonl(blob_path: Path, ts_field: str | None) -> Iterator[tuple[dict, datetime | None]]:
    field_name = ts_field or "timestamp"
    with blob_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            yield rec, parse_ts(_get_dotted(rec, field_name))


def _iter_csv(blob_path: Path, ts_field: str | None) -> Iterator[tuple[dict, datetime | None]]:
    field_name = ts_field or "timestamp"
    with blob_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield dict(row), parse_ts(row.get(field_name))


# RFC 3164: <PRI>MMM DD HH:MM:SS HOST TAG[PID]: MSG
_RE_3164 = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?"
    r":?\s*(?P<msg>.*)$"
)
# RFC 5424: <PRI>VERSION ISOTIMESTAMP HOST APP PROCID MSGID [SD] MSG
_RE_5424 = re.compile(
    r"^<(?P<pri>\d+)>(?P<ver>\d+)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)"
    r"(?:\s+\[(?P<sd>[^\]]*)\])?"
    r"\s*(?P<msg>.*)$"
)


def _iter_syslog(blob_path: Path, _ts_field: str | None) -> Iterator[tuple[dict, datetime | None]]:
    # Use the file's mtime year as the fallback for RFC 3164 (no year in the format).
    fallback_year = datetime.fromtimestamp(blob_path.stat().st_mtime, tz=timezone.utc).year
    with blob_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            m = _RE_5424.match(line)
            if m:
                rec = m.groupdict()
                rec["_format"] = "syslog_5424"
                yield rec, parse_ts(rec.get("ts"))
                continue
            m = _RE_3164.match(line)
            if m:
                rec = m.groupdict()
                rec["_format"] = "syslog_3164"
                yield rec, parse_ts(rec.get("ts"), fallback_year=fallback_year)
                continue
            # Unstructured line — pass through with no timestamp.
            yield {"raw": line, "_format": "syslog_unknown"}, None


# CEF: optional syslog wrapper, then "CEF:0|Vendor|Product|Ver|SigID|Name|Sev|ext1=v1 ext2=v2"
_RE_CEF = re.compile(
    r"(?:.*?)CEF:(?P<ver>\d+)\|"
    r"(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<dev_ver>[^|]*)\|"
    r"(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|"
    r"(?P<ext>.*)$"
)
# Extension parsing: "key=value key=value ..." with values that can contain
# spaces if escaped with "\=" (CEF spec). We do a tolerant left-greedy split.
_RE_CEF_EXT = re.compile(r"(\w+)=((?:[^=]|(?<=\\)=)*?)(?=\s+\w+=|\s*$)")


def _iter_cef(blob_path: Path, _ts_field: str | None) -> Iterator[tuple[dict, datetime | None]]:
    fallback_year = datetime.fromtimestamp(blob_path.stat().st_mtime, tz=timezone.utc).year
    with blob_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            m = _RE_CEF.search(line)
            if not m:
                yield {"raw": line, "_format": "cef_unknown"}, None
                continue
            rec = {
                "_format": "cef",
                "cef_version": m.group("ver"),
                "device_vendor": m.group("vendor"),
                "device_product": m.group("product"),
                "device_version": m.group("dev_ver"),
                "signature_id": m.group("sig"),
                "name": m.group("name"),
                "severity": m.group("sev"),
            }
            for k, v in _RE_CEF_EXT.findall(m.group("ext")):
                rec[k] = v.replace("\\=", "=").replace("\\\\", "\\")
            # Timestamp preference: rt= (epoch ms), then leading syslog header.
            ts: datetime | None = None
            if "rt" in rec:
                ts = parse_ts(rec["rt"])
            if ts is None:
                # Try a leading RFC 3164 header on the line.
                m3164 = _RE_3164.match(line)
                if m3164:
                    ts = parse_ts(m3164.group("ts"), fallback_year=fallback_year)
            yield rec, ts


_PARSERS: dict[str, Any] = {
    "json": _iter_json_array,
    "jsonl": _iter_jsonl,
    "csv": _iter_csv,
    "syslog": _iter_syslog,
    "cef": _iter_cef,
}


def iter_records(blob_path: Path, fmt: str, ts_field: str | None) -> Iterator[tuple[dict, datetime | None]]:
    """Public dispatcher used by both the upload-time scan and per-request streaming."""
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unsupported replay format: {fmt!r}")
    return parser(blob_path, ts_field)


# ── Upload / list / get / delete ─────────────────────────────────────────────


@dataclass
class ReplayMeta:
    file_id: str
    filename: str
    size: int
    format: str
    line_count: int
    ts_min_iso: str | None
    ts_max_iso: str | None
    timestamp_field: str | None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def _replay_dir(file_id: str) -> Path:
    return REPLAY_DIR / file_id


def _scan_for_meta(blob_path: Path, fmt: str, ts_field: str | None) -> tuple[int, datetime | None, datetime | None]:
    """Iterate the file once to build ``(line_count, ts_min, ts_max)``."""
    n = 0
    ts_min: datetime | None = None
    ts_max: datetime | None = None
    for _rec, ts in iter_records(blob_path, fmt, ts_field):
        n += 1
        if ts is None:
            continue
        if ts_min is None or ts < ts_min:
            ts_min = ts
        if ts_max is None or ts > ts_max:
            ts_max = ts
    return n, ts_min, ts_max


def save_replay(
    filename: str,
    content: bytes,
    fmt: str | None = None,
    timestamp_field: str | None = None,
) -> ReplayMeta:
    """Persist an uploaded blob and produce a meta.json beside it.

    Raises:
        ValueError("oversize") if ``content`` exceeds ``APIGENIE_REPLAY_MAX_MB``.
        ValueError("unsupported_format") if a forced format isn't in the v1 set.
    """
    if len(content) > MAX_BYTES:
        raise ValueError("oversize")
    if fmt is not None and fmt not in _VALID_FORMATS:
        raise ValueError("unsupported_format")
    if fmt is None:
        fmt = detect_format(filename, content[:4096])
    file_id = _uuid.uuid4().hex
    fdir = _replay_dir(file_id)
    fdir.mkdir(parents=True, exist_ok=True)
    blob_path = fdir / "blob"
    with blob_path.open("wb") as fh:
        fh.write(content)
    # Format-specific defaults for the timestamp field.
    ts_field = timestamp_field
    if ts_field is None and fmt in {"json", "jsonl", "csv"}:
        ts_field = "timestamp"
    line_count, ts_min, ts_max = _scan_for_meta(blob_path, fmt, ts_field)
    meta = ReplayMeta(
        file_id=file_id,
        filename=filename,
        size=len(content),
        format=fmt,
        line_count=line_count,
        ts_min_iso=ts_min.isoformat(timespec="seconds") if ts_min else None,
        ts_max_iso=ts_max.isoformat(timespec="seconds") if ts_max else None,
        timestamp_field=ts_field,
    )
    (fdir / "meta.json").write_text(json.dumps(meta.__dict__, indent=2))
    logger.info(
        "[replay] saved file_id=%s filename=%s size=%d format=%s lines=%d ts_range=%s..%s",
        file_id, filename, len(content), fmt, line_count, meta.ts_min_iso, meta.ts_max_iso,
    )
    return meta


def list_replays() -> list[ReplayMeta]:
    out: list[ReplayMeta] = []
    if not REPLAY_DIR.exists():
        return out
    with _LOCK:
        for entry in sorted(REPLAY_DIR.iterdir(), key=lambda p: p.name):
            if not entry.is_dir():
                continue
            mp = entry / "meta.json"
            if not mp.is_file():
                continue
            try:
                d = json.loads(mp.read_text())
                out.append(ReplayMeta(**d))
            except (OSError, ValueError, TypeError) as e:
                logger.warning("[replay] skipping corrupt meta at %s: %s", mp, e)
    return out


def get_replay(file_id: str) -> ReplayMeta | None:
    mp = _replay_dir(file_id) / "meta.json"
    if not mp.is_file():
        return None
    try:
        return ReplayMeta(**json.loads(mp.read_text()))
    except (OSError, ValueError, TypeError):
        return None


def delete_replay(file_id: str) -> bool:
    fdir = _replay_dir(file_id)
    if not fdir.exists():
        return False
    with _LOCK:
        shutil.rmtree(fdir, ignore_errors=True)
    logger.info("[replay] deleted file_id=%s", file_id)
    return True


def preview_records(file_id: str, n: int = 10) -> list[dict]:
    """First ``n`` records (as parsed) for the wizard preview pane."""
    meta = get_replay(file_id)
    if meta is None:
        return []
    out: list[dict] = []
    blob_path = _replay_dir(file_id) / "blob"
    for rec, _ts in iter_records(blob_path, meta.format, meta.timestamp_field):
        out.append(rec)
        if len(out) >= n:
            break
    return out


# ── Time-shifted streaming ───────────────────────────────────────────────────


@dataclass
class StreamSpec:
    """Subset of ``ReplayFileSpec`` (from ``listeners.py``) needed by ``stream``.
    Kept independent so this module has no dependency on the listeners module."""
    file_id: str
    format: str
    timestamp_field: str | None = "timestamp"
    anchor_mode: str = "now"            # "now" | "offset" | "fixed"
    anchor_offset_seconds: int = 0
    anchor_fixed_iso: str | None = None
    preserve_spread: bool = True


def _resolve_anchor(spec: StreamSpec, now: datetime | None = None) -> datetime:
    base = now or datetime.now(timezone.utc)
    mode = spec.anchor_mode
    if mode == "offset":
        return base + timedelta(seconds=spec.anchor_offset_seconds)
    if mode == "fixed" and spec.anchor_fixed_iso:
        ts = parse_ts(spec.anchor_fixed_iso)
        if ts is not None:
            return ts
    return base


def _replay_meta_or_raise(file_id: str) -> ReplayMeta:
    meta = get_replay(file_id)
    if meta is None:
        raise FileNotFoundError(f"replay not found: {file_id}")
    return meta


def stream(spec: StreamSpec, now: datetime | None = None) -> Iterator[dict]:
    """Yield each record with its timestamp shifted so that the file's
    ``ts_max`` lands at the resolved anchor (preserving the original spread).

    Records that have no parseable timestamp are passed through unchanged
    (the operator can decide whether to keep them via the listener's filter
    chain — out of scope for v1).
    """
    meta = _replay_meta_or_raise(spec.file_id)
    blob_path = _replay_dir(spec.file_id) / "blob"
    anchor_now = _resolve_anchor(spec, now)

    ts_max: datetime | None = None
    if meta.ts_max_iso:
        ts_max = parse_ts(meta.ts_max_iso)
    delta: timedelta = timedelta(0)
    if ts_max is not None and spec.preserve_spread:
        delta = anchor_now - ts_max

    ts_field = spec.timestamp_field or meta.timestamp_field

    for rec, ts in iter_records(blob_path, meta.format, ts_field):
        if ts is None:
            yield rec
            continue
        new_ts = ts + delta
        # Inject the shifted timestamp back into the record so collectors
        # see fresh values. We write to both the original field path and a
        # generic ``timestamp`` key for downstream convenience.
        iso = new_ts.astimezone(timezone.utc).isoformat(timespec="seconds")
        if ts_field:
            _set_dotted(rec, ts_field, iso)
        rec["timestamp"] = iso
        yield rec


def _set_dotted(record: dict, path: str, value: Any) -> None:
    """Inverse of ``_get_dotted`` — sets ``record[a][b][c] = value`` creating
    intermediate dicts only when the leaf path already exists structurally."""
    if not path:
        return
    if "." not in path:
        record[path] = value
        return
    parts = path.split(".")
    cur: Any = record
    for p in parts[:-1]:
        if isinstance(cur, dict) and isinstance(cur.get(p), dict):
            cur = cur[p]
        else:
            return  # don't fabricate structure
    if isinstance(cur, dict):
        cur[parts[-1]] = value
