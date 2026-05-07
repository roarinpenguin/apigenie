"""Persistent request log — rotational JSONL files with a configurable disk cap.

Every API request traced by ``TraceMiddleware`` is also appended (non-blocking)
to ``<DATA>/request-logs/YYYY-MM-DD.jsonl``. One line per request, one file per
calendar day.

A background thread prunes the oldest daily files whenever the total size exceeds
``APIGENIE_REQUEST_LOG_CAP_GB`` (default 5). Pruning runs once at startup and then
every hour.

The module exposes a search function that scans recent files for a given IP,
used by the investigation dashboard.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.environ.get("APIGENIE_DATA", "/var/lib/apigenie"))
LOG_DIR = _DATA_ROOT / "request-logs"
_CAP_BYTES = int(float(os.environ.get("APIGENIE_REQUEST_LOG_CAP_GB", "5")) * 1_073_741_824)

# ── Write path ──────────────────────────────────────────────────────────────────

_write_lock = threading.Lock()


def _today_file() -> Path:
    return LOG_DIR / (datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".jsonl")


def append(entry: dict[str, Any]) -> None:
    """Append a trace entry to today's JSONL file. Non-blocking best-effort."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, default=str, separators=(",", ":")) + "\n"
        with _write_lock:
            with _today_file().open("a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception as exc:  # noqa: BLE001
        log.debug("request_log: write failed: %s", exc)


# ── Pruner ──────────────────────────────────────────────────────────────────────

_PRUNE_INTERVAL = 3600  # seconds


def _sorted_log_files() -> list[Path]:
    """Return daily JSONL files sorted oldest-first."""
    if not LOG_DIR.is_dir():
        return []
    return sorted(LOG_DIR.glob("*.jsonl"))


def _total_size(files: list[Path]) -> int:
    return sum(f.stat().st_size for f in files if f.exists())


def prune() -> int:
    """Delete oldest daily files until total size is within cap. Returns count deleted."""
    files = _sorted_log_files()
    deleted = 0
    while _total_size(files) > _CAP_BYTES and files:
        victim = files.pop(0)
        try:
            victim.unlink()
            deleted += 1
            log.info("request_log: pruned %s", victim.name)
        except OSError as exc:
            log.warning("request_log: could not prune %s: %s", victim.name, exc)
    return deleted


def _pruner_loop() -> None:
    """Background thread: prune on startup, then every hour."""
    while True:
        try:
            prune()
        except Exception as exc:  # noqa: BLE001
            log.warning("request_log: pruner error: %s", exc)
        time.sleep(_PRUNE_INTERVAL)


_pruner_started = False


def start_pruner() -> None:
    global _pruner_started
    if _pruner_started:
        return
    _pruner_started = True
    t = threading.Thread(target=_pruner_loop, daemon=True, name="request-log-pruner")
    t.start()
    log.info("request_log: pruner started (cap=%.1f GB)", _CAP_BYTES / 1_073_741_824)


# ── Query path (for investigation dashboard) ────────────────────────────────────

def search_by_ip(ip: str, max_days: int = 1, limit: int = 500) -> list[dict[str, Any]]:
    """Return up to ``limit`` entries from the most recent ``max_days`` files
    where ``entry["client"] == ip``. Newest first."""
    files = _sorted_log_files()
    files = files[-max_days:]  # most recent N days
    files.reverse()  # newest-first
    results: list[dict[str, Any]] = []
    for fp in files:
        try:
            with fp.open("r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("client") == ip:
                        results.append(entry)
                        if len(results) >= limit:
                            return results
        except OSError:
            continue
    return results


def total_size_bytes() -> int:
    """Return current total size of all log files."""
    return _total_size(_sorted_log_files())


def file_list() -> list[dict[str, Any]]:
    """Return metadata about each daily log file."""
    return [
        {"name": f.name, "size": f.stat().st_size, "mtime": f.stat().st_mtime}
        for f in _sorted_log_files()
        if f.exists()
    ]
