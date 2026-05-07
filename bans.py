"""IP ban management — persistent bans with expiry.

Bans are stored in ``<DATA>/bans.json`` and loaded on startup. Each ban has an
expiry timestamp; expired bans are lazily cleaned on lookup and on each
periodic pruning pass.

The ``is_banned`` check is O(1) via an in-memory dict and is called from
``TraceMiddleware`` on every request before any routing.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.environ.get("APIGENIE_DATA", "/var/lib/apigenie"))
_BANS_FILE = _DATA_ROOT / "bans.json"

# ip → {"until_iso": str, "reason": str, "created_iso": str}
_bans: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


# ── Persistence ─────────────────────────────────────────────────────────────────

def _load() -> None:
    global _bans
    if not _BANS_FILE.is_file():
        return
    try:
        with _BANS_FILE.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if isinstance(raw, dict):
            _bans = raw
            log.info("bans: loaded %d entries from disk", len(_bans))
    except Exception as exc:  # noqa: BLE001
        log.warning("bans: could not load %s: %s", _BANS_FILE, exc)


def _save() -> None:
    try:
        _DATA_ROOT.mkdir(parents=True, exist_ok=True)
        with _BANS_FILE.open("w", encoding="utf-8") as fh:
            json.dump(_bans, fh, indent=2)
    except Exception as exc:  # noqa: BLE001
        log.warning("bans: could not save %s: %s", _BANS_FILE, exc)


_load()  # on module import


# ── Public API ──────────────────────────────────────────────────────────────────

def is_banned(ip: str) -> bool:
    """Return True if ``ip`` is currently banned (not expired)."""
    with _lock:
        entry = _bans.get(ip)
        if entry is None:
            return False
        until = datetime.fromisoformat(entry["until_iso"])
        if datetime.now(timezone.utc) >= until:
            del _bans[ip]
            _save()
            return False
        return True


def ban_ip(ip: str, minutes: int = 0, hours: int = 0, days: int = 0,
           reason: str = "manual") -> dict[str, Any]:
    """Ban ``ip`` for the given duration. Returns the created ban entry."""
    duration = timedelta(minutes=minutes, hours=hours, days=days)
    if duration.total_seconds() <= 0:
        duration = timedelta(hours=1)  # default 1 hour
    now = datetime.now(timezone.utc)
    until = now + duration
    entry = {
        "until_iso": until.isoformat(timespec="seconds"),
        "created_iso": now.isoformat(timespec="seconds"),
        "reason": reason,
        "duration": str(duration),
    }
    with _lock:
        _bans[ip] = entry
        _save()
    log.info("bans: banned %s until %s (%s)", ip, entry["until_iso"], reason)
    return {"ip": ip, **entry}


def unban_ip(ip: str) -> bool:
    """Remove ban for ``ip``. Returns True if it existed."""
    with _lock:
        if ip in _bans:
            del _bans[ip]
            _save()
            log.info("bans: unbanned %s", ip)
            return True
    return False


def list_bans() -> list[dict[str, Any]]:
    """Return all active (non-expired) bans."""
    now = datetime.now(timezone.utc)
    active: list[dict[str, Any]] = []
    expired_keys: list[str] = []
    with _lock:
        for ip, entry in _bans.items():
            until = datetime.fromisoformat(entry["until_iso"])
            if now >= until:
                expired_keys.append(ip)
            else:
                remaining = until - now
                active.append({
                    "ip": ip,
                    **entry,
                    "remaining_seconds": int(remaining.total_seconds()),
                })
        for k in expired_keys:
            del _bans[k]
        if expired_keys:
            _save()
    return active


def ban_info(ip: str) -> dict[str, Any] | None:
    """Return ban details for a single IP, or None."""
    with _lock:
        entry = _bans.get(ip)
        if entry is None:
            return None
        until = datetime.fromisoformat(entry["until_iso"])
        now = datetime.now(timezone.utc)
        if now >= until:
            del _bans[ip]
            _save()
            return None
        remaining = until - now
        return {"ip": ip, **entry, "remaining_seconds": int(remaining.total_seconds())}
