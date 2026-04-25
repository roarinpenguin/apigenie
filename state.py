"""In-memory state management for stateful mock flows (Tenable async exports)."""

import threading
import time
from typing import Any

TENABLE_EXPORT_TTL = 3600  # seconds

_tenable_cache: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]] = {}
_tenable_lock = threading.Lock()


def tenable_store_export(export_type: str, export_uuid: str, chunks: list[dict[str, Any]]) -> None:
    with _tenable_lock:
        _tenable_cache[(export_type, export_uuid)] = (time.time(), chunks)


def tenable_get_chunks(export_type: str, export_uuid: str) -> list[dict[str, Any]] | None:
    with _tenable_lock:
        _evict_expired()
        entry = _tenable_cache.get((export_type, export_uuid))
        if entry is None:
            return None
        return entry[1]


def tenable_export_exists(export_type: str, export_uuid: str) -> bool:
    with _tenable_lock:
        _evict_expired()
        return (export_type, export_uuid) in _tenable_cache


def _evict_expired() -> None:
    now = time.time()
    expired = [k for k, (ts, _) in _tenable_cache.items() if now - ts > TENABLE_EXPORT_TTL]
    for k in expired:
        del _tenable_cache[k]
