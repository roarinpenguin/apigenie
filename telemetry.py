"""Persistent usage telemetry — minute-granularity request counts in SQLite.

Records are written via ``record(source)`` from the trace middleware. A
background thread flushes the in-memory buffer to disk every 10 s and
prunes rows older than ~1 year once per hour.

Query API:
    ``query(range_key)`` returns time-bucketed counts ready for the
    Observability → Usage-over-Time chart.  ``range_key`` is one of
    ``1h 6h 24h 7d 30d 90d 1y``.
"""

import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.environ.get("APIGENIE_DATA_DIR",
                                  os.environ.get("APIGENIE_DATA", "/var/lib/apigenie")))
DB_PATH = _DATA_ROOT / "telemetry.db"
RETENTION_DAYS = 366

# ── In-memory write buffer ────────────────────────────────────────────────────

_lock = threading.Lock()
_buffer: dict[tuple[str, str], int] = {}   # (minute_bucket, source) → count

# ── SQLite handle (lazy) ──────────────────────────────────────────────────────

_db: sqlite3.Connection | None = None


def _get_db() -> sqlite3.Connection:
    global _db
    if _db is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("PRAGMA synchronous=NORMAL")
        _db.execute("""
            CREATE TABLE IF NOT EXISTS usage (
                ts     TEXT NOT NULL,
                source TEXT NOT NULL,
                count  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (ts, source)
            )
        """)
        _db.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
        _db.commit()
    return _db


# ── Public API ────────────────────────────────────────────────────────────────

def record(source: str) -> None:
    """Increment the current-minute bucket for *source*."""
    bucket = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    key = (bucket, source)
    with _lock:
        _buffer[key] = _buffer.get(key, 0) + 1


def flush() -> None:
    """Write the in-memory buffer to SQLite.  Safe to call often."""
    with _lock:
        if not _buffer:
            return
        snapshot = dict(_buffer)
        _buffer.clear()
    db = _get_db()
    with db:
        for (ts, source), count in snapshot.items():
            db.execute(
                "INSERT INTO usage (ts, source, count) VALUES (?, ?, ?)"
                " ON CONFLICT(ts, source) DO UPDATE SET count = count + excluded.count",
                (ts, source, count),
            )


# ── Range → bucket-size mapping ──────────────────────────────────────────────
# Each entry: (timedelta offset, bucket-size label, aggregation SQL strftime)

_RANGES: dict[str, tuple[timedelta, str, str]] = {
    "1h":  (timedelta(hours=1),    "1min",  "%Y-%m-%dT%H:%M"),
    "6h":  (timedelta(hours=6),    "5min",  None),   # special: floor to 5 min
    "24h": (timedelta(hours=24),   "15min", None),   # special: floor to 15 min
    "7d":  (timedelta(days=7),     "1h",    "%Y-%m-%dT%H"),
    "30d": (timedelta(days=30),    "4h",    None),   # special: floor to 4 h
    "90d": (timedelta(days=90),    "1d",    "%Y-%m-%d"),
    "1y":  (timedelta(days=366),   "1d",    "%Y-%m-%d"),
}


def _floor_minutes(ts: str, n: int) -> str:
    """Floor a '%Y-%m-%dT%H:%M' string to the nearest *n*-minute boundary."""
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M")
    dt = dt.replace(minute=(dt.minute // n) * n)
    return dt.strftime("%Y-%m-%dT%H:%M")


def _floor_hours(ts: str, n: int) -> str:
    """Floor a '%Y-%m-%dT%H:%M' string to the nearest *n*-hour boundary."""
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M")
    dt = dt.replace(hour=(dt.hour // n) * n, minute=0)
    return dt.strftime("%Y-%m-%dT%H:%M")


def query(range_key: str = "24h") -> dict:
    """Return time-bucketed usage data for the admin chart.

    Returns ``{"buckets": [{"ts": ..., "sources": {source: count}}],
               "range": ..., "bucket_size": ...}``.
    """
    flush()  # ensure latest data is visible

    spec = _RANGES.get(range_key)
    if spec is None:
        spec = _RANGES["24h"]
        range_key = "24h"

    delta, bucket_label, fmt = spec
    since = (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M")

    db = _get_db()
    rows = db.execute(
        "SELECT ts, source, count FROM usage WHERE ts >= ? ORDER BY ts",
        (since,),
    ).fetchall()

    # Aggregate into the desired bucket size
    agg: dict[str, dict[str, int]] = {}   # bucket_ts → {source: count}

    for ts, source, count in rows:
        if fmt:
            # Simple strftime-based bucketing
            bk = datetime.strptime(ts, "%Y-%m-%dT%H:%M").strftime(fmt)
        elif bucket_label == "5min":
            bk = _floor_minutes(ts, 5)
        elif bucket_label == "15min":
            bk = _floor_minutes(ts, 15)
        elif bucket_label == "4h":
            bk = _floor_hours(ts, 4)
        else:
            bk = ts

        slot = agg.setdefault(bk, {})
        slot[source] = slot.get(source, 0) + count

    buckets = [{"ts": k, "sources": v} for k, v in sorted(agg.items())]
    return {"buckets": buckets, "range": range_key, "bucket_size": bucket_label}


# ── Background flush + prune thread ──────────────────────────────────────────

_started = False


def _loop() -> None:
    last_prune = 0.0
    while True:
        time.sleep(10)
        try:
            flush()
        except Exception:
            log.exception("telemetry flush error")
        # Prune once per hour
        if time.monotonic() - last_prune > 3600:
            try:
                cutoff = (datetime.now(timezone.utc)
                          - timedelta(days=RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M")
                db = _get_db()
                with db:
                    db.execute("DELETE FROM usage WHERE ts < ?", (cutoff,))
            except Exception:
                log.exception("telemetry prune error")
            last_prune = time.monotonic()


def start() -> None:
    """Start the background flush/prune thread (idempotent)."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, daemon=True, name="telemetry-flush").start()
    log.info("telemetry background thread started — db=%s", DB_PATH)
