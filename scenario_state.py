"""In-process registry of sources currently owned by a running attack scenario.

While a scenario phase is live on a source, the base telemetry engine must
step aside for that source: standing/user detection rules are silenced and the
benign background batch is dropped, so the collector sees ONLY the scenario's
own telemetry (plus its persona narrative). Without this, a single standing
rule fires off the constant background stream on every poll — e.g. a Netskope
"malware upload" rule producing thousands of alerts an hour that drown the
scenario and match on random "unknown device" entities.

Reference-counted: several concurrent phases (or scenarios) may touch the same
source, so the source stays owned until the last holder releases it. Source ids
are canonicalised at the boundary so aliases (``entra_id``/``azure_ad``,
``defender``/``microsoft_defender``) don't leak duplicate keys.

Intentionally tiny and dependency-free so both ``detection_rules`` (hot path)
and ``attack_scenarios`` (scheduler) can import it without cycles.
"""
from __future__ import annotations

import threading
from collections import Counter

_lock = threading.Lock()
_active: Counter = Counter()


def _canon(source: str) -> str:
    try:
        from sources import canonical_source_id
        return canonical_source_id(source)
    except Exception:
        return source


def acquire(source: str) -> None:
    """Register one active phase for *source* (ref-count += 1)."""
    if not source:
        return
    s = _canon(source)
    with _lock:
        _active[s] += 1


def release(source: str) -> None:
    """Drop one active phase for *source* (ref-count -= 1, clamped at 0)."""
    if not source:
        return
    s = _canon(source)
    with _lock:
        if _active.get(s, 0) <= 1:
            _active.pop(s, None)
        else:
            _active[s] -= 1


def is_active(source: str) -> bool:
    """True when at least one running scenario phase owns *source*."""
    s = _canon(source)
    with _lock:
        return _active.get(s, 0) > 0


def active_sources() -> set:
    """Snapshot of the currently owned (canonical) source ids."""
    with _lock:
        return {k for k, v in _active.items() if v > 0}


def reset() -> None:
    """Clear the registry. Test hook only."""
    with _lock:
        _active.clear()
