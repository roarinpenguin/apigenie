"""Push-framework adapter for the ``network`` synthetic topic.

See ``push_sources.synthetic_endpoint`` for the rationale and contract.
"""
from __future__ import annotations

from typing import Any


def generate_event(ctx: Any = None) -> dict[str, Any]:
    """Return a single network-topic synthetic record (Zeek-style flow)."""
    from sources.synthetic import network as _t
    return _t.generate(1)[0]
