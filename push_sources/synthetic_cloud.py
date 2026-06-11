"""Push-framework adapter for the ``cloud`` synthetic topic.

See ``push_sources.synthetic_endpoint`` for the rationale and contract.
"""
from __future__ import annotations

from typing import Any


def generate_event(ctx: Any = None) -> dict[str, Any]:
    """Return a single cloud-topic synthetic record (multi-cloud audit)."""
    from sources.synthetic import cloud as _t
    return _t.generate(1)[0]
