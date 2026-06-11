"""Push-framework adapter for the ``identity`` synthetic topic.

See ``push_sources.synthetic_endpoint`` for the rationale and contract.
"""
from __future__ import annotations

from typing import Any


def generate_event(ctx: Any = None) -> dict[str, Any]:
    """Return a single identity-topic synthetic record (SSO / IAM event)."""
    from sources.synthetic import identity as _t
    return _t.generate(1)[0]
