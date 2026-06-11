"""Push-framework adapter for the ``endpoint`` synthetic topic.

Mirrors the same generator the OTLP listener uses for its synthetic data
source (``sources.synthetic.endpoint.generate``). Wired into the Log Push
framework as a regular source module so a user can stream synthetic EDR-
shaped events to any transport (HTTP / HEC / syslog / OTLP).

Each call to ``generate_event(ctx)`` produces one fresh record. The
generator is stateless; rate and duration are governed by the push loop.
"""
from __future__ import annotations

from typing import Any


def generate_event(ctx: Any = None) -> dict[str, Any]:
    """Return a single endpoint-topic synthetic record."""
    from sources.synthetic import endpoint as _t
    return _t.generate(1)[0]
