"""Push-framework adapter for uploaded replay files.

This source streams records from an admin-uploaded replay file (see
``replay.py``) so a user can re-play an old log capture into any
transport \u2014 HTTP / HEC / syslog / OTLP. It complements the OTLP listener
side: same file, opposite direction.

Stateful contract
-----------------
Unlike the 16 stateless vendor source modules, replay needs to keep a
file iterator alive across calls (we want to yield record #2 on the
second call, not regenerate record #1). The Log Push framework supports
this via the ``make_iterator(profile) -> Iterator[dict]`` hook \u2014 the
push loop builds one iterator at profile-start, then calls ``next(it)``
per event.

The replay file id and stream parameters come from the push profile:

  * ``replay_file_id``  \u2014 required; selects which uploaded file to stream.
  * ``replay_anchor_mode``       \u2014 optional, default ``now``.
  * ``replay_anchor_offset_seconds``  \u2014 optional, default 0.
  * ``replay_anchor_fixed_iso``       \u2014 optional ISO-8601 anchor.
  * ``replay_preserve_spread``        \u2014 optional bool, default ``True``.

When the iterator is exhausted (file end reached) ``StopIteration`` is
raised; the push loop stops the profile gracefully and marks it
``completed``.
"""
from __future__ import annotations

import logging
from typing import Any, Iterator

logger = logging.getLogger(__name__)


def make_iterator(profile: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Build a generator that yields one event at a time from the replay file.

    Raises ``ValueError`` if the profile is missing ``replay_file_id`` so the
    push loop can mark the profile as ``error`` rather than fail silently
    when ``next()`` is first called.
    """
    file_id = (profile.get("replay_file_id") or "").strip()
    if not file_id:
        raise ValueError(
            "replay_file_id is required for source_type=replay_file"
        )
    import replay as _replay
    meta = _replay.get_replay(file_id)
    if meta is None:
        raise ValueError(f"replay file not found: {file_id!r}")

    spec = _replay.StreamSpec(
        file_id=file_id,
        format=meta.format,
        timestamp_field=profile.get("replay_timestamp_field") or meta.timestamp_field,
        anchor_mode=profile.get("replay_anchor_mode", "now"),
        anchor_offset_seconds=int(profile.get("replay_anchor_offset_seconds", 0) or 0),
        anchor_fixed_iso=profile.get("replay_anchor_fixed_iso") or None,
        preserve_spread=profile.get("replay_preserve_spread", True),
    )
    logger.info("replay_file: streaming %s (%d records, format=%s)",
                file_id, meta.line_count, meta.format)
    return _replay.stream(spec)


def generate_event(ctx: Any = None) -> dict[str, Any]:
    """Fallback generator \u2014 not used because ``make_iterator`` exists.

    Defined for completeness so an accidental direct call returns a clear
    error rather than ``AttributeError``.
    """
    raise NotImplementedError(
        "push_sources.replay_file is iterator-based; call make_iterator(profile)"
    )
