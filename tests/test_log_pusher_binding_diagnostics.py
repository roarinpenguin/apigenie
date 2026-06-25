"""Tests for push-loop binding diagnostics on the status endpoint
(v5.3 Step 2, Phase 5).

When the operator runs a push profile with ``link_xdr_assets=True``
they need a fast feedback loop: "is the binding actually happening,
or did the resolver fall back to 'Unknown Device' for some reason?"
Without surfacing it, the only way to know is to grep container
logs or open a UAM alert and look for ``assets[].agentUuid`` — both
out-of-band, both slow.

The status response gains a ``binding`` block::

    {
      "id": "<profile id>",
      "status": "running",
      "events_sent": 42,
      "started_at": "...",
      "binding": {
        "enabled": True,        # ⇐ profile.link_xdr_assets
        "configured": True,     # ⇐ resolver actually built (creds OK)
        "events_bound": 38,     # ⇐ # of events the splice stamped
        "events_skipped": 4,    # ⇐ # of events where resolver missed
        "stats": {              # passthrough from resolver.stats()
          "lookups": 3,
          "hits":    1,
          "misses":  0,
          "cache_hits": 39,
        }
      }
    }

This file tests the data-layer side: ``log_pusher`` exposes a
``record_binding_outcome(profile_id, bound: bool)`` API the splice
calls after each decision, and ``get_status`` surfaces those
counters under the ``binding`` key.
"""
from __future__ import annotations

from unittest.mock import MagicMock


# ── record_binding_outcome / get_status round-trip ─────────────────


def test_get_status_carries_binding_block_for_disabled_profile():
    """A profile with ``link_xdr_assets=False`` should still report
    a ``binding`` block — but with ``enabled=False`` and zeroed
    counters. The UI uses this to render a dimmed pill ("Binding
    off") instead of having to guess."""
    import log_pusher

    p = log_pusher.create_profile(
        {"name": "off", "source_type": "okta",
         "destination": {"host": "x", "port": 1},
         "duration": {"value": 1, "unit": "minutes"}})
    try:
        s = log_pusher.get_status(p["id"])
        assert "binding" in s, ("status response must always include the "
                                 "binding block — even when disabled")
        b = s["binding"]
        assert b["enabled"] is False
        assert b["events_bound"] == 0
        assert b["events_skipped"] == 0
    finally:
        log_pusher.delete_profile(p["id"])


def test_get_status_carries_binding_block_for_enabled_profile():
    """An enabled profile (no events sent yet) reports enabled=True
    and zero counters until the first event lands."""
    import log_pusher

    p = log_pusher.create_profile(
        {"name": "on", "source_type": "okta",
         "destination": {"host": "x", "port": 1},
         "duration": {"value": 1, "unit": "minutes"},
         "link_xdr_assets": True})
    try:
        s = log_pusher.get_status(p["id"])
        assert s["binding"]["enabled"] is True
        assert s["binding"]["events_bound"] == 0
        assert s["binding"]["events_skipped"] == 0
    finally:
        log_pusher.delete_profile(p["id"])


def test_record_binding_outcome_increments_counters():
    """Each call to ``record_binding_outcome`` (made by the splice)
    bumps either ``events_bound`` (success) or ``events_skipped``
    (resolver missed). The status reflects the total after each
    call without any flushing."""
    import log_pusher

    p = log_pusher.create_profile(
        {"name": "counter", "source_type": "okta",
         "destination": {"host": "x", "port": 1},
         "duration": {"value": 1, "unit": "minutes"},
         "link_xdr_assets": True})
    try:
        # 3 bound + 1 skipped
        log_pusher.record_binding_outcome(p["id"], bound=True)
        log_pusher.record_binding_outcome(p["id"], bound=True)
        log_pusher.record_binding_outcome(p["id"], bound=False)
        log_pusher.record_binding_outcome(p["id"], bound=True)

        s = log_pusher.get_status(p["id"])
        assert s["binding"]["events_bound"]   == 3
        assert s["binding"]["events_skipped"] == 1
    finally:
        log_pusher.delete_profile(p["id"])


def test_apply_asset_binding_records_outcome_when_profile_id_provided():
    """The splice optionally accepts ``profile_id`` so the diagnostic
    counters are wired up. The signature stays back-compatible:
    callers that pass only ``(event, source, resolver)`` (the
    direct unit tests in test_log_pusher_asset_binding.py) keep
    working — no profile context means no counter recording.

    With ``profile_id`` supplied, the counters move:
      - hit  ⇒ events_bound + 1
      - miss ⇒ events_skipped + 1
      - kind=none / no resolver / no binding ⇒ NEITHER (those are
        not binding decisions, they're upstream short-circuits).
    """
    import log_pusher

    p = log_pusher.create_profile(
        {"name": "splice", "source_type": "okta",
         "destination": {"host": "x", "port": 1},
         "duration": {"value": 1, "unit": "minutes"},
         "link_xdr_assets": True})
    try:
        resolver = MagicMock()
        # Two hits then one miss.
        resolver.sticky_pick.side_effect = [
            {"uid": "id-1", "upn": "a@b", "display_name": "", "domain": ""},
            {"uid": "id-2", "upn": "c@d", "display_name": "", "domain": ""},
            None,
        ]
        for _ in range(3):
            log_pusher.apply_asset_binding({}, "okta",
                                            resolver=resolver,
                                            profile_id=p["id"])

        s = log_pusher.get_status(p["id"])
        assert s["binding"]["events_bound"]   == 2
        assert s["binding"]["events_skipped"] == 1

        # kind=none short-circuit — must NOT touch the counters even
        # with profile_id supplied.
        log_pusher.apply_asset_binding({}, "wiz", resolver=resolver,
                                        profile_id=p["id"])
        s = log_pusher.get_status(p["id"])
        assert s["binding"]["events_bound"]   == 2
        assert s["binding"]["events_skipped"] == 1
    finally:
        log_pusher.delete_profile(p["id"])
