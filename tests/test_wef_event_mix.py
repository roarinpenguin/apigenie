"""Tests for WEF participation in the Event Mix surface (v5.2).

The WEF source must behave exactly like the other ~21 catalog-aware
sources already plugged into ``event_mix.py`` — operators can re-weight
or disable individual EventID×Channel entries from the admin UI and
those overrides are honoured by the generator.

The acceptance check from the spec: disabling Sysmon EventID 1 in a
500-event run must remove ALL ``EventID=1 / Channel=Sysmon/Operational``
events from the output. With overrides cleared, the same 500-event run
must produce *some* Sysmon EventID 1 events (positive control).

Spec: docs/ROADMAP_2026-06-12.md §"Full Event Mix participation"
+ §"TDD plan" entry "test_wef_event_mix.py".
"""
from __future__ import annotations

import pytest


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _generate(count, mix_overrides=None, seed=42):
    from sources import windows_event_forwarding as wef
    return wef.generate_events(
        count=count,
        mix_overrides=mix_overrides,
        seed=seed,
    )


# ── Output shape ───────────────────────────────────────────────────────

def test_generate_events_returns_dicts_with_event_id_and_channel():
    events = _generate(50)
    assert len(events) == 50
    for ev in events:
        assert isinstance(ev, dict)
        assert "event_id" in ev
        assert "channel" in ev


def test_generate_events_covers_multiple_channels_by_default():
    """With no overrides, a 500-event run must touch at least 3 of the
    six channels (the default weights are non-degenerate)."""
    events = _generate(500)
    channels = {ev["channel"] for ev in events}
    assert len(channels) >= 3, (
        f"Default weights too concentrated — only saw channels {channels}"
    )


# ── Positive control + negative control for Sysmon 1 ──────────────────

def test_sysmon_event_1_appears_with_no_overrides():
    """Sanity: without any overrides, a 500-event run with a fixed seed
    must contain at least one Sysmon EventID 1. If it doesn't, the
    default weights are wrong (or the seed is unlucky — adjust the
    catalog default, not this test)."""
    events = _generate(500)
    sysmon_1 = [
        ev for ev in events
        if ev["event_id"] == 1 and ev["channel"] == SYSMON_CHANNEL
    ]
    assert sysmon_1, (
        "Sysmon EventID 1 missing from a 500-event default run — "
        "check EVENT_CATALOG default weights"
    )


def test_disabling_sysmon_event_1_removes_it_completely():
    overrides = {
        # The canonical key shape every catalog-aware source already uses
        # in event_mix.py: "<channel>:<event_id>" → settings dict.
        f"{SYSMON_CHANNEL}:1": {"enabled": False},
    }
    events = _generate(500, mix_overrides=overrides)
    leaked = [
        ev for ev in events
        if ev["event_id"] == 1 and ev["channel"] == SYSMON_CHANNEL
    ]
    assert not leaked, (
        f"Expected zero Sysmon EventID 1 events after disabling, got {len(leaked)}"
    )


def test_disabling_one_event_does_not_zero_the_whole_channel():
    """Disabling Sysmon 1 must NOT remove every other Sysmon EventID
    from the run. The bug we want to catch: a bad implementation that
    keys off channel instead of (channel, event_id)."""
    overrides = {f"{SYSMON_CHANNEL}:1": {"enabled": False}}
    events = _generate(500, mix_overrides=overrides)
    other_sysmon = [
        ev for ev in events
        if ev["channel"] == SYSMON_CHANNEL and ev["event_id"] != 1
    ]
    assert other_sysmon, (
        "Disabling Sysmon 1 wiped out the whole channel — wrong key shape?"
    )


# ── Channel filtering ──────────────────────────────────────────────────

def test_channels_enabled_argument_filters_output():
    """The binding config carries a ``channels_enabled`` list; passing it
    through to the generator must restrict output to those channels."""
    events = _generate(
        200,
        # We use a kwarg distinct from mix_overrides to verify the two
        # filters compose. ``channels_enabled`` is the binding-level coarse
        # filter; ``mix_overrides`` is the per-event-id fine filter.
    )
    # First call establishes the unfiltered baseline. Now restrict.
    from sources import windows_event_forwarding as wef
    restricted = wef.generate_events(
        count=200,
        channels_enabled=["Security"],
        seed=42,
    )
    assert restricted, "channels_enabled=['Security'] must yield events"
    assert all(ev["channel"] == "Security" for ev in restricted), (
        "channels_enabled filter leaked non-Security channels into output"
    )


# ── Determinism (so this test file is itself reliable) ────────────────

def test_seed_makes_generation_deterministic():
    """Two runs with the same seed must produce identical event sequences."""
    a = _generate(50, seed=12345)
    b = _generate(50, seed=12345)
    # Just check the (event_id, channel) tuples — full dicts may differ
    # in the random user/host substitutions which is acceptable as long
    # as those are also deterministic per-seed downstream.
    assert [(e["event_id"], e["channel"]) for e in a] == \
           [(e["event_id"], e["channel"]) for e in b]
