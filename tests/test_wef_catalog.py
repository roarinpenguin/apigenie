"""Tests for the Windows Event Forwarding event catalog (v5.2).

Verifies the *content* of ``sources.windows_event_forwarding.EVENT_CATALOG``
— the shape every entry must satisfy, the channel coverage requirement
(all six DC-threat-hunting channels must be present), and the alias wiring
in ``sources/__init__.py`` so the bindings UI key ``wef`` canonicalises to
the module name ``windows_event_forwarding``.

Designed to fail at import time during the v5.2 TDD red phase
(the module does not exist yet). When the green phase lands, each test
must pass without modification.

Spec: docs/ROADMAP_2026-06-12.md §"v5.2 — Windows Event Forwarding push
source" → Goals + TDD plan.
"""
from __future__ import annotations

import pytest


# The six channels listed in the v5.2 spec (Goals section).
EXPECTED_CHANNELS = {
    "Security",
    "System",
    "Directory Service",
    "DNS Server",
    "Windows-PowerShell-Operational",
    "Microsoft-Windows-Sysmon/Operational",
}

# Required keys on every EVENT_CATALOG entry.
#
# The first three (id / label / default_weight) match the convention every
# other catalog-aware source already follows (see sources/azure_platform.py)
# so WEF plugs natively into event_mix.merge_catalog_with_mix and the admin
# Event Mix card renders without any WEF-specific branch.
#
# The remaining four (channel / event_id / provider / level) are
# WEF-specific metadata the envelope builder needs to emit a real Windows
# EventLog XML record. They live alongside, not in place of, the standard
# catalog fields.
REQUIRED_ENTRY_KEYS = {
    "id", "label", "default_weight",
    "channel", "event_id", "provider", "level",
}

# Allowed Windows EventLog severity levels (per the EventLog XML schema).
ALLOWED_LEVELS = {"Critical", "Error", "Warning", "Information", "Verbose"}


def _catalog():
    """Import the catalog lazily so an ImportError fails the test rather
    than the collection phase. This keeps the red-phase output readable."""
    from sources import windows_event_forwarding as wef
    return wef.EVENT_CATALOG


# ── Shape ──────────────────────────────────────────────────────────────

def test_catalog_is_a_non_empty_list_of_dicts():
    catalog = _catalog()
    assert isinstance(catalog, list)
    assert len(catalog) >= 100, (
        f"EVENT_CATALOG must contain ~200 entries per spec; found {len(catalog)}"
    )
    assert all(isinstance(entry, dict) for entry in catalog)


def test_every_entry_has_required_keys():
    catalog = _catalog()
    for entry in catalog:
        missing = REQUIRED_ENTRY_KEYS - set(entry.keys())
        assert not missing, (
            f"Catalog entry {entry!r} missing required keys: {missing}"
        )


def test_event_ids_are_positive_integers():
    catalog = _catalog()
    for entry in catalog:
        assert isinstance(entry["event_id"], int)
        assert entry["event_id"] > 0


def test_catalog_ids_follow_channel_event_id_pattern():
    """The catalog ``id`` string is the key used by ``event_mix`` overrides.
    Pinning the canonical ``"<channel>:<event_id>"`` shape lets the admin
    UI build override keys deterministically without consulting the
    catalog row by row."""
    catalog = _catalog()
    for entry in catalog:
        expected_id = f"{entry['channel']}:{entry['event_id']}"
        assert entry["id"] == expected_id, (
            f"Entry id={entry['id']!r} does not match "
            f"channel:event_id = {expected_id!r}"
        )


def test_catalog_ids_are_unique():
    catalog = _catalog()
    ids = [entry["id"] for entry in catalog]
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"Duplicate catalog ids: {duplicates}"


def test_levels_are_from_the_allowed_set():
    catalog = _catalog()
    for entry in catalog:
        assert entry["level"] in ALLOWED_LEVELS, (
            f"Entry id={entry['event_id']} channel={entry['channel']!r} "
            f"has invalid level {entry['level']!r}"
        )


# ── Channel coverage (v5.2 spec — all six channels must be present) ───

def test_all_six_channels_present():
    catalog = _catalog()
    seen = {entry["channel"] for entry in catalog}
    missing = EXPECTED_CHANNELS - seen
    assert not missing, f"Channels missing from EVENT_CATALOG: {missing}"


@pytest.mark.parametrize("channel", sorted(EXPECTED_CHANNELS))
def test_each_channel_has_at_least_one_event(channel):
    catalog = _catalog()
    matching = [e for e in catalog if e["channel"] == channel]
    assert matching, f"No catalog entries for channel {channel!r}"


def test_security_channel_has_logon_events_4624_and_4625():
    """The two most-hunted Security events MUST be in the catalog —
    failed (4625) and successful (4624) account logon. If these slip out
    of the catalog the whole feature is useless for SOC use cases."""
    catalog = _catalog()
    sec = {e["event_id"] for e in catalog if e["channel"] == "Security"}
    assert 4624 in sec, "Security 4624 (logon success) missing"
    assert 4625 in sec, "Security 4625 (logon failure) missing"


def test_sysmon_channel_includes_process_create_event_id_1():
    catalog = _catalog()
    sysmon = {e["event_id"] for e in catalog
              if e["channel"] == "Microsoft-Windows-Sysmon/Operational"}
    assert 1 in sysmon, "Sysmon EventID 1 (process create) missing"


# ── Weights ────────────────────────────────────────────────────────────

def test_default_weights_are_non_negative_and_some_are_strictly_positive():
    catalog = _catalog()
    weights = [float(entry["default_weight"]) for entry in catalog]
    assert all(w >= 0 for w in weights)
    assert sum(weights) > 0, "Catalog default_weights all zero — distribution is degenerate"


# ── Source-id alias ───────────────────────────────────────────────────

def test_canonical_source_id_resolves_wef_alias():
    from sources import canonical_source_id
    assert canonical_source_id("wef") == "windows_event_forwarding"


def test_module_is_discoverable_via_get_event_catalog():
    from sources import get_event_catalog
    catalog = get_event_catalog("windows_event_forwarding")
    assert catalog is not None
    assert len(catalog) >= 100
