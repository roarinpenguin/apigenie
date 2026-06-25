"""Tests for persona-bundle lifecycle on scenarios (v5.3 Step 1, Layer 4).

The scenario record itself is the single source of truth for the
persona bundle — it must be stamped at creation time, preserved on
update, copied through import, and stripped on export so the same
bundle never bleeds between two operators' lab instances.

Contract enforced here:

* ``create_scenario(...)`` auto-generates a complete persona bundle
  on the new record (operator did not provide one).
* ``create_scenario(..., personas=...)`` honours an operator-supplied
  bundle — round-trip is lossless. Used by the (future) persona
  editor UI to override the auto-rolled one.
* The bundle survives ``update_scenario`` even if the operator
  doesn't re-send it. An update that DOES pass ``personas`` replaces
  the stored bundle. Either way the in-flight scenario's persona
  identity is stable across edits.
* ``import_scenario(...)`` rolls a FRESH bundle on the imported
  copy. Reusing the source bundle would make every operator who
  imports the same template hit the same victim, defeating the
  point of templating.
* ``export_scenario(...)`` strips the ``personas`` key — the export
  is a portable template, not a runtime instance.
"""
from __future__ import annotations


def _minimal_phase(source: str = "okta") -> dict:
    """A phase that passes ``validate_scenario_payload`` so the
    create/import path doesn't reject our test fixture."""
    return {
        "phase_id":       "p1",
        "name":           "Initial access",
        "source":         source,
        "mitre_tactic":   "TA0001",
        "mitre_technique": "T1078",
        "time_offset_pct": 0,
        "duration_pct":   100,
        "periodicity":    5,
        "field_overrides": {},
    }


def _minimal_payload(**overrides) -> dict:
    """Smallest scenario payload that create_scenario / import_scenario
    accepts. Tests can override individual fields by kwarg."""
    base = {
        "name":     "Test scenario",
        "duration": {"value": 1, "unit": "hours"},
        "phases":   [_minimal_phase()],
    }
    base.update(overrides)
    return base


# ── create ─────────────────────────────────────────────────────────


def test_create_scenario_auto_generates_persona_bundle():
    """A scenario created without an explicit ``personas`` key gets
    a fresh, fully-populated bundle. Without this every demo would
    fall back to source-side random and the whole feature would be
    inert."""
    import attack_scenarios
    import personas

    s = attack_scenarios.create_scenario(_minimal_payload())
    try:
        assert "personas" in s, "personas bundle missing on new scenario"
        problems = personas.validate_bundle(s["personas"])
        assert problems == [], f"bundle on new scenario is corrupt: {problems}"
    finally:
        attack_scenarios.delete_scenario(s["id"])


def test_create_scenario_honours_operator_supplied_bundle():
    """If the caller passes ``personas`` (e.g. from a custom persona
    editor) the create path persists it verbatim, doesn't reroll."""
    import attack_scenarios

    custom = {
        "victim_user": {"name": "CEO", "username": "ceo",
                        "email": "ceo@acme.test", "upn": "ceo@acme.test",
                        "object_id": "u-ceo"},
        "victim_host": {"hostname": "CEO-LAPTOP", "ip": "10.0.0.99",
                        "os": "macOS 14", "agent_uuid": "h-ceo"},
        "attacker":    {"ip": "185.220.101.42", "country": "RU",
                        "email": "x@evil.test", "domain": "evil.test",
                        "asn": "AS9009"},
        "malicious":   {"file_name": "x.docm", "sha256": "a"*64,
                        "md5": "b"*32, "process": "WINWORD.EXE",
                        "cmd_line": "winword.exe x.docm"},
    }
    s = attack_scenarios.create_scenario(_minimal_payload(personas=custom))
    try:
        assert s["personas"] == custom, (
            "operator-supplied persona bundle must be persisted verbatim")
    finally:
        attack_scenarios.delete_scenario(s["id"])


# ── update ─────────────────────────────────────────────────────────


def test_update_scenario_preserves_existing_bundle():
    """Editing the name / phases of a running scenario must NOT
    re-roll the persona bundle — that would change the victim
    halfway through the attack story."""
    import attack_scenarios

    s = attack_scenarios.create_scenario(_minimal_payload())
    try:
        original = dict(s["personas"])
        updated = attack_scenarios.update_scenario(
            s["id"], {"name": "Renamed"})
        assert updated["personas"] == original, (
            "update must preserve the existing persona bundle")
    finally:
        attack_scenarios.delete_scenario(s["id"])


def test_update_scenario_accepts_new_bundle():
    """An update that explicitly sends ``personas`` replaces the
    stored bundle (used by the persona-editor UI)."""
    import attack_scenarios

    s = attack_scenarios.create_scenario(_minimal_payload())
    try:
        new_bundle = {
            "victim_user": {"name": "New Victim", "username": "nv",
                            "email": "nv@acme.test", "upn": "nv@acme.test",
                            "object_id": "u-nv"},
            "victim_host": {"hostname": "NV-PC", "ip": "10.0.0.42",
                            "os": "Windows 11", "agent_uuid": "h-nv"},
            "attacker":    {"ip": "198.51.100.7", "country": "CN",
                            "email": "y@bad.test", "domain": "bad.test",
                            "asn": "AS4837"},
            "malicious":   {"file_name": "f", "sha256": "c"*64,
                            "md5": "d"*32, "process": "p", "cmd_line": "c"},
        }
        updated = attack_scenarios.update_scenario(
            s["id"], {"personas": new_bundle})
        assert updated["personas"] == new_bundle
    finally:
        attack_scenarios.delete_scenario(s["id"])


# ── import / export ────────────────────────────────────────────────


def test_export_scenario_strips_personas():
    """An exported template carries phases + duration but NOT the
    persona bundle — the bundle is per-instance, not part of the
    portable template format."""
    import attack_scenarios

    s = attack_scenarios.create_scenario(_minimal_payload())
    try:
        exported = attack_scenarios.export_scenario(s["id"])
        assert "personas" not in exported, (
            "export must not leak the source instance's persona bundle")
    finally:
        attack_scenarios.delete_scenario(s["id"])


def test_import_scenario_rolls_a_fresh_bundle():
    """Two operators who import the same template must end up with
    two different victims. If import reused the template's bundle
    (when one was sneaked in) the demos would collide."""
    import attack_scenarios

    payload = _minimal_payload()
    a = attack_scenarios.import_scenario(payload)
    b = attack_scenarios.import_scenario(payload)
    try:
        assert "personas" in a and "personas" in b
        assert a["personas"] != b["personas"], (
            "two imports of the same template must produce distinct bundles")
    finally:
        attack_scenarios.delete_scenario(a["id"])
        attack_scenarios.delete_scenario(b["id"])
