"""v5.1.10 — phase ↔ vendor STAR rule mapping (``target_rules``)
schema + round-trip regression.

The scenario card in the admin UI reads ``phase.target_rules`` to
render the 🎯 marker and the clickable s1ql preview modal. For the
feature to survive every code path the operator can touch
(create-from-template → edit → save → export → import → re-render)
we guard:

  1. The BEC template ships a non-empty ``target_rules`` on every
     phase, each entry carrying ``name`` + ``s1ql``.
  2. ``validate_scenario_payload`` accepts payloads with
     ``target_rules`` and rejects malformed ones (non-list, list of
     non-dicts, dicts missing ``name``).
  3. ``create_scenario`` persists ``target_rules`` verbatim on every
     phase so the UI gets the same object back from ``get_scenario``.
  4. ``export_scenario`` includes ``target_rules`` in the portable
     JSON — i.e. the round-trip is lossless.
  5. ``import_scenario`` accepts that exported JSON and the resulting
     scenario carries the same ``target_rules``.
"""
from __future__ import annotations

import pytest

import attack_scenarios as scen
import attack_scenarios_library as lib


# ── 1. Template invariant ─────────────────────────────────────────────────────


def test_bec_template_every_phase_has_target_rules():
    bec = lib.TEMPLATES["bec_phishing"]
    for p in bec["phases"]:
        tr = p.get("target_rules")
        assert isinstance(tr, list) and tr, (
            f"phase {p['phase_id']} must ship at least one target_rules entry "
            f"(found: {tr!r})")
        for r in tr:
            assert isinstance(r, dict), r
            assert isinstance(r.get("name"), str) and r["name"].strip(), r
            # ``s1ql`` and ``severity`` / ``mitre`` are advisory but the BEC
            # template should always populate s1ql so the operator can see
            # the query body in the preview modal.
            assert isinstance(r.get("s1ql"), str) and r["s1ql"].strip(), r


# ── 2. Validation ─────────────────────────────────────────────────────────────


def _valid_payload(extra_phase: dict | None = None) -> dict:
    """Build a minimal-but-valid scenario payload for the validator."""
    base = {
        "name": "test",
        "duration": {"value": 1, "unit": "hours"},
        "phases": [{
            "name": "p1",
            "source": "okta",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078",
            "time_offset_pct": 0,
            "duration_pct": 100,
            "periodicity": 5,
            "field_overrides": {},
        }],
    }
    if extra_phase:
        base["phases"][0].update(extra_phase)
    return base


def test_validate_accepts_payload_with_target_rules():
    p = _valid_payload({
        "target_rules": [
            {"name": "Some Rule", "severity": "High", "s1ql": "X = 1"},
        ],
    })
    assert scen.validate_scenario_payload(p) == []


def test_validate_accepts_payload_without_target_rules():
    """``target_rules`` is OPTIONAL — pre-v5.1.10 scenarios on disk and
    user-defined custom scenarios must keep validating cleanly."""
    p = _valid_payload()
    assert scen.validate_scenario_payload(p) == []


def test_validate_rejects_non_list_target_rules():
    p = _valid_payload({"target_rules": "not-a-list"})
    errs = scen.validate_scenario_payload(p)
    assert any("target_rules" in e and "array" in e for e in errs), errs


def test_validate_rejects_target_rule_entry_without_name():
    p = _valid_payload({"target_rules": [{"severity": "High"}]})
    errs = scen.validate_scenario_payload(p)
    assert any("name" in e for e in errs), errs


def test_validate_rejects_target_rule_entry_not_a_dict():
    p = _valid_payload({"target_rules": ["just a string"]})
    errs = scen.validate_scenario_payload(p)
    assert any("must be an object" in e for e in errs), errs


# ── 3 + 4 + 5. Create / Export / Import round-trip ────────────────────────────


def test_create_persists_target_rules_verbatim():
    s = scen.create_scenario({
        "name": "RT-1",
        "duration": {"value": 1, "unit": "hours"},
        "phases": [{
            "phase_id": "p1",
            "name": "phase1",
            "source": "okta",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1528",
            "time_offset_pct": 0,
            "duration_pct": 100,
            "periodicity": 5,
            "field_overrides": {"eventType": "x"},
            "target_rules": [
                {
                    "name": "Okta Test Rule",
                    "source": "okta",
                    "severity": "High",
                    "mitre": "T1528",
                    "s1ql": "dataSource.name='Okta'",
                },
            ],
        }],
    })
    assert s["phases"][0]["target_rules"][0]["name"] == "Okta Test Rule"
    assert s["phases"][0]["target_rules"][0]["s1ql"] == "dataSource.name='Okta'"


def test_export_includes_target_rules():
    s = scen.create_scenario({
        "name": "RT-2",
        "duration": {"value": 1, "unit": "hours"},
        "phases": [{
            "phase_id": "p1",
            "name": "phase1",
            "source": "m365",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1098.002",
            "time_offset_pct": 0,
            "duration_pct": 100,
            "periodicity": 5,
            "field_overrides": {},
            "target_rules": [{"name": "Rule X", "s1ql": "Q1"}],
        }],
    })
    exported = scen.export_scenario(s["id"])
    assert exported is not None
    assert exported["phases"][0]["target_rules"][0]["name"] == "Rule X"


def test_import_preserves_target_rules():
    """Lossless round-trip: export ⇒ import ⇒ the imported scenario
    must carry the same ``target_rules`` as the source."""
    src = scen.create_scenario({
        "name": "RT-3",
        "duration": {"value": 1, "unit": "hours"},
        "phases": [{
            "phase_id": "p1",
            "name": "phase1",
            "source": "proofpoint",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1566.001",
            "time_offset_pct": 0,
            "duration_pct": 100,
            "periodicity": 5,
            "field_overrides": {},
            "target_rules": [{
                "name": "Proofpoint Impostor Email Unblocked",
                "severity": "High",
                "s1ql": "unmapped.threatsInfoMap contains 'impostor'",
            }],
        }],
    })
    exported = scen.export_scenario(src["id"])
    imported = scen.import_scenario(exported)
    assert imported["phases"][0]["target_rules"] == \
        src["phases"][0]["target_rules"]


def test_legacy_phase_without_target_rules_still_imports():
    """A scenario JSON written before v5.1.10 has no ``target_rules`` on
    its phases. The import path must NOT reject it and must NOT
    synthesise a target_rules entry — it stays absent."""
    legacy = {
        "name": "Legacy",
        "duration": {"value": 1, "unit": "hours"},
        "phases": [{
            "phase_id": "p1",
            "name": "phase1",
            "source": "okta",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1078",
            "time_offset_pct": 0,
            "duration_pct": 100,
            "periodicity": 5,
            "field_overrides": {},
        }],
        "_apigenie_schema": "attack_scenario/v1",
    }
    imported = scen.import_scenario(legacy)
    assert "target_rules" not in imported["phases"][0]
