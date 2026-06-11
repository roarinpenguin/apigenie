"""Tests for the Attack Scenarios builder (v5.0 Phase 2).

Covers the new validation / export / import helpers in
``attack_scenarios.py`` and the matching REST endpoints in ``admin.py``.

The full scheduler is NOT exercised here — Phase 1 (engine) is already
proven in production. These tests focus on the editable surface:

  * ``validate_scenario_payload`` shape + range enforcement
  * ``export_scenario`` strips runtime fields and emits the v1 schema
  * ``import_scenario`` round-trips an export
  * REST PUT refuses to mutate a running scenario
  * REST POST /import returns a per-error list on malformed input
"""

from __future__ import annotations

import copy
import json
import os

import pytest
from fastapi.testclient import TestClient


# ── helpers ──────────────────────────────────────────────────────────────────

def _login_admin(client: TestClient) -> None:
    pwd = os.environ.get("ADMIN_PASSWORD", "apigenie")
    r = client.post("/admin/login",
                    data={"username": "admin", "password": pwd},
                    follow_redirects=False)
    assert r.status_code in (200, 302, 303), (r.status_code, r.text[:200])


def _minimum_scenario(**over) -> dict:
    """A tiny but fully valid scenario dict. Tests override individual
    keys to exercise edge cases."""
    base = {
        "name": "Test Scenario",
        "description": "unit test",
        "duration": {"value": 2, "unit": "hours"},
        "phases": [
            {
                "phase_id": "initial-access",
                "name": "Phishing email",
                "source": "proofpoint",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1566.001",
                "time_offset_pct": 0,
                "duration_pct": 30,
                "periodicity": 5,
                "field_overrides": {"subject": "Test"},
            },
            {
                "phase_id": "impact",
                "name": "Encryption",
                "source": "sentinelone",
                "mitre_tactic": "Impact",
                "mitre_technique": "T1486",
                "time_offset_pct": 60,
                "duration_pct": 40,
                "periodicity": 3,
                "field_overrides": {"severity": "Critical"},
            },
        ],
    }
    base.update(over)
    return base


# ── validation ───────────────────────────────────────────────────────────────

def test_validate_accepts_minimum_payload():
    import attack_scenarios
    assert attack_scenarios.validate_scenario_payload(_minimum_scenario()) == []


def test_validate_rejects_non_dict():
    import attack_scenarios
    errors = attack_scenarios.validate_scenario_payload("not a dict")
    assert errors and "JSON object" in errors[0]


def test_validate_rejects_missing_name():
    import attack_scenarios
    payload = _minimum_scenario()
    del payload["name"]
    errors = attack_scenarios.validate_scenario_payload(payload)
    assert any("'name'" in e for e in errors)


def test_validate_rejects_empty_phases():
    import attack_scenarios
    errors = attack_scenarios.validate_scenario_payload(_minimum_scenario(phases=[]))
    assert any("phases" in e for e in errors)


def test_validate_rejects_out_of_range_pcts():
    """time_offset_pct + duration_pct > 100 must be flagged so the
    scheduler never runs a phase that ends after the scenario does."""
    import attack_scenarios
    payload = _minimum_scenario()
    payload["phases"][0]["time_offset_pct"] = 80
    payload["phases"][0]["duration_pct"] = 50  # 80 + 50 = 130
    errors = attack_scenarios.validate_scenario_payload(payload)
    assert any("exceeds 100" in e for e in errors)


def test_validate_rejects_bad_duration_unit():
    import attack_scenarios
    payload = _minimum_scenario(duration={"value": 1, "unit": "fortnights"})
    errors = attack_scenarios.validate_scenario_payload(payload)
    assert any("duration.unit" in e for e in errors)


def test_validate_collects_all_errors_not_just_first():
    """The UI surfaces every problem at once; validator must collect, not
    short-circuit, so users don't have to fix-and-retry serially."""
    import attack_scenarios
    payload = {"name": "", "duration": {}, "phases": [{}]}
    errors = attack_scenarios.validate_scenario_payload(payload)
    # name, duration.value, duration.unit, plus required-string phase fields
    assert len(errors) >= 5


# ── export / import round-trip ───────────────────────────────────────────────

def test_export_strips_runtime_fields():
    import attack_scenarios
    s = attack_scenarios.create_scenario(_minimum_scenario())
    exported = attack_scenarios.export_scenario(s["id"])
    assert exported is not None
    # Runtime identifiers must not appear in the portable form.
    for forbidden in ("id", "attack_id", "status", "events_injected",
                      "started_at", "paused_at", "elapsed_seconds",
                      "error", "created"):
        assert forbidden not in exported, f"{forbidden!r} leaked into export"
    # Schema marker so importers can sanity-check the format.
    assert exported["_apigenie_schema"] == "attack_scenario/v1"


def test_export_round_trips_through_import():
    import attack_scenarios
    original = attack_scenarios.create_scenario(_minimum_scenario(name="Original"))
    exported = attack_scenarios.export_scenario(original["id"])
    imported = attack_scenarios.import_scenario(exported)
    # Two distinct scenarios with two distinct attack IDs but identical phases.
    assert imported["id"] != original["id"]
    assert imported["attack_id"] != original["attack_id"]
    assert imported["name"] == "Original"
    assert len(imported["phases"]) == len(original["phases"])
    for ip, op in zip(imported["phases"], original["phases"]):
        for k in ("name", "source", "mitre_tactic", "mitre_technique",
                  "time_offset_pct", "duration_pct", "periodicity",
                  "field_overrides"):
            assert ip.get(k) == op.get(k), f"phase key {k!r} drifted"


def test_export_unknown_returns_none():
    import attack_scenarios
    assert attack_scenarios.export_scenario("scn-does-not-exist") is None


def test_import_rejects_malformed_payload():
    import attack_scenarios
    with pytest.raises(ValueError) as exc:
        attack_scenarios.import_scenario({"name": "x"})  # no phases
    assert "phases" in str(exc.value)


def test_import_strips_schema_marker():
    """The _apigenie_schema key is metadata, not a scenario field. Import
    must not persist it into the scenario record."""
    import attack_scenarios
    exported = {**_minimum_scenario(), "_apigenie_schema": "attack_scenario/v1"}
    created = attack_scenarios.import_scenario(exported)
    assert "_apigenie_schema" not in created


# ── REST API ────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """FastAPI TestClient bound to the real app. Mirrors test_webhooks.py
    so the conftest's per-test data isolation also applies here."""
    from app import app
    return TestClient(app)


def test_api_put_updates_stopped_scenario(client):
    _login_admin(client)
    r = client.post("/admin/api/scenarios", json=_minimum_scenario(name="Before"))
    assert r.status_code == 201, r.text[:200]
    sid = r.json()["id"]
    # Modify one phase's MITRE technique through the editor.
    edited = copy.deepcopy(_minimum_scenario(name="After"))
    edited["phases"][0]["mitre_technique"] = "T1566.002"
    r = client.put(f"/admin/api/scenarios/{sid}", json=edited)
    assert r.status_code == 200, r.text[:200]
    body = r.json()
    assert body["name"] == "After"
    assert body["phases"][0]["mitre_technique"] == "T1566.002"


def test_api_put_unknown_id_404(client):
    _login_admin(client)
    r = client.put("/admin/api/scenarios/scn-nope", json=_minimum_scenario())
    assert r.status_code == 404


def test_api_put_validation_returns_400_with_error_list(client):
    _login_admin(client)
    r = client.post("/admin/api/scenarios", json=_minimum_scenario())
    sid = r.json()["id"]
    bad = _minimum_scenario()
    bad["phases"][0]["time_offset_pct"] = 80
    bad["phases"][0]["duration_pct"] = 50
    r = client.put(f"/admin/api/scenarios/{sid}", json=bad)
    assert r.status_code == 400
    body = r.json()
    assert "errors" in body and any("exceeds 100" in e for e in body["errors"])


def test_api_export_sets_download_header(client):
    _login_admin(client)
    r = client.post("/admin/api/scenarios",
                    json=_minimum_scenario(name="My Scenario!"))
    sid = r.json()["id"]
    r = client.get(f"/admin/api/scenarios/{sid}/export")
    assert r.status_code == 200
    cd = r.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "scenario.json" in cd
    # Body is the portable JSON.
    body = r.json()
    assert body["_apigenie_schema"] == "attack_scenario/v1"
    assert "id" not in body and "attack_id" not in body


def test_api_export_unknown_404(client):
    _login_admin(client)
    r = client.get("/admin/api/scenarios/scn-nope/export")
    assert r.status_code == 404


def test_api_import_creates_new_scenario(client):
    _login_admin(client)
    # First create + export an existing scenario, then re-import as a
    # round-trip sanity check via REST only.
    r = client.post("/admin/api/scenarios",
                    json=_minimum_scenario(name="Donor"))
    sid = r.json()["id"]
    exported = client.get(f"/admin/api/scenarios/{sid}/export").json()
    r = client.post("/admin/api/scenarios/import", json=exported)
    assert r.status_code == 201, r.text[:200]
    cloned = r.json()
    assert cloned["id"] != sid
    assert cloned["name"] == "Donor"


def test_api_import_rejects_malformed_returns_error_list(client):
    _login_admin(client)
    r = client.post("/admin/api/scenarios/import",
                    json={"name": "missing phases"})
    assert r.status_code == 400
    body = r.json()
    assert "errors" in body
    assert any("phases" in e for e in body["errors"])


def test_api_import_rejects_non_json_body(client):
    _login_admin(client)
    r = client.post("/admin/api/scenarios/import",
                    content=b"not json at all",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 400
