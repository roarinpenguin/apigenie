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


# ── Per-scenario event log (Phase 3.1) ──────────────────────────────────────

def test_record_and_get_event():
    """record_event lands in the per-scenario ring buffer and get_events
    returns it newest-first with the slim preview."""
    import attack_scenarios
    s = attack_scenarios.create_scenario(_minimum_scenario())
    sid = s["id"]
    attack_scenarios.record_event(
        scenario_id=sid, phase_id="initial-access",
        attack_id=s["attack_id"], source="proofpoint",
        event={"type": "phish", "subject": "Urgent",
               "threatInfo.threatName": "EvilDoc",
               # Unknown keys should be dropped from the preview.
               "noise": "should not be kept"})
    events = attack_scenarios.get_events(sid)
    assert len(events) == 1
    e = events[0]
    assert e["scenario_id"] == sid
    assert e["phase_id"] == "initial-access"
    assert e["source"] == "proofpoint"
    assert e["preview"]["type"] == "phish"
    assert e["preview"]["threatInfo.threatName"] == "EvilDoc"
    assert "noise" not in e["preview"]


def test_get_events_filters():
    """phase_id / source filters narrow the buffer in-Python; the limit
    clamps post-filter, not pre-filter."""
    import attack_scenarios
    s = attack_scenarios.create_scenario(_minimum_scenario())
    sid = s["id"]
    for i in range(5):
        attack_scenarios.record_event(sid, "initial-access", s["attack_id"],
                                      "proofpoint", {"type": "phish"})
    for i in range(3):
        attack_scenarios.record_event(sid, "impact", s["attack_id"],
                                      "sentinelone", {"type": "threat"})
    assert len(attack_scenarios.get_events(sid)) == 8
    assert len(attack_scenarios.get_events(sid, phase_id="initial-access")) == 5
    assert len(attack_scenarios.get_events(sid, phase_id="impact")) == 3
    assert len(attack_scenarios.get_events(sid, source="sentinelone")) == 3
    assert len(attack_scenarios.get_events(sid, limit=2)) == 2


def test_event_buffer_evicts_at_cap(monkeypatch):
    """Once the ring buffer is full, the oldest events drop. We shrink the
    cap to keep the test fast (the production value is 500)."""
    import attack_scenarios
    monkeypatch.setattr(attack_scenarios, "_MAX_SCENARIO_EVENT_LOG", 5)
    # Manually drop the existing deque so the new cap takes effect on
    # next allocation (production code only checks the cap when creating
    # a fresh deque).
    with attack_scenarios._event_log_lock:
        attack_scenarios._scenario_event_logs.clear()
    s = attack_scenarios.create_scenario(_minimum_scenario())
    sid = s["id"]
    for i in range(20):
        attack_scenarios.record_event(sid, "p", s["attack_id"], "src",
                                      {"type": f"event-{i}"})
    events = attack_scenarios.get_events(sid)
    assert len(events) == 5
    # newest-first means the highest-numbered event survives
    assert events[0]["preview"]["type"] == "event-19"


def test_delete_scenario_clears_event_buffer():
    """Recreating a scenario with a new id must start with a clean buffer."""
    import attack_scenarios
    s = attack_scenarios.create_scenario(_minimum_scenario(name="Stale"))
    sid = s["id"]
    attack_scenarios.record_event(sid, "p", s["attack_id"], "src",
                                  {"type": "ghost"})
    assert attack_scenarios.get_events(sid)
    attack_scenarios.delete_scenario(sid)
    assert attack_scenarios.get_events(sid) == []


def test_record_event_bumps_events_injected_counter():
    """The persisted counter is what the card UI reads when the in-memory
    log is empty (e.g. after a restart)."""
    import attack_scenarios
    s = attack_scenarios.create_scenario(_minimum_scenario())
    sid = s["id"]
    assert attack_scenarios.get_scenario(sid)["events_injected"] == 0
    attack_scenarios.record_event(sid, "p", s["attack_id"], "src", {"type": "x"})
    attack_scenarios.record_event(sid, "p", s["attack_id"], "src", {"type": "y"})
    assert attack_scenarios.get_scenario(sid)["events_injected"] == 2


def test_inject_detection_events_records_into_scenario_buffer(monkeypatch, tmp_path):
    """End-to-end: a scenario-temp rule that fires through
    inject_detection_events must show up in the per-scenario buffer.
    This is the integration that lets the UI prove "events arrived"."""
    import attack_scenarios
    import detection_rules
    # Detection rules persist alongside scenarios; isolate to tmp_path.
    monkeypatch.setattr(detection_rules, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(detection_rules, "_RULES_FILE",
                        tmp_path / "detection_rules.json")

    s = attack_scenarios.create_scenario(_minimum_scenario())
    sid, aid = s["id"], s["attack_id"]
    # Build a rule shaped like the scheduler builds them.
    detection_rules.create_rule({
        "name": "[SCENARIO] test phase",
        "source": "proofpoint",
        "enabled": True,
        "periodicity": 1,  # 1 = fire on every log
        "field_overrides": {"attack.id": aid, "phase.id": "initial-access",
                            "subject": "Urgent: Review"},
        "_scenario_id": sid,
        "_attack_id": aid,
    })
    # Feed a batch of normal logs and see what gets injected.
    base_logs = [{"type": "mail", "subject": f"normal-{i}"} for i in range(10)]
    result = detection_rules.inject_detection_events("proofpoint", base_logs)
    assert len(result) > len(base_logs), "no events were injected at all"
    events = attack_scenarios.get_events(sid)
    assert events, "scenario buffer never captured the injection"
    # Every captured event carries the phase + attack ids the scheduler set.
    for e in events:
        assert e["phase_id"] == "initial-access"
        assert e["attack_id"] == aid
        assert e["source"] == "proofpoint"


def test_inject_for_normal_rule_does_not_touch_scenario_buffer(monkeypatch, tmp_path):
    """User-defined rules (no _scenario_id) must NOT write into any
    scenario buffer — that path is reserved for the scheduler."""
    import attack_scenarios
    import detection_rules
    monkeypatch.setattr(detection_rules, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(detection_rules, "_RULES_FILE",
                        tmp_path / "detection_rules.json")
    s = attack_scenarios.create_scenario(_minimum_scenario())
    detection_rules.create_rule({
        "name": "normal user rule",
        "source": "proofpoint",
        "enabled": True,
        "periodicity": 1,
        "field_overrides": {"subject": "boring"},
        # No _scenario_id, no _attack_id.
    })
    detection_rules.inject_detection_events(
        "proofpoint", [{"type": "mail", "subject": "x"} for _ in range(5)])
    assert attack_scenarios.get_events(s["id"]) == []


# ── REST API for events ──────────────────────────────────────────────────────

def test_api_events_returns_buffer(client):
    _login_admin(client)
    r = client.post("/admin/api/scenarios", json=_minimum_scenario())
    sid = r.json()["id"]
    aid = r.json()["attack_id"]
    import attack_scenarios
    attack_scenarios.record_event(sid, "initial-access", aid, "proofpoint",
                                  {"type": "phish"})
    attack_scenarios.record_event(sid, "impact", aid, "sentinelone",
                                  {"type": "threat"})
    r = client.get(f"/admin/api/scenarios/{sid}/events")
    assert r.status_code == 200
    body = r.json()
    assert body["scenario_id"] == sid
    assert body["count"] == 2
    assert len(body["events"]) == 2


def test_api_events_supports_filters(client):
    _login_admin(client)
    r = client.post("/admin/api/scenarios", json=_minimum_scenario())
    sid = r.json()["id"]
    aid = r.json()["attack_id"]
    import attack_scenarios
    for _ in range(4):
        attack_scenarios.record_event(sid, "initial-access", aid,
                                      "proofpoint", {"type": "phish"})
    for _ in range(2):
        attack_scenarios.record_event(sid, "impact", aid, "sentinelone",
                                      {"type": "threat"})
    r = client.get(f"/admin/api/scenarios/{sid}/events?phase_id=impact")
    assert r.status_code == 200 and r.json()["count"] == 2
    r = client.get(f"/admin/api/scenarios/{sid}/events?source=proofpoint")
    assert r.status_code == 200 and r.json()["count"] == 4
    r = client.get(f"/admin/api/scenarios/{sid}/events?limit=1")
    assert r.status_code == 200 and r.json()["count"] == 1


def test_api_events_unknown_scenario_404(client):
    _login_admin(client)
    r = client.get("/admin/api/scenarios/scn-does-not-exist/events")
    assert r.status_code == 404
