"""Cloud Account Takeover scenario — phase→rule alignment regression.

Companion to ``test_m365_blob_cache.py`` (the BEC fix). This locks in the
v5.1.25 alignment of the Cloud Account Takeover template against what the
usea1-purple lake actually ingests (verified 2026-06-28):

* Only M365 + Okta flow for this scenario (Entra ID / Azure AD is NOT
  ingested), so phase 6 ("Backdoor service principal created") was retargeted
  from ``entra_id`` to ``m365`` — the identical directory op arrives via the
  M365 Management Activity feed (``activity_name='Add service principal.'``).
* The Okta phase 1 fires the shipped "Okta High Severity Threat Detected"
  rule via ``eventType=security.threat.detected`` + ``severity=HIGH`` (the
  collector drops ``debugContext.debugData.risk/behaviors``).
* The consent phase fires the ACTIVE "Admin Consent for All Principals" rule,
  so it must carry the ``ConsentType: AllPrincipals`` marker.
* The PIM phase needs a CUSTOM STAR rule (no shipped rule matches the
  O365-sourced PIM activation), keyed on ``unmapped.RoleName``.

These tests assert (a) the template wiring and (b) that each capped M365 phase
event survives the two-step content→audit poll carrying the discriminator
fields its target rule keys on.
"""
from __future__ import annotations

from urllib.parse import urlparse

import pytest

import attack_scenarios_library as L


def _phase(phase_id: str) -> dict:
    t = L.get_template("cloud_account_takeover")
    for p in t["phases"]:
        if p["phase_id"] == phase_id:
            return p
    raise AssertionError(f"phase {phase_id} not found")


def _reset_injector_state():
    import detection_rules
    from sources import m365
    detection_rules._injected_total.clear()
    detection_rules._last_fired.clear()
    m365._BLOB_CACHE.clear()


def _make_rule(source: str, overrides: dict):
    import detection_rules
    return detection_rules.create_rule({
        "name": "[SCENARIO-TEST] cloud takeover phase",
        "source": source,
        "field_overrides": overrides,
        "periodicity": 2,
        "max_events": 1,
        "visibility": "public",
    })


# ── Structural wiring ────────────────────────────────────────────────────────


def test_phase6_retargeted_to_m365():
    p = _phase("persistence-2")
    assert p["source"] == "m365", "phase 6 must be retargeted entra_id→m365"
    assert p["field_overrides"]["Operation"] == "Add service principal."
    assert p["field_overrides"]["Workload"] == "AzureActiveDirectory"


def test_consent_phase_carries_allprincipals_marker():
    p = _phase("persistence")
    mp = p["field_overrides"].get("ModifiedProperties", "")
    assert "ConsentType: AllPrincipals" in mp, (
        "consent phase must carry the AllPrincipals marker the shipped rule keys on")


@pytest.mark.parametrize("phase_id, expected_in_s1ql", [
    ("credential-access", "security.threat.detected"),
    ("persistence", "ConsentType: AllPrincipals"),
    ("privilege-escalation", "unmapped.RoleName = 'Global Administrator'"),
    ("collection", None),  # Bulk File Download — anomaly rule, no s1ql asserted
    ("persistence-2", "activity_name = 'Add service principal.'"),
])
def test_each_alerting_phase_documents_target_rule(phase_id, expected_in_s1ql):
    p = _phase(phase_id)
    trs = p.get("target_rules", [])
    assert trs, f"phase {phase_id} must document a target rule"
    if expected_in_s1ql is not None:
        s1ql = trs[0].get("s1ql", "")
        assert expected_in_s1ql in s1ql, (
            f"phase {phase_id} target rule s1ql must contain {expected_in_s1ql!r}, got: {s1ql!r}")


# ── Delivery: M365 capped phases survive the two-step content→audit poll ─────


@pytest.mark.parametrize("phase_id, operation, marker_field, marker_value", [
    ("persistence", "Consent to application.", "ModifiedProperties", "ConsentType: AllPrincipals"),
    ("privilege-escalation", "Activate eligible role.", "RoleName", "Global Administrator"),
    ("persistence-2", "Add service principal.", "Workload", "AzureActiveDirectory"),
])
def test_m365_phase_event_reaches_collector_with_discriminator(
        phase_id, operation, marker_field, marker_value):
    from fastapi.testclient import TestClient

    import app as apigenie_app

    _reset_injector_state()
    _make_rule("m365", _phase(phase_id)["field_overrides"])

    client = TestClient(apigenie_app.app)
    tenant = "my-roarin-111-m365tenant"
    headers = {"Authorization": "Bearer eyJ.fake.jwt"}

    r = client.get(
        f"/api/v1.0/{tenant}/activity/feed/subscriptions/content",
        params={"contentType": "Audit.General"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    blobs = r.json()
    assert blobs, "content listing must return blobs"

    matches = []
    for blob in blobs:
        path = urlparse(blob["contentUri"]).path
        r2 = client.get(path, headers=headers)
        assert r2.status_code == 200, r2.text
        matches.extend(e for e in r2.json() if e.get("Operation") == operation)

    assert len(matches) == 1, (
        f"capped {operation!r} event must be ingested exactly once, got {len(matches)}")
    delivered = str(matches[0].get(marker_field, ""))
    assert marker_value in delivered, (
        f"{operation!r}: delivered event {marker_field} must contain {marker_value!r}, "
        f"got {delivered!r}")


# ── Delivery: Okta phase fires the ThreatInsight rule shape ──────────────────


def test_okta_phase_emits_security_threat_detected():
    import detection_rules
    from sources import okta

    detection_rules._injected_total.clear()
    detection_rules._last_fired.clear()
    _make_rule("okta", _phase("credential-access")["field_overrides"])

    logs, _ = okta.get_logs_response(limit=100)
    threat = [e for e in logs if e.get("eventType") == "security.threat.detected"]
    assert len(threat) == 1, (
        f"Okta phase must emit exactly one security.threat.detected event, got {len(threat)}")
    ev = threat[0]
    assert ev.get("severity") == "HIGH", "severity must be HIGH (not INFO/WARN) to fire the rule"
    assert ev.get("outcome", {}).get("result") == "SUCCESS", "status must not be DENY"
