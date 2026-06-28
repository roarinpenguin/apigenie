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
    detection_rules._save_rules([])  # wipe persisted rules — test isolation
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


def test_phase4_targets_entra_via_azure_role_rule():
    p = _phase("privilege-escalation")
    assert p["source"] == "entra_id", "phase 4 must target Entra ID (Azure AD)"
    fo = p["field_overrides"]
    assert fo["activityDisplayName"] == "Add member to role"
    assert fo["operationType"] == "Assign", (
        "operationType must be 'Assign' (background uses 'Add') to fire the rule "
        "without background noise")
    assert any("Global Administrator" in str(t) for t in fo["targetResources"])


def test_consent_phase_carries_allprincipals_marker():
    p = _phase("persistence")
    mp = p["field_overrides"].get("ModifiedProperties", "")
    assert "ConsentType: AllPrincipals" in mp, (
        "consent phase must carry the AllPrincipals marker the shipped rule keys on")


@pytest.mark.parametrize("phase_id, expected_in_s1ql", [
    ("credential-access", "security.threat.detected"),
    ("persistence", "ConsentType: AllPrincipals"),
    ("privilege-escalation", "unmapped.operationType = 'Assign'"),
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


def test_consent_phase_allprincipals_marker_survives_two_step():
    """The consent phase event must reach the collector carrying the
    ``ConsentType: AllPrincipals`` marker the ACTIVE shipped rule keys on.

    We filter by the marker (not by Operation) because the M365 *background*
    also emits ``Consent to application.`` — only the scenario injection sets
    the AllPrincipals ModifiedProperties, so the marker uniquely isolates the
    capped event. (The generic exactly-once two-step delivery guarantee is
    covered by ``test_m365_blob_cache.py``.)
    """
    from fastapi.testclient import TestClient

    import app as apigenie_app

    _reset_injector_state()
    _make_rule("m365", _phase("persistence")["field_overrides"])

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

    marked = []
    for blob in blobs:
        path = urlparse(blob["contentUri"]).path
        r2 = client.get(path, headers=headers)
        assert r2.status_code == 200, r2.text
        marked.extend(
            e for e in r2.json()
            if "ConsentType: AllPrincipals" in str(e.get("ModifiedProperties", "")))

    assert len(marked) == 1, (
        f"the capped AllPrincipals consent event must reach the collector exactly "
        f"once, got {len(marked)}")
    assert marked[0].get("Operation") == "Consent to application."


# ── Delivery: Okta phase fires the ThreatInsight rule shape ──────────────────


def test_pim_phase4_injects_into_entra_via_alias_canonicalization():
    """Phase 4 (source='entra_id') must inject into the azure_ad generator.

    Regression for the alias bug: ``inject_detection_events`` keyed rules on an
    EXACT source match, so an 'entra_id' rule never matched the 'azure_ad'
    generator. The fix canonicalizes both sides. Here we create the rule with
    the alias ('entra_id', exactly as the scenario engine tags it) and assert
    the azure_ad audit feed injects the Azure role-assignment event.
    """
    import detection_rules
    from sources import azure_ad

    _reset_injector_state()
    _make_rule("entra_id", _phase("privilege-escalation")["field_overrides"])

    resp = azure_ad.get_audit_logs_response(limit=50)
    events = resp["value"]
    hits = [e for e in events
            if e.get("activityDisplayName") == "Add member to role"
            and e.get("operationType") == "Assign"]
    assert len(hits) == 1, (
        f"entra_id phase rule must inject exactly one Azure role assignment, got {len(hits)}")
    assert "Global Administrator" in str(hits[0].get("targetResources")), (
        "delivered event targetResources must carry the privileged role name")


def test_collection_phase_mints_unique_objectids_and_user_type():
    """The bulk-download phase must mint a UNIQUE ``unmapped.ObjectId`` per
    event (via the ``{{seq}}`` placeholder) and force ``UserType=0`` so the
    shipped "Office 365 Bulk File Download" threshold rule trips.

    Regression for att-20260628-4125: static overrides built on a RANDOM base
    event collapsed to ~20 distinct ObjectIds (54/84 empty) and only ~15
    type-User events, so ``estimate_distinct(unmapped.ObjectId) >= 100 AND
    actor.user.type='User'`` never matched.
    """
    import detection_rules

    p = _phase("collection")
    fo = p["field_overrides"]
    assert fo["UserType"] == 0, "must force actor.user.type='User'"
    assert "{{seq}}" in fo["ObjectId"], "ObjectId must mint a unique value per event"
    assert p["max_events"] >= 110, "burst must clear the >=100 distinct threshold with margin"

    events = [detection_rules._apply_overrides({"seed": 1}, fo) for _ in range(150)]
    object_ids = {e["ObjectId"] for e in events}
    assert len(object_ids) == 150, (
        f"each injected download must carry a unique ObjectId, got {len(object_ids)} distinct")
    assert all(e["UserType"] == 0 for e in events)
    assert all(e["Operation"] == "FileDownloaded" for e in events)


def test_seq_placeholder_only_expands_when_present():
    """``{{seq}}`` expansion must be a no-op for static overrides (no token)
    and for non-string values, so it can never corrupt existing phases."""
    import detection_rules

    static = detection_rules._apply_overrides(
        {}, {"Operation": "Consent to application.", "UserType": 0})
    assert static["Operation"] == "Consent to application."
    assert static["UserType"] == 0

    a = detection_rules._apply_overrides({}, {"ObjectId": "f-{{seq}}"})["ObjectId"]
    b = detection_rules._apply_overrides({}, {"ObjectId": "f-{{seq}}"})["ObjectId"]
    assert a != b, "consecutive expansions must differ"


def test_okta_phase_emits_security_threat_detected():
    import detection_rules
    from sources import okta

    _reset_injector_state()
    _make_rule("okta", _phase("credential-access")["field_overrides"])

    logs, _ = okta.get_logs_response(limit=100)
    threat = [e for e in logs if e.get("eventType") == "security.threat.detected"]
    assert len(threat) == 1, (
        f"Okta phase must emit exactly one security.threat.detected event, got {len(threat)}")
    ev = threat[0]
    assert ev.get("severity") == "HIGH", "severity must be HIGH (not INFO/WARN) to fire the rule"
    assert ev.get("outcome", {}).get("result") == "SUCCESS", "status must not be DENY"
