"""Insider Threat scenario — phase→rule alignment regression.

Companion to ``test_cloud_takeover_phases.py``. Locks the v5.2 alignment of
the Insider Threat template against the REAL shipped SentinelOne platform
rules discovered on usea1-purple (detection-library catalog, 2026-06-29):

* collection        → "Office 365 Bulk File Download" (threshold rule —
  reuses the validated {{seq}} ObjectId + UserType:0 + max_events 150 pattern).
* exfiltration      → "Office 365 New Mailbox Forwarding Rule" (ForwardTo
  parameter + ResultStatus='Succeeded').
* exfiltration-2    → "Netskope Insider Threat Suspicious Activity"
  (activity_name='Uba', scenario='Insider threat', activity='Upload',
  count>1, file_size>1MB).
* persistence       → "Cisco Duo Authentication Attempt from Untrusted
  Endpoint" (event_type='authentication', status_detail~endpoint_is_not_trusted,
  status='success').
* defense-evasion   → "Office 365 Inbox Rule to Automatically Delete All
  Messages" (DeleteMessage:True, no condition predicates).
* credential-access → "Okta High Severity Threat Detected"
  (security.threat.detected + severity HIGH).

These assert the template WIRING (field_overrides carry each rule's
discriminator + target_rules document the real s1ql). End-to-end firing is
verified live on the tenant — the s1ql / field-landing notes in the template
flag the two collectors (Netskope, Duo) still pending lake confirmation.
"""
from __future__ import annotations

import json

import pytest

import attack_scenarios_library as L


def _phase(phase_id: str) -> dict:
    t = L.get_template("insider_threat")
    assert t is not None, "insider_threat template must exist"
    for p in t["phases"]:
        if p["phase_id"] == phase_id:
            return p
    raise AssertionError(f"phase {phase_id} not found")


def _params_json(phase: dict) -> str:
    return json.dumps(phase["field_overrides"].get("Parameters", []))


# ── Template visibility ──────────────────────────────────────────────────────

def test_insider_threat_is_selectable():
    keys = {t["key"] for t in L.get_templates()}
    assert "insider_threat" in keys, "insider_threat must stay in the picker"


def test_template_passes_scenario_validation():
    import attack_scenarios

    t = L.get_template("insider_threat")
    payload = {
        "name": "Insider Threat test",
        "duration": {"value": 2, "unit": "hours"},
        "phases": t["phases"],
    }
    errors = attack_scenarios.validate_scenario_payload(payload)
    assert errors == [], f"template must be a valid scenario payload, got: {errors}"


# ── Every alerting phase documents a real target rule ────────────────────────

@pytest.mark.parametrize("phase_id, rule_name, expected_in_s1ql", [
    ("collection",        "Office 365 Bulk File Download",                         None),
    ("exfiltration",      "Office 365 New Mailbox Forwarding Rule",                "ForwardTo"),
    ("exfiltration-2",    "Netskope Insider Threat Suspicious Activity",          "unmapped.scenario = 'Insider threat'"),
    ("persistence",       "Cisco Duo Authentication Attempt from Untrusted Endpoint", "endpoint_is_not_trusted"),
    ("defense-evasion",   "Office 365 Inbox Rule to Automatically Delete All Messages", "DeleteMessage"),
    ("credential-access", "Okta High Severity Threat Detected",                   "security.threat.detected"),
])
def test_phase_documents_target_rule(phase_id, rule_name, expected_in_s1ql):
    p = _phase(phase_id)
    trs = p.get("target_rules", [])
    assert trs, f"phase {phase_id} must document a target rule"
    assert trs[0]["name"] == rule_name, (
        f"phase {phase_id} primary target must be {rule_name!r}, got {trs[0]['name']!r}")
    if expected_in_s1ql is not None:
        s1ql = trs[0].get("s1ql", "")
        assert expected_in_s1ql in s1ql, (
            f"phase {phase_id} s1ql must contain {expected_in_s1ql!r}, got: {s1ql!r}")


# ── Per-phase field_overrides satisfy the target rule's discriminators ───────

def test_collection_is_bulk_download_threshold_shape():
    p = _phase("collection")
    fo = p["field_overrides"]
    assert p["max_events"] == 150, "bulk-download threshold needs a >=100 burst with margin"
    assert fo["UserType"] == 0, "actor.user.type must resolve to 'User'"
    assert "{{seq}}" in fo["ObjectId"], "ObjectId must be unique per event for estimate_distinct"
    assert fo["Operation"] == "FileDownloaded"


def test_forwarding_phase_carries_forwardto_and_succeeded():
    p = _phase("exfiltration")
    fo = p["field_overrides"]
    assert fo["Operation"] in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
    assert fo["Workload"] == "Exchange"
    assert fo["ResultStatus"] == "Succeeded", "rule keys ResultStatus in ('Succeeded','True')"
    assert "ForwardTo" in _params_json(p), "Parameters must carry a ForwardTo entry"


def test_netskope_phase_satisfies_insider_threat_rule():
    p = _phase("exfiltration-2")
    fo = p["field_overrides"]
    assert fo["alert_type"] == "uba"
    assert fo["scenario"] == "Insider threat"
    assert fo["activity"] == "Upload"
    assert fo["count"] > 1, "rule requires count > 1"
    assert fo["file_size"] > 1_000_000, "rule requires file_size > 1MB"


def test_duo_phase_satisfies_untrusted_endpoint_rule():
    p = _phase("persistence")
    fo = p["field_overrides"]
    assert fo["event_type"] == "authentication"
    assert fo["result"] == "success", "collector maps result→status; rule needs status='success'"
    assert fo["reason"] == "endpoint_is_not_trusted", (
        "collector maps reason→status_detail; rule needs status_detail~endpoint_is_not_trusted")


def test_defense_evasion_deletes_without_conditions():
    p = _phase("defense-evasion")
    fo = p["field_overrides"]
    pj = _params_json(p)
    assert fo["Operation"] in ("New-InboxRule", "Set-InboxRule")
    assert '"DeleteMessage"' in pj and '"True"' in pj, "must set DeleteMessage:True"
    # The High-severity rule excludes any condition predicate — none may appear.
    for cond in ("FromAddressContainsWords", "SentTo", "SubjectContainsWords",
                 "BodyContainsWords", "HasAttachment"):
        assert cond not in pj, f"condition predicate {cond} would suppress the rule"


def test_okta_phase_reuses_high_severity_threat_pattern():
    p = _phase("credential-access")
    fo = p["field_overrides"]
    assert fo["eventType"] == "security.threat.detected"
    assert fo["severity"] == "HIGH", "rule excludes unmapped.severity in ('INFO','WARN')"
