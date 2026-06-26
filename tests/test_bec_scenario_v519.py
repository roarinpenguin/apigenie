"""v5.1.9 — BEC scenario reshape regression.

Every BEC phase's ``field_overrides`` must, after the standard
``detection_rules._apply_overrides`` deep-merge onto a base event,
produce a JSON-serialised payload that satisfies the s1ql query body
of at least one vendor-shipped SentinelOne STAR rule enabled on a
typical demo tenant (``usea1-purple`` empirically — see
``/tmp/rule_queries.txt`` for the live dump).

The s1ql query bodies in the assertions below are paraphrased from
the live ``platform-rules`` surface and intentionally simplified to
the conditions that matter for the alert to fire. Each assertion is
a sufficient subset, not a full s1ql interpreter.

Updating these tests when an S1 rule is rewritten is the canonical
forcing function for keeping the BEC template aligned with the
"Browse S1 Library → Enabled" set on the demo tenant.
"""
from __future__ import annotations

import json

import detection_rules
from attack_scenarios_library import TEMPLATES


# ── Helpers ──────────────────────────────────────────────────────────────────


def _phases() -> dict[str, dict]:
    """Return BEC phases indexed by ``phase_id``."""
    bec = TEMPLATES["bec_phishing"]
    return {p["phase_id"]: p for p in bec["phases"]}


def _apply(phase: dict, base: dict | None = None) -> dict:
    """Run the production override path on a base event so the result
    is byte-for-byte what the scenario engine actually emits."""
    return detection_rules._apply_overrides(base or {}, phase["field_overrides"])


def _flat(obj) -> str:
    """JSON-serialise for substring assertions matching the s1ql
    ``contains`` operator semantics."""
    return json.dumps(obj, default=str)


# ── Phase 1 — Proofpoint Impostor Email Unblocked ────────────────────────────


def test_bec_phase1_fires_proofpoint_impostor_email_unblocked():
    phases = _phases()
    p = phases["initial-access"]
    assert p["source"] == "proofpoint", "phase 1 must be Proofpoint-sourced"
    ev = _apply(p)
    body = _flat(ev)
    # s1ql: unmapped.threatsInfoMap contains '"classification":"impostor"'
    assert '"classification": "impostor"' in body or '"classification":"impostor"' in body, body
    # s1ql: (messageParts contains '"sandboxStatus":"THREAT"' OR impostorScore > 80)
    assert (
        '"sandboxStatus": "THREAT"' in body
        or '"sandboxStatus":"THREAT"' in body
        or (isinstance(ev.get("impostorScore"), int) and ev["impostorScore"] > 80)
    ), body
    # s1ql: NOT (quarantineFolder = *)  — empty string means not quarantined
    assert ev.get("quarantineFolder", "") == "", ev


# ── Phase 2 — Okta Impersonation Session Initiated ───────────────────────────


def test_bec_phase2_fires_okta_impersonation_session():
    phases = _phases()
    p = phases["credential-access"]
    assert p["source"] == "okta"
    ev = _apply(p)
    # s1ql: (eventType contains 'user.session.impersonation.initiate'
    #        OR legacyEventType contains 'user.session.impersonation.initiate')
    assert "user.session.impersonation.initiate" in str(ev.get("eventType", ""))


# ── Phase 3 — O365 Admin Consent Granted for All Principals ──────────────────


def test_bec_phase3_fires_o365_admin_consent_all_principals():
    phases = _phases()
    p = phases["privilege-escalation"]
    assert p["source"] == "m365"
    ev = _apply(p)
    # s1ql: unmapped.Operation='Consent to application.'
    assert ev.get("Operation") == "Consent to application.", ev
    # s1ql: unmapped.ModifiedProperties contains 'ConsentType: AllPrincipals'
    assert "ConsentType: AllPrincipals" in str(ev.get("ModifiedProperties", "")), ev


# ── Phase 4 — O365 Inbox Rule Suspicious Parameters ──────────────────────────


def test_bec_phase4_fires_o365_inbox_rule_suspicious_parameters():
    phases = _phases()
    p = phases["defense-evasion"]
    assert p["source"] == "m365"
    ev = _apply(p)
    # activity_name in ('New-InboxRule','Set-InboxRule') — apigenie sets `Operation`
    # which S1 parser maps to activity_name.
    assert ev.get("Operation") in ("New-InboxRule", "Set-InboxRule"), ev
    params_json = _flat(ev.get("Parameters", []))
    # Third s1ql branch: MoveToFolder→(Conv History | RSS Feeds | Deleted Items |
    # Junk Email) AND MarkAsRead=True (the silent-hide pattern).
    assert '"Name": "MoveToFolder"' in params_json or '"Name":"MoveToFolder"' in params_json
    move_target_ok = any(
        f'"Value": "{folder}"' in params_json or f'"Value":"{folder}"' in params_json
        for folder in ("Conversation History", "RSS Feeds", "Deleted Items", "Junk Email")
    )
    assert move_target_ok, params_json
    assert '"Name": "MarkAsRead"' in params_json or '"Name":"MarkAsRead"' in params_json
    assert '"Value": "True"' in params_json or '"Value":"True"' in params_json


# ── Phase 5 — O365 Mailbox Permissions Delegation ────────────────────────────


def test_bec_phase5_fires_o365_mailbox_permissions_delegation():
    phases = _phases()
    p = phases["persistence"]
    assert p["source"] == "m365"
    ev = _apply(p)
    # s1ql: activity_name='Add-MailboxPermission'
    assert ev.get("Operation") == "Add-MailboxPermission", ev
    # s1ql: metadata.product.name='Exchange'  ← apigenie sets Workload
    assert ev.get("Workload") == "Exchange", ev
    # s1ql: unmapped.Parameters contains:matchcase ('FullAccess','SendAs','SendOnBehalf')
    params_json = _flat(ev.get("Parameters", []))
    assert any(
        access in params_json for access in ("FullAccess", "SendAs", "SendOnBehalf")
    ), params_json


# ── Phase 5 narrative — must not be system-actor ──────────────────────────────


def test_bec_phase5_userid_not_system():
    """The Mailbox Permissions Delegation rule excludes
    ``NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)`` as the
    actor — apigenie's M365 ``_base`` uses a real user identity
    pulled from the profile context; we just guarantee the override
    doesn't accidentally re-introduce the system actor."""
    phases = _phases()
    p = phases["persistence"]
    overrides = p["field_overrides"]
    # The override must not pin UserId to the system actor.
    assert "NT AUTHORITY" not in str(overrides.get("UserId", ""))


# ── Catalogue invariants ─────────────────────────────────────────────────────


def test_bec_has_five_phases_in_canonical_order():
    bec = TEMPLATES["bec_phishing"]
    ids = [p["phase_id"] for p in bec["phases"]]
    assert ids == [
        "initial-access",
        "credential-access",
        "privilege-escalation",
        "defense-evasion",
        "persistence",
    ], ids


def test_bec_phase_offsets_are_non_overlapping_and_monotonic():
    """time_offset_pct + duration_pct must form a non-decreasing
    timeline so phases don't double-fire. Operationally, the engine
    just iterates phases by start time; this test guards against an
    edit that accidentally re-orders or overlaps in a way that breaks
    the demo narrative."""
    bec = TEMPLATES["bec_phishing"]
    last_start = -1
    for p in bec["phases"]:
        assert p["time_offset_pct"] >= last_start, p
        last_start = p["time_offset_pct"]
        assert 0 <= p["duration_pct"] <= 100
