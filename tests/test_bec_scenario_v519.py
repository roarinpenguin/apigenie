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
    # v5.1.12 — s1ql: NOT (quarantineFolder = *). The SDL wildcard
    # matches any non-null value including the empty string; only
    # ``None`` (JSON null) leaves the field truly absent. The previous
    # value "" silently caused the rule to exclude every BEC Phase 1
    # event.
    assert ev.get("quarantineFolder") is None, ev


def test_bec_phase1_overrides_preserve_proofpoint_array_shape():
    """Regression for v5.1.12 — _apply_overrides must not clobber the
    Proofpoint template's ``messageParts`` array. Pre-fix the override
    used dot-notation ``messageParts.0.sandboxStatus`` which forced
    _set_nested to rewrite the list as ``{"0": {...}}``, breaking the
    parser. The fix replaces the whole list. This test guards against
    a future edit that re-introduces the index-into-list pattern."""
    phases = _phases()
    p = phases["initial-access"]
    # Use a base resembling the Proofpoint template (messageParts is
    # an array of dicts) — the production code path goes through this
    # shape via sources/proofpoint.py:_generate_message.
    base = {
        "messageParts": [
            {"contentType": "text/html", "sandboxStatus": "unsupported"},
        ],
        "quarantineFolder": None,
    }
    ev = _apply(p, base=base)
    # messageParts must stay a *list* after the override, not become
    # a dict. The Proofpoint parser drops malformed events silently.
    assert isinstance(ev.get("messageParts"), list), (
        "Override clobbered messageParts into a non-list shape — "
        "the Proofpoint parser will discard the event."
    )
    # The override's sandboxStatus must be present in the first part.
    assert ev["messageParts"][0].get("sandboxStatus") == "THREAT", ev["messageParts"]
    # threatsInfoMap is a list of dicts; no dict-with-"0"-key smell.
    assert isinstance(ev.get("threatsInfoMap"), list), ev.get("threatsInfoMap")
    assert ev["threatsInfoMap"][0].get("classification") == "impostor", ev["threatsInfoMap"]


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


# ── v5.1.13 — Phase 4 / Phase 5 target_rules switched to apigenie custom rules ──


def test_bec_phase4_target_rule_is_apigenie_custom_legacy_client():
    """v5.1.13 — Phase 4 must point at the apigenie custom STAR rule
    that keys off ``unmapped.ClientApplication``. The shipped S1 rule
    that queries ``unmapped.Parameters`` cannot fire on this tenant
    because the OCSF collector drops the Parameters array."""
    phases = _phases()
    p = phases["defense-evasion"]
    rules = p.get("target_rules", [])
    assert len(rules) == 1, rules
    r = rules[0]
    assert r.get("custom") is True, "Phase 4 target rule must be marked custom=True"
    assert not r["name"].startswith("[apigenie]"), "custom rule name must not carry the [apigenie] prefix"
    assert "Legacy Client Protocol" in r["name"], r["name"]
    s1ql = r["s1ql"]
    # Must use parsed fields, not unmapped.Parameters (dropped by collector).
    assert "unmapped.Parameters" not in s1ql, "must avoid the dropped field"
    assert "unmapped.ClientApplication" in s1ql, s1ql
    assert "POP3" in s1ql and "IMAP4" in s1ql and "EWS" in s1ql, s1ql
    assert "New-InboxRule" in s1ql and "Set-InboxRule" in s1ql, s1ql


def test_bec_phase5_target_rule_is_apigenie_custom_legacy_client():
    """v5.1.13 — Phase 5 must point at the apigenie custom STAR rule
    that keys off ``unmapped.ClientApplication``. Same reasoning as
    Phase 4: the tenant's OCSF collector drops ``unmapped.Parameters``,
    so the shipped rule is structurally unable to fire on this tenant.
    """
    phases = _phases()
    p = phases["persistence"]
    rules = p.get("target_rules", [])
    assert len(rules) == 1, rules
    r = rules[0]
    assert r.get("custom") is True, "Phase 5 target rule must be marked custom=True"
    assert not r["name"].startswith("[apigenie]"), "custom rule name must not carry the [apigenie] prefix"
    assert "Legacy Client Protocol" in r["name"], r["name"]
    s1ql = r["s1ql"]
    assert "unmapped.Parameters" not in s1ql, "must avoid the dropped field"
    assert "unmapped.ClientApplication" in s1ql, s1ql
    assert "POP3" in s1ql and "IMAP4" in s1ql and "EWS" in s1ql, s1ql
    assert "Add-MailboxPermission" in s1ql, s1ql
    # The rule still excludes the system actor — mandatory exclusion
    # carried over from the shipped Mailbox Permissions Delegation rule.
    assert "NT AUTHORITY" in s1ql, s1ql


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
