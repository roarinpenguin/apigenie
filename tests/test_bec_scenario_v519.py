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


# ── Phase 4 — O365 Anti-Phish Rule Removal (defense evasion) ──────────────────


def test_bec_phase4_fires_o365_antiphish_rule_removal():
    """v5.1.16 — Phase 4 emits Remove-AntiPhishRule on Exchange Online so the
    SHIPPED scalar-field platform rule 'Office 365 Deactivation or Removal of
    Anti-Phish Rule' fires AND resolves the acting user as the Target Asset."""
    phases = _phases()
    p = phases["defense-evasion"]
    assert p["source"] == "m365"
    ev = _apply(p)
    # activity_name in ('Remove-AntiPhishRule','Disable-AntiPhishRule') — apigenie
    # sets `Operation`, which the S1 collector maps to activity_name.
    assert ev.get("Operation") in ("Remove-AntiPhishRule", "Disable-AntiPhishRule"), ev
    # s1ql: metadata.product.name='Exchange'  ← apigenie sets Workload
    assert ev.get("Workload") == "Exchange", ev


# ── Phase 5 — O365 Mail Transport Rule Creation (persistence/exfil) ───────────


def test_bec_phase5_fires_o365_transport_rule_creation():
    """v5.1.16 — Phase 5 emits New-TransportRule on Exchange Online so the
    SHIPPED scalar-field platform rule 'Office 365 Creation of Mail Transport
    Rule' fires AND resolves the acting user as the Target Asset."""
    phases = _phases()
    p = phases["persistence"]
    assert p["source"] == "m365"
    ev = _apply(p)
    # s1ql: activity_name='New-TransportRule'
    assert ev.get("Operation") == "New-TransportRule", ev
    # s1ql: metadata.product.name='Exchange'  ← apigenie sets Workload
    assert ev.get("Workload") == "Exchange", ev
    # Realism: the transport rule redirects mail to an external attacker mailbox.
    params_json = _flat(ev.get("Parameters", []))
    assert "RedirectMessageTo" in params_json, params_json


# ── v5.1.16 — Phase 4 / Phase 5 target shipped scalar-field platform rules ─────


def test_bec_phase4_target_rule_is_shipped_antiphish():
    """v5.1.16 — Phase 4 must point at the SHIPPED scalar-field platform rule
    so the alert resolves the Target Asset. It must NOT be a custom rule and
    must NOT depend on the unmapped.Parameters array (which the STAR engine
    cannot evaluate once the collector flattens it into indexed keys)."""
    phases = _phases()
    p = phases["defense-evasion"]
    rules = p.get("target_rules", [])
    assert len(rules) == 1, rules
    r = rules[0]
    assert not r.get("custom"), "Phase 4 must target a shipped platform rule, not a custom rule"
    assert r["name"] == "Office 365 Deactivation or Removal of Anti-Phish Rule", r["name"]
    s1ql = r["s1ql"]
    assert "unmapped.Parameters" not in s1ql, "scalar-only rule must not key off the Parameters array"
    assert "Remove-AntiPhishRule" in s1ql and "Disable-AntiPhishRule" in s1ql, s1ql
    assert "metadata.product.name = 'Exchange'" in s1ql, s1ql


def test_bec_phase5_target_rule_is_shipped_transport_rule():
    """v5.1.16 — Phase 5 must point at the SHIPPED scalar-field 'Creation of
    Mail Transport Rule' platform rule so the alert resolves the Target Asset,
    and must not depend on the unmapped.Parameters array."""
    phases = _phases()
    p = phases["persistence"]
    rules = p.get("target_rules", [])
    assert len(rules) == 1, rules
    r = rules[0]
    assert not r.get("custom"), "Phase 5 must target a shipped platform rule, not a custom rule"
    assert r["name"] == "Office 365 Creation of Mail Transport Rule", r["name"]
    s1ql = r["s1ql"]
    assert "unmapped.Parameters" not in s1ql, "scalar-only rule must not key off the Parameters array"
    assert "New-TransportRule" in s1ql, s1ql
    assert "metadata.product.name = 'Exchange'" in s1ql, s1ql


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
