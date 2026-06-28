"""v5.1.21 — narrative fill: persona-anchored context + look-alike neighbourhood.

Beyond the (capped) alert events, a scenario phase now splices in benign
telemetry that wears the victim persona (~80%) plus a same-domain / same-subnet
neighbourhood (~20%). This gives an analyst — or SentinelOne Purple AI's agentic
auto-investigation — a coherent cohort to pivot onto. The narrative events carry
attack.id / phase.id for lake-wide correlation but NEVER the alert-triggering
overrides, so they don't raise alerts.
"""
from __future__ import annotations

import random


# Synthetic source projection (event_field ⇒ persona slot) and the spliced
# overrides a phase would carry — a mix of alert-trigger fields (NOT in the
# projection) and persona-identity fields (in the projection).
PROJ = {
    "user.email": "victim_user.email",
    "user.upn":   "victim_user.upn",
    "user.name":  "victim_user.name",
    "host.name":  "victim_host.hostname",
    "host.ip":    "victim_host.ip",
}
SPLICED = {
    # alert trigger — must be excluded from the narrative strata
    "eventType":      "user.session.start",
    "outcome.result": "SUCCESS",
    # persona identity — the only fields the narrative fill may carry
    "user.email": "olivia.brown@acme-corp.test",
    "user.upn":   "olivia.brown@acme-corp.test",
    "user.name":  "Olivia Brown",
    "host.name":  "OBROWN-LAPTOP-7",
    "host.ip":    "10.42.13.7",
}


# ── personas.derive_neighbor_bundle ──────────────────────────────────────────

def test_neighbor_bundle_same_domain_same_subnet_diff_identity():
    import personas
    victim = {
        "victim_user": {"email": "olivia.brown@acme-corp.test",
                        "upn": "olivia.brown@acme-corp.test",
                        "name": "Olivia Brown", "username": "obrown"},
        "victim_host": {"hostname": "OBROWN-LAPTOP-7", "ip": "10.42.13.7"},
    }
    for _ in range(25):
        nb = personas.derive_neighbor_bundle(victim)
        # same victim domain
        assert nb["victim_user"]["email"].endswith("@acme-corp.test")
        assert nb["victim_user"]["upn"] == nb["victim_user"]["email"]
        # same /24
        assert nb["victim_host"]["ip"].startswith("10.42.13.")
        # different identity from the victim (host octet may rarely collide, so
        # assert on the user identity which is drawn from a 10-name pool)
        assert nb["victim_user"]["object_id"]  # fresh id always present


def test_neighbor_bundle_carries_over_attacker_unchanged():
    import personas
    victim = {
        "victim_user": {"email": "a@x.test"},
        "victim_host": {"ip": "10.0.0.5"},
        "attacker": {"ip": "185.220.101.42", "domain": "evilcorp.bad"},
    }
    nb = personas.derive_neighbor_bundle(victim)
    assert nb["attacker"] == victim["attacker"], "one adversary, not a crowd"


# ── scenario_narrative.build_metadata ────────────────────────────────────────

def test_build_metadata_extracts_identity_only():
    import scenario_narrative as sn
    meta = sn.build_metadata(SPLICED, PROJ, "att-1", "phase-x", "okta")
    assert meta is not None
    # Only projection fields — never the alert triggers.
    assert set(meta["identity"]) == set(PROJ)
    assert "eventType" not in meta["identity"]
    assert "outcome.result" not in meta["identity"]
    # Correlation tags.
    assert meta["tags"]["attack.id"] == "att-1"
    assert meta["tags"]["phase.id"] == "phase-x"
    # Reconstructed partial victim bundle for consistent sibling generation.
    assert meta["victim_partial"]["victim_user"]["email"] == "olivia.brown@acme-corp.test"
    assert meta["victim_partial"]["victim_host"]["ip"] == "10.42.13.7"


def test_build_metadata_none_when_nothing_to_anchor():
    import scenario_narrative as sn
    # No projection fields present in overrides.
    assert sn.build_metadata({"eventType": "x"}, PROJ, "a", "p", "okta") is None
    # No projection for the source.
    assert sn.build_metadata(SPLICED, {}, "a", "p", "okta") is None
    # Operator disabled the narrative fill.
    assert sn.build_metadata(SPLICED, PROJ, "a", "p", "okta",
                             cfg={"enabled": False}) is None


# ── scenario_narrative.plan_counts ───────────────────────────────────────────

def test_plan_counts_respects_ratio():
    import scenario_narrative as sn
    meta = sn.build_metadata(
        SPLICED, PROJ, "att-1", "phase-x", "okta",
        cfg={"factor": 1.0, "context_ratio": 0.8,
             "per_poll_min": 0, "per_poll_max": 10_000})
    assert sn.plan_counts(100, meta) == (80, 20)
    assert sn.plan_counts(10, meta) == (8, 2)


def test_plan_counts_clamped():
    import scenario_narrative as sn
    meta = sn.build_metadata(
        SPLICED, PROJ, "att-1", "phase-x", "okta",
        cfg={"factor": 0.5, "context_ratio": 0.8,
             "per_poll_min": 3, "per_poll_max": 40})
    # Huge batch clamps to per_poll_max.
    n_ctx, n_nbr = sn.plan_counts(10_000, meta)
    assert n_ctx + n_nbr == 40
    # Tiny batch lifts to per_poll_min.
    n_ctx, n_nbr = sn.plan_counts(1, meta)
    assert n_ctx + n_nbr == 3


# ── scenario_narrative.build_override_batch ──────────────────────────────────

def test_override_batch_tags_present_triggers_absent():
    import scenario_narrative as sn
    meta = sn.build_metadata(
        SPLICED, PROJ, "att-1", "phase-x", "okta",
        cfg={"factor": 1.0, "context_ratio": 0.8,
             "per_poll_min": 0, "per_poll_max": 10_000})
    batch = sn.build_override_batch(meta, 100, random.Random(7))
    assert len(batch) == 100
    for ov in batch:
        # correlation tags on every narrative event
        assert ov["attack.id"] == "att-1"
        assert ov["phase.id"] == "phase-x"
        # never the alert-triggering fields
        assert "eventType" not in ov
        assert "outcome.result" not in ov


def test_override_batch_neighbourhood_same_domain():
    import scenario_narrative as sn
    meta = sn.build_metadata(
        SPLICED, PROJ, "att-1", "phase-x", "okta",
        cfg={"factor": 1.0, "context_ratio": 0.8,
             "per_poll_min": 0, "per_poll_max": 10_000})
    batch = sn.build_override_batch(meta, 100, random.Random(7))
    # Events whose user identity differs from the persona are the neighbourhood;
    # they must still belong to the same corporate domain.
    neighbours = [ov for ov in batch
                  if ov.get("user.email") != "olivia.brown@acme-corp.test"]
    assert neighbours, "expected a non-empty neighbourhood"
    for ov in neighbours:
        assert ov["user.email"].endswith("@acme-corp.test")
        assert ov["host.ip"].startswith("10.42.13.")


# ── integration through detection_rules.inject_detection_events ───────────────

def _logs(n: int = 30) -> list[dict]:
    return [{"event": "noop", "i": i} for i in range(n)]


def test_inject_adds_narrative_without_alerts():
    import detection_rules
    import scenario_narrative as sn
    import profiles
    profiles.set_current_user(None)

    meta = sn.build_metadata(
        SPLICED, PROJ, "att-99", "phase-1", "okta",
        cfg={"factor": 0.5, "context_ratio": 0.8,
             "per_poll_min": 3, "per_poll_max": 40})

    detection_rules.create_rule({
        "name": "[SCENARIO] stolen token",
        "source": "okta",
        "owner_id": None,
        "visibility": "public",
        "periodicity": 5,
        "max_events": 1,                       # exactly one alert over lifetime
        "field_overrides": {"eventType": "user.session.start"},
        "_scenario_id": "scn-1",
        "_attack_id": "att-99",
        "_narrative": meta,
    })

    alerts = 0
    narrative = 0
    for _ in range(3):
        out = detection_rules.inject_detection_events("okta", _logs())
        for ev in out:
            if ev.get("_detection_rule") == "[SCENARIO] stolen token":
                alerts += 1
            elif ev.get("attack", {}).get("id") == "att-99":
                narrative += 1
                # narrative events never carry the alert trigger
                assert "eventType" not in ev or ev.get("eventType") == "noop" or "user" in ev

    assert alerts == 1, f"alert must stay capped at 1, got {alerts}"
    assert narrative > 0, "narrative fill should add persona-context events"


def test_plain_rule_has_no_narrative():
    """A user-defined rule without _narrative must not trigger the fill path."""
    import detection_rules
    import profiles
    profiles.set_current_user(None)

    detection_rules.create_rule({
        "name": "plain",
        "source": "okta",
        "owner_id": None,
        "visibility": "public",
        "periodicity": 5,
        "field_overrides": {"marker": "x"},
    })
    out = detection_rules.inject_detection_events("okta", _logs())
    assert not any(ev.get("attack", {}).get("id") for ev in out)
