"""v5.1.19 — total-event cap on detection rules.

A rule carrying ``max_events`` must emit at most that many events across
ALL collector poll batches over its lifetime, instead of the legacy
count-based behaviour that injects ``len(logs)//periodicity`` events on
EVERY poll (which made a single BEC admin-action phase produce hundreds
of alerts). Uncapped rules keep the legacy unbounded behaviour.
"""
from __future__ import annotations


def _logs(n: int = 30) -> list[dict]:
    return [{"event": "noop", "i": i} for i in range(n)]


def _count(logs: list[dict], name: str) -> int:
    return sum(1 for ev in logs if ev.get("_detection_rule") == name)


def test_max_events_caps_total_across_polls():
    import detection_rules
    import profiles
    profiles.set_current_user(None)

    rule = detection_rules.create_rule({
        "name": "capped_rule",
        "source": "okta",
        "owner_id": None,            # admin/global → fires for everyone
        "visibility": "public",
        "periodicity": 1,            # count-based would inject len(logs) each poll
        "max_events": 2,
        "field_overrides": {"marker": "capped"},
    })
    assert rule.get("max_events") == 2

    total = 0
    # Simulate five collector polls; an uncapped periodicity=1 rule would
    # inject ~len(logs) events PER poll (~150 total). Capped → exactly 2.
    for _ in range(5):
        out = detection_rules.inject_detection_events("okta", _logs())
        total += _count(out, "capped_rule")
    assert total == 2, f"expected exactly 2 events total, got {total}"


def test_uncapped_rule_still_floods():
    """Control: without max_events the count-based path still injects many
    events per poll (legacy behaviour preserved)."""
    import detection_rules
    import profiles
    profiles.set_current_user(None)

    detection_rules.create_rule({
        "name": "uncapped_rule",
        "source": "okta",
        "owner_id": None,
        "visibility": "public",
        "periodicity": 1,
        "field_overrides": {"marker": "uncapped"},
    })
    out = detection_rules.inject_detection_events("okta", _logs(30))
    # periodicity=1 → len(logs)//1 = 30 events in a single poll.
    assert _count(out, "uncapped_rule") >= 30


def test_max_events_survives_zero_remaining_after_cap():
    """Once the cap is reached, later polls inject nothing for that rule."""
    import detection_rules
    import profiles
    profiles.set_current_user(None)

    detection_rules.create_rule({
        "name": "one_shot",
        "source": "okta",
        "owner_id": None,
        "visibility": "public",
        "periodicity": 1,
        "max_events": 1,
        "field_overrides": {"marker": "one"},
    })
    first = _count(detection_rules.inject_detection_events("okta", _logs()), "one_shot")
    second = _count(detection_rules.inject_detection_events("okta", _logs()), "one_shot")
    assert first == 1
    assert second == 0
