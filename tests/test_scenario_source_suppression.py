"""v5.2 — scenario source ownership (#2) + stable "Other" identity (#3).

#2  While an attack-scenario phase is live on a source, the base engine steps
    aside for that source: standing/user detection rules are silenced (so a
    single "malware upload" rule can't fire thousands of times an hour off the
    constant background stream) and the benign base batch is dropped, so the
    collector sees ONLY the scenario's own telemetry.

#3  Background (non-scenario) detection-rule matches land on a STABLE per-source
    "Other Device" / "Other User" instead of a freshly-randomised unknown
    device, so every background alert for a source correlates to one entity.
"""
from __future__ import annotations

import pytest


def _logs(n: int = 20) -> list[dict]:
    return [{"event": "noop", "i": i, "benign": True} for i in range(n)]


@pytest.fixture(autouse=True)
def _clean_scenario_state():
    import detection_rules
    import scenario_state
    scenario_state.reset()
    detection_rules._injected_total.clear()
    detection_rules._last_fired.clear()
    yield
    scenario_state.reset()


# ── scenario_state registry ─────────────────────────────────────────────────

def test_registry_acquire_release_refcount():
    import scenario_state as st
    assert not st.is_active("netskope")
    st.acquire("netskope")
    assert st.is_active("netskope")
    st.acquire("netskope")           # second phase on same source
    st.release("netskope")
    assert st.is_active("netskope"), "still owned after 1 of 2 releases"
    st.release("netskope")
    assert not st.is_active("netskope")
    assert st.active_sources() == set()


def test_registry_canonicalises_aliases():
    import scenario_state as st
    st.acquire("entra_id")
    assert st.is_active("azure_ad"), "aliases resolve to the same canonical id"
    st.release("azure_ad")
    assert not st.is_active("entra_id")


def test_registry_ignores_empty_source():
    import scenario_state as st
    st.acquire("")
    st.release("")
    assert st.active_sources() == set()


# ── #2 suppression in inject_detection_events ───────────────────────────────

def _standing(name="malware upload"):
    import detection_rules
    return detection_rules.create_rule({
        "name": name, "source": "netskope", "owner_id": None,
        "visibility": "public", "periodicity": 10,
        "field_overrides": {"alert.type": "malware", "standing.marker": "STAND"},
    })


def _scenario_rule():
    import detection_rules
    return detection_rules.create_rule({
        "name": "[SCENARIO] p1", "source": "netskope", "owner_id": None,
        "visibility": "public", "periodicity": 5,
        "field_overrides": {"attack.id": "att-1", "scn.marker": "SCN"},
        "_scenario_id": "sid-1", "_attack_id": "att-1",
    })


def test_not_owned_keeps_background_and_standing_rules():
    import detection_rules
    _standing()
    out = detection_rules.inject_detection_events("netskope", _logs())
    assert any(e.get("_detection_rule") for e in out), "standing rule injects"
    assert any(not e.get("_detection_rule") for e in out), "benign base passes through"


def test_owned_suppresses_benign_and_standing_rules():
    import detection_rules
    import scenario_state as st
    _standing()
    _scenario_rule()
    st.acquire("netskope")
    out = detection_rules.inject_detection_events("netskope", _logs())
    # Only injected events survive — the raw benign base batch is dropped.
    assert out and all(e.get("_detection_rule") for e in out)
    # The standing rule is silenced (its marker never appears).
    assert all(e.get("standing") is None for e in out)
    # The scenario's own rule still fires.
    assert any(e.get("scn", {}).get("marker") == "SCN" for e in out)


def test_owned_but_idle_returns_empty_batch():
    import detection_rules
    import scenario_state as st
    _standing()                       # only a standing rule, no scenario rule
    st.acquire("netskope")
    out = detection_rules.inject_detection_events("netskope", _logs())
    assert out == [], "owned+idle drops the benign background entirely"


def test_release_restores_background():
    import detection_rules
    import scenario_state as st
    _standing()
    st.acquire("netskope")
    st.release("netskope")
    out = detection_rules.inject_detection_events("netskope", _logs())
    assert any(not e.get("_detection_rule") for e in out), "background is back"


def test_ownership_is_per_source():
    """A scenario on netskope must not suppress an unrelated source (okta)."""
    import detection_rules
    import scenario_state as st
    detection_rules.create_rule({
        "name": "okta standing", "source": "okta", "owner_id": None,
        "visibility": "public", "periodicity": 10,
        "field_overrides": {"marker": "okta"},
    })
    st.acquire("netskope")
    out = detection_rules.inject_detection_events("okta", _logs())
    assert any(not e.get("_detection_rule") for e in out), "okta background untouched"
    assert any(e.get("_detection_rule") for e in out), "okta standing rule still fires"


# ── #3 stable per-source "Other" identity for background alerts ─────────────

def test_other_bundle_stable_and_per_source():
    import personas
    a = personas.other_bundle("netskope")
    assert personas.other_bundle("netskope") == a, "stable across calls"
    b = personas.other_bundle("okta")
    assert a["victim_host"]["hostname"] != b["victim_host"]["hostname"], "distinct per source"
    assert a["victim_host"]["hostname"].startswith("OTHER-DEVICE-")
    assert a["victim_user"]["name"] == "Other User"


def test_background_alert_carries_other_identity(monkeypatch):
    import detection_rules
    import personas
    import sources
    proj = {"user.email": "victim_user.email", "device.name": "victim_host.hostname"}
    monkeypatch.setattr(sources, "get_persona_projection",
                        lambda s: proj if sources.canonical_source_id(s) == "netskope" else {})
    _standing()
    out = detection_rules.inject_detection_events("netskope", _logs())
    ob = personas.other_bundle("netskope")
    alerts = [e for e in out if e.get("_detection_rule")]
    assert alerts
    for e in alerts:
        assert e["user"]["email"] == ob["victim_user"]["email"]
        assert e["device"]["name"] == ob["victim_host"]["hostname"]


def test_rule_authored_identity_field_wins(monkeypatch):
    import detection_rules
    import sources
    proj = {"user.email": "victim_user.email", "device.name": "victim_host.hostname"}
    monkeypatch.setattr(sources, "get_persona_projection",
                        lambda s: proj if sources.canonical_source_id(s) == "netskope" else {})
    detection_rules.create_rule({
        "name": "explicit", "source": "netskope", "owner_id": None,
        "visibility": "public", "periodicity": 10,
        "field_overrides": {"user.email": "explicit@x.test", "alert.type": "x"},
    })
    out = detection_rules.inject_detection_events("netskope", _logs())
    alerts = [e for e in out if e.get("_detection_rule") == "explicit"]
    assert alerts and all(e["user"]["email"] == "explicit@x.test" for e in alerts)


def test_scenario_rule_does_not_get_other_identity(monkeypatch):
    """Scenario temp rules keep their own persona bundle; #3 must not touch them."""
    import detection_rules
    import personas
    import scenario_state as st
    import sources
    proj = {"user.email": "victim_user.email"}
    monkeypatch.setattr(sources, "get_persona_projection", lambda s: proj)
    detection_rules.create_rule({
        "name": "[SCENARIO] p1", "source": "netskope", "owner_id": None,
        "visibility": "public", "periodicity": 5,
        "field_overrides": {"attack.id": "att-1", "user.email": "victim@acme.test"},
        "_scenario_id": "sid-1", "_attack_id": "att-1",
    })
    st.acquire("netskope")
    out = detection_rules.inject_detection_events("netskope", _logs())
    ob = personas.other_bundle("netskope")
    alerts = [e for e in out if e.get("_detection_rule")]
    assert alerts
    for e in alerts:
        assert e["user"]["email"] == "victim@acme.test"
        assert e["user"]["email"] != ob["victim_user"]["email"]
