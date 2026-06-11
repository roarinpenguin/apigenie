"""Tests for the ``event_mix`` resolver + cisco_duo pilot wiring.

The resolver is the only thing standing between a configured mix and a
request response — getting it wrong silently distorts what every collector
sees. Pinned cases here:

* Storage CRUD (global + per-user override).
* ``apply()`` math: disabled events removed, weights replaced, renormalised
  to sum to 1.0, fallback to defaults when nothing configured / everything
  disabled / all weights zero.
* Per-user override shadows the global mix only for that user.
* ``cisco_duo`` pilot — the source's ``_AUTH_TEMPLATES`` / ``_ADMIN_TEMPLATES``
  keys match the catalog ids exactly (so an admin's overrides actually
  bind), and a configured mix actually moves the empirical distribution at
  scale.
"""
from __future__ import annotations

import collections
import os
import random
from pathlib import Path

import pytest


# ── Per-test isolation ──────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_data_root(tmp_path, monkeypatch):
    """Redirect APIGENIE_DATA_ROOT to a temp dir + reload event_mix so its
    module-level Path constants pick up the override.

    Without the reload, ``event_mix._MIX_FILE`` would still point at the
    real ``/var/lib/apigenie`` from import time.
    """
    monkeypatch.setenv("APIGENIE_DATA_ROOT", str(tmp_path))
    import importlib

    import event_mix as em
    importlib.reload(em)
    yield em
    # Reset request-scoped current user so tests don't bleed into each other.
    import profiles
    profiles._CURRENT_USER.set(None)


# ── Storage CRUD ────────────────────────────────────────────────────────────

def test_set_mix_writes_global_record(_isolate_data_root):
    em = _isolate_data_root
    rec = em.set_mix("cisco_duo", [
        {"event_id": "auth.success", "enabled": True, "weight": 0.9},
        {"event_id": "auth.failure", "enabled": False, "weight": 0.0},
    ])
    assert rec["source"] == "cisco_duo"
    assert rec["owner_id"] is None
    ids = [e["event_id"] for e in rec["mix"]]
    assert ids == ["auth.success", "auth.failure"]


def test_get_mix_returns_global_when_no_user_override(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [{"event_id": "auth.success", "enabled": True, "weight": 0.9}])
    rec = em.get_mix("cisco_duo", user_id="u-anyone")
    assert rec is not None
    assert rec["mix"][0]["event_id"] == "auth.success"


def test_user_mix_shadows_global_only_for_that_user(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [{"event_id": "auth.success", "enabled": True, "weight": 0.5}])
    em.set_mix("cisco_duo",
               [{"event_id": "auth.failure", "enabled": True, "weight": 0.8}],
               owner_id="u-alice")
    # Alice sees her own.
    alice = em.get_mix("cisco_duo", user_id="u-alice")
    assert alice["mix"][0]["event_id"] == "auth.failure"
    # Bob falls through to the global.
    bob = em.get_mix("cisco_duo", user_id="u-bob")
    assert bob["mix"][0]["event_id"] == "auth.success"


def test_reset_mix_removes_only_the_targeted_record(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [{"event_id": "auth.success", "enabled": True, "weight": 1.0}])
    em.set_mix("cisco_duo",
               [{"event_id": "auth.failure", "enabled": True, "weight": 1.0}],
               owner_id="u-alice")
    assert em.reset_mix("cisco_duo", owner_id="u-alice") is True
    assert em.get_mix("cisco_duo", user_id="u-alice") is not None  # falls through to global
    assert em.get_mix("cisco_duo", user_id="u-alice")["owner_id"] is None
    # Re-reset is a no-op.
    assert em.reset_mix("cisco_duo", owner_id="u-alice") is False


def test_list_mixes_isolates_global_from_user_records(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [{"event_id": "auth.success", "enabled": True, "weight": 1.0}])
    em.set_mix("cisco_duo",
               [{"event_id": "auth.failure", "enabled": True, "weight": 1.0}],
               owner_id="u-alice")
    glob = em.list_mixes()
    assert list(glob.keys()) == ["cisco_duo"]
    own = em.list_mixes_for_user("u-alice")
    assert list(own.keys()) == ["cisco_duo"]
    assert own["cisco_duo"]["mix"][0]["event_id"] == "auth.failure"


def test_set_mix_normalises_bad_entries(_isolate_data_root):
    em = _isolate_data_root
    rec = em.set_mix("cisco_duo", [
        {"event_id": "  ", "enabled": True, "weight": 1.0},          # blank id dropped
        {"event_id": "auth.success", "enabled": True, "weight": "x"}, # bad weight → 0.0
        {"event_id": "auth.failure", "enabled": True, "weight": -5.0},# negative → 0.0
        {"event_id": "auth.fraud",   "enabled": "yes", "weight": 0.3},# truthy enabled
    ])
    ids = {e["event_id"]: e for e in rec["mix"]}
    assert "auth.success" in ids and ids["auth.success"]["weight"] == 0.0
    assert "auth.failure" in ids and ids["auth.failure"]["weight"] == 0.0
    assert "auth.fraud"   in ids and ids["auth.fraud"]["enabled"] is True
    assert all(e["event_id"].strip() for e in rec["mix"])


# ── apply() math ────────────────────────────────────────────────────────────

_TEMPL = {
    "auth.success": ({"r": "S"}, 0.70),
    "auth.failure": ({"r": "F"}, 0.15),
    "auth.fraud":   ({"r": "X"}, 0.10),
    "auth.error":   ({"r": "E"}, 0.05),
}


def test_apply_returns_input_unchanged_when_no_override(_isolate_data_root):
    em = _isolate_data_root
    out = em.apply(_TEMPL, "cisco_duo", user_id=None)
    assert out is _TEMPL  # same object — no copy when there's nothing to do


def test_apply_strips_disabled_and_renormalises(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [
        {"event_id": "auth.fraud", "enabled": False, "weight": 0.0},
    ])
    out = em.apply(_TEMPL, "cisco_duo", user_id=None)
    assert "auth.fraud" not in out
    total = sum(w for _, w in out.values())
    assert abs(total - 1.0) < 1e-9


def test_apply_overrides_weights_then_renormalises(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [
        {"event_id": "auth.success", "enabled": True, "weight": 0.5},
        {"event_id": "auth.failure", "enabled": True, "weight": 0.5},
        # fraud + error not mentioned → keep defaults (0.10 + 0.05)
    ])
    out = em.apply(_TEMPL, "cisco_duo", user_id=None)
    # All four still present.
    assert set(out.keys()) == set(_TEMPL.keys())
    # Total stays 1.0 after renormalisation.
    assert abs(sum(w for _, w in out.values()) - 1.0) < 1e-9
    # success and failure are equal post-renormalisation.
    assert abs(out["auth.success"][1] - out["auth.failure"][1]) < 1e-9


def test_apply_falls_back_to_defaults_when_everything_disabled(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [
        {"event_id": k, "enabled": False, "weight": 0.0} for k in _TEMPL.keys()
    ])
    out = em.apply(_TEMPL, "cisco_duo", user_id=None)
    # Defaults restored — would otherwise emit nothing.
    assert out is _TEMPL


def test_apply_spreads_evenly_when_all_weights_zero(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [
        {"event_id": k, "enabled": True, "weight": 0.0} for k in _TEMPL.keys()
    ])
    out = em.apply(_TEMPL, "cisco_duo", user_id=None)
    weights = [w for _, w in out.values()]
    assert all(abs(w - weights[0]) < 1e-9 for w in weights)


def test_apply_picks_up_current_user_from_context(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo",
               [{"event_id": "auth.failure", "enabled": True, "weight": 1.0}],
               owner_id="u-alice")
    import profiles
    tok = profiles.set_current_user("u-alice")
    try:
        out = em.apply(_TEMPL, "cisco_duo")  # sentinel "__current__"
        # Default weights would make auth.success the heaviest (0.70); after
        # Alice's per-user override that pushes auth.failure to 1.0, the
        # renormalisation must flip auth.failure into the top spot.
        top = max(out.items(), key=lambda kv: kv[1][1])[0]
        assert top == "auth.failure", out
    finally:
        profiles.reset_current_user(tok)


# ── Empirical distribution check (the whole point of the resolver) ──────────

def test_apply_actually_moves_the_empirical_distribution(_isolate_data_root):
    """A 1000-sample weighted_choice run should land within ±5% of the
    configured mix. This is the property collectors rely on — anything
    looser and the 'event mix' UI would be a lie."""
    em = _isolate_data_root
    em.set_mix("cisco_duo", [
        {"event_id": "auth.success", "enabled": True, "weight": 0.1},
        {"event_id": "auth.failure", "enabled": True, "weight": 0.9},
        {"event_id": "auth.fraud",   "enabled": False, "weight": 0.0},
        {"event_id": "auth.error",   "enabled": False, "weight": 0.0},
    ])
    out = em.apply(_TEMPL, "cisco_duo", user_id=None)
    from generators import weighted_choice
    random.seed(1234)
    counts: collections.Counter[str] = collections.Counter()
    for _ in range(2000):
        picked = weighted_choice(out)
        counts[picked["r"]] += 1
    total = sum(counts.values())
    # Fraud / Error never appear.
    assert counts.get("X", 0) == 0
    assert counts.get("E", 0) == 0
    # Success ≈ 10%, Failure ≈ 90%, ±5pp.
    assert abs(counts["S"] / total - 0.10) < 0.05
    assert abs(counts["F"] / total - 0.90) < 0.05


# ── merge_catalog_with_mix ──────────────────────────────────────────────────

def test_merge_catalog_with_mix_marks_enabled_and_weight(_isolate_data_root):
    em = _isolate_data_root
    catalog = [
        {"id": "auth.success", "label": "ok",   "default_weight": 0.7},
        {"id": "auth.failure", "label": "fail", "default_weight": 0.2},
        {"id": "auth.fraud",   "label": "frd",  "default_weight": 0.1},
    ]
    em.set_mix("cisco_duo", [
        {"event_id": "auth.success", "enabled": True, "weight": 0.5},
        {"event_id": "auth.fraud",   "enabled": False, "weight": 0.0},
    ])
    merged = em.merge_catalog_with_mix(catalog, "cisco_duo", user_id=None)
    by_id = {e["id"]: e for e in merged}
    assert by_id["auth.success"]["enabled"] is True
    assert by_id["auth.success"]["weight"] == 0.5
    assert by_id["auth.failure"]["enabled"] is True
    assert by_id["auth.failure"]["weight"] == 0.2  # untouched → default
    assert by_id["auth.fraud"]["enabled"] is False


# ── cisco_duo pilot wiring ──────────────────────────────────────────────────

def test_cisco_duo_catalog_ids_match_template_keys():
    """The catalog and the per-template dicts must agree on event ids; a
    drift here means an admin's UI overrides silently no-op against the
    generator."""
    from sources import cisco_duo
    declared = {e["id"] for e in cisco_duo.EVENT_CATALOG}
    keyed = set(cisco_duo._AUTH_TEMPLATES) | set(cisco_duo._ADMIN_TEMPLATES)
    assert declared == keyed, (
        f"catalog vs template-key drift; only-in-catalog={declared-keyed}, "
        f"only-in-templates={keyed-declared}"
    )


def test_cisco_duo_catalog_default_weights_sum_per_endpoint():
    """Per-endpoint default weights should sum to ~1.0 — the
    weighted_choice contract within a single response family."""
    from sources import cisco_duo
    by_ep: dict[str, float] = collections.defaultdict(float)
    for entry in cisco_duo.EVENT_CATALOG:
        by_ep[entry["endpoint"]] += entry["default_weight"]
    for ep, total in by_ep.items():
        assert abs(total - 1.0) < 1e-6, f"{ep} catalog weights sum to {total}, not 1.0"


def test_cisco_duo_disabling_fraud_zeros_it_in_auth_logs(_isolate_data_root):
    em = _isolate_data_root
    em.set_mix("cisco_duo", [
        {"event_id": "auth.fraud", "enabled": False, "weight": 0.0},
    ])
    from sources import cisco_duo
    random.seed(7)
    results = collections.Counter()
    for _ in range(500):
        log = cisco_duo._make_auth_log(ctx=None)
        results[log["result"]] += 1
    assert results.get("FRAUD", 0) == 0
    # Other categories still appear in approximately their renormalised ratios.
    assert results["SUCCESS"] > results["FAILURE"] > 0
