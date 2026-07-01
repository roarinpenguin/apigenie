"""v5.2 — quiet lead-in (F1) + opt-in auto-enable of target rules (F2).

F1  ``lead_in_seconds`` is a non-negative knob that (a) survives create/update
    round-trips and (b) is rejected by validation when negative / non-numeric.

F2  When ``auto_enable_rules`` is set, the scheduler resolves every phase's
    ``target_rules`` on the saved S1 console and enables the ones that are
    currently Disabled, remembering exactly which ids it flipped so they can be
    restored (re-disabled) at teardown. Rules already Enabled are left alone.
"""
from __future__ import annotations

import sys
import types

import pytest


# ── fake s1_detection_library ───────────────────────────────────────────────

class _FakeS1:
    """Minimal stand-in for ``s1_detection_library`` used by F2 helpers."""

    def __init__(self, catalog: dict[str, dict], *, configured: bool = True):
        # catalog: rid -> {"name", "status", "source"}
        self.catalog = catalog
        self._configured = configured
        self.enabled: list[str] = []
        self.disabled: list[str] = []

    def is_configured(self) -> bool:
        return self._configured

    def _normalize_rule_status(self, status):
        s = str(status or "").strip().lower()
        if s in ("enabled", "active", "on"):
            return "Enabled"
        if s in ("disabled", "inactive", "off"):
            return "Disabled"
        return None

    def query_rules(self, source=None, query=None, limit=20):
        q = (query or "").strip().lower()
        hits = [
            {"id": rid, "name": r["name"], "status": r["status"]}
            for rid, r in self.catalog.items()
            if q and q in r["name"].lower()
        ]
        return {"rules": hits[:limit]}

    def get_platform_rule(self, rid):
        r = self.catalog.get(rid)
        return {"id": rid, "name": r["name"], "status": r["status"]} if r else {}

    def enable_rule(self, rid):
        if rid not in self.catalog:
            return {"error": "not found"}
        self.catalog[rid]["status"] = "Enabled"
        self.enabled.append(rid)
        return {"ok": True}

    def disable_rule(self, rid):
        if rid not in self.catalog:
            return {"error": "not found"}
        self.catalog[rid]["status"] = "Disabled"
        self.disabled.append(rid)
        return {"ok": True}


@pytest.fixture
def fake_s1(monkeypatch):
    def _install(catalog, *, configured=True):
        fake = _FakeS1(catalog, configured=configured)
        mod = types.ModuleType("s1_detection_library")
        for attr in ("is_configured", "_normalize_rule_status", "query_rules",
                     "get_platform_rule", "enable_rule", "disable_rule"):
            setattr(mod, attr, getattr(fake, attr))
        monkeypatch.setitem(sys.modules, "s1_detection_library", mod)
        return fake
    return _install


@pytest.fixture
def data_root(tmp_path, monkeypatch):
    """Point attack_scenarios' JSON store at an isolated tmp file."""
    import attack_scenarios as A
    monkeypatch.setattr(A, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(A, "_SCENARIOS_FILE", tmp_path / "attack_scenarios.json")
    return tmp_path


def _phase(**kw):
    p = {
        "name": "p", "source": "netskope",
        "mitre_tactic": "TA0010", "mitre_technique": "T1567",
        "time_offset_pct": 0, "duration_pct": 100, "periodicity": 10,
    }
    p.update(kw)
    return p


# ── F1: lead_in_seconds validation + persistence ────────────────────────────

def test_validate_accepts_zero_and_positive_lead_in():
    import attack_scenarios as A
    base = {"name": "s", "duration": {"value": 1, "unit": "hours"},
            "phases": [_phase()]}
    assert A.validate_scenario_payload({**base, "lead_in_seconds": 0}) == []
    assert A.validate_scenario_payload({**base, "lead_in_seconds": 30}) == []


@pytest.mark.parametrize("bad", [-1, -0.5, "x", True])
def test_validate_rejects_bad_lead_in(bad):
    import attack_scenarios as A
    errs = A.validate_scenario_payload({
        "name": "s", "duration": {"value": 1, "unit": "hours"},
        "phases": [_phase()], "lead_in_seconds": bad,
    })
    assert any("lead_in_seconds" in e for e in errs)


def test_create_and_update_roundtrip_v52_knobs(data_root):
    import attack_scenarios as A
    s = A.create_scenario({
        "name": "s", "attack_id": "att-x",
        "duration": {"value": 1, "unit": "hours"},
        "phases": [_phase()],
        "lead_in_seconds": 45, "auto_enable_rules": True,
    })
    assert s["lead_in_seconds"] == 45
    assert s["auto_enable_rules"] is True
    got = A.get_scenario(s["id"])
    assert got["lead_in_seconds"] == 45 and got["auto_enable_rules"] is True

    upd = A.update_scenario(s["id"], {"lead_in_seconds": 0,
                                      "auto_enable_rules": False})
    assert upd["lead_in_seconds"] == 0 and upd["auto_enable_rules"] is False


def test_create_clamps_negative_lead_in(data_root):
    import attack_scenarios as A
    s = A.create_scenario({
        "name": "s", "attack_id": "att-x",
        "duration": {"value": 1, "unit": "hours"},
        "phases": [_phase()], "lead_in_seconds": -99,
    })
    assert s["lead_in_seconds"] == 0


# ── F2: _resolve_target_rule ────────────────────────────────────────────────

def test_resolve_prefers_explicit_platform_rule_id(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({"R1": {"name": "Malware upload", "status": "Disabled"}})
    rid, status = A._resolve_target_rule(
        fake, {"platform_rule_id": "R1", "name": "ignored"}, "netskope")
    assert rid == "R1" and status == "Disabled"


def test_resolve_by_exact_name_match(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({
        "R1": {"name": "Malware upload detected", "status": "Enabled"},
        "R2": {"name": "Malware upload", "status": "Disabled"},
    })
    rid, status = A._resolve_target_rule(
        fake, {"name": "malware upload"}, "netskope")
    assert rid == "R2" and status == "Disabled"


def test_resolve_returns_none_when_unmatched(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({"R1": {"name": "Something else", "status": "Enabled"}})
    rid, status = A._resolve_target_rule(fake, {"name": "no such rule"}, "netskope")
    assert rid is None and status is None


# ── F2: _ensure_target_rules_enabled ────────────────────────────────────────

def test_enable_flips_only_disabled_rules(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({
        "R1": {"name": "rule one", "status": "Disabled"},
        "R2": {"name": "rule two", "status": "Enabled"},
    })
    scenario = {"phases": [
        {"source": "netskope", "target_rules": [{"name": "rule one"}]},
        {"source": "okta", "target_rules": [{"name": "rule two"}]},
    ]}
    flipped = A._ensure_target_rules_enabled(scenario)
    assert flipped == ["R1"], "only the Disabled rule is enabled"
    assert fake.catalog["R1"]["status"] == "Enabled"


def test_enable_dedupes_repeated_target_rules(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({"R1": {"name": "dup rule", "status": "Disabled"}})
    scenario = {"phases": [
        {"source": "netskope", "target_rules": [{"name": "dup rule"}]},
        {"source": "netskope", "target_rules": [{"name": "dup rule"}]},
    ]}
    flipped = A._ensure_target_rules_enabled(scenario)
    assert flipped == ["R1"]
    assert fake.enabled == ["R1"], "enabled exactly once despite two phases"


def test_enable_noop_when_console_unconfigured(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({"R1": {"name": "rule one", "status": "Disabled"}},
                   configured=False)
    scenario = {"phases": [{"source": "netskope",
                            "target_rules": [{"name": "rule one"}]}]}
    assert A._ensure_target_rules_enabled(scenario) == []
    assert fake.catalog["R1"]["status"] == "Disabled"


# ── F2: _restore_auto_enabled_rules ─────────────────────────────────────────

def test_restore_redisables_only_listed_rules(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({
        "R1": {"name": "rule one", "status": "Enabled"},
        "R2": {"name": "rule two", "status": "Enabled"},
    })
    A._restore_auto_enabled_rules(["R1"])
    assert fake.catalog["R1"]["status"] == "Disabled"
    assert fake.catalog["R2"]["status"] == "Enabled", "untouched rule left ON"


def test_restore_empty_list_is_noop(fake_s1):
    import attack_scenarios as A
    fake = fake_s1({"R1": {"name": "rule one", "status": "Enabled"}})
    A._restore_auto_enabled_rules([])
    assert fake.disabled == []
