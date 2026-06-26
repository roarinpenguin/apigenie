"""Tests for ``scenario_persona_view.inspect_scenario`` — the
read-only diagnostic that mirrors what ``_splice_persona_overrides``
would put on the wire, without starting the scenario.

These tests pin the contract the apigenie UI consumes:

* persona bundle round-trips verbatim
* per-phase projection rows resolve each ``slot_path`` against the
  bundle, including the ``source_of_truth`` flag (``persona`` /
  ``operator`` / ``unresolved``)
* operator-authored ``field_overrides`` win over the persona
  projection (matches runtime precedence in
  ``attack_scenarios._splice_persona_overrides``)
* coverage map summarises which canonical slots are exercised across
  the scenario's sources
* legacy scenarios (no ``personas`` key, no projection on the
  source) degrade gracefully — never raises
"""
from __future__ import annotations

import pytest

import personas
from scenario_persona_view import inspect_scenario


# ── Helpers ─────────────────────────────────────────────────────────


@pytest.fixture
def fixed_bundle():
    """Deterministic persona bundle so tests can assert exact values
    without depending on the RNG in ``personas.generate_bundle``."""
    return {
        "victim_user": {
            "name": "John Doe", "username": "jdoe",
            "email": "john.doe@acme-corp.test",
            "upn":   "john.doe@acme-corp.test",
            "object_id": "00000000-0000-0000-0000-000000000001",
        },
        "victim_host": {
            "hostname": "JDOE-LAPTOP-7", "ip": "10.42.5.7",
            "os": "Windows 11",
            "agent_uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        "attacker": {
            "ip": "185.220.101.42", "country": "RU",
            "email":  "billing@evilcorp.bad",
            "domain": "evilcorp.bad",
            "asn":    "AS9009",
        },
        "malicious": {
            "file_name": "Invoice_Q4.docm",
            "sha256":    "a" * 64, "md5": "b" * 32,
            "process":   "WINWORD.EXE",
            "cmd_line":  "WINWORD.EXE /quiet",
        },
    }


# ── Happy path ──────────────────────────────────────────────────────


class TestPersonaProjectionResolution:
    def test_simple_okta_phase_resolves_email_and_ip(self, fixed_bundle):
        """One Okta phase with no operator overrides → every Okta
        projection row resolves a non-None value pulled from the
        persona bundle."""
        scenario = {
            "id": "s1", "name": "demo", "personas": fixed_bundle,
            "phases": [{
                "phase_id": "p1", "source": "okta",
                "mitre_tactic": "Credential Access",
                "field_overrides": {},
            }],
        }
        out = inspect_scenario(scenario)
        # Bundle round-trips verbatim
        assert out["persona"] == fixed_bundle
        # validate_bundle returns [] for the deterministic happy-path
        assert out["persona_problems"] == []
        # Exactly one phase, populated projection
        assert len(out["phases"]) == 1
        ph = out["phases"][0]
        assert ph["source"] == "okta"
        assert ph["missing_projection"] is False
        # Every row should resolve from the persona bundle
        for row in ph["projection"]:
            assert row["source_of_truth"] == "persona", (
                f"row {row['event_field']} unexpectedly unresolved: "
                f"{row}")
            assert row["resolved_value"], (
                f"row {row['event_field']} resolved to empty")

    def test_operator_override_wins_and_is_flagged(self, fixed_bundle):
        """If a phase carries a ``field_overrides`` entry that maps
        to the same event_field as a projection row, the runtime
        splicer keeps the operator value and skips the projection.
        The inspector must mirror that — and tag the source of truth
        so the operator can tell at a glance where the value came
        from."""
        scenario = {
            "id": "s2", "personas": fixed_bundle,
            "phases": [{
                "phase_id": "p1", "source": "okta",
                "mitre_tactic": "Credential Access",
                # actor.alternateId is in Okta's PERSONA_PROJECTION;
                # an operator override on it must win.
                "field_overrides": {
                    "actor.alternateId": "cfo@victim-corp.test",
                },
            }],
        }
        out = inspect_scenario(scenario)
        ph = out["phases"][0]
        ov_row = next(r for r in ph["projection"]
                      if r["event_field"] == "actor.alternateId")
        assert ov_row["resolved_value"] == "cfo@victim-corp.test"
        assert ov_row["source_of_truth"] == "operator"
        # The override is consumed by the projection row, so it
        # mustn't be double-listed under operator_overrides (which
        # is meant for *extra* overrides outside the projection set).
        assert "actor.alternateId" not in ph["operator_overrides"]

    def test_operator_overrides_outside_projection_kept_separate(
            self, fixed_bundle):
        """An operator override on a field that has NO projection
        mapping survives in ``operator_overrides`` so the UI can
        render it as a free-form addition."""
        scenario = {
            "id": "s3", "personas": fixed_bundle,
            "phases": [{
                "phase_id": "p1", "source": "okta",
                "mitre_tactic": "Credential Access",
                "field_overrides": {
                    # Not in Okta's PERSONA_PROJECTION.
                    "custom.note": "BEC scenario kickoff",
                },
            }],
        }
        out = inspect_scenario(scenario)
        ph = out["phases"][0]
        assert ph["operator_overrides"] == {"custom.note":
                                            "BEC scenario kickoff"}


# ── Coverage map ────────────────────────────────────────────────────


class TestCoverageMap:
    def test_multi_source_coverage_aggregates_per_slot(self, fixed_bundle):
        """When multiple sources reference the same canonical slot
        (e.g. okta + m365 both reading ``victim_user.email`` via
        their respective projections), the coverage map should list
        both sources under that slot — so the operator can confirm
        the lateral-movement story actually crosses sources."""
        scenario = {
            "id": "s4", "personas": fixed_bundle,
            "phases": [
                {"phase_id": "p1", "source": "okta",
                 "mitre_tactic": "Credential Access"},
                {"phase_id": "p2", "source": "m365",
                 "mitre_tactic": "Collection"},
            ],
        }
        out = inspect_scenario(scenario)
        vu = out["coverage"].get("victim_user")
        assert vu is not None, (
            "victim_user must appear in coverage when both okta and "
            "m365 reference it")
        assert "okta" in vu["sources"]
        assert "m365" in vu["sources"]

    def test_unused_slot_absent_from_coverage(self, fixed_bundle):
        """A canonical slot that no projection references must NOT
        appear in the coverage map — this is how the UI surfaces
        "your scenario never touches the malicious.cmd_line slot"."""
        scenario = {
            "id": "s5", "personas": fixed_bundle,
            "phases": [
                # cisco_duo projection has no ``malicious`` entries.
                {"phase_id": "p1", "source": "cisco_duo",
                 "mitre_tactic": "Credential Access"},
            ],
        }
        out = inspect_scenario(scenario)
        assert "malicious" not in out["coverage"]


# ── Edge cases / robustness ─────────────────────────────────────────


class TestRobustness:
    def test_legacy_scenario_without_personas_does_not_crash(self):
        """Pre-v5.x scenario records have no ``personas`` key. The
        inspector must return a structurally-valid view with empty
        bundle and a single problem entry — the UI can render the
        'this scenario predates personas' message off that."""
        scenario = {
            "id": "legacy", "name": "old", "phases": [{
                "phase_id": "p1", "source": "okta",
                "mitre_tactic": "Credential Access",
            }],
        }
        out = inspect_scenario(scenario)
        assert out["persona"] == {}
        assert out["persona_problems"] and "pre-v5" in out[
            "persona_problems"][0]
        # Phase still listed but every projection row should be
        # ``unresolved`` since there's no bundle to walk.
        ph = out["phases"][0]
        for row in ph["projection"]:
            assert row["source_of_truth"] == "unresolved"
            assert row["resolved_value"] is None

    def test_source_without_projection_flagged(self, fixed_bundle):
        """A phase whose source doesn't ship a
        ``PERSONA_PROJECTION`` (e.g. a vendor we haven't wired yet)
        must be flagged so the operator knows the persona will NOT
        reach that source's events."""
        scenario = {
            "id": "s6", "personas": fixed_bundle,
            "phases": [{
                "phase_id": "p1", "source": "definitely_not_a_real_source",
                "mitre_tactic": "Initial Access",
            }],
        }
        out = inspect_scenario(scenario)
        ph = out["phases"][0]
        assert ph["missing_projection"] is True
        assert ph["projection"] == []

    def test_partial_bundle_marks_unresolved_rows(self, fixed_bundle):
        """If the bundle has a slot but a sub-field is missing, the
        affected projection rows show up as ``unresolved`` — and the
        rest still resolve. Catches the historical bug where an
        operator hand-edited the JSON file and removed
        ``victim_user.upn`` thinking nothing would notice."""
        broken = {**fixed_bundle, "victim_user": {
            **fixed_bundle["victim_user"], "upn": ""}}
        scenario = {
            "id": "s7", "personas": broken,
            "phases": [{
                "phase_id": "p1", "source": "m365",
                "mitre_tactic": "Collection",
            }],
        }
        out = inspect_scenario(scenario)
        ph = out["phases"][0]
        # UserId on m365 maps to victim_user.upn — should be unresolved.
        upn_row = next(r for r in ph["projection"]
                       if r["event_field"] == "UserId")
        # resolve_path returns "" verbatim for an empty string, which
        # IS truthy-different from None — but inspect_scenario's
        # resolved_value contract is "value as-is, source_of_truth
        # tells you reliability". An empty string is not a
        # successful resolution, so it must be flagged.
        assert upn_row["resolved_value"] in ("", None)
        # And persona_problems lists the empty upn so the UI can show
        # an actionable warning.
        assert any("upn" in p for p in out["persona_problems"])

    def test_non_dict_input_returns_error(self):
        """Defensive: anything that isn't a dict must produce an
        error response, not a crash. Belt-and-braces for buggy
        callers."""
        out = inspect_scenario("not a scenario")  # type: ignore[arg-type]
        assert "error" in out
