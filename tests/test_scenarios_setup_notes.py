"""v5.1 Phase C.2 — Auto-generated scenario setup notes.

A scenario's phases each declare a `source`. To play the scenario out
fully, the operator must configure a collector / push profile / bus
consumer for every source it touches. We pre-compute that list at
create/update time and surface it as `setup_notes` on the scenario.

The block is **derived** from `phases`, not authoritative — it's
regenerated whenever the phases change, never round-tripped through
import/export (the import path regenerates from phases too).
"""
from __future__ import annotations

import pytest


# ── helpers ──────────────────────────────────────────────────────────────────


def _scenario_with_phases(*sources: str, name: str = "Phase C test") -> dict:
    """Build the minimal create_scenario payload that the validator
    accepts, with one phase per source. Spreads the phases evenly over
    the default 4 h duration."""
    n = len(sources)
    phases = []
    span = 100 // max(n, 1)
    for i, src in enumerate(sources):
        phases.append({
            "phase_id": f"phase-{i}",
            "name": f"Phase {i}",
            "source": src,
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1566.001",
            "time_offset_pct": i * span,
            "duration_pct": min(span, 100 - i * span),
            "periodicity": 5,
            "field_overrides": {},
        })
    return {"name": name, "phases": phases}


# ── Auto-generation on create / update ───────────────────────────────────────


class TestSetupNotesAutoFill:
    def test_create_attaches_a_setup_notes_block(self):
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _scenario_with_phases("okta", "aws_cloudtrail")
        )
        assert "setup_notes" in s, "scenarios must surface a setup_notes block"
        notes = s["setup_notes"]
        assert isinstance(notes, dict)
        assert "generated_at" in notes
        assert "summary" in notes and isinstance(notes["summary"], str)
        assert "sources" in notes and isinstance(notes["sources"], list)

    def test_one_entry_per_unique_source_sorted(self):
        """Two phases on the same source must collapse into a single
        setup_notes row; multiple distinct sources are sorted by
        source name for stable rendering."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _scenario_with_phases("okta", "aws_cloudtrail", "okta")
        )
        sources = [row["source"] for row in s["setup_notes"]["sources"]]
        assert sources == sorted(set(["okta", "aws_cloudtrail"])), \
            f"expected dedup+sort, got {sources}"

    def test_known_source_carries_full_hint(self):
        """A source registered in _SOURCE_SETUP_HINTS must produce a
        row with every documented key — operators rely on the table
        being complete."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(_scenario_with_phases("okta"))
        row = s["setup_notes"]["sources"][0]
        for k in ("source", "kind", "endpoint", "auth", "options", "notes"):
            assert k in row, f"setup notes row is missing '{k}': {row}"
        assert row["source"] == "okta"
        # Okta is an HTTP-pull source.
        assert row["kind"] == "pull"
        assert isinstance(row["options"], list)
        assert isinstance(row["notes"], str) and row["notes"]

    def test_unknown_source_produces_placeholder_row(self):
        """A source typo (or a custom source we haven't hinted yet)
        must surface as a kind=unknown row with a clear hint, NOT be
        silently dropped — silent drops hide configuration bugs."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _scenario_with_phases("not_a_real_source", "okta")
        )
        rows = {r["source"]: r for r in s["setup_notes"]["sources"]}
        assert "not_a_real_source" in rows
        assert rows["not_a_real_source"]["kind"] == "unknown"
        assert "no setup hint" in rows["not_a_real_source"]["notes"].lower()

    def test_update_regenerates_block_for_new_phases(self):
        import attack_scenarios
        s = attack_scenarios.create_scenario(_scenario_with_phases("okta"))
        first_sources = [r["source"] for r in s["setup_notes"]["sources"]]
        assert first_sources == ["okta"]

        # Swap to a different set of sources.
        new_payload = _scenario_with_phases("aws_cloudtrail", "microsoft_defender")
        updated = attack_scenarios.update_scenario(s["id"], {"phases": new_payload["phases"]})
        assert updated is not None
        new_sources = [r["source"] for r in updated["setup_notes"]["sources"]]
        assert new_sources == sorted(["aws_cloudtrail", "microsoft_defender"])

    def test_summary_mentions_source_count_and_duration(self):
        """The summary line is what the launch modal will surface
        front-and-centre; it must include the two facts operators need
        most: how many distinct sources, and the duration."""
        import attack_scenarios
        payload = _scenario_with_phases("okta", "aws_cloudtrail", "microsoft_defender")
        payload["duration"] = {"value": 6, "unit": "hours"}
        s = attack_scenarios.create_scenario(payload)
        summary = s["setup_notes"]["summary"]
        assert "3" in summary, f"summary should mention source count: {summary}"
        assert ("6" in summary and "hour" in summary.lower()), \
            f"summary should mention duration: {summary}"


# ── get_scenario / export_scenario integration ───────────────────────────────


class TestSetupNotesSurfacing:
    def test_get_scenario_includes_setup_notes(self):
        import attack_scenarios
        s = attack_scenarios.create_scenario(_scenario_with_phases("okta"))
        got = attack_scenarios.get_scenario(s["id"])
        assert got is not None
        assert "setup_notes" in got

    def test_export_scenario_excludes_setup_notes(self):
        """The export payload is consumed by import_scenario on another
        host. The notes are derived from phases — re-derived on import —
        so round-tripping them would just bloat the JSON and create a
        risk of stale notes if someone hand-edits the export."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(_scenario_with_phases("okta"))
        exported = attack_scenarios.export_scenario(s["id"])
        assert exported is not None
        assert "setup_notes" not in exported, \
            "export should not include the derived setup_notes block"

    def test_import_scenario_regenerates_setup_notes(self):
        """Re-importing an exported scenario must produce a fresh
        setup_notes block (since import goes through create_scenario)."""
        import attack_scenarios
        original = attack_scenarios.create_scenario(_scenario_with_phases("okta"))
        exported = attack_scenarios.export_scenario(original["id"])
        reimported = attack_scenarios.import_scenario(exported)
        assert "setup_notes" in reimported
        assert reimported["setup_notes"]["sources"][0]["source"] == "okta"
