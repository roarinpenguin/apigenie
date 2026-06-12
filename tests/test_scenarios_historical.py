"""v5.1 Phase C.1 — Historical-mode scenarios.

A scenario launched with ``mode="historical"`` does **not** start a
scheduler thread. Instead, ``start_scenario`` pre-computes every event
the scenario would have emitted over its duration, backdates each one
to a timestamp inside its phase's window, and writes them to a
per-scenario on-disk backlog. The first collector pull on each source
drains its slice of the backlog ahead of the live event mix — making
the entire attack story immediately visible at realistic historical
timestamps for demos / investigations.

The realtime mode (the only mode that exists today) must keep working
bit-for-bit; this file pins both the new behaviour and the regression.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest


# ── helpers ──────────────────────────────────────────────────────────────────


def _payload(*sources: str,
             duration_hours: int = 4,
             visibility: str = "public",
             owner_id: str | None = None,
             mode: str = "historical",
             events_per_phase: int | None = None) -> dict:
    """Build a create_scenario payload with one phase per source,
    spread evenly over the duration. Defaults to historical mode (the
    new code path under test)."""
    n = len(sources)
    span = 100 // max(n, 1)
    phases = []
    for i, src in enumerate(sources):
        phases.append({
            "phase_id": f"phase-{i}",
            "name": f"Phase {i} — {src}",
            "source": src,
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1566.001",
            "time_offset_pct": i * span,
            "duration_pct": min(span, 100 - i * span),
            "periodicity": 5,
            "field_overrides": {"_marker": f"phase-{i}"},
        })
    out = {
        "name": "Historical test",
        "duration": {"value": duration_hours, "unit": "hours"},
        "phases": phases,
        "mode": mode,
        "visibility": visibility,
    }
    if owner_id is not None:
        out["owner_id"] = owner_id
    if events_per_phase is not None:
        out["events_per_phase"] = events_per_phase
    return out


def _backlog_paths(scenario_id: str) -> tuple[Path, Path]:
    """Return the (jsonl, idx) backlog paths for a scenario in the
    test's tmp_path data root."""
    import attack_scenarios
    root = Path(attack_scenarios._DATA_ROOT) / "attack_scenarios"
    return (root / f"{scenario_id}_backlog.jsonl",
            root / f"{scenario_id}_backlog.idx.json")


# ── Scenario schema extensions ───────────────────────────────────────────────


class TestScenarioSchemaExtensions:
    def test_mode_defaults_to_realtime(self):
        """Back-compat: a scenario created without ``mode`` keeps the
        existing UX (scheduler thread, live injection)."""
        import attack_scenarios
        s = attack_scenarios.create_scenario({
            "name": "default mode",
            "phases": [{
                "phase_id": "p0", "name": "p", "source": "okta",
                "mitre_tactic": "T", "mitre_technique": "T1",
                "time_offset_pct": 0, "duration_pct": 50,
                "periodicity": 5, "field_overrides": {},
            }],
        })
        assert s["mode"] == "realtime"

    def test_visibility_defaults_to_private(self):
        import attack_scenarios
        s = attack_scenarios.create_scenario(_payload("okta"))
        # _payload sets visibility=public; create one without it.
        s2 = attack_scenarios.create_scenario({
            "name": "vis default",
            "phases": _payload("okta")["phases"],
        })
        assert s2["visibility"] == "private"

    def test_explicit_mode_and_visibility_round_trip(self):
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", mode="historical", visibility="public")
        )
        assert s["mode"] == "historical"
        assert s["visibility"] == "public"


# ── Pre-staging ──────────────────────────────────────────────────────────────


class TestPreStaging:
    def test_writes_backlog_files_with_expected_count(self, monkeypatch):
        """events_per_phase=5 + 3 phases ⇒ 15 events on disk, in a
        single JSONL file. The sidecar index points past the last
        consumed byte for each source (initially 0)."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", "aws_cloudtrail", "microsoft_defender",
                     events_per_phase=5)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        jsonl, idx = _backlog_paths(s["id"])
        assert jsonl.is_file(), "pre-staging must write the backlog jsonl"
        assert idx.is_file(),   "pre-staging must write the sidecar index"

        lines = [json.loads(line) for line in jsonl.read_text().splitlines() if line]
        assert len(lines) == 15, f"expected 15 events on disk, got {len(lines)}"

        # Every line carries the bookkeeping headers the drain needs.
        for line in lines:
            for k in ("_source", "_ts", "_scenario_id", "_phase_id",
                      "_owner_id", "_visibility"):
                assert k in line, f"backlog entry missing '{k}': {line}"
            assert line["_scenario_id"] == s["id"]

        # Index has one entry per source, each holding a per-caller
        # cursor map (initially empty — no caller has pulled yet).
        idx_data = json.loads(idx.read_text())
        assert set(idx_data.keys()) == {"okta", "aws_cloudtrail", "microsoft_defender"}
        assert all(v == {} for v in idx_data.values()), \
            f"per-caller cursors should start empty: {idx_data}"

    def test_event_timestamps_fall_inside_phase_windows(self):
        """Each phase declares a percent-offset and percent-duration of
        the total run. After pre-staging, every event for that phase
        must have a `_ts` inside ``[start, end]`` of its phase, where
        ``[start, end]`` is in the past (``now - duration .. now``).
        """
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", "aws_cloudtrail", duration_hours=4,
                     events_per_phase=4)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])
        jsonl, _ = _backlog_paths(s["id"])

        now = time.time()
        total = 4 * 3600
        phases = {p["phase_id"]: p for p in s["phases"]}

        for line in jsonl.read_text().splitlines():
            ev = json.loads(line)
            phase = phases[ev["_phase_id"]]
            offset_pct = phase["time_offset_pct"] / 100.0
            duration_pct = phase["duration_pct"] / 100.0
            t_start = now - total + total * offset_pct
            t_end = t_start + total * duration_pct
            # 2 s slack on either side for the wall-clock drift between
            # the scenario being staged and this assertion running.
            assert t_start - 2 <= ev["_ts"] <= t_end + 2, (
                f"event _ts={ev['_ts']} outside phase window "
                f"[{t_start}, {t_end}] for phase {ev['_phase_id']}"
            )

    def test_realtime_mode_creates_no_backlog(self):
        """Regression: a realtime-mode scenario must not write any
        backlog artifact on disk."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", mode="realtime")
        )
        # Realtime + start_scenario would launch the thread; we only
        # care here that pre-staging is a no-op (or refused) for
        # realtime mode.
        attack_scenarios.pre_stage_historical_events(s["id"])
        jsonl, idx = _backlog_paths(s["id"])
        assert not jsonl.exists(), "realtime mode must not write a backlog"
        assert not idx.exists()


# ── Drain ────────────────────────────────────────────────────────────────────


class TestDrain:
    def test_drain_returns_only_requested_source(self):
        """Pulling source X must NEVER hand back events tagged for
        source Y — each source has its own drain cursor."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", "aws_cloudtrail",
                     visibility="public", events_per_phase=3)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        events = attack_scenarios.drain_historical_backlog("okta")
        assert events, "drain returned nothing for okta"
        assert all(e["_source"] == "okta" for e in events), \
            "drain leaked events from another source into the okta batch"

    def test_drain_advances_only_its_cursor(self):
        """Cursors are per (source, caller). After draining okta with no
        caller bound, the okta entry has a non-zero cursor for the
        unauthenticated key (""), and the aws_cloudtrail entry stays
        untouched."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", "aws_cloudtrail",
                     visibility="public", events_per_phase=3)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        _, idx = _backlog_paths(s["id"])

        attack_scenarios.drain_historical_backlog("okta")
        idx_data = json.loads(idx.read_text())
        # Per-source map exists and has an entry for the (unauth) caller.
        assert idx_data["okta"].get("", 0) > 0, \
            f"okta cursor did not advance: {idx_data}"
        # aws_cloudtrail cursor map exists but stays empty (or 0).
        assert idx_data["aws_cloudtrail"].get("", 0) == 0, \
            f"okta drain wrongly advanced the aws_cloudtrail cursor: {idx_data}"

        # A second drain on okta is now empty.
        again = attack_scenarios.drain_historical_backlog("okta")
        assert again == []

        # And aws_cloudtrail still has its events ready.
        ct = attack_scenarios.drain_historical_backlog("aws_cloudtrail")
        assert ct and all(e["_source"] == "aws_cloudtrail" for e in ct)

    def test_drain_respects_visibility_for_private_scenarios(self, make_user):
        """A private scenario owned by Alice must NOT drain to Bob's
        caller context. It MUST drain to Alice's. The model mirrors
        ``detection_rules._rule_visible_to_caller``."""
        import attack_scenarios
        import profiles
        alice = make_user("alice")
        bob = make_user("bob")
        s = attack_scenarios.create_scenario(
            _payload("okta", visibility="private",
                     owner_id=alice["id"], events_per_phase=4)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        # Bob's context — must see nothing.
        profiles.set_current_user(bob["id"])
        bob_drain = attack_scenarios.drain_historical_backlog("okta")
        assert bob_drain == [], \
            "private scenario leaked to non-owner caller"

        # Alice's context — must see everything.
        profiles.set_current_user(alice["id"])
        alice_drain = attack_scenarios.drain_historical_backlog("okta")
        assert alice_drain, "private scenario hid from its owner"
        assert all(e["_owner_id"] == alice["id"] for e in alice_drain)

    def test_public_scenario_drains_to_any_caller(self, make_user):
        import attack_scenarios
        import profiles
        bob = make_user("bob")
        s = attack_scenarios.create_scenario(
            _payload("okta", visibility="public",
                     owner_id="someone-else", events_per_phase=2)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        profiles.set_current_user(bob["id"])
        out = attack_scenarios.drain_historical_backlog("okta")
        assert out, "public scenario did not drain to a non-owner caller"

    def test_unauthenticated_caller_sees_public_only(self):
        """Bus-based / unauthenticated ingest (caller_id is None) must
        see only public scenarios — same fallback as live rules."""
        import attack_scenarios
        import profiles
        # Public scenario — visible
        pub = attack_scenarios.create_scenario(
            _payload("okta", visibility="public", events_per_phase=2)
        )
        attack_scenarios.pre_stage_historical_events(pub["id"])
        # Private scenario — invisible
        priv = attack_scenarios.create_scenario(
            _payload("okta", visibility="private",
                     owner_id="alice", events_per_phase=2)
        )
        attack_scenarios.pre_stage_historical_events(priv["id"])

        profiles.set_current_user(None)
        out = attack_scenarios.drain_historical_backlog("okta")
        # Only public events should come through.
        assert out
        assert all(e["_visibility"] == "public" for e in out), \
            "unauthenticated drain leaked private events"


# ── Lifecycle ────────────────────────────────────────────────────────────────


class TestLifecycle:
    def test_start_scenario_in_historical_mode_skips_thread_and_pre_stages(self):
        """Historical-mode launch must:
          (a) pre-stage events on disk
          (b) NOT spin up a scheduler thread
          (c) mark the scenario as completed immediately."""
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", mode="historical",
                     visibility="public", events_per_phase=3)
        )
        result = attack_scenarios.start_scenario(s["id"])
        assert isinstance(result, dict), \
            f"start_scenario refused: {result}"

        # No thread.
        assert s["id"] not in attack_scenarios._active_threads or \
               not attack_scenarios._active_threads[s["id"]].is_alive()

        # Pre-staged on disk.
        jsonl, _ = _backlog_paths(s["id"])
        assert jsonl.is_file()

        # Marked completed.
        again = attack_scenarios.get_scenario(s["id"])
        assert again["status"] == "completed"

    def test_delete_scenario_removes_backlog_files(self):
        import attack_scenarios
        s = attack_scenarios.create_scenario(
            _payload("okta", visibility="public", events_per_phase=2)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        jsonl, idx = _backlog_paths(s["id"])
        assert jsonl.is_file() and idx.is_file()

        attack_scenarios.delete_scenario(s["id"])
        assert not jsonl.exists(), \
            "delete_scenario left an orphan backlog jsonl"
        assert not idx.exists(), \
            "delete_scenario left an orphan backlog index"


# ── Integration with detection_rules.inject_detection_events ────────────────


class TestInjectionHook:
    def test_inject_prepends_drained_events(self):
        """The drain hook lives at the top of
        ``detection_rules.inject_detection_events``. A live batch of
        logs for source X must come back with the historical backlog
        prepended."""
        import attack_scenarios
        import detection_rules

        s = attack_scenarios.create_scenario(
            _payload("okta", visibility="public", events_per_phase=3)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        live = [{"_live": True, "i": i} for i in range(5)]
        merged = detection_rules.inject_detection_events("okta", live)
        # All 5 live events still present, in order.
        live_only = [e for e in merged if e.get("_live")]
        assert live_only == live, "live events were dropped or reordered"
        # And the backlog events (tagged _scenario_id) are also there.
        scn_events = [e for e in merged if e.get("_scenario_id") == s["id"]]
        assert len(scn_events) == 3, \
            f"expected 3 backlogged events in the merged batch, got {len(scn_events)}"

    def test_inject_for_unrelated_source_does_not_drain(self):
        """Pulling source Y must never drain backlogged events tagged
        for source X."""
        import attack_scenarios
        import detection_rules

        s = attack_scenarios.create_scenario(
            _payload("okta", visibility="public", events_per_phase=4)
        )
        attack_scenarios.pre_stage_historical_events(s["id"])

        merged = detection_rules.inject_detection_events(
            "aws_cloudtrail", [{"i": 0}],
        )
        # Only the live event survives — no scenario events leaked.
        assert not any(e.get("_scenario_id") == s["id"] for e in merged)
