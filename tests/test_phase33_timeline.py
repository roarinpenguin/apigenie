"""Phase 3.3 — exportable attack timeline.

Two surfaces under test:

  1. ``attack_scenarios.build_timeline`` — assembles a chronological
     phase-boundary + event JSON snapshot from a scenario's persisted
     state plus the in-memory event ring buffer.

  2. ``GET /admin/api/scenarios/{id}/timeline`` — REST wrapper, with an
     optional ``?download=1`` mode that returns the same payload as a
     downloadable attachment.

The tests deliberately avoid running the scheduler — that's covered by
``test_attack_scenarios.py``. Here we exercise the *export* shape and
ordering directly, by constructing a scenario via the public CRUD helpers
and synthetically seeding the event log.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient


# ── helpers ──────────────────────────────────────────────────────────────────


def _login_admin(client: TestClient) -> None:
    pwd = os.environ.get("ADMIN_PASSWORD", "apigenie")
    r = client.post(
        "/admin/login",
        data={"username": "admin", "password": pwd},
        follow_redirects=False,
    )
    assert r.status_code in (200, 302, 303), (r.status_code, r.text[:200])


def _minimum_scenario(**over) -> dict:
    base = {
        "name": "Ransomware Demo",
        "description": "Two-phase scenario for timeline tests",
        "duration": {"value": 4, "unit": "hours"},
        "phases": [
            {
                "phase_id": "initial-access",
                "name": "Phishing email",
                "source": "proofpoint",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1566.001",
                "time_offset_pct": 0,
                "duration_pct": 25,
                "periodicity": 5,
                "field_overrides": {"subject": "Q4 Invoice"},
            },
            {
                "phase_id": "impact",
                "name": "Encryption",
                "source": "sentinelone",
                "mitre_tactic": "Impact",
                "mitre_technique": "T1486",
                "time_offset_pct": 70,
                "duration_pct": 30,
                "periodicity": 3,
                "field_overrides": {"severity": "Critical"},
            },
        ],
    }
    base.update(over)
    return base


@pytest.fixture
def client():
    from app import app
    return TestClient(app)


@pytest.fixture
def make_scenario():
    """Create a fresh scenario; yield (scenario_id, scenario_dict)."""
    import attack_scenarios

    def _make(**over) -> tuple[str, dict]:
        created = attack_scenarios.create_scenario(_minimum_scenario(**over))
        return created["id"], created

    return _make


# ── build_timeline: shape + ordering ─────────────────────────────────────────


def test_build_timeline_unknown_scenario_returns_none():
    import attack_scenarios

    assert attack_scenarios.build_timeline("scn-does-not-exist") is None


def test_build_timeline_never_run_has_phase_metadata_no_anchors(make_scenario):
    """A scenario that's been created but never started exposes its phase
    catalogue but contains zero timeline anchors (no real timestamps to
    fabricate)."""
    import attack_scenarios

    sid, _ = make_scenario()
    tl = attack_scenarios.build_timeline(sid)
    assert tl is not None
    assert tl["scenario_id"] == sid
    assert tl["status"] == "stopped"
    assert tl["started_at"] == ""
    assert len(tl["phases"]) == 2
    assert tl["timeline"] == []  # no started_at → no anchors


def test_build_timeline_running_has_anchors_in_order(make_scenario):
    """When started_at is set, scenario_start + per-phase start/end anchors
    appear in oldest-first chronological order. No scenario_end on a still-
    running run — that would be in the future."""
    import attack_scenarios

    sid, _ = make_scenario()
    # Fake "just started" state. Using a fixed UTC stamp keeps the assertions
    # deterministic.
    started = "2026-05-26T14:00:00+00:00"
    attack_scenarios._update_scenario_status(
        sid, status="running", started_at=started, attack_id="att-20260526-0001",
    )

    tl = attack_scenarios.build_timeline(sid)
    kinds = [e["kind"] for e in tl["timeline"]]
    # Two phases → 1 scenario_start + 2 × (phase_start + phase_end) = 5 anchors
    assert kinds.count("scenario_start") == 1
    assert kinds.count("phase_start") == 2
    assert kinds.count("phase_end") == 2
    assert "scenario_end" not in kinds  # still running

    # Ordering: scenario_start is first, anchors are non-decreasing in ts.
    assert kinds[0] == "scenario_start"
    timestamps = [e["ts"] for e in tl["timeline"]]
    assert timestamps == sorted(timestamps)

    # Phase boundaries derived from offset/duration_pct on a 4-hour run.
    # Phase 1: offset 0%, duration 25% → 14:00–15:00.
    # Phase 2: offset 70%, duration 30% → 16:48–18:00.
    by_phase = {
        e["phase_id"]: e for e in tl["timeline"] if e["kind"] == "phase_start"
    }
    assert by_phase["initial-access"]["ts"].startswith("2026-05-26T14:00:00")
    assert by_phase["impact"]["ts"].startswith("2026-05-26T16:48:00")


def test_build_timeline_completed_appends_scenario_end(make_scenario):
    import attack_scenarios

    sid, _ = make_scenario()
    started = "2026-05-26T14:00:00+00:00"
    attack_scenarios._update_scenario_status(
        sid, status="completed", started_at=started, attack_id="att-20260526-0002",
    )

    tl = attack_scenarios.build_timeline(sid)
    kinds = [e["kind"] for e in tl["timeline"]]
    assert kinds[-1] == "scenario_end"
    # 4-hour run starting at 14:00 → scenario_end at 18:00.
    end = tl["timeline"][-1]
    assert end["ts"].startswith("2026-05-26T18:00:00")


def test_build_timeline_interleaves_events_with_anchors(make_scenario):
    """Seeded events with realistic timestamps interleave with the derived
    phase anchors when sorted by ts."""
    import attack_scenarios

    sid, _ = make_scenario()
    started = "2026-05-26T14:00:00+00:00"
    attack_scenarios._update_scenario_status(
        sid, status="running", started_at=started, attack_id="att-20260526-0003",
    )
    # Seed events DIRECTLY into the ring buffer with deterministic timestamps
    # so we don't depend on record_event's "now" stamp.
    import collections

    with attack_scenarios._event_log_lock:
        buf = collections.deque(maxlen=10)
        buf.appendleft({
            "ts": "2026-05-26T14:15:00+00:00",
            "scenario_id": sid,
            "phase_id": "initial-access",
            "attack_id": "att-20260526-0003",
            "source": "proofpoint",
            "preview": {"subject": "Q4 Invoice"},
        })
        buf.appendleft({
            "ts": "2026-05-26T17:00:00+00:00",
            "scenario_id": sid,
            "phase_id": "impact",
            "attack_id": "att-20260526-0003",
            "source": "sentinelone",
            "preview": {"severity": "Critical"},
        })
        attack_scenarios._scenario_event_logs[sid] = buf

    tl = attack_scenarios.build_timeline(sid)
    events = [e for e in tl["timeline"] if e["kind"] == "event"]
    assert len(events) == 2
    # Events carry the per-event payload from Phase 3.1 unchanged.
    initial = next(e for e in events if e["phase_id"] == "initial-access")
    assert initial["source"] == "proofpoint"
    assert initial["preview"] == {"subject": "Q4 Invoice"}

    # The chronological merge places the 14:15 event AFTER the 14:00
    # scenario_start anchor and BEFORE the 15:00 phase_end anchor.
    timestamps = [e["ts"] for e in tl["timeline"]]
    assert timestamps == sorted(timestamps)


def test_build_timeline_metadata_fields(make_scenario):
    """The top-level dict carries everything an offline reviewer needs."""
    import attack_scenarios

    sid, _ = make_scenario(name="HR Phish")
    started = "2026-05-26T14:00:00+00:00"
    attack_scenarios._update_scenario_status(
        sid, status="running", started_at=started, attack_id="att-20260526-0004",
        events_injected=42,
    )

    tl = attack_scenarios.build_timeline(sid)
    for key in (
        "scenario_id", "name", "description", "attack_id", "status",
        "started_at", "duration", "elapsed_seconds", "events_injected",
        "generated_at", "phases", "timeline",
    ):
        assert key in tl, f"missing key {key!r}"
    assert tl["name"] == "HR Phish"
    assert tl["attack_id"] == "att-20260526-0004"
    assert tl["events_injected"] == 42
    # generated_at is current UTC and parseable.
    gen = datetime.fromisoformat(tl["generated_at"])
    assert gen.tzinfo is not None


# ── REST endpoint ────────────────────────────────────────────────────────────


def test_api_timeline_unauthenticated_is_401(client):
    r = client.get("/admin/api/scenarios/anything/timeline")
    assert r.status_code == 401


def test_api_timeline_unknown_scenario_is_404(client):
    _login_admin(client)
    r = client.get("/admin/api/scenarios/scn-nope/timeline")
    assert r.status_code == 404


def test_api_timeline_returns_json_payload(client, make_scenario):
    _login_admin(client)
    sid, _ = make_scenario()
    r = client.get(f"/admin/api/scenarios/{sid}/timeline")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["scenario_id"] == sid
    assert "timeline" in body
    assert "phases" in body


def test_api_timeline_download_sends_attachment(client, make_scenario):
    """``?download=1`` switches the response to an attachment so the
    browser opens its save dialog. Filename must be sortable and safe."""
    _login_admin(client)
    sid, _ = make_scenario(name="BEC / Wire Fraud")  # exercises name sanitiser

    r = client.get(f"/admin/api/scenarios/{sid}/timeline?download=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    disp = r.headers.get("content-disposition", "")
    assert disp.startswith("attachment;")
    assert "filename=" in disp
    # Slashes / spaces must not survive into the filename.
    assert "/" not in disp
    # Body is still valid JSON.
    payload = json.loads(r.content)
    assert payload["scenario_id"] == sid
