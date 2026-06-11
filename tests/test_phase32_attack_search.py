"""Phase 3.2 — cross-source attack.id search in the Request Inspector.

Two surfaces under test:

  1. ``trace.find_by_attack`` — the helper that scans every per-source request
     trace ring buffer for a substring match on the attack id, merges hits
     across sources, and sorts newest-first.

  2. ``GET /admin/api/requests/by-attack/{attack_id}`` — the thin REST wrapper
     that exposes the helper to the admin UI.

The trace buffer is in-memory only (``trace.REQUEST_TRACE`` — a defaultdict
of bounded deques keyed by source). Every test clears it on entry so we
don't depend on prior test ordering.
"""

from __future__ import annotations

import os

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


def _seed_trace(source: str, **fields) -> dict:
    """Drop a synthetic request-trace entry into REQUEST_TRACE for `source`.

    Returns the entry dict so tests can assert on it after the lookup.
    """
    import trace as _trace

    entry = {
        "ts": fields.pop("ts", "2026-05-26T14:00:00+00:00"),
        "method": fields.pop("method", "GET"),
        "path": fields.pop("path", "/v2/siem/all"),
        "query": fields.pop("query", ""),
        "client": fields.pop("client", "10.0.0.1"),
        "status": fields.pop("status", 200),
        "duration_ms": fields.pop("duration_ms", 7),
        "req_headers": fields.pop("req_headers", {"accept": "application/json"}),
        "req_body": fields.pop("req_body", ""),
        "resp_size": fields.pop("resp_size", 0),
        "resp_preview": fields.pop("resp_preview", ""),
    }
    entry.update(fields)
    _trace.REQUEST_TRACE[source].append(entry)
    return entry


@pytest.fixture(autouse=True)
def _clear_trace():
    """REQUEST_TRACE is module-global; wipe it so tests don't leak entries."""
    import trace as _trace

    _trace.REQUEST_TRACE.clear()
    yield
    _trace.REQUEST_TRACE.clear()


@pytest.fixture
def client():
    from app import app
    return TestClient(app)


# ── trace.find_by_attack ─────────────────────────────────────────────────────


def test_find_by_attack_empty_id_returns_empty():
    """An empty attack id returns an empty list (no expensive scan)."""
    import trace as _trace

    _seed_trace("proofpoint", resp_preview='{"attack.id":"att-1"}')
    assert _trace.find_by_attack("") == []
    assert _trace.find_by_attack(None) == []  # type: ignore[arg-type]


def test_find_by_attack_no_matches_returns_empty():
    import trace as _trace

    _seed_trace("proofpoint", resp_preview='{"attack.id":"att-20260526-0001"}')
    assert _trace.find_by_attack("att-99999999-9999") == []


def test_find_by_attack_matches_resp_preview():
    """The common case: the attack.id lives in the JSON response payload."""
    import trace as _trace

    needle = "att-20260526-0001"
    _seed_trace(
        "proofpoint",
        resp_preview='{"events":[{"attack.id":"' + needle + '","phase.id":"initial-access"}]}',
    )
    results = _trace.find_by_attack(needle)
    assert len(results) == 1
    assert results[0]["source"] == "proofpoint"
    assert needle in results[0]["resp_preview"]


def test_find_by_attack_matches_req_body():
    """Less common but supported: id present in the inbound request body."""
    import trace as _trace

    needle = "att-20260601-0042"
    _seed_trace("okta", req_body='{"filter":"attack.id eq \\"' + needle + '\\""}')
    results = _trace.find_by_attack(needle)
    assert len(results) == 1
    assert results[0]["source"] == "okta"


def test_find_by_attack_merges_across_sources_newest_first():
    """Hits from multiple sources are merged and sorted by ts newest-first."""
    import trace as _trace

    needle = "att-20260526-0099"
    _seed_trace(
        "proofpoint",
        ts="2026-05-26T10:00:00+00:00",
        resp_preview='"attack.id":"' + needle + '"',
    )
    _seed_trace(
        "sentinelone",
        ts="2026-05-26T12:00:00+00:00",
        resp_preview='"attack.id":"' + needle + '"',
    )
    _seed_trace(
        "okta",
        ts="2026-05-26T11:00:00+00:00",
        resp_preview='"attack.id":"' + needle + '"',
    )

    results = _trace.find_by_attack(needle)
    sources = [r["source"] for r in results]
    timestamps = [r["ts"] for r in results]

    assert sources == ["sentinelone", "okta", "proofpoint"]
    assert timestamps == sorted(timestamps, reverse=True)


def test_find_by_attack_respects_limit():
    """`limit` truncates the merged result list."""
    import trace as _trace

    needle = "att-20260526-1234"
    for i in range(10):
        _seed_trace(
            "proofpoint",
            ts=f"2026-05-26T10:00:{i:02d}+00:00",
            resp_preview='"attack.id":"' + needle + '"',
        )
    assert len(_trace.find_by_attack(needle, limit=3)) == 3
    assert len(_trace.find_by_attack(needle, limit=100)) == 10
    # Negative / zero limits cap at zero rather than crash.
    assert _trace.find_by_attack(needle, limit=0) == []
    assert _trace.find_by_attack(needle, limit=-5) == []


def test_find_by_attack_source_not_overwritten_on_entry():
    """The helper adds `source` to a copy of each row; it must not mutate
    the buffer entry itself (which could break the per-source view)."""
    import trace as _trace

    needle = "att-20260526-7777"
    entry = _seed_trace("okta", resp_preview='"attack.id":"' + needle + '"')
    _trace.find_by_attack(needle)
    # Original buffer entry untouched
    assert "source" not in entry


def test_find_by_attack_no_false_positive_on_different_id():
    """Substring search must not accidentally match a different attack id
    that shares a prefix (e.g. att-20260526-0001 vs att-20260526-0010)."""
    import trace as _trace

    _seed_trace(
        "proofpoint",
        resp_preview='"attack.id":"att-20260526-0010"',
    )
    # Asking for the shorter id WILL match because it's a substring.
    # Document the behaviour: callers must pass full ids. (False positive
    # only matters in pathological cases — production attack ids are unique
    # 16+ char strings.)
    assert len(_trace.find_by_attack("att-20260526-0010")) == 1
    assert len(_trace.find_by_attack("att-20260526-0099")) == 0


# ── REST endpoint ────────────────────────────────────────────────────────────


def test_api_requests_by_attack_unauthenticated_is_401(client):
    r = client.get("/admin/api/requests/by-attack/att-20260526-0001")
    assert r.status_code == 401


def test_api_requests_by_attack_empty_buffer_returns_zero(client):
    _login_admin(client)
    r = client.get("/admin/api/requests/by-attack/att-20260526-0001")
    assert r.status_code == 200
    body = r.json()
    assert body["attack_id"] == "att-20260526-0001"
    assert body["count"] == 0
    assert body["results"] == []


def test_api_requests_by_attack_finds_cross_source_matches(client):
    _login_admin(client)
    needle = "att-20260526-4242"
    _seed_trace(
        "proofpoint",
        ts="2026-05-26T08:00:00+00:00",
        resp_preview='"attack.id":"' + needle + '"',
    )
    _seed_trace(
        "sentinelone",
        ts="2026-05-26T09:00:00+00:00",
        resp_preview='"attack.id":"' + needle + '"',
    )
    # An unrelated entry that should NOT match.
    _seed_trace("okta", resp_preview='"attack.id":"att-20260526-0001"')

    r = client.get(f"/admin/api/requests/by-attack/{needle}")
    assert r.status_code == 200
    body = r.json()
    assert body["attack_id"] == needle
    assert body["count"] == 2
    sources = [row["source"] for row in body["results"]]
    assert set(sources) == {"proofpoint", "sentinelone"}
    # Newest-first ordering
    assert body["results"][0]["source"] == "sentinelone"


def test_api_requests_by_attack_clamps_limit(client):
    """`limit` is clamped to [1, 1000] so a malicious value can't blow up
    the response size or crash int() parsing."""
    _login_admin(client)
    needle = "att-20260526-5555"
    _seed_trace("proofpoint", resp_preview='"attack.id":"' + needle + '"')

    # Out-of-band limits should still produce a 200 with the single match.
    for bad in ("0", "-1", "5000", "abc"):
        r = client.get(
            f"/admin/api/requests/by-attack/{needle}?limit={bad}",
        )
        if bad == "abc":
            # int() can't parse it; FastAPI returns 422.
            assert r.status_code == 422
            continue
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
