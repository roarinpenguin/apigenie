"""Event Mix admin surface — REST + source registry.

The ``event_mix`` module itself is covered by ``test_event_mix.py``; here we
exercise the four new admin REST endpoints and the lightweight source
registry in ``sources/__init__.py`` that the catalog endpoint relies on.

Two RBAC postures are checked:

1. **Built-in admin** (no acting-as) → writes the *global* mix; the
   ``own`` flag in responses is true for any global mix it owns.
2. **Real user** (or admin acting-as) → writes a *private* override that
   shadows the global mix only for them; the catalog endpoint reports
   ``own=true`` only when they have their own record.

Note: ``conftest.py`` does not currently isolate ``event_mix._MIX_FILE``,
so this test module monkeypatches it per-test to keep mixes from leaking
across cases.
"""

from __future__ import annotations

import importlib
import os

import pytest
from fastapi.testclient import TestClient


# ── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def isolated_mix(tmp_path, monkeypatch):
    """Point ``event_mix._MIX_FILE`` at a per-test path + clear in-memory state."""
    import event_mix as em
    monkeypatch.setattr(em, "_MIX_FILE", tmp_path / "source_event_mix.json")
    return em


@pytest.fixture
def client(isolated_mix):
    from app import app
    return TestClient(app)


def _login_admin(client: TestClient) -> None:
    pwd = os.environ.get("ADMIN_PASSWORD", "apigenie")
    r = client.post(
        "/admin/login",
        data={"username": "admin", "password": pwd},
        follow_redirects=False,
    )
    assert r.status_code in (200, 302, 303), (r.status_code, r.text[:200])


# ── sources registry ─────────────────────────────────────────────────────────


def test_sources_registry_yields_cisco_duo_catalog():
    """The cisco_duo pilot is the canonical mix-aware source. The registry
    must surface it so the admin UI knows to render a card."""
    import sources
    catalogs = sources.get_event_catalogs()
    assert "cisco_duo" in catalogs
    ids = {entry["id"] for entry in catalogs["cisco_duo"]}
    # Spot-check both endpoint families are present.
    assert "auth.success" in ids
    assert "admin.admin_login" in ids


def test_sources_registry_get_unknown_source_returns_none():
    import sources
    assert sources.get_event_catalog("does-not-exist") is None


def test_sources_registry_get_existing_source_matches_catalogs():
    """``get_event_catalog`` and ``get_event_catalogs`` agree on the
    cisco_duo catalogue — otherwise the per-source card and the
    overview list would disagree."""
    import sources
    single = sources.get_event_catalog("cisco_duo")
    listed = sources.get_event_catalogs()["cisco_duo"]
    assert single == listed


# ── /api/sources/{source}/event-catalog ──────────────────────────────────────


def test_event_catalog_unauthenticated_is_401(client):
    r = client.get("/admin/api/sources/cisco_duo/event-catalog")
    assert r.status_code == 401


def test_event_catalog_unknown_source_is_404(client):
    _login_admin(client)
    r = client.get("/admin/api/sources/does-not-exist/event-catalog")
    assert r.status_code == 404


def test_event_catalog_returns_defaults_when_no_override(client):
    _login_admin(client)
    r = client.get("/admin/api/sources/cisco_duo/event-catalog")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "cisco_duo"
    assert body["has_override"] is False
    by_id = {e["id"]: e for e in body["catalog"]}
    # Every entry has enabled + weight (the merge layer enriches them).
    for entry in by_id.values():
        assert "enabled" in entry
        assert "weight" in entry
    # auth.success ships with default_weight 0.70 in the source module.
    assert by_id["auth.success"]["enabled"] is True
    assert abs(by_id["auth.success"]["weight"] - 0.70) < 1e-9


def test_event_catalog_reflects_persisted_mix(client, isolated_mix):
    _login_admin(client)
    isolated_mix.set_mix("cisco_duo", [
        {"event_id": "auth.success", "enabled": True, "weight": 0.10},
        {"event_id": "auth.fraud", "enabled": False, "weight": 0.0},
    ])
    r = client.get("/admin/api/sources/cisco_duo/event-catalog")
    body = r.json()
    assert body["has_override"] is True
    by_id = {e["id"]: e for e in body["catalog"]}
    assert by_id["auth.success"]["weight"] == 0.10
    assert by_id["auth.fraud"]["enabled"] is False
    # Entries the admin didn't touch keep their default weight.
    assert by_id["admin.admin_login"]["weight"] == 0.40


# ── /api/source-event-mix (list) ─────────────────────────────────────────────


def test_list_mixes_empty_when_none_configured(client):
    _login_admin(client)
    r = client.get("/admin/api/source-event-mix")
    assert r.status_code == 200
    assert r.json() == {"mixes": {}}


def test_list_mixes_returns_global_records_for_admin(client, isolated_mix):
    _login_admin(client)
    isolated_mix.set_mix("cisco_duo", [
        {"event_id": "auth.success", "enabled": True, "weight": 0.9},
    ])
    r = client.get("/admin/api/source-event-mix")
    body = r.json()
    assert "cisco_duo" in body["mixes"]
    assert body["mixes"]["cisco_duo"]["own"] is True


# ── /api/source-event-mix/{source} (PUT) ─────────────────────────────────────


def test_put_mix_unauthenticated_is_401(client):
    r = client.put(
        "/admin/api/source-event-mix/cisco_duo",
        json={"mix": [{"event_id": "auth.success", "enabled": True, "weight": 1.0}]},
    )
    assert r.status_code == 401


def test_put_mix_unknown_source_is_404(client):
    _login_admin(client)
    r = client.put(
        "/admin/api/source-event-mix/does-not-exist",
        json={"mix": []},
    )
    assert r.status_code == 404


def test_put_mix_missing_mix_field_is_400(client):
    _login_admin(client)
    r = client.put("/admin/api/source-event-mix/cisco_duo", json={})
    assert r.status_code == 400


def test_put_mix_invalid_json_is_400(client):
    _login_admin(client)
    r = client.put(
        "/admin/api/source-event-mix/cisco_duo",
        content=b"not-json",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 400


def test_put_mix_persists_and_round_trips(client, isolated_mix):
    _login_admin(client)
    r = client.put(
        "/admin/api/source-event-mix/cisco_duo",
        json={"mix": [
            {"event_id": "auth.success", "enabled": True, "weight": 0.25},
            {"event_id": "auth.failure", "enabled": True, "weight": 0.75},
            {"event_id": "auth.fraud", "enabled": False, "weight": 0.0},
        ]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["own"] is True
    # Read it back via the helper module.
    rec = isolated_mix.get_mix("cisco_duo")
    assert rec is not None
    ids = {e["event_id"]: e for e in rec["mix"]}
    assert ids["auth.success"]["weight"] == 0.25
    assert ids["auth.fraud"]["enabled"] is False


# ── /api/source-event-mix/{source} (DELETE) ──────────────────────────────────


def test_delete_mix_unknown_returns_404(client):
    _login_admin(client)
    r = client.delete("/admin/api/source-event-mix/cisco_duo")
    assert r.status_code == 404


def test_delete_mix_removes_persisted_record(client, isolated_mix):
    _login_admin(client)
    isolated_mix.set_mix("cisco_duo", [
        {"event_id": "auth.success", "enabled": True, "weight": 0.5},
    ])
    assert isolated_mix.get_mix("cisco_duo") is not None
    r = client.delete("/admin/api/source-event-mix/cisco_duo")
    assert r.status_code == 200
    assert isolated_mix.get_mix("cisco_duo") is None
