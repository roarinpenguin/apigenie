"""RBAC Phase 3.5 — API surface tests for /admin/api/me/* self-service endpoints.

Drives the real FastAPI app through TestClient so we exercise the role-guard
middleware, cookie handling, and the new caller-context wiring end-to-end.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    # Import inside the fixture so conftest's env redirection is applied first.
    from app import app
    return TestClient(app)


def _login_as_user(client: TestClient, username: str, password: str) -> None:
    """Log in to the user portal (sets the ag_session cookie on the client)."""
    r = client.post("/portal/login",
                    data={"username": username, "password": password},
                    follow_redirects=False)
    assert r.status_code in (200, 303), r.text


# ── /admin/api/me/account ───────────────────────────────────────────────────

class TestMeAccount:
    def test_unauthenticated_returns_401(self, client):
        r = client.get("/admin/api/me/account")
        assert r.status_code == 401

    def test_user_sees_their_email_and_console_state(self, client, make_user):
        u = make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.get("/admin/api/me/account")
        assert r.status_code == 200
        d = r.json()
        assert d["is_builtin_admin"] is False
        assert d["user_id"] == u["id"]
        assert d["username"] == "alice"
        assert d["email"] == "alice@test.local"
        assert d["console_url"] == ""
        assert d["has_console_token"] is False


# ── /admin/api/me/email ────────────────────────────────────────────────────

class TestMeEmail:
    def test_put_updates_email(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.put("/admin/api/me/email", json={"email": "new@example.com"})
        assert r.status_code == 200, r.text
        assert r.json()["email"] == "new@example.com"
        # Round-trip via /me/account
        d = client.get("/admin/api/me/account").json()
        assert d["email"] == "new@example.com"

    def test_put_rejects_invalid_email(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.put("/admin/api/me/email", json={"email": "not-an-email"})
        assert r.status_code == 400
        assert "email" in r.json()["error"].lower()


# ── /admin/api/me/password ─────────────────────────────────────────────────

class TestMePassword:
    def test_change_password_happy_path(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.put("/admin/api/me/password",
                       json={"current": "testpassw0rd", "new": "brand-N3wPass"})
        assert r.status_code == 200, r.text
        # Old password no longer works
        r2 = client.post("/portal/login",
                        data={"username": "alice", "password": "testpassw0rd"},
                        follow_redirects=False)
        assert r2.status_code == 401
        # New password works
        client.cookies.clear()
        r3 = client.post("/portal/login",
                        data={"username": "alice", "password": "brand-N3wPass"},
                        follow_redirects=False)
        assert r3.status_code in (200, 303)

    def test_wrong_current_rejected(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.put("/admin/api/me/password",
                       json={"current": "WRONG", "new": "brand-N3wPass"})
        assert r.status_code == 400
        assert "current" in r.json()["error"].lower()

    def test_short_new_rejected(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.put("/admin/api/me/password",
                       json={"current": "testpassw0rd", "new": "short"})
        assert r.status_code == 400


# ── /admin/api/me/s1-console ───────────────────────────────────────────────

class TestMeS1Console:
    def test_put_then_get_round_trip(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.put("/admin/api/me/s1-console",
                       json={"console_url": "https://alice.sentinelone.net/",
                             "api_token": "alice-secret-001"})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["console_url"] == "https://alice.sentinelone.net"  # trailing slash stripped
        assert d["has_console_token"] is True

        g = client.get("/admin/api/me/s1-console").json()
        assert g["console_url"] == "https://alice.sentinelone.net"
        assert g["has_console_token"] is True

    def test_put_preserves_token_when_only_url_changes(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        client.put("/admin/api/me/s1-console",
                   json={"console_url": "https://alice.sentinelone.net",
                         "api_token": "alice-secret-001"})
        # Now change only the URL — token must remain saved
        r = client.put("/admin/api/me/s1-console",
                       json={"console_url": "https://alice2.sentinelone.net",
                             "api_token": ""})
        assert r.status_code == 200
        g = client.get("/admin/api/me/s1-console").json()
        assert g["console_url"] == "https://alice2.sentinelone.net"
        assert g["has_console_token"] is True  # preserved

    def test_delete_clears_override(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        client.put("/admin/api/me/s1-console",
                   json={"console_url": "https://alice.sentinelone.net",
                         "api_token": "alice-secret-001"})
        r = client.delete("/admin/api/me/s1-console")
        assert r.status_code == 200
        g = client.get("/admin/api/me/s1-console").json()
        assert g["console_url"] == ""
        assert g["has_console_token"] is False


# ── Caller context wiring (middleware) ─────────────────────────────────────

class TestCallerContextMiddleware:
    def test_admin_api_request_sets_caller_to_session_user(self, client, make_user):
        """The Phase 3.5 middleware sets profiles.set_current_user() for every
        /admin/api/ request so caller-aware helpers (s1._resolved_settings,
        profiles.get_context, …) see the right uid without manual plumbing."""
        import profiles
        import s1_detection_library as s1

        u = make_user("alice")
        # Configure a per-user S1 console for alice.
        _login_as_user(client, "alice", "testpassw0rd")
        client.put("/admin/api/me/s1-console",
                   json={"console_url": "https://alice.sentinelone.net",
                         "api_token": "alice-secret-001"})

        # Now fetch /admin/api/me — the middleware should bind caller=alice
        # for the duration of the request, so _resolved_settings (called from
        # any handler that consults it) would resolve to her values.
        captured = {}

        original = s1._resolved_settings
        def _spy():
            captured["snapshot"] = dict(original())
            return original()
        s1._resolved_settings = _spy
        try:
            # Any cheap /admin/api/ endpoint that runs through the middleware.
            r = client.get("/admin/api/me")
            assert r.status_code == 200
            # The middleware runs even when the endpoint itself does not call
            # _resolved_settings, so we trigger it manually inside a follow-up
            # request handler by hitting one that does.
            r = client.get("/admin/api/s1/settings")
            # /api/s1/settings calls is_configured() → _resolved_settings()
            assert r.status_code == 200
        finally:
            s1._resolved_settings = original

        assert captured.get("snapshot", {}).get("_source") == "per_user", \
            "middleware did not bind alice's caller context for /admin/api/s1/*"
        assert captured["snapshot"]["console_url"] == "https://alice.sentinelone.net"
        assert captured["snapshot"]["api_token"] == "alice-secret-001"

        # And after the request, the contextvar must be reset back to None so
        # state can't leak between requests/workers.
        assert profiles.get_current_user() is None
