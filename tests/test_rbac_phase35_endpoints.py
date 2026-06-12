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

    def test_user_sees_their_email(self, client, make_user):
        u = make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        r = client.get("/admin/api/me/account")
        assert r.status_code == 200
        d = r.json()
        assert d["is_builtin_admin"] is False
        assert d["user_id"] == u["id"]
        assert d["username"] == "alice"
        assert d["email"] == "alice@test.local"
        # v5.1 Phase A — the per-user S1 console URL + token live only in
        # the browser. The legacy `console_url` / `has_console_token`
        # fields must NOT be present on this payload.
        assert "console_url" not in d
        assert "has_console_token" not in d


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


# ── /admin/api/me/s1-console (REMOVED in v5.1 Phase A) ─────────────────────

class TestMeS1ConsoleEndpointsRemoved:
    """v5.1 Phase A regression — the per-user S1 console URL + token used
    to round-trip through GET/PUT/DELETE /admin/api/me/s1-console. They now
    live in browser localStorage only, so those endpoints have been deleted.
    A future regression that resurrects server-side persistence would have
    to re-add them; this guard pins the deletion.
    """

    @pytest.mark.parametrize("method", ["get", "put", "delete"])
    def test_endpoints_are_gone(self, client, make_user, method):
        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")
        if method == "get":
            r = client.get("/admin/api/me/s1-console")
        elif method == "put":
            r = client.put("/admin/api/me/s1-console",
                           json={"console_url": "https://x.sentinelone.net",
                                 "api_token": "t"})
        else:
            r = client.delete("/admin/api/me/s1-console")
        # FastAPI returns 405 for an unknown method on a defined path, and
        # 404 for an entirely-undefined path — either way, the endpoint is
        # gone and *not* persisting anything.
        assert r.status_code in (404, 405), (method, r.status_code, r.text)


# ── Header-based S1 override middleware (v5.1 Phase A) ─────────────────────

class TestS1HeaderOverrideMiddleware:
    """The app.py middleware reads `X-S1-Console-URL` + `X-S1-Console-Token`
    off every request and installs them into the s1_detection_library
    ContextVar override for the duration of the request. After the response
    is dispatched, the override is cleared so the next request sees a clean
    context (no cross-request leakage on the same worker).
    """

    def test_headers_install_browser_override_for_one_request(
        self, client, make_user
    ):
        import s1_detection_library as s1

        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")

        captured = {}
        original = s1._resolved_settings

        def _spy():
            snap = dict(original())
            captured["snapshot"] = snap
            return snap
        s1._resolved_settings = _spy
        try:
            # /admin/api/s1/settings reads is_configured() → _resolved_settings.
            r = client.get(
                "/admin/api/s1/settings",
                headers={
                    "X-S1-Console-URL":   "https://alice.sentinelone.net",
                    "X-S1-Console-Token": "alice-browser-secret",
                },
            )
            assert r.status_code == 200, r.text
        finally:
            s1._resolved_settings = original

        snap = captured.get("snapshot", {})
        assert snap.get("_source") == "browser_override", \
            "middleware did not install the X-S1-Console-* headers as an override"
        assert snap["console_url"] == "https://alice.sentinelone.net"
        assert snap["api_token"] == "alice-browser-secret"

    def test_override_cleared_after_response(self, client, make_user):
        """Once the response is back, the ContextVar must be reset — the
        next request without headers must see the global settings only."""
        import s1_detection_library as s1

        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")

        # First request: headers present, override is installed.
        client.get(
            "/admin/api/s1/settings",
            headers={
                "X-S1-Console-URL":   "https://alice.sentinelone.net",
                "X-S1-Console-Token": "alice-browser-secret",
            },
        )
        # Outside any request, the contextvar in the test process must be
        # back to its default (None).
        out = s1._resolved_settings()
        assert out.get("_source") == "global", \
            "browser override leaked past the request lifecycle"

    def test_partial_headers_do_not_override(self, client, make_user):
        """URL-only (or token-only) headers must NOT replace the admin-global
        credentials — pairing the admin's token with an unrelated tenant URL
        would be a credential leak."""
        import s1_detection_library as s1

        make_user("alice")
        _login_as_user(client, "alice", "testpassw0rd")

        captured = {}
        original = s1._resolved_settings
        def _spy():
            snap = dict(original())
            captured["snapshot"] = snap
            return snap
        s1._resolved_settings = _spy
        try:
            r = client.get(
                "/admin/api/s1/settings",
                headers={"X-S1-Console-URL": "https://alice.sentinelone.net"},
            )
            assert r.status_code == 200
        finally:
            s1._resolved_settings = original

        assert captured.get("snapshot", {}).get("_source") != "browser_override"
