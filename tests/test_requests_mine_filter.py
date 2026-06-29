"""Request Inspector — "only my identifiers" filter.

Two layers are pinned:

* ``trace.resolve_caller_id`` — the per-request attribution that tags every
  trace entry with the user_id whose registered identifier the call's
  credential matched. This mirrors auth.py's credential extraction (Bearer /
  SSWS token headers, Basic username, Tenable x-apikeys, OAuth tenant in the
  path) so the Inspector attributes a call to the same user auth.py resolves.

* ``GET /admin/api/requests/{source}?mine=1`` — the endpoint that drives the
  UI toggle. With ``mine=1`` it keeps only the calls whose ``caller_id``
  matches the (act-as-aware) session user, and enriches every returned row
  with the caller's username + a ``caller_is_me`` flag for rendering.
"""
from __future__ import annotations

from base64 import b64encode

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request


@pytest.fixture
def client():
    from app import app
    return TestClient(app)


def _login_as_user(client: TestClient, username: str, password: str = "testpassw0rd") -> None:
    r = client.post("/portal/login",
                    data={"username": username, "password": password},
                    follow_redirects=False)
    assert r.status_code in (200, 303), r.text


def _req(headers: dict[str, str], path: str = "/api/v1/logs") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({
        "type": "http", "method": "GET", "path": path,
        "headers": raw, "query_string": b"",
    })


def _entry(caller_id, ts="2026-01-01T00:00:00"):
    return {
        "ts": ts, "method": "GET", "path": "/api/v1/logs", "query": "",
        "client": "1.2.3.4", "status": 200, "duration_ms": 5,
        "req_headers": {}, "req_body": "", "resp_size": 0,
        "resp_preview": "", "caller_id": caller_id,
    }


# ── trace.resolve_caller_id ──────────────────────────────────────────────────

class TestResolveCallerId:
    def test_bearer_token_resolves_to_owner(self, make_user):
        import accounts, trace
        u = make_user("alice")
        accounts.add_identifier(u["id"], "okta", "bearer_token", "alice-okta-tok-xyz")
        req = _req({"authorization": "Bearer alice-okta-tok-xyz"})
        assert trace.resolve_caller_id(req, "/api/v1/logs", "", "okta") == u["id"]

    def test_ssws_scheme_resolves(self, make_user):
        import accounts, trace
        u = make_user("alice")
        accounts.add_identifier(u["id"], "okta", "bearer_token", "alice-ssws-001")
        req = _req({"authorization": "SSWS alice-ssws-001"})
        assert trace.resolve_caller_id(req, "/api/v1/logs", "", "okta") == u["id"]

    def test_basic_username_resolves(self, make_user):
        import accounts, trace
        u = make_user("alice")
        accounts.add_identifier(u["id"], "cisco_duo", "basic_user", "alice-ikey-001")
        creds = b64encode(b"alice-ikey-001:some-secret").decode()
        req = _req({"authorization": f"Basic {creds}"}, path="/admin/v1/logs/authentication")
        assert trace.resolve_caller_id(req, "/admin/v1/logs/authentication", "", "cisco_duo") == u["id"]

    def test_tenant_in_oauth_path_resolves(self, make_user):
        import accounts, trace
        u = make_user("alice")
        accounts.add_identifier(u["id"], "m365", "tenant_id", "contoso-tenant-guid")
        path = "/contoso-tenant-guid/oauth2/v2.0/token"
        req = _req({}, path=path)
        assert trace.resolve_caller_id(req, path, "", "m365") == u["id"]

    def test_unregistered_credential_returns_none(self):
        import trace
        req = _req({"authorization": "Bearer nobody-registered-this"})
        assert trace.resolve_caller_id(req, "/api/v1/logs", "", "okta") is None

    def test_jwt_access_token_is_not_a_candidate(self):
        import trace
        # A real OAuth access token must never be treated as an identifier.
        cands = trace._credential_candidates(
            _req({"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"}),
            "/api/v1.0/...", "")
        assert all(not c.startswith("eyJ") for c in cands)


# ── GET /admin/api/requests/{source}?mine=1 ─────────────────────────────────

class TestMineFilterEndpoint:
    def _seed(self, source, alice_id, bob_id):
        import trace
        buf = trace.REQUEST_TRACE[source]
        buf.clear()
        buf.appendleft(_entry(None))         # anonymous / shared
        buf.appendleft(_entry(bob_id))       # someone else
        buf.appendleft(_entry(alice_id))     # mine

    def test_without_mine_returns_all_and_enriches_caller(self, client, make_user):
        import trace
        alice = make_user("alice")
        bob = make_user("bob")
        self._seed("okta", alice["id"], bob["id"])
        _login_as_user(client, "alice")

        r = client.get("/admin/api/requests/okta")
        assert r.status_code == 200, r.text
        data = r.json()
        assert len(data) == 3
        by_caller = {row.get("caller"): row for row in data}
        assert by_caller["alice"]["caller_is_me"] is True
        assert by_caller["bob"]["caller_is_me"] is False
        # The anonymous row carries no caller enrichment.
        assert any(row.get("caller") is None for row in data)
        trace.REQUEST_TRACE["okta"].clear()

    def test_mine_keeps_only_my_calls(self, client, make_user):
        import trace
        alice = make_user("alice")
        bob = make_user("bob")
        self._seed("okta", alice["id"], bob["id"])
        _login_as_user(client, "alice")

        r = client.get("/admin/api/requests/okta?mine=1")
        assert r.status_code == 200, r.text
        data = r.json()
        assert len(data) == 1
        assert data[0]["caller_id"] == alice["id"]
        assert data[0]["caller"] == "alice"
        assert data[0]["caller_is_me"] is True
        trace.REQUEST_TRACE["okta"].clear()

    def test_mine_is_empty_when_user_has_no_matches(self, client, make_user):
        import trace
        alice = make_user("alice")
        bob = make_user("bob")
        # Only bob and an anonymous call recorded — alice owns nothing here.
        buf = trace.REQUEST_TRACE["okta"]
        buf.clear()
        buf.appendleft(_entry(None))
        buf.appendleft(_entry(bob["id"]))
        _login_as_user(client, "alice")

        r = client.get("/admin/api/requests/okta?mine=1")
        assert r.status_code == 200, r.text
        assert r.json() == []
        trace.REQUEST_TRACE["okta"].clear()

    def test_mine_requires_auth(self, client):
        r = client.get("/admin/api/requests/okta?mine=1")
        assert r.status_code == 401
