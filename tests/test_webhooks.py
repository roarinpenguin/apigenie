"""Tests for the v5.0 Webhook composer (webhooks.py + /admin/api/webhooks).

Coverage:
  - Renderer: variable resolution, missing-var markers, deterministic
    profile picks across the same render pass, custom vars + env
    allowlist gating.
  - Storage: CRUD round-trip, validation rejects bad payloads, list/get/
    delete idempotency, clone produces a private copy.
  - Send pipeline (stub http.server): allowlist guard rejects loopback by
    default and accepts it when allowlisted, redaction in the effective
    request, JSON body validation, response body 64 KiB cap, header /
    URL / body templating end-to-end.
  - REST API: visibility filter, CRUD endpoints, send wires through to
    webhooks.send_webhook, /clone produces a private copy.

The tests deliberately avoid network egress: the send-pipeline tests
spin up a stub ``http.server`` on 127.0.0.1 and bypass the allowlist by
setting APIGENIE_WEBHOOK_ALLOWED_HOSTS to cover loopback.
"""
from __future__ import annotations

import http.server
import json
import os
import socketserver
import threading
import time
from contextlib import contextmanager
from urllib.parse import urlparse, parse_qs

import pytest
from fastapi.testclient import TestClient


# ── helpers ──────────────────────────────────────────────────────────────────

def _login_admin(client: TestClient) -> None:
    """Log in as the built-in admin via the form endpoint."""
    pwd = os.environ.get("ADMIN_PASSWORD", "apigenie")
    r = client.post("/admin/login",
                    data={"username": "admin", "password": pwd},
                    follow_redirects=False)
    assert r.status_code in (200, 302, 303), (r.status_code, r.text[:200])


@contextmanager
def _stub_http_server(handler_cls):
    """Spin up a stub HTTP server on an ephemeral port (one request per thread)."""
    # ThreadingTCPServer keeps the response thread separate from accept(), so a
    # large response body won't pin the accept loop and starve httpx.
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_cls,
                                          bind_and_activate=False)
    srv.allow_reuse_address = True
    srv.daemon_threads = True
    srv.server_bind()
    srv.server_activate()
    try:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            yield port
        finally:
            srv.shutdown()
            t.join(timeout=2)
    finally:
        srv.server_close()


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    """Echoes the inbound request back as JSON so tests can introspect it."""

    received: list[dict] = []  # class-level capture buffer

    def _handle(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        self.__class__.received.append({
            "method":  self.command,
            "path":    self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body":    body.decode("utf-8", errors="replace"),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Echo", "ok")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler API
        self._handle()

    def do_POST(self):  # noqa: N802
        self._handle()

    def do_PUT(self):  # noqa: N802
        self._handle()

    def do_DELETE(self):  # noqa: N802
        self._handle()

    def log_message(self, *a, **kw):  # silence stub-server access logs
        pass


@pytest.fixture
def echo_server(monkeypatch):
    """Stub HTTP echo server + loopback allowlisted so send_webhook can hit it."""
    monkeypatch.setenv("APIGENIE_WEBHOOK_ALLOWED_HOSTS", "127.0.0.0/8")
    _EchoHandler.received = []  # reset per-test capture buffer
    with _stub_http_server(_EchoHandler) as port:
        yield port


@pytest.fixture
def sample_profile():
    """A profile dict shaped like profiles.get_profile() returns."""
    return {
        "id":          "p-test",
        "name":        "Test profile",
        "owner_id":    None,
        "visibility":  "public",
        "users": [
            {"username": "alice",  "email": "alice@acme.test",  "name": "Alice"},
            {"username": "bob",    "email": "bob@acme.test",    "name": "Bob"},
        ],
        "machines": [
            {"hostname": "ws-01", "ip": "10.1.1.10"},
            {"hostname": "ws-02", "ip": "10.1.1.11"},
        ],
        "c2_servers":   [{"fqdn": "evil.example", "ip": "203.0.113.7"}],
        "malware":      [{"name": "WickedRAT",   "sha256": "deadbeef" * 8}],
        "mail_senders": [{"address": "ceo@partner.test"}],
    }


# ── renderer ─────────────────────────────────────────────────────────────────

def test_renderer_resolves_profile_pool_variables(sample_profile):
    import webhooks
    ctx = webhooks.RenderContext(profile=sample_profile)
    rendered = webhooks.render("hi {{profile.user.email}}", ctx)
    assert rendered.startswith("hi ")
    assert "@acme.test" in rendered
    # The same render call must reuse the same pick across multiple lookups,
    # so user.email and user.username refer to the *same* person.
    rendered = webhooks.render("u={{profile.user.username}} e={{profile.user.email}}", ctx)
    user_part = rendered.split(" ")[0].split("=")[1]
    email_part = rendered.split(" ")[1].split("=")[1]
    expected = next(u for u in sample_profile["users"] if u["username"] == user_part)
    assert email_part == expected["email"]


def test_renderer_missing_var_becomes_marker(sample_profile):
    import webhooks
    ctx = webhooks.RenderContext(profile=sample_profile)
    out = webhooks.render("{{profile.user.does_not_exist}} / {{custom.unset}}", ctx)
    assert out == "{{?profile.user.does_not_exist}} / {{?custom.unset}}"


def test_renderer_custom_vars(sample_profile):
    import webhooks
    ctx = webhooks.RenderContext(profile=sample_profile, custom={"title": "BOOM"})
    assert webhooks.render("alert={{custom.title}}", ctx) == "alert=BOOM"


def test_renderer_env_allowlist_gates_resolution(monkeypatch, sample_profile):
    import webhooks
    monkeypatch.setenv("APIGENIE_DOMAIN", "example.test")
    monkeypatch.setenv("SECRET", "should_not_leak")
    ctx = webhooks.RenderContext(profile=sample_profile)
    assert webhooks.render("{{env.APIGENIE_DOMAIN}}", ctx) == "example.test"
    # Not in ENV_ALLOWLIST → renders as a miss marker, regardless of what the
    # real environment holds.
    assert webhooks.render("{{env.SECRET}}", ctx) == "{{?env.SECRET}}"


def test_renderer_singletons(sample_profile):
    import webhooks
    ctx = webhooks.RenderContext(profile=sample_profile)
    out = webhooks.render(
        "now={{now}} epoch={{epoch}} epoch_ms={{epoch_ms}} uuid={{uuid}}", ctx)
    assert "now=" in out and "epoch=" in out and "uuid=" in out
    # epoch and epoch_ms must be integers and roughly aligned.
    epoch = int([p for p in out.split() if p.startswith("epoch=")][0].split("=")[1])
    epoch_ms = int([p for p in out.split() if p.startswith("epoch_ms=")][0].split("=")[1])
    assert abs(epoch_ms - epoch * 1000) < 1500
    # UUID render must be stable across the same RenderContext.
    uuid_first = [p for p in out.split() if p.startswith("uuid=")][0].split("=")[1]
    out2 = webhooks.render("{{uuid}}", ctx)
    assert out2 == uuid_first


# ── validation & storage CRUD ────────────────────────────────────────────────

def _minimum_webhook(**overrides) -> dict:
    base = {
        "name":          "Smoke webhook",
        "url":           "https://hook.test/in",
        "method":        "POST",
        "body_template": '{"hello": "{{custom.who}}"}',
        "body_format":   "json",
        "owner_id":      "u-test",
        "visibility":    "private",
    }
    base.update(overrides)
    return base


def test_validation_rejects_missing_url():
    import webhooks
    with pytest.raises(ValueError) as exc:
        webhooks.create_webhook({"name": "no url"})
    assert "url" in str(exc.value).lower()


def test_validation_rejects_bad_method():
    import webhooks
    with pytest.raises(ValueError):
        webhooks.create_webhook(_minimum_webhook(method="TELEPORT"))


def test_validation_rejects_bad_body_format():
    import webhooks
    with pytest.raises(ValueError):
        webhooks.create_webhook(_minimum_webhook(body_format="xml"))


def test_validation_rejects_bad_headers_shape():
    import webhooks
    with pytest.raises(ValueError):
        webhooks.create_webhook(_minimum_webhook(headers=[{"no_key_here": "x"}]))


def test_crud_round_trip():
    import webhooks
    wh = webhooks.create_webhook(_minimum_webhook(name="One"))
    assert wh["id"].startswith("wh-")
    fetched = webhooks.get_webhook(wh["id"])
    assert fetched == wh
    updated = webhooks.update_webhook(wh["id"], {"name": "Two"})
    assert updated and updated["name"] == "Two"
    assert updated["updated_at"] >= wh["created_at"]
    assert webhooks.list_webhooks() and webhooks.list_webhooks()[0]["name"] == "Two"
    assert webhooks.delete_webhook(wh["id"]) is True
    assert webhooks.get_webhook(wh["id"]) is None
    # idempotent: deleting an unknown id returns False, not raises.
    assert webhooks.delete_webhook(wh["id"]) is False


def test_clone_produces_private_copy_with_marker():
    import webhooks
    wh = webhooks.create_webhook(_minimum_webhook(name="Original",
                                                  visibility="public"))
    clone = webhooks.clone_webhook(wh["id"], owner_id="u-other")
    assert clone is not None
    assert clone["id"] != wh["id"]
    assert clone["owner_id"] == "u-other"
    assert clone["visibility"] == "private"
    assert clone["name"].endswith("(copy)")
    # Re-cloning must not double-append (copy).
    second = webhooks.clone_webhook(clone["id"], owner_id="u-other")
    assert second["name"].endswith("(copy)") and "(copy) (copy)" not in second["name"]


# ── send pipeline ────────────────────────────────────────────────────────────

def test_send_rejects_loopback_by_default(monkeypatch):
    """Without an explicit allowlist, 127.0.0.1 must be refused (SSRF guard)."""
    import webhooks
    monkeypatch.delenv("APIGENIE_WEBHOOK_ALLOWED_HOSTS", raising=False)
    wh = webhooks.create_webhook(_minimum_webhook(url="http://127.0.0.1:1/"))
    res = webhooks.send_webhook(wh)
    assert res["status"] == 0
    assert "egress blocked" in (res["error"] or "")


def test_send_rejects_imds_by_default(monkeypatch):
    """The cloud IMDS endpoint must never be reachable by default."""
    import webhooks
    monkeypatch.delenv("APIGENIE_WEBHOOK_ALLOWED_HOSTS", raising=False)
    wh = webhooks.create_webhook(_minimum_webhook(url="http://169.254.169.254/latest/meta-data/"))
    res = webhooks.send_webhook(wh)
    assert res["status"] == 0
    assert "egress blocked" in (res["error"] or "")


def test_send_allowlist_unlocks_loopback(monkeypatch, echo_server, sample_profile):
    import webhooks
    wh = webhooks.create_webhook(_minimum_webhook(
        url=f"http://127.0.0.1:{echo_server}/in",
        body_template='{"user": "{{profile.user.email}}", "alert": "{{custom.title}}"}',
        headers=[{"key": "X-Trace", "value": "t-{{custom.trace}}"}],
        query=[{"key": "src", "value": "apigenie"}],
    ))
    res = webhooks.send_webhook(wh, profile=sample_profile,
                                custom_vars={"title": "BOOM", "trace": "abc"})
    assert res["status"] == 200, res
    assert res["error"] is None
    # echo server received what we expect
    assert _EchoHandler.received, "stub server never received the request"
    rec = _EchoHandler.received[-1]
    assert rec["method"] == "POST"
    parsed = urlparse(rec["path"])
    assert parse_qs(parsed.query) == {"src": ["apigenie"]}
    assert rec["headers"]["x-trace"] == "t-abc"
    parsed_body = json.loads(rec["body"])
    assert parsed_body["alert"] == "BOOM"
    assert parsed_body["user"].endswith("@acme.test")
    # The "effective request" surfaces a *redacted* Authorization header — we
    # didn't set one here so just make sure the structure exists.
    assert "url" in res["effective_request"]


def test_send_json_body_validation_fails_fast(monkeypatch, echo_server):
    import webhooks
    wh = webhooks.create_webhook(_minimum_webhook(
        url=f"http://127.0.0.1:{echo_server}/in",
        body_template='{not json',
        body_format="json",
    ))
    res = webhooks.send_webhook(wh)
    assert res["status"] == 0
    assert "did not render to valid JSON" in (res["error"] or "")


def test_send_redacts_authorization_in_effective_request(monkeypatch, echo_server):
    import webhooks
    wh = webhooks.create_webhook(_minimum_webhook(
        url=f"http://127.0.0.1:{echo_server}/in",
        auth={"type": "bearer", "token_value": "super-secret-token"},
    ))
    res = webhooks.send_webhook(wh)
    assert res["status"] == 200
    auth = res["effective_request"]["headers"].get("Authorization", "")
    assert "<redacted:" in auth
    assert "super-secret-token" not in auth


def test_send_caps_response_body(monkeypatch):
    """A bloated response must be truncated to RESPONSE_BODY_CAP bytes."""
    import webhooks

    class _BigResponseHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            payload = b"x" * (webhooks.RESPONSE_BODY_CAP * 2)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a, **kw):
            pass

    monkeypatch.setenv("APIGENIE_WEBHOOK_ALLOWED_HOSTS", "127.0.0.0/8")
    with _stub_http_server(_BigResponseHandler) as port:
        wh = webhooks.create_webhook(_minimum_webhook(
            url=f"http://127.0.0.1:{port}/in",
            body_template='{"ping": "pong"}'))
        res = webhooks.send_webhook(wh)
    assert res["status"] == 200, res  # surface error text on failure
    assert res["response_truncated"] is True
    assert len(res["response_body"]) == webhooks.RESPONSE_BODY_CAP


# ── REST API ─────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    from app import app
    return TestClient(app)


def test_api_list_create_get_update_delete(client):
    _login_admin(client)
    # initially empty
    r = client.get("/admin/api/webhooks")
    assert r.status_code == 200
    assert r.json()["webhooks"] == []
    # create
    r = client.post("/admin/api/webhooks", json={
        "name": "Pipedream demo", "url": "https://hook.test/in",
        "method": "POST", "body_template": "{}", "body_format": "json",
    })
    assert r.status_code == 201, r.text
    wid = r.json()["id"]
    # get
    r = client.get(f"/admin/api/webhooks/{wid}")
    assert r.status_code == 200
    assert r.json()["name"] == "Pipedream demo"
    # update
    r = client.put(f"/admin/api/webhooks/{wid}", json={"name": "Renamed"})
    assert r.status_code == 200
    assert r.json()["name"] == "Renamed"
    # 400 on invalid update
    r = client.put(f"/admin/api/webhooks/{wid}", json={"url": "not-a-url"})
    assert r.status_code == 400
    # list now has one
    r = client.get("/admin/api/webhooks")
    assert r.status_code == 200
    assert r.json()["count"] == 1
    # delete
    r = client.delete(f"/admin/api/webhooks/{wid}")
    assert r.status_code == 200
    # second delete → 404
    r = client.delete(f"/admin/api/webhooks/{wid}")
    assert r.status_code == 404


def test_api_clone(client):
    _login_admin(client)
    r = client.post("/admin/api/webhooks", json={
        "name": "Original", "url": "https://hook.test/in", "method": "POST",
        "body_template": "{}", "body_format": "json",
    })
    wid = r.json()["id"]
    r = client.post(f"/admin/api/webhooks/{wid}/clone")
    assert r.status_code == 201
    clone = r.json()
    assert clone["id"] != wid
    assert clone["visibility"] == "private"
    assert clone["name"].endswith("(copy)")


def test_api_send_uses_renderer_and_allowlist(client, monkeypatch, echo_server,
                                              sample_profile):
    _login_admin(client)
    # Create the profile the webhook references (so the renderer can resolve it).
    import profiles
    saved = profiles.create_profile(sample_profile)
    pid = saved["id"]

    r = client.post("/admin/api/webhooks", json={
        "name": "Send test",
        "url": f"http://127.0.0.1:{echo_server}/from-api",
        "method": "POST",
        "profile_id": pid,
        "body_template": '{"who": "{{profile.user.email}}", "msg": "{{custom.msg}}"}',
        "body_format": "json",
    })
    wid = r.json()["id"]

    r = client.post(f"/admin/api/webhooks/{wid}/send",
                    json={"custom_vars": {"msg": "hello"}})
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["status"] == 200
    assert result["error"] is None
    last = _EchoHandler.received[-1]
    body = json.loads(last["body"])
    assert body["msg"] == "hello"
    assert body["who"].endswith("@acme.test")


def test_api_send_returns_egress_block_when_target_private(client, monkeypatch):
    _login_admin(client)
    monkeypatch.delenv("APIGENIE_WEBHOOK_ALLOWED_HOSTS", raising=False)
    r = client.post("/admin/api/webhooks", json={
        "name": "private", "url": "http://10.0.0.1/", "method": "POST",
        "body_template": "{}", "body_format": "json",
    })
    wid = r.json()["id"]
    r = client.post(f"/admin/api/webhooks/{wid}/send", json={})
    assert r.status_code == 200  # the API returns 200 with the SendResult dict
    result = r.json()
    assert result["status"] == 0
    assert "egress blocked" in (result["error"] or "")


def test_api_get_unknown_is_404(client):
    _login_admin(client)
    r = client.get("/admin/api/webhooks/wh-does-not-exist")
    assert r.status_code == 404


# ── RBAC: non-admin user without entitlement is denied ──────────────────────

def test_api_create_denied_without_entitlement(client, make_user):
    """A user with no webhook entitlement cannot create."""
    import accounts
    # Entitlement with no webhook perms — just LOG_PROFILES.list so the user
    # is a valid registered account but has zero webhook capabilities.
    ent = accounts.create_entitlement(
        "no-webhooks", "",
        {accounts.Category.LOG_PROFILES: [accounts.Perm.VIEW]},
    )
    user = make_user(username="bob", entitlement_id=ent["id"], confirmed=True)
    # Log in via the portal so the session is bound to a registered user.
    r = client.post("/portal/login",
                    data={"username": "bob", "password": "testpassw0rd"},
                    follow_redirects=False)
    assert r.status_code in (200, 302, 303)
    r = client.post("/admin/api/webhooks", json={
        "name": "x", "url": "https://hook.test/in", "method": "POST",
        "body_template": "{}", "body_format": "json",
    })
    # The RBAC gate returns 403; 401 would mean the session itself was bad.
    assert r.status_code == 403, (r.status_code, r.text[:200])


# ── Persisted egress allowlist (Settings card) ───────────────────────────────

def test_settings_default_empty():
    """Fresh deployment: persisted allowlist is empty and load_settings
    returns the expected default shape rather than raising."""
    import webhooks
    assert webhooks.load_settings() == {"allowed_hosts": []}


def test_settings_round_trip():
    """save_settings normalises entries and load_settings reads them back."""
    import webhooks
    saved = webhooks.save_settings({
        "allowed_hosts": ["192.168.0.0/16", "  collector.LAB  ", "10.0.0.1"]
    })
    # Hostname lower-cased, single IP retained as a /32, CIDR canonicalised.
    assert "192.168.0.0/16" in saved["allowed_hosts"]
    assert "collector.lab" in saved["allowed_hosts"]
    assert any(h.startswith("10.0.0.1") for h in saved["allowed_hosts"])
    assert webhooks.load_settings()["allowed_hosts"] == saved["allowed_hosts"]


def test_settings_validation_rejects_garbage():
    """Entries that are neither CIDR/IP nor RFC1123 hostnames are refused
    with a human-readable reason so the UI can surface it."""
    import webhooks
    with pytest.raises(ValueError) as exc:
        webhooks.save_settings({"allowed_hosts": ["rm -rf /", "ok.host"]})
    assert "rm -rf /" in str(exc.value)
    # Nothing should have been persisted.
    assert webhooks.load_settings()["allowed_hosts"] == []


def test_settings_persisted_unlocks_loopback(monkeypatch, echo_server):
    """A persisted 127.0.0.0/8 entry must override the default block list
    even when APIGENIE_WEBHOOK_ALLOWED_HOSTS is empty — that's the whole
    point of the Settings UI."""
    import webhooks
    monkeypatch.delenv("APIGENIE_WEBHOOK_ALLOWED_HOSTS", raising=False)
    webhooks.save_settings({"allowed_hosts": ["127.0.0.0/8"]})
    wh = webhooks.create_webhook(_minimum_webhook(
        url=f"http://127.0.0.1:{echo_server}/in",
        body_template='{"ok": true}'))
    res = webhooks.send_webhook(wh)
    assert res["status"] == 200, res


def test_settings_env_and_persisted_union(monkeypatch):
    """Env var supplies one CIDR, persisted file another — both must be
    honoured by the guard. Avoids the foot-gun of one source silently
    replacing the other."""
    import webhooks
    monkeypatch.setenv("APIGENIE_WEBHOOK_ALLOWED_HOSTS", "10.0.0.0/8")
    webhooks.save_settings({"allowed_hosts": ["192.168.0.0/16"]})
    ok_env, _ = webhooks._is_url_allowed("http://10.1.2.3/x")
    ok_persisted, _ = webhooks._is_url_allowed("http://192.168.1.5/x")
    ok_blocked, why = webhooks._is_url_allowed("http://172.16.1.1/x")
    assert ok_env, "env-var CIDR should still apply"
    assert ok_persisted, "persisted CIDR should apply"
    assert not ok_blocked and "172.16.1.1" in why


def test_settings_api_admin_only(client):
    """REST GET/PUT of /admin/api/webhook-settings is admin-only. The
    ADMIN_ONLY_API_PREFIXES gate returns 403 for user-role sessions."""
    _login_admin(client)
    r = client.get("/admin/api/webhook-settings")
    assert r.status_code == 200, r.text[:200]
    body = r.json()
    assert "allowed_hosts" in body and "env_allowed_hosts" in body
    assert "default_blocked" in body and body["default_blocked"]
    # Save round-trip via the API.
    r = client.put("/admin/api/webhook-settings",
                   json={"allowed_hosts": ["192.168.0.0/16"]})
    assert r.status_code == 200, r.text[:200]
    assert "192.168.0.0/16" in r.json()["allowed_hosts"]
    # Garbage entries should yield a 400 with the offending value echoed.
    r = client.put("/admin/api/webhook-settings",
                   json={"allowed_hosts": ["not a host"]})
    assert r.status_code == 400, r.text[:200]
    assert "not a host" in r.text


def test_settings_api_denied_for_user(client, make_user):
    """A regular user-portal session must be refused — even one holding
    every Webhooks entitlement — because editing the SSRF allowlist
    would let them probe arbitrary internal hosts."""
    make_user(username="eve", confirmed=True)
    r = client.post("/portal/login",
                    data={"username": "eve", "password": "testpassw0rd"},
                    follow_redirects=False)
    assert r.status_code in (200, 302, 303)
    r = client.get("/admin/api/webhook-settings")
    # Role middleware kicks the request out before the handler runs.
    assert r.status_code in (401, 403), (r.status_code, r.text[:200])
    r = client.put("/admin/api/webhook-settings",
                   json={"allowed_hosts": ["127.0.0.0/8"]})
    assert r.status_code in (401, 403), (r.status_code, r.text[:200])
