"""HTTP-level tests for the /admin/api/wef/bindings/* surface (v5.2 Phase C).

Exercise the routes added in admin.py against a real ``TestClient(app)``:
auth + RBAC, JSON shape, error codes, cross-store consistency
(``delete_binding`` must also drop the cert bundle, ``cert`` upload must
flip ``cert_uploaded`` flag, ``test`` must call ``push_once``).

Mirrors ``tests/test_webhooks.py``'s ``_login_admin`` helper / fixture
pattern so a future contributor copying the layout for new endpoints
(``/admin/api/wef/<something>``) has a single template to follow.
"""
from __future__ import annotations

import base64
import os

import pytest
from fastapi.testclient import TestClient


# ── Helpers ───────────────────────────────────────────────────────────

def _login_admin(client: TestClient) -> None:
    """Log in as the built-in admin via the form endpoint."""
    pwd = os.environ.get("ADMIN_PASSWORD", "apigenie")
    r = client.post("/admin/login",
                    data={"username": "admin", "password": pwd},
                    follow_redirects=False)
    assert r.status_code in (200, 302, 303), (r.status_code, r.text[:200])


_VALID_CONFIG = {
    "target_host": "wec1.lab.example.com",
    "target_port": 5986,
    "target_path": "/wsman/SubscriptionManager/WEC",
    "auth_method": "basic",
    "basic_username": "wef-svc",
    "tls_verify": True,
    "ca_bundle_path": None,
    "rate_per_min": 60,
    "batch_size": 10,
    "jitter_pct": 0,
    "channels_enabled": ["Security"],
}


PEM_BUNDLE = (
    b"-----BEGIN CERTIFICATE-----\nFAKE-CERT\n-----END CERTIFICATE-----\n"
    b"-----BEGIN PRIVATE KEY-----\nFAKE-KEY\n-----END PRIVATE KEY-----\n"
)


@pytest.fixture
def client():
    from app import app
    return TestClient(app)


def _create(client: TestClient, name: str = "DC01",
            **cfg_overrides) -> dict:
    """POST a binding via the API and return the created row."""
    cfg = {**_VALID_CONFIG, **cfg_overrides}
    r = client.post("/admin/api/wef/bindings", json={
        "name": name,
        "config": cfg,
        "password": "sekrit",
    })
    assert r.status_code == 201, (r.status_code, r.text[:200])
    return r.json()


# ── Auth ──────────────────────────────────────────────────────────────

def test_endpoints_require_session(client):
    """Without a session cookie every WEF endpoint returns 401."""
    for method, url in [
        ("GET", "/admin/api/wef/bindings"),
        ("POST", "/admin/api/wef/bindings"),
        ("GET", "/admin/api/wef/bindings/wef-x"),
        ("PUT", "/admin/api/wef/bindings/wef-x"),
        ("DELETE", "/admin/api/wef/bindings/wef-x"),
        ("POST", "/admin/api/wef/bindings/wef-x/cert"),
        ("PUT", "/admin/api/wef/bindings/wef-x/enabled"),
        ("POST", "/admin/api/wef/bindings/wef-x/test"),
        # Phase F: history endpoints follow the same auth model.
        ("GET", "/admin/api/wef/history"),
        ("GET", "/admin/api/wef/bindings/wef-x/history"),
    ]:
        r = client.request(method, url, json={})
        assert r.status_code == 401, (method, url, r.status_code)


# ── CRUD happy path ───────────────────────────────────────────────────

def test_list_starts_empty_then_reflects_creates(client):
    _login_admin(client)
    r = client.get("/admin/api/wef/bindings")
    assert r.status_code == 200
    assert r.json()["count"] == 0

    a = _create(client, "A")
    b = _create(client, "B")
    r = client.get("/admin/api/wef/bindings")
    body = r.json()
    assert body["count"] == 2
    ids = {x["id"] for x in body["bindings"]}
    assert {a["id"], b["id"]} == ids


def test_create_rejects_invalid_config_with_400(client):
    _login_admin(client)
    r = client.post("/admin/api/wef/bindings", json={
        "name": "broken",
        "config": {**_VALID_CONFIG, "target_host": ""},  # invalid
        "password": "x",
    })
    assert r.status_code == 400
    assert "target_host" in r.json()["error"]


def test_get_unknown_returns_404(client):
    _login_admin(client)
    r = client.get("/admin/api/wef/bindings/wef-does-not-exist")
    assert r.status_code == 404


def test_update_partial_preserves_other_fields(client):
    _login_admin(client)
    bnd = _create(client)
    r = client.put(f"/admin/api/wef/bindings/{bnd['id']}",
                   json={"name": "Renamed"})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Renamed"
    assert body["config"]["target_host"] == _VALID_CONFIG["target_host"]


def test_get_never_returns_plaintext_password(client):
    """The password field accepted at create time must NEVER round-trip
    back to any GET response — only the encrypted form lives in the
    binding (and even that is fine to surface because the UI uses it
    just as a 'password set' badge)."""
    _login_admin(client)
    bnd = _create(client)
    r = client.get(f"/admin/api/wef/bindings/{bnd['id']}")
    assert r.status_code == 200
    raw = r.text
    assert "sekrit" not in raw, (
        "Plaintext Basic password leaked into a WEF binding GET response"
    )
    # The encrypted form is fine to surface — the UI uses its presence
    # as a 'password configured' indicator.
    body = r.json()
    enc = body["config"].get("basic_password_enc") or ""
    assert enc.startswith("gAAAAA"), (
        "Expected Fernet ciphertext in basic_password_enc"
    )


def test_delete_removes_binding_and_cert(client):
    _login_admin(client)
    from sources import windows_event_forwarding as wef
    bnd = _create(client)
    # Drop a cert bundle on disk so we can prove delete cleans it up.
    wef.save_cert_bundle(bnd["id"], PEM_BUNDLE)
    assert wef.load_cert_bundle(bnd["id"]) == PEM_BUNDLE
    r = client.delete(f"/admin/api/wef/bindings/{bnd['id']}")
    assert r.status_code == 200
    # Row gone …
    assert client.get(f"/admin/api/wef/bindings/{bnd['id']}").status_code == 404
    # … and cert gone with it.
    assert wef.load_cert_bundle(bnd["id"]) is None


# ── Cert upload ───────────────────────────────────────────────────────

def test_cert_upload_writes_bundle_and_flips_flag(client):
    """Cert upload is meaningful only for mTLS bindings; the binding
    normaliser clears ``cert_uploaded`` whenever ``auth_method=basic``
    so a stale flag can't outlive an auth-method switch. Create the
    binding as ``client_cert`` first, then upload — the flag should
    flip to True and the encrypted bundle should round-trip.
    """
    _login_admin(client)
    from sources import windows_event_forwarding as wef
    # mTLS binding has no Basic credentials by design.
    r = client.post("/admin/api/wef/bindings", json={
        "name": "mTLS-1",
        "config": {**_VALID_CONFIG, "auth_method": "client_cert",
                   "basic_username": None},
    })
    assert r.status_code == 201, r.text
    bnd = r.json()
    assert bnd["config"]["cert_uploaded"] is False

    r = client.post(
        f"/admin/api/wef/bindings/{bnd['id']}/cert",
        json={"pem": base64.b64encode(PEM_BUNDLE).decode("ascii")},
    )
    assert r.status_code == 200, r.text
    after = r.json()
    assert after["config"]["cert_uploaded"] is True
    # And the bundle decrypts back to the bytes we sent.
    assert wef.load_cert_bundle(bnd["id"]) == PEM_BUNDLE


def test_cert_upload_rejects_non_pem_payload(client):
    _login_admin(client)
    bnd = _create(client)
    r = client.post(
        f"/admin/api/wef/bindings/{bnd['id']}/cert",
        json={"pem": base64.b64encode(b"not a pem at all").decode("ascii")},
    )
    assert r.status_code == 400
    assert "PEM" in r.json()["error"]


def test_cert_upload_rejects_bad_base64(client):
    _login_admin(client)
    bnd = _create(client)
    r = client.post(
        f"/admin/api/wef/bindings/{bnd['id']}/cert",
        json={"pem": "this is definitely not base64 @@@"},
    )
    # We accept overly-lenient base64 decoders → the resulting bytes may
    # not look like a PEM, so a 400 is the expected outcome either way.
    assert r.status_code == 400


# ── Start / stop / test push ──────────────────────────────────────────

def test_set_enabled_flips_flag(client):
    _login_admin(client)
    bnd = _create(client)
    assert bnd["enabled"] is False
    r = client.put(f"/admin/api/wef/bindings/{bnd['id']}/enabled",
                   json={"enabled": True})
    assert r.status_code == 200
    assert r.json()["enabled"] is True
    # Idempotent: flipping it on twice is a 200.
    r2 = client.put(f"/admin/api/wef/bindings/{bnd['id']}/enabled",
                    json={"enabled": True})
    assert r2.status_code == 200
    assert r2.json()["enabled"] is True


def test_test_push_returns_result_dict_even_when_target_unreachable(client):
    """The /test endpoint runs one push_once cycle. Even when the
    binding points at a closed port, the response is a structured JSON
    result with ok=False + error string — the endpoint must never
    raise into the FastAPI error handler."""
    _login_admin(client)
    # Bind to a closed loopback port → emitter constructs successfully,
    # the actual POST fails fast, push_once captures the error.
    bnd = _create(client, target_host="127.0.0.1", target_port=1,
                  basic_username="x")
    r = client.post(f"/admin/api/wef/bindings/{bnd['id']}/test")
    assert r.status_code == 200, r.text
    result = r.json()
    # Either ok=False with an error, or a status_code that's non-2xx —
    # both are valid "we couldn't reach the WEC" surfaces.
    assert result.get("ok") is False
    assert result.get("error"), (
        "Test push against a closed port must yield an error string"
    )


def test_test_push_records_status_into_binding(client):
    """After /test runs, GET on the binding must show the latest
    last_push_at / last_error fields. The status block is the only
    surface the UI uses to render a binding's health."""
    _login_admin(client)
    bnd = _create(client, target_host="127.0.0.1", target_port=1,
                  basic_username="x")
    client.post(f"/admin/api/wef/bindings/{bnd['id']}/test")
    after = client.get(f"/admin/api/wef/bindings/{bnd['id']}").json()
    assert after["status"]["last_push_at"] is not None
    assert after["status"]["last_error"], (
        "Test push against an unreachable target must populate last_error"
    )


# ── RBAC: non-admin without entitlement is denied ─────────────────────

def test_create_denied_without_entitlement(client, make_user):
    """A registered user with an entitlement that doesn't grant
    WEF_BINDINGS.CREATE gets a 403 from the central RBAC gate when
    they POST a binding. Mirrors the test_webhooks.py pattern: a
    full entitlement minus this category isolates the failure mode.
    """
    import accounts
    ent = accounts.create_entitlement(
        "no-wef", "",
        {accounts.Category.LOG_PROFILES: [accounts.Perm.VIEW]},
    )
    make_user(username="bob", entitlement_id=ent["id"], confirmed=True)
    # Registered users log into the portal session, not /admin/login.
    r = client.post("/portal/login",
                    data={"username": "bob", "password": "testpassw0rd"},
                    follow_redirects=False)
    assert r.status_code in (200, 302, 303), r.text[:200]

    r = client.post("/admin/api/wef/bindings", json={
        "name": "by-user", "config": _VALID_CONFIG, "password": "x",
    })
    # 403 = RBAC gate fired. 401 here would mean the session itself
    # was rejected (which would be a different bug to investigate).
    assert r.status_code == 403, (r.status_code, r.text[:200])


# ── Phase F: push history endpoints ───────────────────────────────────

def test_global_history_starts_empty(client):
    """A fresh process exposes an empty global feed \u2014 the UI relies on
    the `count: 0` to render the "No recent pushes" empty state."""
    import wef_runner
    wef_runner.clear_history()
    _login_admin(client)
    r = client.get("/admin/api/wef/history")
    assert r.status_code == 200
    body = r.json()
    assert body == {"history": [], "count": 0}


def test_test_push_populates_global_history(client):
    """Running the /test endpoint must surface a row in the global
    feed \u2014 same writer that drives the per-binding badge."""
    import wef_runner
    wef_runner.clear_history()
    _login_admin(client)
    bnd = _create(client, target_host="127.0.0.1", target_port=1,
                  basic_username="x")
    client.post(f"/admin/api/wef/bindings/{bnd['id']}/test")
    r = client.get("/admin/api/wef/history")
    assert r.status_code == 200
    entries = r.json()["history"]
    assert entries, "test push must produce a history row"
    assert entries[0]["binding_id"] == bnd["id"]
    assert entries[0]["binding_name"] == bnd["name"]
    # Closed port \u2192 ok=False with a populated error string.
    assert entries[0]["ok"] is False
    assert entries[0]["error"]


def test_per_binding_history_returns_only_that_binding(client):
    """Two bindings + two test pushes \u2192 the per-binding history endpoint
    must filter down to one row each, while the global feed shows both."""
    import wef_runner
    wef_runner.clear_history()
    _login_admin(client)
    a = _create(client, name="A", target_host="127.0.0.1",
                target_port=1, basic_username="x")
    b = _create(client, name="B", target_host="127.0.0.1",
                target_port=1, basic_username="x")
    client.post(f"/admin/api/wef/bindings/{a['id']}/test")
    client.post(f"/admin/api/wef/bindings/{b['id']}/test")
    ra = client.get(f"/admin/api/wef/bindings/{a['id']}/history")
    rb = client.get(f"/admin/api/wef/bindings/{b['id']}/history")
    assert ra.status_code == 200 and rb.status_code == 200
    entries_a = ra.json()["history"]
    entries_b = rb.json()["history"]
    assert {e["binding_id"] for e in entries_a} == {a["id"]}
    assert {e["binding_id"] for e in entries_b} == {b["id"]}
    # Global feed sees both.
    glob = client.get("/admin/api/wef/history").json()["history"]
    assert {e["binding_id"] for e in glob} == {a["id"], b["id"]}


def test_per_binding_history_returns_404_for_unknown(client):
    """A history request against a deleted/unknown binding must 404 \u2014
    same code the /bindings/{bid} GET returns so the UI can recover."""
    _login_admin(client)
    r = client.get("/admin/api/wef/bindings/wef-nope/history")
    assert r.status_code == 404


def test_history_limit_is_clamped(client):
    """A caller asking for limit=10_000 must NOT get more than
    `_HISTORY_MAX` rows back \u2014 protects the response size."""
    import wef_runner
    wef_runner.clear_history()
    _login_admin(client)
    # Synthesise more rows than _HISTORY_MAX so the clamp is observable.
    for i in range(wef_runner._HISTORY_MAX + 5):
        wef_runner.record_push(
            "bid-X", ok=True, sent=i, status_code=200,
            binding_name="X",
        )
    r = client.get("/admin/api/wef/history?limit=10000")
    assert r.status_code == 200
    body = r.json()
    assert len(body["history"]) == wef_runner._HISTORY_MAX
    assert body["count"] == wef_runner._HISTORY_MAX
