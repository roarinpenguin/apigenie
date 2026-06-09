"""Alert Push Phase 4.2 — HTTP API surface tests (FastAPI TestClient).

These exercise the routes added to ``admin.py`` end-to-end:

* /admin/api/alerts/templates                (list, get one)
* /admin/api/alerts/profiles                 (CRUD)
* /admin/api/alerts/profiles/{id}/clone

Coverage focus:

* Unauthenticated requests bounce with 401.
* A logged-in user can create + read + update + delete their own
  profile, and the response NEVER includes the plaintext UAM token
  (only has_uam_service_token: bool).
* _can_see_obj filtering: alice cannot see bob's private profile.
* _can_write_obj enforcement: alice cannot PUT/DELETE bob's profile.
* Clone creates a private copy under the caller, drops the token.
* RBAC: a user without ALERT_PUSH:create can't POST.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from app import app
    return TestClient(app)


def _login_as_user(client: TestClient, username: str, password: str = "testpassw0rd") -> None:
    r = client.post("/portal/login",
                    data={"username": username, "password": password},
                    follow_redirects=False)
    assert r.status_code in (200, 303), r.text


def _login_as_admin(client: TestClient) -> None:
    """The built-in admin uses /admin/login with a master password seeded by
    conftest. We read it back from the password file that conftest set up."""
    import os
    pw_file = os.environ.get("ADMIN_PASSWORD_FILE")
    if pw_file and os.path.isfile(pw_file):
        with open(pw_file) as f:
            pw = f.read().strip()
    else:
        pw = "admin"
    r = client.post("/admin/login", data={"password": pw}, follow_redirects=False)
    assert r.status_code in (200, 303), r.text


def _make_entitlement_with_alert_push(perms: tuple[str, ...] = ("view", "create",
                                                                "modify", "delete",
                                                                "manage"),
                                      name: str = "alert-push-tester") -> str:
    """Create an entitlement granting the given perms on the ALERT_PUSH
    category and return its id."""
    import accounts
    ent = accounts.create_entitlement(
        name=name,
        permissions={accounts.Category.ALERT_PUSH: list(perms)},
    )
    return ent["id"]


# ── Templates listing ────────────────────────────────────────────────────────

class TestTemplatesEndpoint:
    def test_unauthenticated_returns_401(self, client):
        r = client.get("/admin/api/alerts/templates")
        assert r.status_code == 401

    def test_lists_all_templates(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice")
        r = client.get("/admin/api/alerts/templates")
        assert r.status_code == 200
        templates = r.json()["templates"]
        assert len(templates) >= 70
        ids = {t["id"] for t in templates}
        assert "default_alert" in ids
        assert "o365_bec_inbox_rule" in ids

    def test_get_single_template(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice")
        r = client.get("/admin/api/alerts/templates/o365_bec_inbox_rule")
        assert r.status_code == 200
        d = r.json()
        assert d["template_id"] == "o365_bec_inbox_rule"
        assert "finding_info" in d["template"]
        assert d["template"]["finding_info"]["title"].startswith("Office 365")

    def test_get_missing_template(self, client, make_user):
        make_user("alice")
        _login_as_user(client, "alice")
        r = client.get("/admin/api/alerts/templates/nope_xyz")
        assert r.status_code == 404


# ── Profile CRUD ─────────────────────────────────────────────────────────────

class TestProfileCreate:
    def test_create_minimal(self, client, make_user):
        alice = make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/profiles", json={
            "name": "My BEC",
            "template_id": "o365_bec_inbox_rule",
        })
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["name"] == "My BEC"
        assert body["template_id"] == "o365_bec_inbox_rule"
        assert body["owner_id"] == alice["id"]
        assert body["visibility"] == "private"
        # Token surface
        assert "uam_service_token" not in body
        assert body["has_uam_service_token"] is False

    def test_create_with_token_does_not_echo_back(self, client, make_user):
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/profiles", json={
            "name": "P",
            "template_id": "default_alert",
            "uam_service_token": "super-secret",
            "uam_account_id": "acct-1",
        })
        assert r.status_code == 201
        body = r.json()
        assert "uam_service_token" not in body
        assert body["has_uam_service_token"] is True

    def test_create_requires_name(self, client, make_user):
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/profiles", json={
            "template_id": "default_alert",
        })
        assert r.status_code == 400
        assert "name" in r.json()["error"].lower()

    def test_create_rejects_unknown_template(self, client, make_user):
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/profiles", json={
            "name": "X", "template_id": "made_up_template",
        })
        assert r.status_code == 400
        assert "template" in r.json()["error"].lower()

    def test_create_without_alert_push_create_perm_forbidden(self, client, make_user):
        """A user with VIEW only on alert_push must not be able to POST."""
        ent_id = _make_entitlement_with_alert_push(perms=("view",), name="view-only")
        make_user("alice", entitlement_id=ent_id)
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/profiles", json={
            "name": "X", "template_id": "default_alert",
        })
        assert r.status_code == 403


class TestProfileRead:
    def test_get_own_profile(self, client, make_user):
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "A", "template_id": "default_alert",
        }).json()["id"]
        r = client.get(f"/admin/api/alerts/profiles/{pid}")
        assert r.status_code == 200
        assert r.json()["name"] == "A"

    def test_get_unknown_404(self, client, make_user):
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        r = client.get("/admin/api/alerts/profiles/does-not-exist")
        assert r.status_code == 404

    def test_alice_cannot_read_bobs_private_profile(self, client, make_user):
        ent = _make_entitlement_with_alert_push()
        make_user("alice", entitlement_id=ent)
        make_user("bob", entitlement_id=ent)
        # Bob creates a private profile
        _login_as_user(client, "bob")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "Bob private", "template_id": "default_alert",
        }).json()["id"]
        # Alice tries to read it
        client.cookies.clear()
        _login_as_user(client, "alice")
        r = client.get(f"/admin/api/alerts/profiles/{pid}")
        assert r.status_code == 403

    def test_alice_can_read_bobs_public_profile(self, client, make_user):
        ent = _make_entitlement_with_alert_push()
        make_user("alice", entitlement_id=ent)
        make_user("bob", entitlement_id=ent)
        _login_as_user(client, "bob")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "Bob public", "template_id": "default_alert",
            "visibility": "public",
        }).json()["id"]
        client.cookies.clear()
        _login_as_user(client, "alice")
        r = client.get(f"/admin/api/alerts/profiles/{pid}")
        assert r.status_code == 200

    def test_list_filters_by_visibility(self, client, make_user):
        ent = _make_entitlement_with_alert_push()
        make_user("alice", entitlement_id=ent)
        make_user("bob", entitlement_id=ent)
        _login_as_user(client, "bob")
        client.post("/admin/api/alerts/profiles", json={
            "name": "Bob priv", "template_id": "default_alert",
            "visibility": "private",
        })
        client.post("/admin/api/alerts/profiles", json={
            "name": "Bob pub", "template_id": "default_alert",
            "visibility": "public",
        })
        client.cookies.clear()
        _login_as_user(client, "alice")
        # Alice's own (none yet) + Bob's public, but NOT Bob's private.
        names = {p["name"] for p in client.get("/admin/api/alerts/profiles").json()["profiles"]}
        assert names == {"Bob pub"}


class TestProfileUpdate:
    def test_update_own_profile(self, client, make_user):
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "Orig", "template_id": "default_alert",
        }).json()["id"]
        r = client.put(f"/admin/api/alerts/profiles/{pid}", json={
            "name": "Renamed",
            "overrides": {"finding_info.title": "Custom title"},
        })
        assert r.status_code == 200
        body = r.json()
        assert body["name"] == "Renamed"
        assert body["overrides"]["finding_info.title"] == "Custom title"

    def test_update_token_preservation_via_api(self, client, make_user):
        """Empty UAM token in PUT must preserve the saved token (UX:
        a user editing the URL doesn't have to re-paste the secret)."""
        import alert_push
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "T", "template_id": "default_alert",
            "uam_service_token": "ORIGINAL",
        }).json()["id"]
        client.put(f"/admin/api/alerts/profiles/{pid}", json={
            "name": "Renamed", "uam_service_token": "",
        })
        # Re-read from server-side storage (the raw, un-redacted dict)
        assert alert_push.get_uam_token(pid) == "ORIGINAL"

    def test_alice_cannot_update_bobs_profile(self, client, make_user):
        ent = _make_entitlement_with_alert_push()
        make_user("alice", entitlement_id=ent)
        make_user("bob", entitlement_id=ent)
        _login_as_user(client, "bob")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "Bob", "template_id": "default_alert",
            "visibility": "public",  # alice can SEE but not WRITE
        }).json()["id"]
        client.cookies.clear()
        _login_as_user(client, "alice")
        r = client.put(f"/admin/api/alerts/profiles/{pid}", json={"name": "Hijack"})
        assert r.status_code == 403


class TestProfileDelete:
    def test_delete_own(self, client, make_user):
        make_user("alice", entitlement_id=_make_entitlement_with_alert_push())
        _login_as_user(client, "alice")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "D", "template_id": "default_alert",
        }).json()["id"]
        r = client.delete(f"/admin/api/alerts/profiles/{pid}")
        assert r.status_code == 200
        assert client.get(f"/admin/api/alerts/profiles/{pid}").status_code == 404

    def test_alice_cannot_delete_bobs(self, client, make_user):
        ent = _make_entitlement_with_alert_push()
        make_user("alice", entitlement_id=ent)
        make_user("bob", entitlement_id=ent)
        _login_as_user(client, "bob")
        pid = client.post("/admin/api/alerts/profiles", json={
            "name": "B", "template_id": "default_alert", "visibility": "public",
        }).json()["id"]
        client.cookies.clear()
        _login_as_user(client, "alice")
        r = client.delete(f"/admin/api/alerts/profiles/{pid}")
        assert r.status_code == 403


class TestProfileClone:
    def test_clone_public_under_caller(self, client, make_user):
        import alert_push
        ent = _make_entitlement_with_alert_push()
        bob = make_user("bob", entitlement_id=ent)
        alice = make_user("alice", entitlement_id=ent)
        _login_as_user(client, "bob")
        src_id = client.post("/admin/api/alerts/profiles", json={
            "name": "Bob public", "template_id": "default_alert",
            "visibility": "public",
            "uam_service_token": "bob-secret",
            "uam_account_id": "acct-bob",
        }).json()["id"]
        client.cookies.clear()
        _login_as_user(client, "alice")
        r = client.post(f"/admin/api/alerts/profiles/{src_id}/clone")
        assert r.status_code == 201
        clone = r.json()
        assert clone["owner_id"] == alice["id"]
        assert clone["visibility"] == "private"
        # Token did NOT travel from bob to alice.
        assert clone["has_uam_service_token"] is False
        assert alert_push.get_uam_token(clone["id"]) is None
        # Account ID (non-secret) DID copy across.
        assert clone["uam_account_id"] == "acct-bob"
        # bob's original is untouched.
        assert alert_push.get_uam_token(src_id) == "bob-secret"
        assert alert_push.get_profile(src_id)["owner_id"] == bob["id"]
