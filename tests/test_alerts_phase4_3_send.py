"""Alert Push Phase 4.3 — oneshot send, custom send, history ring buffer.

Tests the wiring between ``admin.py`` route handlers, ``alert_push.py``
history bookkeeping, and ``alerts.send_alert`` / ``alerts.send_custom_alert``.

``alerts.egress_alert`` is monkeypatched to a stub so we don't depend on
real UAM ingest; that path is already covered end-to-end in
``test_alerts_phase4.py`` via ``httpx.MockTransport``.
"""
from __future__ import annotations

from typing import Any

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


def _ent(perms=("view", "create", "modify", "delete", "manage"),
         name="alert-push-tester") -> str:
    import accounts
    ent = accounts.create_entitlement(
        name=name,
        permissions={accounts.Category.ALERT_PUSH: list(perms)},
    )
    return ent["id"]


@pytest.fixture
def stub_egress(monkeypatch):
    """Replace ``alerts.egress_alert`` with a controllable in-memory stub.

    By default it returns a 202-accepted success. Each call increments
    ``stub.calls`` and the per-call args are captured in ``stub.captured``
    so tests can assert wiring (e.g. that the profile's UAM creds reach
    egress_alert verbatim).
    """
    import alerts

    class Stub:
        def __init__(self):
            self.calls = 0
            self.captured: list[dict[str, Any]] = []
            self.next_response: dict[str, Any] = {
                "success": True,
                "status": 202,
                "alert_uid": "stub-uid",
                "error": "",
            }

        def __call__(self, alert, *, uam_ingest_url, service_token,
                     account_id, site_id=None, group_id=None, client=None):
            self.calls += 1
            self.captured.append({
                "uam_ingest_url": uam_ingest_url,
                "service_token": service_token,
                "account_id": account_id,
                "site_id": site_id,
                "alert_uid": alert.get("finding_info", {}).get("uid"),
            })
            # Build a per-call response so the alert_uid reflects this alert.
            resp = dict(self.next_response)
            if resp.get("success") and not resp.get("alert_uid"):
                resp["alert_uid"] = alert.get("finding_info", {}).get("uid", "stub-uid")
            return resp

    stub = Stub()
    monkeypatch.setattr(alerts, "egress_alert", stub)
    return stub


def _make_sendable_profile(client: TestClient,
                           name: str = "P",
                           template_id: str = "default_alert",
                           **overrides) -> dict[str, Any]:
    """POST a profile via the API with the minimum fields needed to send."""
    payload = {
        "name": name,
        "template_id": template_id,
        "uam_ingest_url": "https://ingest.test",
        "uam_account_id": "acct-test",
        "uam_service_token": "tok-test",
    }
    payload.update(overrides)
    r = client.post("/admin/api/alerts/profiles", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


# ── Oneshot send ─────────────────────────────────────────────────────────────

class TestSendOneshot:
    def test_send_single_alert(self, client, make_user, stub_egress):
        import alert_push
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client, name="P1")
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send")
        assert r.status_code == 200, r.text
        body = r.json()
        # Stub was hit once with the profile's UAM creds.
        assert stub_egress.calls == 1
        captured = stub_egress.captured[0]
        assert captured["uam_ingest_url"] == "https://ingest.test"
        assert captured["service_token"] == "tok-test"
        assert captured["account_id"] == "acct-test"
        # Response shape: summary + per-alert results.
        assert body["summary"]["count"] == 1
        assert body["summary"]["success_count"] == 1
        assert body["summary"]["failure_count"] == 0
        assert body["summary"]["template_id"] == "default_alert"
        assert len(body["results"]) == 1
        # History was recorded; alerts_sent on the profile bumped.
        hist = alert_push.get_history(prof["id"])
        assert len(hist) == 1
        assert hist[0]["success_count"] == 1
        assert alert_push.get_profile(prof["id"])["alerts_sent"] == 1

    def test_send_with_count_n(self, client, make_user, stub_egress):
        import alert_push
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 5})
        assert r.status_code == 200
        assert stub_egress.calls == 5
        assert r.json()["summary"]["success_count"] == 5
        assert alert_push.get_profile(prof["id"])["alerts_sent"] == 5

    def test_count_zero_clamped_to_one(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 0})
        assert r.status_code == 200
        assert stub_egress.calls == 1

    def test_count_huge_clamped_to_100(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 9999})
        assert r.status_code == 200
        assert stub_egress.calls == 100

    def test_send_missing_uam_token_rejected(self, client, make_user, stub_egress):
        """A profile without uam_service_token must NOT trigger egress."""
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/profiles", json={
            "name": "P", "template_id": "default_alert",
            "uam_ingest_url": "https://ingest.test",
            "uam_account_id": "acct",
            # NO uam_service_token
        })
        pid = r.json()["id"]
        r2 = client.post(f"/admin/api/alerts/profiles/{pid}/send")
        assert r2.status_code == 400
        assert "token" in r2.json()["error"].lower()
        assert stub_egress.calls == 0

    def test_send_unknown_profile_404(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/profiles/does-not-exist/send")
        assert r.status_code == 404

    def test_alice_cannot_send_bobs_private_profile(self, client, make_user, stub_egress):
        ent = _ent()
        make_user("bob", entitlement_id=ent)
        make_user("alice", entitlement_id=ent)
        _login_as_user(client, "bob")
        prof = _make_sendable_profile(client, name="Bob")
        client.cookies.clear()
        _login_as_user(client, "alice")
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send")
        assert r.status_code == 403
        assert stub_egress.calls == 0

    def test_failed_send_recorded_but_no_counter_bump(self, client, make_user,
                                                     stub_egress):
        """When the UAM ingest rejects (401, 500, etc), the history entry
        must capture the failure but the lifetime alerts_sent counter must
        NOT advance — that field tracks accepted-by-UAM alerts only."""
        import alert_push
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        stub_egress.next_response = {
            "success": False, "status": 401,
            "alert_uid": "", "error": "Unauthorized",
        }
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 3})
        assert r.status_code == 200  # API call succeeded; UAM rejected
        body = r.json()
        assert body["summary"]["success_count"] == 0
        assert body["summary"]["failure_count"] == 3
        assert body["summary"]["status"] == 401
        assert body["summary"]["error"] == "Unauthorized"
        # Lifetime counter must stay at zero.
        assert alert_push.get_profile(prof["id"])["alerts_sent"] == 0

    def test_send_requires_manage_or_modify_perm(self, client, make_user, stub_egress):
        """A user with only VIEW+CREATE on alert_push can create a profile
        but cannot POST /send (which requires MANAGE or MODIFY)."""
        ent = _ent(perms=("view", "create"), name="view-create-only")
        make_user("alice", entitlement_id=ent)
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send")
        assert r.status_code == 403
        assert stub_egress.calls == 0


# ── send-custom (ad-hoc) ─────────────────────────────────────────────────────

class TestSendCustom:
    _alert = {
        "finding_info": {"title": "Ad-hoc", "uid": "will-be-replaced"},
        "severity_id": 5,
    }

    def test_send_custom_happy_path(self, client, make_user, stub_egress):
        import alert_push
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/send-custom", json={
            "alert_json": self._alert,
            "uam_ingest_url": "https://ingest.test",
            "uam_account_id": "acct-x",
            "uam_service_token": "tok-x",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert stub_egress.calls == 1
        assert body["summary"]["success_count"] == 1
        # Stored under the synthetic _custom slot in history.
        hist = alert_push.get_history("_custom")
        assert len(hist) == 1

    def test_send_custom_missing_alert_json(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/send-custom", json={
            "uam_ingest_url": "https://ingest.test",
            "uam_account_id": "acct-x",
            "uam_service_token": "tok-x",
        })
        assert r.status_code == 400
        assert "alert_json" in r.json()["error"].lower()
        assert stub_egress.calls == 0

    def test_send_custom_missing_uam_creds(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/send-custom", json={
            "alert_json": self._alert,
            "uam_ingest_url": "https://ingest.test",
            # missing account_id + token
        })
        assert r.status_code == 400
        assert "required" in r.json()["error"].lower()
        assert stub_egress.calls == 0

    def test_send_custom_requires_create_perm(self, client, make_user, stub_egress):
        ent = _ent(perms=("view",), name="view-only")
        make_user("alice", entitlement_id=ent)
        _login_as_user(client, "alice")
        r = client.post("/admin/api/alerts/send-custom", json={
            "alert_json": self._alert,
            "uam_ingest_url": "https://ingest.test",
            "uam_account_id": "acct-x",
            "uam_service_token": "tok-x",
        })
        assert r.status_code == 403
        assert stub_egress.calls == 0


# ── History endpoints ────────────────────────────────────────────────────────

class TestHistory:
    def test_history_empty_initially(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        r = client.get(f"/admin/api/alerts/profiles/{prof['id']}/history")
        assert r.status_code == 200
        assert r.json()["history"] == []

    def test_history_after_sends_is_newest_first(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        for _ in range(3):
            client.post(f"/admin/api/alerts/profiles/{prof['id']}/send")
        r = client.get(f"/admin/api/alerts/profiles/{prof['id']}/history")
        assert r.status_code == 200
        hist = r.json()["history"]
        assert len(hist) == 3
        # Each entry is a summary with count=1, success_count=1
        for entry in hist:
            assert entry["success_count"] == 1
        # Newest first: timestamps are non-strictly-decreasing
        assert hist[0]["ts"] >= hist[-1]["ts"]

    def test_global_history_only_shows_visible_profiles(self, client, make_user,
                                                       stub_egress):
        """Cross-profile feed must filter out profiles the caller can't see."""
        ent = _ent()
        make_user("bob", entitlement_id=ent)
        make_user("alice", entitlement_id=ent)
        # Bob creates a private profile and sends 2 alerts.
        _login_as_user(client, "bob")
        bob_prof = _make_sendable_profile(client, name="Bob priv")
        for _ in range(2):
            client.post(f"/admin/api/alerts/profiles/{bob_prof['id']}/send")
        client.cookies.clear()
        # Alice creates her own and sends 1.
        _login_as_user(client, "alice")
        alice_prof = _make_sendable_profile(client, name="Alice priv")
        client.post(f"/admin/api/alerts/profiles/{alice_prof['id']}/send")
        # Alice queries global history — must NOT see bob's entries.
        r = client.get("/admin/api/alerts/history")
        assert r.status_code == 200
        entries = r.json()["history"]
        pids = {e.get("profile_id") for e in entries}
        assert alice_prof["id"] in pids
        assert bob_prof["id"] not in pids

    def test_global_history_includes_custom_sends(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        client.post("/admin/api/alerts/send-custom", json={
            "alert_json": {"finding_info": {"title": "X"}},
            "uam_ingest_url": "https://ingest.test",
            "uam_account_id": "acct-x",
            "uam_service_token": "tok-x",
        })
        r = client.get("/admin/api/alerts/history")
        entries = r.json()["history"]
        assert any(e.get("profile_id") == "_custom" for e in entries)

    def test_history_delete_clears_buffer(self, client, make_user, stub_egress):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_sendable_profile(client)
        client.post(f"/admin/api/alerts/profiles/{prof['id']}/send")
        # Confirm there's an entry
        assert len(client.get(f"/admin/api/alerts/profiles/{prof['id']}/history")
                   .json()["history"]) == 1
        # Wipe
        r = client.delete(f"/admin/api/alerts/profiles/{prof['id']}/history")
        assert r.status_code == 200
        assert client.get(f"/admin/api/alerts/profiles/{prof['id']}/history") \
                     .json()["history"] == []

    def test_alice_cannot_delete_bobs_history(self, client, make_user, stub_egress):
        ent = _ent()
        make_user("bob", entitlement_id=ent)
        make_user("alice", entitlement_id=ent)
        _login_as_user(client, "bob")
        prof = _make_sendable_profile(client, name="Bob", visibility="public")
        client.post(f"/admin/api/alerts/profiles/{prof['id']}/send")
        client.cookies.clear()
        _login_as_user(client, "alice")
        # Alice CAN see Bob's public profile via GET, but cannot DELETE history.
        assert client.get(f"/admin/api/alerts/profiles/{prof['id']}/history") \
                     .status_code == 200
        r = client.delete(f"/admin/api/alerts/profiles/{prof['id']}/history")
        assert r.status_code == 403


# ── Unauthenticated access ───────────────────────────────────────────────────

class TestUnauthenticated:
    def test_send_requires_login(self, client):
        r = client.post("/admin/api/alerts/profiles/anything/send")
        assert r.status_code == 401

    def test_send_custom_requires_login(self, client):
        r = client.post("/admin/api/alerts/send-custom", json={})
        assert r.status_code == 401

    def test_history_requires_login(self, client):
        r = client.get("/admin/api/alerts/history")
        assert r.status_code == 401
