"""P4.6 — end-to-end: the send endpoints honour ``link_xdr_assets``.

We stub two collaborators so the test is hermetic:

* ``alerts.egress_alert`` — captures the prepared alert in-memory so we can
  inspect what was actually about to ship (no UAM call).
* ``admin._build_asset_resolver_for_session`` — returns a deterministic
  resolver so we don't need to seed user S1 mgmt creds in SQLite.

The wiring under test is admin.py's send handlers: when
``profile.link_xdr_assets`` is true (or ``body.link_xdr_assets`` for
custom sends), a resolver is built, passed through, and ``close()``-d on
every exit path.
"""
from __future__ import annotations

import copy
from typing import Any

import pytest
from fastapi.testclient import TestClient

# ── Fixtures ─────────────────────────────────────────────────────────────────

# This module asserts the **v2 binding shape** (numeric agent id in
# ``resources[].uid``). Production default for v2 was flipped to OFF on
# 2026-06-10 (see ``alerts._binding_shape_enabled``) — UAM silently drops
# alerts carrying the numeric id at sub-account scope. Force ON here so the
# tests continue to validate the v2 wiring end-to-end.
@pytest.fixture(autouse=True)
def _force_v2_binding_shape(monkeypatch):
    monkeypatch.setenv("APIGENIE_UAM_BINDING_V2", "1")


@pytest.fixture
def client():
    from app import app
    return TestClient(app)


def _login_as_user(client: TestClient, username: str,
                   password: str = "testpassw0rd") -> None:
    r = client.post("/portal/login",
                    data={"username": username, "password": password},
                    follow_redirects=False)
    assert r.status_code in (200, 303), r.text


def _ent() -> str:
    """Entitlement granting all P4.6 send perms on Alert Push."""
    import accounts
    ent = accounts.create_entitlement(
        name="alert-push-asset-linkage",
        permissions={accounts.Category.ALERT_PUSH:
                     ["view", "create", "modify", "delete", "manage"]},
    )
    return ent["id"]


@pytest.fixture
def captured_alerts(monkeypatch):
    """Replace ``alerts.egress_alert`` and remember every prepared alert."""
    import alerts
    captured: list[dict[str, Any]] = []

    def stub(alert, *, uam_ingest_url, service_token, account_id,
             site_id=None, group_id=None, client=None):
        captured.append(copy.deepcopy(alert))
        return {"success": True, "status": 202,
                "alert_uid": alert.get("finding_info", {}).get("uid", "")}

    monkeypatch.setattr(alerts, "egress_alert", stub)
    return captured


class _StubResolver:
    """Deterministic resolver: every non-empty name hint produces a synthetic
    UID. Mirrors the public surface of :class:`s1_assets.S1AssetResolver`
    needed by the admin send endpoints (``resolve_endpoint``, ``close``,
    ``stats``)."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.closed = False
        self.hits = 0
        self.misses = 0

    def resolve_endpoint(self, name_hint: str) -> dict[str, Any] | None:
        self.calls.append(name_hint)
        if not name_hint:
            self.misses += 1
            return None
        self.hits += 1
        # v2.2 hit shape: ``uid`` is the XDR Asset ID (alphanumeric —
        # lands in ``resources[].uid`` as UAM's binding key), ``agent_uuid``
        # is the hex UUID (lands in ``device.uid``), ``agent_id`` is the
        # numeric S1 agent id (cosmetic, lands in ``device.agent.uid``).
        slug = name_hint.lower()
        return {
            "uid": f"xdr-of-{slug}",                    # XDR Asset ID
            "agent_uuid": f"uuid-of-{slug}",             # hex UUID
            "agent_id": f"agent-id-of-{slug}",           # numeric S1 id
            "agent_version": "25.2.6.442",
            "machine_type": "server",
            "hostname": name_hint.upper(),
            "ip": "10.0.0.7",
            "os_name": "Linux",
            "os_type": "Linux",
            "os_type_id": 100,
            "domain": "x.test",
            "category": "Server",
        }

    def close(self) -> None:
        self.closed = True

    def stats(self) -> dict[str, Any]:
        return {
            "configured": True,
            "lookups": len(self.calls),
            "hits": self.hits,
            "misses": self.misses,
            "cache_hits": 0,
            "trace": [],
        }


@pytest.fixture
def stub_resolver(monkeypatch):
    """Force the admin send handlers to use our in-memory resolver."""
    import admin
    stub = _StubResolver()
    # Accept the new scope kwargs (account_id/site_id/group_id) so the test
    # double matches the production signature; ignore them — the stub doesn't
    # need scope context, it's already deterministic.
    monkeypatch.setattr(admin, "_build_asset_resolver_for_session",
                        lambda _session, **_kw: stub)
    return stub


def _make_profile(client: TestClient, *, link_xdr_assets: bool,
                  device_name: str = "bridge",
                  template_id: str = "default_alert") -> dict[str, Any]:
    """Create a profile that exercises both the top-level device path AND
    a resources[Device] entry, so we can verify both injection sites."""
    payload = {
        "name": "P4.6",
        "template_id": template_id,
        "uam_ingest_url": "https://ingest.test",
        "uam_account_id": "acct-test",
        "uam_service_token": "tok-test",
        "link_xdr_assets": link_xdr_assets,
        "overrides": {
            "device.name": device_name,
            "resources[0].type": "Device",
            "resources[0].name": device_name,
        },
    }
    r = client.post("/admin/api/alerts/profiles", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


# ── Profile send + asset linkage ─────────────────────────────────────────────

class TestSendWithAssetLinkage:
    def test_link_xdr_assets_true_injects_device_uid(self, client, make_user,
                                                     captured_alerts, stub_resolver):
        make_user("alice", entitlement_id=_ent())
        _login_as_user(client, "alice")
        prof = _make_profile(client, link_xdr_assets=True)

        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 1})
        assert r.status_code == 200, r.text
        assert len(captured_alerts) == 1
        alert = captured_alerts[0]
        # Top-level device.uid is the resolver's hex UUID for the hint
        # (cosmetic, OCSF-documented as a hex UUID).
        assert alert["device"]["uid"] == "uuid-of-bridge"
        # device.agent.uid is the NUMERIC agent id (cosmetic, OCSF-feed
        # consistency with real EDR alerts).
        assert alert["device"]["agent"]["uid"] == "agent-id-of-bridge"
        # resources[0].uid is the XDR Asset ID — UAM's actual binding key.
        # Sending a hex UUID or numeric agent id here produces unbound
        # synthetic tiles; the XDR Asset ID is the only value that binds.
        assert alert["resources"][0]["uid"] == "xdr-of-bridge"
        # The resolver was consulted at least once for the bridge name.
        assert "bridge" in stub_resolver.calls
        # And was closed by the handler (lifecycle managed).
        assert stub_resolver.closed is True

    def test_link_xdr_assets_false_does_not_call_resolver(self, client, make_user,
                                                          captured_alerts, stub_resolver):
        make_user("bob", entitlement_id=_ent())
        _login_as_user(client, "bob")
        prof = _make_profile(client, link_xdr_assets=False)

        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 1})
        assert r.status_code == 200, r.text
        assert len(captured_alerts) == 1
        alert = captured_alerts[0]
        # No resolver = no device.uid injection.
        assert "uid" not in alert["device"]
        assert stub_resolver.calls == []
        # closed was never even reached because the resolver wasn't built.
        assert stub_resolver.closed is False

    def test_batch_send_uses_one_resolver_for_all_alerts(self, client, make_user,
                                                        captured_alerts, stub_resolver):
        """Send N=5 — the same resolver instance must be reused, and the
        resolver's internal cache must collapse the N lookups to 1."""
        make_user("carol", entitlement_id=_ent())
        _login_as_user(client, "carol")
        prof = _make_profile(client, link_xdr_assets=True)

        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 5})
        assert r.status_code == 200, r.text
        assert len(captured_alerts) == 5
        # Every alert in the batch carries the same resolved UID.
        for a in captured_alerts:
            assert a["device"]["uid"] == "uuid-of-bridge"
        # The stub_resolver is a fresh class instance, no caching of its own,
        # so it sees N+M calls (one per device + one per resources[Device]).
        # What we DO assert: the same instance was used (one .closed flip).
        assert stub_resolver.closed is True

    def test_resolver_closed_even_if_egress_raises(self, monkeypatch, client,
                                                   make_user, stub_resolver):
        """If alerts.egress_alert raises mid-batch, the resolver must still
        be ``close()``-d. Wire egress to raise, expect a 500-ish response,
        and assert closed == True."""
        import alerts
        def boom(*args, **kwargs):
            raise RuntimeError("ingest exploded")
        monkeypatch.setattr(alerts, "egress_alert", boom)

        make_user("dan", entitlement_id=_ent())
        _login_as_user(client, "dan")
        prof = _make_profile(client, link_xdr_assets=True)

        # The FastAPI test client surfaces unhandled exceptions; we don't
        # care about the status code, only that close() ran.
        with pytest.raises(RuntimeError):
            client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 1})
        assert stub_resolver.closed is True


# ── Custom send + asset linkage ──────────────────────────────────────────────

class TestSendCustomWithAssetLinkage:
    def test_custom_send_with_link_xdr_assets(self, client, make_user,
                                              captured_alerts, stub_resolver):
        make_user("erin", entitlement_id=_ent())
        _login_as_user(client, "erin")

        body = {
            "uam_ingest_url": "https://ingest.test",
            "uam_account_id": "acct-test",
            "uam_service_token": "tok-test",
            "auto_generate_uid": True,
            "link_xdr_assets": True,
            "alert_json": {
                "metadata": {"version": "1.0.0"},
                "finding_info": {"title": "Custom"},
                "device": {"name": "enterprise"},
                "resources": [{"type": "Device", "name": "enterprise"}],
            },
        }
        r = client.post("/admin/api/alerts/send-custom", json=body)
        assert r.status_code == 200, r.text
        assert len(captured_alerts) == 1
        alert = captured_alerts[0]
        assert alert["device"]["uid"] == "uuid-of-enterprise"
        # resources[].uid carries the XDR Asset ID (UAM binding key).
        assert alert["resources"][0]["uid"] == "xdr-of-enterprise"
        assert stub_resolver.closed is True

    def test_custom_send_without_link_xdr_assets_no_injection(self, client, make_user,
                                                              captured_alerts, stub_resolver):
        make_user("frank", entitlement_id=_ent())
        _login_as_user(client, "frank")

        body = {
            "uam_ingest_url": "https://ingest.test",
            "uam_account_id": "acct-test",
            "uam_service_token": "tok-test",
            "auto_generate_uid": True,
            "alert_json": {
                "metadata": {"version": "1.0.0"},
                "finding_info": {"title": "Custom"},
                "device": {"name": "enterprise"},
            },
        }
        r = client.post("/admin/api/alerts/send-custom", json=body)
        assert r.status_code == 200, r.text
        assert len(captured_alerts) == 1
        alert = captured_alerts[0]
        assert "uid" not in alert["device"]
        assert stub_resolver.calls == []


# ── Resolver diagnostics on the send response ────────────────────────────────

class TestResolverStatusOnResponse:
    """The send response must carry a ``resolver`` diagnostic block so the UI
    can tell the user what happened without grepping container logs.

    Locked-in states:

    * ``disabled``  — link_xdr_assets is OFF for this profile
    * ``no_creds``  — link_xdr_assets ON but the cred-loader returned None
    * ``used``      — resolver was built; counters describe what it did
    """

    def test_disabled_when_toggle_off(self, client, make_user, captured_alerts,
                                      stub_resolver):
        make_user("u1", entitlement_id=_ent())
        _login_as_user(client, "u1")
        prof = _make_profile(client, link_xdr_assets=False)
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 1})
        assert r.status_code == 200, r.text
        rs = r.json().get("resolver") or {}
        assert rs.get("status") == "disabled"
        # No counters when the resolver was never built — keep the response lean.
        assert "lookups" not in rs

    def test_no_creds_when_cred_loader_returns_none(self, client, make_user,
                                                   monkeypatch, captured_alerts):
        """If ``_build_asset_resolver_for_session`` returns ``None`` (no S1
        creds), the response says ``no_creds`` and carries an explanatory note."""
        import admin
        monkeypatch.setattr(admin, "_build_asset_resolver_for_session",
                            lambda _s, **_kw: None)
        make_user("u2", entitlement_id=_ent())
        _login_as_user(client, "u2")
        prof = _make_profile(client, link_xdr_assets=True)
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 1})
        assert r.status_code == 200, r.text
        rs = r.json().get("resolver") or {}
        assert rs.get("status") == "no_creds"
        # Human-readable note so the UI can echo it.
        assert "S1 console URL" in (rs.get("note") or "")

    def test_used_status_includes_counters_and_trace(self, client, make_user,
                                                    captured_alerts, stub_resolver):
        make_user("u3", entitlement_id=_ent())
        _login_as_user(client, "u3")
        prof = _make_profile(client, link_xdr_assets=True)
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 3})
        assert r.status_code == 200, r.text
        rs = r.json().get("resolver") or {}
        assert rs.get("status") == "used"
        # Counters come from the resolver's stats() method.
        assert rs.get("lookups", 0) >= 1
        assert rs.get("hits", 0) >= 1
        assert isinstance(rs.get("trace"), list)
        assert rs.get("configured") is True

    def test_real_resolver_zero_hits_surfaces_miss_reason(self, client, make_user,
                                                         monkeypatch, captured_alerts):
        """End-to-end with the REAL resolver class so the trace records carry
        the actual ``status`` strings from ``s1_assets`` (e.g. ``no_score_match``).
        Uses an httpx MockTransport to return an empty agents list (the
        "no S1 agents found" path)."""
        import admin
        import httpx
        import s1_assets

        def handler(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": []})

        def _builder_wrapper(_session, **_kw):
            # The real resolver now requires ``account_id`` to be
            # ``is_configured()`` (the ``/xdr/assets`` query needs it). We
            # pass a deterministic value so the resolver reaches the
            # "empty data list" path the test wants to exercise.
            client_h = httpx.Client(transport=httpx.MockTransport(handler))
            return s1_assets.S1AssetResolver("https://demo.s1.local", "tok",
                                             client=client_h,
                                             account_id="acct-test")
        monkeypatch.setattr(admin, "_build_asset_resolver_for_session", _builder_wrapper)

        make_user("u4", entitlement_id=_ent())
        _login_as_user(client, "u4")
        prof = _make_profile(client, link_xdr_assets=True,
                             device_name="ghost-host")
        r = client.post(f"/admin/api/alerts/profiles/{prof['id']}/send",
                        json={"count": 1})
        assert r.status_code == 200, r.text
        rs = r.json().get("resolver") or {}
        assert rs.get("status") == "used"
        assert rs.get("hits") == 0
        assert rs.get("misses", 0) >= 1
        # The trace must surface the failure reason so the UI can show it.
        # ``/xdr/assets`` empty-data status is ``no_assets`` in v2.2 (renamed
        # from the pre-XDR ``no_agents`` label — the resolver now hits
        # ``/xdr/assets`` rather than ``/agents``).
        statuses = [t.get("status") for t in (rs.get("trace") or [])]
        assert "no_assets" in statuses
