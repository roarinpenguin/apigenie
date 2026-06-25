"""Tests for asset binding in the push loop (v5.3 Step 2, Phase 3).

The push loop owns:

* a *boolean profile flag* ``link_xdr_assets`` (default False) that
  toggles binding on or off without touching the push schema,
* a *per-profile resolver instance* built once at loop entry,
* a *per-event splice* that stamps ``class_uid`` and
  ``device.uid`` / ``user.uid`` on the generated event before the
  detection-rule injection runs.

This file isolates the splice — the function called for every event
inside ``_push_loop``. Testing the splice independently lets us
cover all the corner cases (resolver None, kind=none, missing hit,
identity vs endpoint routing, idempotency on re-bind) without
spinning up a real push loop.

Contract enforced here:

* ``log_pusher.apply_asset_binding(event, source, resolver)`` returns
  the event UNCHANGED when the resolver is ``None`` (operator did
  not opt in) — the push profile keeps running without binding.
* When the source has ``kind="none"`` (Snyk / Tenable / Wiz), the
  splice is a no-op even with a resolver — explicit governance
  opt-out.
* When the binding succeeds, the event carries ``class_uid`` from
  the registry AND a uid field on the right side:
    - kind=endpoint/cloud/network → ``device.uid``
    - kind=identity               → ``user.uid``
* If the resolver returns ``None`` (empty inventory / 404 on
  identity / unconfigured), the event still ships but WITHOUT a
  uid field and WITHOUT class_uid — the push profile must never
  fall over because of asset binding.
* Operator-authored fields on the event win — if the source module
  already populated ``device.uid`` (a real scenario for the
  ``sentinelone`` self-source), the splice MUST NOT clobber it.
* Profile create / update accept the ``link_xdr_assets`` field and
  default it to False so existing profiles round-trip unchanged.
"""
from __future__ import annotations

from unittest.mock import MagicMock


# ── apply_asset_binding splice ─────────────────────────────────────


def test_apply_asset_binding_noop_when_resolver_is_none():
    """No opt-in ⇒ no resolver ⇒ event is returned unchanged. The
    push loop calls this for every event so the no-op path MUST be
    cheap and side-effect-free."""
    import log_pusher

    event = {"timestamp": "2026-06-25T10:00:00Z"}
    out = log_pusher.apply_asset_binding(event, "okta", resolver=None)
    assert out is event, "no-resolver path must return the same dict"
    assert "class_uid" not in event
    assert "user" not in event and "device" not in event


def test_apply_asset_binding_noop_when_source_kind_is_none():
    """Governance sources (Snyk / Tenable / Wiz) have kind='none' in
    the registry. Even with a resolver wired, the splice must skip
    them — those sources don't bind to assets at all."""
    import log_pusher

    resolver = MagicMock()
    event = {"x": 1}
    out = log_pusher.apply_asset_binding(event, "wiz", resolver=resolver)
    assert "class_uid" not in event
    # Resolver MUST NOT be touched for kind=none — saves an HTTP call.
    resolver.sticky_pick.assert_not_called()


def test_apply_asset_binding_endpoint_stamps_class_uid_and_device_uid():
    """Endpoint source (microsoft_defender) ⇒ class_uid 1007 + device.uid."""
    import log_pusher

    resolver = MagicMock()
    resolver.sticky_pick.return_value = {
        "uid": "xdr-abc-123",
        "hostname": "ALICE-LAPTOP-1",
        "agent_uuid": "aaaa1111",
    }
    event = {"_origin": "defender"}
    out = log_pusher.apply_asset_binding(event, "microsoft_defender",
                                          resolver=resolver)
    assert out is event  # mutate in place — caller already owns it
    assert event["class_uid"] == 1007
    assert event["device"]["uid"] == "xdr-abc-123"
    # Sticky pick was called for the right kind.
    resolver.sticky_pick.assert_called_once_with("endpoint")


def test_apply_asset_binding_identity_routes_to_user_uid():
    """Identity source (okta) ⇒ class_uid 3002 + user.uid (not device)."""
    import log_pusher

    resolver = MagicMock()
    resolver.sticky_pick.return_value = {
        "uid":          "id-bob-1",
        "upn":          "bob@acme.test",
        "display_name": "Bob",
        "domain":       "ACME",
    }
    event: dict = {}
    log_pusher.apply_asset_binding(event, "okta", resolver=resolver)
    assert event["class_uid"] == 3002
    assert event["user"]["uid"] == "id-bob-1"
    # Endpoint sub-tree must NOT be created on identity events.
    assert "device" not in event
    resolver.sticky_pick.assert_called_once_with("identity")


def test_apply_asset_binding_cloud_routes_to_device_uid():
    """Cloud sources (aws_cloudtrail) bind on device.uid per the v5.3
    plan — S1 catalogs the cloud asset under the inventory's device
    family so device.uid is the right target."""
    import log_pusher

    resolver = MagicMock()
    resolver.sticky_pick.return_value = {"uid": "xdr-cloud-1",
                                          "hostname": "i-0a1b2c3d",
                                          "agent_uuid": ""}
    event: dict = {}
    log_pusher.apply_asset_binding(event, "aws_cloudtrail",
                                    resolver=resolver)
    assert event["class_uid"] == 6003
    assert event["device"]["uid"] == "xdr-cloud-1"


def test_apply_asset_binding_resolver_miss_does_not_stamp():
    """Resolver returned ``None`` (empty tenant / 404 / unconfigured)
    ⇒ event ships unchanged. The push loop must never fail because
    of an empty inventory."""
    import log_pusher

    resolver = MagicMock()
    resolver.sticky_pick.return_value = None
    event: dict = {}
    log_pusher.apply_asset_binding(event, "okta", resolver=resolver)
    assert "class_uid" not in event
    assert "user" not in event and "device" not in event


def test_apply_asset_binding_does_not_overwrite_existing_uid():
    """If the source module pre-populated ``device.uid`` (e.g. the
    ``sentinelone`` self-source emits real agent UUIDs), the splice
    must preserve it — STAR rules might bind on the original value
    and stamping a random XDR id would break the demo story."""
    import log_pusher

    resolver = MagicMock()
    resolver.sticky_pick.return_value = {"uid": "xdr-RANDOM",
                                          "hostname": "h",
                                          "agent_uuid": ""}
    event = {"device": {"uid": "REAL-AGENT-UUID",
                         "hostname": "REAL-HOST"}}
    log_pusher.apply_asset_binding(event, "microsoft_defender",
                                    resolver=resolver)
    assert event["device"]["uid"] == "REAL-AGENT-UUID", (
        "existing device.uid must win over the random pick")
    # class_uid still gets stamped — the kind-correctness of the
    # event is independent of whose uid it was.
    assert event["class_uid"] == 1007


def test_apply_asset_binding_alias_source_resolves():
    """Push profile may store ``defender`` (UI alias) as source_type.
    The splice MUST resolve through the registry alias map — without
    this, alias-named profiles would silently skip binding."""
    import log_pusher

    resolver = MagicMock()
    resolver.sticky_pick.return_value = {"uid": "xdr-1",
                                          "hostname": "h",
                                          "agent_uuid": ""}
    event: dict = {}
    log_pusher.apply_asset_binding(event, "defender", resolver=resolver)
    # 'defender' alias → microsoft_defender → endpoint/1007.
    assert event["class_uid"] == 1007
    assert event["device"]["uid"] == "xdr-1"


# ── Profile schema accepts the flag ────────────────────────────────


def test_create_profile_accepts_link_xdr_assets_flag(tmp_path,
                                                      monkeypatch):
    """The push profile schema gains ``link_xdr_assets`` (default
    False). Existing profiles without this field round-trip
    unchanged — the default keeps binding off until the operator
    opts in."""
    import log_pusher

    p1 = log_pusher.create_profile(
        {"name": "no flag", "source_type": "okta",
         "destination": {"host": "x", "port": 1},
         "duration": {"value": 1, "unit": "minutes"}})
    try:
        assert p1.get("link_xdr_assets") is False, (
            "create_profile default must be False")
    finally:
        log_pusher.delete_profile(p1["id"])

    p2 = log_pusher.create_profile(
        {"name": "opt in", "source_type": "okta",
         "destination": {"host": "x", "port": 1},
         "duration": {"value": 1, "unit": "minutes"},
         "link_xdr_assets": True})
    try:
        assert p2.get("link_xdr_assets") is True, (
            "create_profile must honour an explicit True")
    finally:
        log_pusher.delete_profile(p2["id"])


def test_update_profile_can_toggle_link_xdr_assets():
    """Once the toggle is wired the operator can flip it on/off
    without recreating the profile."""
    import log_pusher

    p = log_pusher.create_profile(
        {"name": "toggle", "source_type": "okta",
         "destination": {"host": "x", "port": 1},
         "duration": {"value": 1, "unit": "minutes"}})
    try:
        u = log_pusher.update_profile(p["id"],
                                        {"link_xdr_assets": True})
        assert u["link_xdr_assets"] is True
        u = log_pusher.update_profile(p["id"],
                                        {"link_xdr_assets": False})
        assert u["link_xdr_assets"] is False
    finally:
        log_pusher.delete_profile(p["id"])
