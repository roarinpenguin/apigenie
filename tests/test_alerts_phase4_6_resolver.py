"""End-to-end tests for the resolver→alert injection wiring (v2.2).

Pins the contract between ``s1_assets.S1AssetResolver`` and
``alerts.prepare_alert``:

* ``resources[].uid`` carries the **XDR Asset ID** (alphanumeric) on a
  hit — that's UAM's binding key. The bind makes ``assets[].agentUuid``
  populated in the UAM view.
* ``device.uid`` (when the template has a device block) carries the
  **hex agent UUID** — display only.
* ``device.agent.uid`` carries the **numeric agent id** — cosmetic, for
  OCSF-feed consistency with real S1 EDR alerts.
* In v2 (default), the legacy auto-promote-to-top-level-device behaviour
  is OFF. The bound HELIOS reference proves resources-only is
  sufficient and a phantom ``device.uid`` could create a conflicting
  binding hint.
* User-typed resources are never agent-looked-up.
* Empty-name resources are never agent-looked-up.

The earlier ``s1_metadata`` / ``s1_detection_metadata`` injection
(experiment 2026-06-10) has been removed — those blocks are
UAM-post-ingest annotations on the bound alert, not inputs to binding.
"""
from __future__ import annotations

from typing import Any

import pytest

import alerts


# v2 is the production default; pin it via env so a regression in the
# default can't silently disable the v2-shape assertions.
@pytest.fixture(autouse=True)
def _force_v2_binding_shape(monkeypatch):
    monkeypatch.setenv("APIGENIE_UAM_BINDING_V2", "1")


# ── Helpers ──────────────────────────────────────────────────────────────────

class _StubResolver:
    """Minimal AssetResolverProto stub with a name -> hit dict."""

    def __init__(self, hits: dict[str, dict[str, Any]]) -> None:
        self._hits = {k.lower(): v for k, v in hits.items()}
        self.calls: list[str] = []

    def resolve_endpoint(self, name_hint: str) -> dict[str, Any] | None:
        self.calls.append(name_hint)
        return self._hits.get((name_hint or "").lower())


def _template(**extra: Any) -> dict[str, Any]:
    """A minimal OCSF-shaped template with device + resources."""
    base: dict[str, Any] = {
        "metadata": {"version": "1.0.0"},
        "time": "DYNAMIC",
        "finding_info": {"title": "Test", "uid": "placeholder_uid"},
        "device": {"name": "bridge"},
        "resources": [
            {"type": "Device", "name": "bridge"},
            {"type": "User",   "name": "jeanluc"},
        ],
    }
    base.update(extra)
    return base


def _hit(uuid: str, hostname: str = "USS-Bridge-Prod", **extra: Any) -> dict[str, Any]:
    """Shape of what ``S1AssetResolver.resolve_endpoint`` returns on a hit.

    The ``uuid`` param represents the hex agent UUID (kept as the named
    parameter to stay readable across the test file). The hit dict
    derives:

    * ``uid``        — XDR Asset ID (``"xdr-<uuid>"``) — the binding key
      that lands in ``resources[].uid``.
    * ``agent_uuid`` — the hex UUID itself — lands in ``device.uid``
      (display) and ``device.agent.uuid`` (cosmetic).
    * ``agent_id``   — numeric S1 agent id (``"agent-id-for-<uuid>"``)
      — lands in ``device.agent.uid`` (cosmetic).
    """
    base = {
        "uid": f"xdr-{uuid}",                       # XDR Asset ID (binding key)
        "agent_uuid": uuid,                         # hex UUID (device.uid)
        "agent_id": f"agent-id-for-{uuid}",         # numeric (device.agent.uid)
        "agent_version": "25.2.6.442",
        "machine_type": "server",
        "hostname": hostname,
        "ip": "10.42.0.7",
        "os_name": "Windows Server 2022",
        "os_type": "Windows",
        "os_type_id": 200,
        "domain": "enterprise.local",
        "category": "Server",
    }
    base.update(extra)
    return base


# ── Injection on hit ────────────────────────────────────────────────────────

class TestPrepareAlertWithResolver:
    def test_device_uid_is_hex_uuid_on_hit(self):
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        # device.uid is OCSF-documented as a hex UUID; cosmetic for binding.
        assert alert["device"]["uid"] == "uuid-bridge"

    def test_resources_device_uid_is_xdr_asset_id(self):
        """``resources[].uid`` MUST be the XDR Asset ID (alphanumeric) —
        the field UAM correlates on to bind the alert to an existing
        asset tile. Verified on ``usea1-purple`` 2026-06-10 by sending
        an alert with this exact shape and observing
        ``assets[].agentUuid`` populated in the UAM view."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        dev_resource = next(r for r in alert["resources"]
                            if r["type"].startswith(("Windows", "Linux", "Mac", "Device")))
        assert dev_resource["uid"] == "xdr-uuid-bridge"
        # device.uid is a different identifier space (hex UUID).
        assert alert["device"]["uid"] == "uuid-bridge"

    def test_user_resource_left_alone(self):
        """We deliberately do not touch user identities."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge"),
                                  "jeanluc": _hit("uuid-jeanluc")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        user_resource = next(r for r in alert["resources"] if r["type"] == "User")
        # Whatever the placeholder UID generator produced is fine — what
        # MUST NOT happen is the user's UID being set to an asset id.
        assert user_resource["uid"] != "xdr-uuid-jeanluc"
        assert user_resource["uid"] != "uuid-jeanluc"

    def test_resolver_only_called_for_device_entities(self):
        """User-type resources MUST NOT trigger a lookup."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alerts.prepare_alert(_template(), resolver=resolver)
        # device + resources[Device] both lookup 'bridge'; resources[User]
        # 'jeanluc' must not appear.
        assert "jeanluc" not in resolver.calls

    def test_resolver_called_for_device_shape_variants(self):
        """``resources[].type`` values like ``"Windows Server"`` /
        ``"Linux Workstation"`` / ``"Endpoint"`` MUST trigger an asset
        lookup — they're descriptive device variants, not separate kinds.
        """
        for type_label in ("Windows Server", "Linux Workstation",
                            "Endpoint", "Server", "Host", "macOS Laptop",
                            "Windows Desktop"):
            resolver = _StubResolver({"roarinsrv2022": _hit("uuid-roar")})
            tmpl: dict[str, Any] = {
                "metadata": {"version": "1.0.0"},
                "time": "DYNAMIC",
                "finding_info": {"title": "T", "uid": "placeholder_uid"},
                # No top-level device — exercise the resources-only path.
                "resources": [{"type": type_label, "name": "roarinsrv2022"}],
            }
            alert = alerts.prepare_alert(tmpl, resolver=resolver)
            assert resolver.calls == ["roarinsrv2022"], (
                f"type={type_label!r} should trigger a lookup but didn't "
                f"(calls={resolver.calls})"
            )
            # The hit's XDR Asset ID lands in resources[].uid.
            assert alert["resources"][0]["uid"] == "xdr-uuid-roar"
            # v2 does NOT auto-promote a top-level device block (resources-only
            # binding is the proven shape).
            assert "device" not in alert

    def test_resolver_not_called_for_non_device_explicit_types(self):
        """Explicit non-device OCSF types must be left untouched."""
        for type_label in ("File", "Process", "Network Activity", "URL",
                            "Email Message", "Folder", "Registry Key"):
            resolver = _StubResolver({"foo": _hit("uuid-foo")})
            tmpl: dict[str, Any] = {
                "metadata": {"version": "1.0.0"},
                "time": "DYNAMIC",
                "finding_info": {"title": "T", "uid": "placeholder_uid"},
                "resources": [{"type": type_label, "name": "foo"}],
            }
            alerts.prepare_alert(tmpl, resolver=resolver)
            assert resolver.calls == [], (
                f"type={type_label!r} should NOT trigger a lookup but did "
                f"(calls={resolver.calls})"
            )

    def test_enrichment_authority_swap_overwrites_name_and_hostname(self):
        """On a hit, the canonical asset name replaces whatever
        ``device.name`` / ``device.hostname`` the template carried.
        Other explicitly-set fields are honoured.
        """
        tmpl = _template()
        tmpl["device"] = {
            "name": "bridge",
            "hostname": "user-supplied-host",
            "ip": "192.0.2.99",
            "os": {"name": "Custom OS", "type": "custom", "type_id": 42},
        }
        resolver = _StubResolver({"bridge": _hit("uuid-bridge",
                                                  hostname="BRIDGE-CANONICAL")})
        alert = alerts.prepare_alert(tmpl, resolver=resolver)
        d = alert["device"]
        assert d["uid"] == "uuid-bridge"
        # Authority swap: canonical wins.
        assert d["name"] == "BRIDGE-CANONICAL"
        assert d["hostname"] == "BRIDGE-CANONICAL"
        # Non-name fields still respect the template's explicit choices.
        assert d["ip"] == "192.0.2.99"
        assert d["os"]["name"] == "Custom OS"
        assert d["os"]["type"] == "custom"
        assert d["os"]["type_id"] == 42

    def test_enrichment_fills_when_template_is_sparse(self):
        tmpl = _template()
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(tmpl, resolver=resolver)
        d = alert["device"]
        assert d["uid"] == "uuid-bridge"
        assert d["name"] == "USS-Bridge-Prod"        # canonical from hit
        assert d["hostname"] == "USS-Bridge-Prod"
        assert d["ip"] == "10.42.0.7"
        assert d["os"]["name"] == "Windows Server 2022"
        # OCSF-normalised OS fields: Pascal label + int enum.
        assert d["os"]["type"] == "Windows"
        assert d["os"]["type_id"] == 200
        assert d["domain"] == "enterprise.local"


# ── No-op cases ──────────────────────────────────────────────────────────────

class TestPrepareAlertResolverNoOps:
    def test_resolver_none_leaves_alert_unchanged_apart_from_uids(self):
        before_dev = dict(_template()["device"])
        alert = alerts.prepare_alert(_template())   # no resolver
        # device.uid is NOT touched by the auto-UID step (only resources[]).
        assert "uid" not in alert["device"]
        assert alert["device"]["name"] == before_dev["name"]

    def test_miss_leaves_device_uid_unset(self):
        resolver = _StubResolver({})   # nothing matches
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        assert "uid" not in alert["device"]

    def test_user_supplied_device_uid_is_preserved(self):
        """An override that pre-sets ``device.uid`` must beat the resolver."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(
            _template(),
            overrides={"device.uid": "manual-override"},
            resolver=resolver,
        )
        assert alert["device"]["uid"] == "manual-override"

    def test_no_device_section_does_not_call_resolver(self):
        tmpl = {"finding_info": {"uid": "placeholder_uid"}, "resources": []}
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alerts.prepare_alert(tmpl, resolver=resolver)
        assert resolver.calls == []


# ── Batch behaviour (cache hits on identical names) ──────────────────────────

class TestBatchCachingBehaviour:
    def test_send_n_with_same_name_uses_resolver_cache(self):
        """The resolver's cache means 1 ``/xdr/assets`` fetch per batch
        even when we call ``prepare_alert`` N times. We exercise the
        alerts side here — the cache itself is covered in
        ``test_s1_assets.py``.
        """
        import httpx

        from s1_assets import S1AssetResolver

        # Shape of /xdr/assets response: one record with an agent
        # sub-block, name matches the template's `bridge` resource.
        assets_returned: list[dict[str, Any]] = [
            {
                "id": "xdr-uuid-bridge",
                "name": "bridge",
                "category": "Server",
                "agent": {
                    "id": "agent-id-for-uuid-bridge",
                    "uuid": "uuid-bridge",
                    "computerName": "bridge",
                    "osName": "Linux",
                    "osType": "linux",
                    "lastReportedIp": "10.0.0.1",
                    "externalIp": "203.0.113.1",
                    "domain": "x.y",
                },
            }
        ]
        call_count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(200, json={"data": assets_returned,
                                              "pagination": {}})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        resolver = S1AssetResolver("https://x", "tok", client=client,
                                   account_id="acct")
        try:
            for _ in range(5):
                alerts.prepare_alert(_template(), resolver=resolver)
        finally:
            resolver.close()

        # Same name across 5 prep calls → exactly 1 API call.
        assert call_count["n"] == 1


# ── Heuristic typing (no top-level device promotion in v2) ──────────────────

class TestHeuristicTypingNoPromotion:
    """Heuristic-typing covers templates whose ``resources[0]`` carries a
    name but no explicit ``type``. Without the heuristic the resolver
    would skip them entirely and UAM would mint phantom "Unknown Device"
    tiles. v2 explicitly does NOT auto-promote a top-level device block
    when one is missing — that was the legacy behaviour and the bound-
    alert reference proves it's unnecessary.
    """

    def _typeless(self, name: str) -> dict[str, Any]:
        return {
            "metadata": {"version": "1.0.0"},
            "finding_info": {"title": "Phishing", "uid": "placeholder_uid"},
            "resources": [{"uid": "DYNAMIC_RESOURCE_UID", "name": name}],
        }

    def test_email_name_materialised_as_user(self):
        """A name with ``@`` and no explicit type is tagged ``User`` so
        UAM doesn't auto-classify it as a device. No lookup is made."""
        resolver = _StubResolver({"jeanluc@starfleet.com": _hit("uuid-X")})
        alert = alerts.prepare_alert(self._typeless("jeanluc@starfleet.com"),
                                     resolver=resolver)
        r0 = alert["resources"][0]
        assert r0["type"] == "User"
        assert resolver.calls == []
        # No top-level device promotion.
        assert "device" not in alert

    def test_hostname_shape_attempted_as_device(self):
        """A name with no ``@`` is treated as a Device candidate. On a hit
        the resource's ``uid`` becomes the **XDR Asset ID** and ``type``
        becomes the descriptive form."""
        resolver = _StubResolver({"webby": _hit("uuid-webby")})
        alert = alerts.prepare_alert(self._typeless("webby"), resolver=resolver)
        r0 = alert["resources"][0]
        assert r0["uid"] == "xdr-uuid-webby"
        assert r0["type"] == "Windows server"
        assert resolver.calls == ["webby"]
        # v2: no auto-promote.
        assert "device" not in alert

    def test_device_miss_does_not_materialise_type(self):
        """If the lookup misses we MUST NOT tag the resource as Device —
        UAM would mint an Unknown Device tile (the failure mode we're
        trying to avoid)."""
        resolver = _StubResolver({})
        alert = alerts.prepare_alert(self._typeless("ghost-host"),
                                     resolver=resolver)
        r0 = alert["resources"][0]
        assert "type" not in r0
        assert resolver.calls == ["ghost-host"]

    def test_explicit_type_beats_heuristic_then_resolver_upgrades(self):
        """If the template author set ``type=Device`` explicitly we bypass
        the @-shape heuristic and DO run an asset lookup. On a hit the
        resolver upgrades the generic ``Device`` type to the descriptive
        \"{Os} {machine_type}\" form."""
        resolver = _StubResolver({"jeanluc@starfleet.com": _hit("uuid-X")})
        tmpl = self._typeless("jeanluc@starfleet.com")
        tmpl["resources"][0]["type"] = "Device"   # paradoxical but explicit
        alert = alerts.prepare_alert(tmpl, resolver=resolver)
        assert resolver.calls == ["jeanluc@starfleet.com"]
        assert alert["resources"][0]["type"] == "Windows server"

    def test_no_top_level_device_promoted_in_v2_on_resources_hit(self):
        """v2 explicitly suppresses the legacy top-level device promotion
        even when the template has no ``device`` and a resources entry
        hits. The bound HELIOS reference proves resources-only binding
        is sufficient."""
        resolver = _StubResolver({"webby": _hit("uuid-webby",
                                                hostname="WEBBY-01",
                                                ip="10.0.0.1")})
        alert = alerts.prepare_alert(self._typeless("webby"), resolver=resolver)
        # resources[0] still gets the XDR Asset ID + descriptive type.
        assert alert["resources"][0]["uid"] == "xdr-uuid-webby"
        # But NO synthesised top-level device.
        assert "device" not in alert

    def test_existing_top_level_device_is_resolved_in_place(self):
        """If the template already provides a ``device`` block, the
        resolver fills it in place (display fields only — binding
        happens via ``resources[].uid``)."""
        resolver = _StubResolver({"webby": _hit("uuid-webby")})
        tmpl = {
            "metadata": {"version": "1.0.0"},
            "finding_info": {"title": "T", "uid": "placeholder_uid"},
            "device": {"name": "bridge"},   # different hint than resources[0]
            "resources": [{"name": "webby"}],
        }
        # bridge isn't in the stub, so top-level device stays UID-less but
        # remains the canonical device. resources[0] still gets resolved.
        alert = alerts.prepare_alert(tmpl, resolver=resolver)
        assert "uid" not in alert["device"]
        assert alert["device"]["name"] == "bridge"
        # resources[].uid is the XDR Asset ID.
        assert alert["resources"][0]["uid"] == "xdr-uuid-webby"

    def test_proofpoint_jeanluc_endtoend_shape(self):
        """The Proofpoint template layout that produced the original
        Unknown Device screenshot. The user-shaped resource is tagged
        User and no device promotion occurs."""
        resolver = _StubResolver({})
        tmpl = {
            "finding_info": {"title": "Proofpoint Phishing Email Link Clicked",
                             "uid": "placeholder_uid"},
            "resources": [{"uid": "DYNAMIC_RESOURCE_UID",
                           "name": "jeanluc@starfleet.com"}],
            "severity_id": 4,
        }
        alert = alerts.prepare_alert(tmpl, resolver=resolver)
        r0 = alert["resources"][0]
        assert r0["type"] == "User"
        assert resolver.calls == []
        assert "device" not in alert
        # Resources UID is still filled (UUID4 fallback so UAM gets a value).
        assert r0["uid"] not in alerts._PLACEHOLDER_UIDS
        assert r0["uid"] != "DYNAMIC_RESOURCE_UID"


def test_override_renames_device_then_resolver_uses_new_name():
    """Step ordering: overrides apply BEFORE the resolver, so an override
    that changes ``device.name`` directs the *top-level* lookup at the
    new value."""
    resolver = _StubResolver({
        "enterprise": _hit("uuid-enterprise", hostname="USS-Enterprise"),
        "bridge":     _hit("uuid-bridge"),
    })
    alert = alerts.prepare_alert(
        _template(),  # default device.name == "bridge"
        overrides={"device.name": "enterprise"},
        resolver=resolver,
    )
    assert alert["device"]["uid"] == "uuid-enterprise"
    assert "enterprise" in resolver.calls


# ── UAM-binding shape regression (v2.2) ──────────────────────────────────────
#
# Locks in the exact shape that produces a bound alert in UAM (verified
# 2026-06-10 on usea1-purple by replicating the HELIOS recipe):
#   * resources[].uid  = XDR Asset ID (alphanumeric)
#   * resources[].name = canonical asset name
#   * resources[].type = "{Os} {machine_type}" descriptive label
#   * device.uid       = hex agent UUID (display)
#   * device.agent.*   = cosmetic OCSF-feed mirror of agent fields
#   * NO s1_metadata / s1_detection_metadata blocks (those were UAM
#     post-ingest annotations on the bound reference; sending them
#     does not affect binding either way).

class TestUAMBindingShape:
    def test_resources_uid_is_xdr_asset_id_not_hex_uuid_or_agent_id(self):
        """The critical regression-guard for this whole effort."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        dev_resource = next(r for r in alert["resources"]
                            if r.get("type", "").startswith(("Windows", "Linux", "Mac")))
        # The XDR Asset ID.
        assert dev_resource["uid"] == "xdr-uuid-bridge"
        # MUST NOT be the hex UUID (original P4.6 bug).
        assert dev_resource["uid"] != "uuid-bridge"
        # MUST NOT be the numeric agent id (intermediate v2.1 bug).
        assert dev_resource["uid"] != "agent-id-for-uuid-bridge"

    def test_resources_type_is_descriptive(self):
        """``resources[].type`` is ``"{Os} {machine_type}"`` form."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        dev_resource = next(r for r in alert["resources"]
                            if r.get("uid") == "xdr-uuid-bridge")
        assert dev_resource["type"] == "Windows server"

    def test_resources_type_falls_back_to_os_when_machine_type_missing(self):
        resolver = _StubResolver({"bridge": _hit("uuid-bridge", machine_type="")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        dev_resource = next(r for r in alert["resources"]
                            if r.get("uid") == "xdr-uuid-bridge")
        assert dev_resource["type"] == "Windows"

    def test_no_s1_metadata_block_on_resources(self):
        """The earlier ``s1_metadata`` injection has been removed —
        verified to not be required for binding. Make sure we don't
        accidentally re-introduce it."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        for r in alert["resources"]:
            assert "s1_metadata" not in r

    def test_no_s1_detection_metadata_at_top_level(self):
        """Same: top-level ``s1_detection_metadata`` is gone for good."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        assert "s1_detection_metadata" not in alert

    def test_device_agent_block_is_populated_on_hit_for_existing_device(self):
        """When a template has a ``device`` block, the agent sub-block
        is filled with the numeric S1 id (cosmetic, for OCSF-feed
        consistency with real EDR alerts). UAM doesn't read it for
        binding, but real alerts ship with it."""
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        agent = alert["device"].get("agent")
        assert isinstance(agent, dict)
        # Numeric agent id (cosmetic).
        assert agent["uid"] == "agent-id-for-uuid-bridge"
        # Hex UUID mirror of device.uid.
        assert agent["uuid"] == "uuid-bridge"
        assert alert["device"]["uid"] == "uuid-bridge"
        assert agent.get("version") == "25.2.6.442"

    def test_device_type_id_defaults_to_other_when_unset(self):
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        assert alert["device"]["type_id"] == 99

    def test_device_type_id_respects_explicit_template_value(self):
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        tmpl = _template()
        tmpl["device"]["type_id"] = 5      # OCSF "Mobile"
        alert = alerts.prepare_alert(tmpl, resolver=resolver)
        assert alert["device"]["type_id"] == 5


# ── Legacy / v2-off mode ─────────────────────────────────────────────────────

class TestLegacyV2OffMode:
    """When ``APIGENIE_UAM_BINDING_V2=0`` is set (diagnostic fallback),
    the resolver injection reverts to the pre-binding hex-UUID shape:
    ``resources[].uid`` is the hex UUID, no agent block, and legacy
    top-level device promotion kicks in when the template lacks one.
    """

    @pytest.fixture(autouse=True)
    def _force_v2_off(self, monkeypatch):
        monkeypatch.setenv("APIGENIE_UAM_BINDING_V2", "0")

    def test_resources_uid_is_hex_uuid_in_legacy(self):
        resolver = _StubResolver({"bridge": _hit("uuid-bridge")})
        alert = alerts.prepare_alert(_template(), resolver=resolver)
        dev_resource = next(r for r in alert["resources"]
                            if r["type"] == "Device")
        assert dev_resource["uid"] == "uuid-bridge"

    def test_legacy_promotes_top_level_device(self):
        """Legacy mode keeps the old auto-promote behaviour for
        templates without a ``device`` block."""
        tmpl = {
            "metadata": {"version": "1.0.0"},
            "finding_info": {"title": "T", "uid": "placeholder_uid"},
            "resources": [{"type": "Device", "name": "webby"}],
        }
        resolver = _StubResolver({"webby": _hit("uuid-webby")})
        alert = alerts.prepare_alert(tmpl, resolver=resolver)
        assert alert.get("device", {}).get("uid") == "uuid-webby"
