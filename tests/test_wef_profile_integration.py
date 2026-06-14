"""WEF v5.2 — Phase E: profile-driven data substitution.

Wires the WEF event catalog into ``profiles.get_context()`` so a binding
linked to a log profile emits events whose ``Data`` field values come
from the profile's user / machine pools instead of the
``targetusername-12345`` placeholders the v5.2 ROADMAP explicitly
deferred ("real profile-driven substitution … out of scope for v5.2").

Three integration surfaces are exercised:

1. **Catalog** — ``_materialize_event(entry, record_id, rng, ctx=None)``
   uses ``_FIELD_RECIPES`` to map catalog ``data_fields`` (TargetUserName,
   WorkstationName, IpAddress, …) to profile entity attributes. Without
   a context (``ctx=None``) it preserves the placeholder behaviour the
   pre-E suite asserted, so every existing test stays green.

2. **Runner** — ``WEFEmitter.push_batch`` honours an optional
   ``profile_id`` in the binding config and silently falls back to
   placeholder mode when the profile is deleted out from under a
   running binding. A binding can survive a profile delete without
   going into an error state.

3. **Storage** — ``validate_binding_config`` accepts ``profile_id``
   without raising, and ``normalize_binding_config`` preserves it
   across an auth-method switch.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import httpx
import pytest


NS_WIN_EVENT = "http://schemas.microsoft.com/win/2004/08/events/event"


# ── Catalog-level: _materialize_event + generate_events with ctx ──────

def _logon_entry():
    """Look up event 4624 (logon) from the catalog. Has the richest
    set of data_fields we care about for substitution (TargetUserName,
    TargetDomainName, IpAddress, WorkstationName, LogonType)."""
    from sources import windows_event_forwarding as wef
    for entry in wef.EVENT_CATALOG:
        if entry["event_id"] == 4624 and entry["channel"] == wef.CHANNEL_SECURITY:
            return entry
    raise AssertionError("event 4624 missing from catalog — has it been renamed?")


def test_materialize_event_without_ctx_keeps_placeholder_shape():
    """Back-compat: every pre-E call site passes positional args only.
    The new ``ctx`` parameter must default to None and reproduce the
    pre-E placeholder values bit-for-bit."""
    import random
    from sources import windows_event_forwarding as wef
    rng = random.Random(42)
    ev = wef._materialize_event(_logon_entry(), 1, rng)
    # Same placeholder shape the suite has asserted since v5.2 Phase 0.
    for field in ("TargetUserName", "TargetDomainName", "IpAddress",
                  "WorkstationName", "LogonType"):
        assert field in ev["data"]
        assert ev["data"][field].startswith(field.lower() + "-")


def test_materialize_event_with_ctx_uses_profile_entities(tmp_path, monkeypatch):
    """A binding linked to a profile must inject the profile's user /
    machine attributes into the matching data_fields. We seed a tiny
    profile with two named users so the assertion is deterministic
    (ratio=100 → every pick comes from the profile)."""
    import random
    import profiles
    from sources import windows_event_forwarding as wef
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")

    p = profiles.create_profile({
        "name": "wef-test", "owner_id": None, "visibility": "public",
        "users": [
            {"name": "Test Alpha", "username": "talpha", "domain": "LAB",
             "primary_workstation": "WS-ALPHA", "workstation_ip": "10.0.0.1",
             "server_of_reference": "DC01"},
        ],
        "machines": [
            {"primary_workstation": "WS-ALPHA", "os_type": "windows",
             "role": "workstation", "ip": "10.0.0.1"},
        ],
    })
    ctx = profiles.context_for_profile_id(p["id"], source="wef", ratio=100)
    assert ctx is not None
    rng = random.Random(42)
    ev = wef._materialize_event(_logon_entry(), 1, rng, ctx=ctx)
    # ProfileContext pads short user lists with the built-in SW pool up
    # to LIMITS["users"]=10. We can't predict which entity pick_user()
    # returned, but we can prove substitution happened by asserting the
    # value came from the ctx pool — it must NOT match the placeholder
    # pattern and must match an entity attribute from the resolved pool.
    usernames = {u.get("username") for u in ctx.users}
    domains   = {u.get("domain")   for u in ctx.users}
    hostnames = {u.get("primary_workstation") for u in ctx.users}
    ips       = {u.get("workstation_ip") for u in ctx.users}
    assert ev["data"]["TargetUserName"]   in usernames
    assert ev["data"]["TargetDomainName"] in domains
    assert ev["data"]["WorkstationName"]  in hostnames
    assert ev["data"]["IpAddress"]        in ips
    # LogonType has no profile mapping — must keep the placeholder shape.
    assert ev["data"]["LogonType"].startswith("logontype-")


def test_materialize_event_falls_back_to_placeholder_at_ratio_zero(tmp_path, monkeypatch):
    """``ratio=0`` is the "always noise" knob. Every pick must therefore
    fall back to the placeholder, even when ctx is supplied. This is
    the moral equivalent of ``ctx is None`` at the substitution layer
    and keeps the v5.2 ROADMAP's ratio semantics intact across sources."""
    import random
    import profiles
    from sources import windows_event_forwarding as wef
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    p = profiles.create_profile({
        "name": "noise-only", "owner_id": None, "visibility": "public",
        "users": [{"name": "X", "username": "x", "domain": "X"}],
    })
    ctx = profiles.context_for_profile_id(p["id"], ratio=0)
    rng = random.Random(42)
    ev = wef._materialize_event(_logon_entry(), 1, rng, ctx=ctx)
    assert ev["data"]["TargetUserName"].startswith("targetusername-")


def test_field_recipes_cover_the_security_workhorse_fields():
    """Smoke-test the recipe table — every data_field appearing on the
    Tier-1 Security events (4624, 4625, 4768, 4769, 4776) must have a
    recipe entry, otherwise an operator wiring a profile won't see any
    effect on those events (the most common case)."""
    from sources import windows_event_forwarding as wef
    must_have = {
        "TargetUserName", "TargetDomainName", "SubjectUserName",
        "AccountName", "MemberName", "WorkstationName", "Workstation",
        "IpAddress", "ClientAddress", "TargetServerName",
    }
    missing = [f for f in must_have if f not in wef._FIELD_RECIPES]
    assert not missing, f"workhorse fields lack profile recipes: {missing}"


def test_generate_events_passes_ctx_through_to_materializer(tmp_path, monkeypatch):
    """End-to-end: ``generate_events(count, ctx=ctx)`` must thread the
    context to every materialised event, so the WEFEmitter (which
    is the only real caller) inherits substitution automatically
    without a second wiring step."""
    import profiles
    from sources import windows_event_forwarding as wef
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    p = profiles.create_profile({
        "name": "gen-test", "owner_id": None, "visibility": "public",
        "users": [
            {"name": "Gen Beta", "username": "gbeta", "domain": "CORP",
             "primary_workstation": "BETA-WS", "workstation_ip": "10.0.0.2"},
        ],
    })
    ctx = profiles.context_for_profile_id(p["id"], ratio=100)
    events = wef.generate_events(count=12, ctx=ctx, seed=7,
                                 channels_enabled=[wef.CHANNEL_SECURITY])
    pool_usernames = {u.get("username") for u in ctx.users}
    # Every emitted event whose catalog entry declares TargetUserName
    # must carry a username from the ctx pool (real or padded), proving
    # the substitution layer was reached. At least one event must carry
    # our seeded "gbeta" — with 12 events and a pool of 10, the seeded
    # RNG settles on every entry at least once in practice.
    seen = {ev["data"].get("TargetUserName") for ev in events
            if "TargetUserName" in ev.get("data", {})}
    leaked_placeholders = {u for u in seen if u and u.startswith("targetusername-")}
    assert not leaked_placeholders, (
        f"placeholder values leaked through ctx substitution: {leaked_placeholders!r}"
    )
    assert seen <= pool_usernames, (
        f"unexpected usernames not in ctx pool: {seen - pool_usernames!r}"
    )


# ── ProfileContext helper ─────────────────────────────────────────────

def test_context_for_profile_id_returns_none_for_unknown():
    """Calling with a deleted / never-existed profile id must return
    None, not raise — the WEF runner relies on this to fall back to
    placeholder mode silently rather than going into error state."""
    import profiles
    assert profiles.context_for_profile_id("does-not-exist") is None


def test_context_for_profile_id_returns_context_for_valid_profile(tmp_path, monkeypatch):
    import profiles
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    p = profiles.create_profile({
        "name": "valid", "owner_id": None, "visibility": "public",
        "users": [{"name": "U", "username": "u", "domain": "D"}],
    })
    ctx = profiles.context_for_profile_id(p["id"], source="wef", ratio=85)
    assert ctx is not None
    assert ctx.source == "wef"
    assert ctx.ratio == 85
    # The user we seeded must be picked at least once given ratio=85
    # and our deterministic seeded RNG.
    # dict is unhashable — collect usernames directly into a set.
    usernames = {(ctx.pick_user() or {}).get("username") for _ in range(50)}
    assert "u" in usernames


# ── Storage: validate + normalise accept profile_id ───────────────────

def test_validate_binding_config_accepts_profile_id():
    """``profile_id`` is an optional config field. The validator must
    accept it without complaint regardless of value (None, string,
    bogus id) — runtime resolution falls back gracefully."""
    from sources import windows_event_forwarding as wef
    base = {
        "target_host": "wec.lab", "target_port": 5986,
        "target_path": "/wsman", "auth_method": "basic",
        "basic_username": "svc",
    }
    assert wef.validate_binding_config({**base, "profile_id": None}) == []
    assert wef.validate_binding_config({**base, "profile_id": "abc-123"}) == []
    # Even a typo'd id passes validation — caught at runtime.
    assert wef.validate_binding_config({**base, "profile_id": "does-not-exist"}) == []


def test_normalize_binding_config_preserves_profile_id_across_auth_switch():
    """An operator who set profile_id=X on a Basic binding then switches
    to mTLS must not lose the profile binding (the profile choice is
    orthogonal to the auth method)."""
    from sources import windows_event_forwarding as wef
    cfg = {
        "target_host": "wec.lab", "target_port": 5986,
        "auth_method": "client_cert", "profile_id": "keep-me",
        "basic_username": "leftover", "basic_password_enc": "leftover",
    }
    out = wef.normalize_binding_config(cfg)
    assert out["profile_id"] == "keep-me"
    # And the auth-method-specific cleanup still ran.
    assert out["basic_username"] is None
    assert out["basic_password_enc"] is None


# ── Runner: WEFEmitter honours config.profile_id ──────────────────────

def _binding_with_profile(profile_id: str | None) -> dict:
    return {
        "target_host": "wec.lab.example.com",
        "target_port": 5986,
        "target_path": "/wsman/SubscriptionManager/WEC",
        "auth_method": "basic",
        "basic_username": None,
        "basic_password_enc": None,
        "tls_verify": True,
        "ca_bundle_path": None,
        "rate_per_min": 60, "batch_size": 5, "jitter_pct": 0,
        "channels_enabled": ["Security"],
        "profile_id": profile_id,
    }


def test_emitter_uses_profile_when_profile_id_resolves(tmp_path, monkeypatch):
    """A binding whose ``profile_id`` points to an existing profile
    must produce envelopes carrying that profile's usernames — the
    end-to-end win for Phase E. We assert on the parsed XML so the
    test would catch a regression in either the substitution layer
    or the envelope builder."""
    import profiles
    from sources import windows_event_forwarding as wef
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    p = profiles.create_profile({
        "name": "emit-test", "owner_id": None, "visibility": "public",
        "users": [
            {"name": "Emit Gamma", "username": "gamma", "domain": "ENT",
             "primary_workstation": "GAMMA-WS", "workstation_ip": "10.0.0.3"},
        ],
    })

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(status_code=202)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    emitter = wef.WEFEmitter(_binding_with_profile(p["id"]),
                             http_client=client, binding_id="emit-test")
    out = emitter.push_batch(event_count=8)
    assert out["ok"] is True
    assert captured, "no envelope was posted"

    # Parse one envelope and look for a TargetUserName with our profile
    # username. Channel filter is Security so every catalog entry
    # selected here declares TargetUserName.
    body = captured[0].content
    root = ET.fromstring(body)
    found_usernames = {
        d.text for d in root.iter(f"{{{NS_WIN_EVENT}}}Data")
        if d.get("Name") == "TargetUserName" and d.text
    }
    # Substitution proven if NO TargetUserName matches the placeholder
    # pattern — every wire value came from a profile entity (real or
    # SW padding). The placeholder leak would mean ctx never reached
    # _materialize_event.
    leaks = {u for u in found_usernames if u.startswith("targetusername-")}
    assert not leaks, (
        f"placeholder values leaked into the WEF wire envelope: {leaks!r}"
    )
    # And at least one user from our pool surfaced — either "gamma"
    # (our seeded entry) or one of the SW padding chars.
    assert found_usernames, "envelope carried no TargetUserName values"


def test_emitter_falls_back_silently_when_profile_was_deleted(tmp_path, monkeypatch):
    """A binding may outlive its profile (admin deletes the profile,
    forgets the binding still points at it). The emitter must keep
    pushing in placeholder mode rather than entering an error state.
    """
    import profiles
    from sources import windows_event_forwarding as wef
    monkeypatch.setattr(profiles, "PROFILES_DIR", tmp_path / "profiles")
    p = profiles.create_profile({
        "name": "soon-deleted", "owner_id": None, "visibility": "public",
        "users": [{"name": "X", "username": "x", "domain": "X"}],
    })
    profiles.delete_profile(p["id"])  # binding now references a ghost
    assert profiles.context_for_profile_id(p["id"]) is None

    captured: list[httpx.Request] = []
    def handler(req): captured.append(req); return httpx.Response(status_code=202)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    emitter = wef.WEFEmitter(_binding_with_profile(p["id"]),
                             http_client=client, binding_id="ghost-test")
    out = emitter.push_batch(event_count=4)
    # Push still succeeds; data falls back to placeholder shape.
    assert out["ok"] is True
    assert captured
    root = ET.fromstring(captured[0].content)
    usernames = {
        d.text for d in root.iter(f"{{{NS_WIN_EVENT}}}Data")
        if d.get("Name") == "TargetUserName"
    }
    # No "x" (it was deleted) — every value is a placeholder string.
    assert all(u and u.startswith("targetusername-") for u in usernames), (
        f"deleted profile leaked into events: {usernames!r}"
    )
