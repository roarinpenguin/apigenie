"""Tests for S1AssetResolver random-pick API (v5.3 Step 2, Phase 2).

The push loop binds events to real S1 assets to make STAR / Custom
Detection rules fire on the analyst's tenant instead of on "Unknown
Device". Unlike the alert-send path (which has a hostname hint to
match), the push loop is shoveling synthetic noise — there's no
name to look up. We just want each event to LAND on a real asset.

Three new methods on the resolver:

* ``random_endpoint()`` — pick a random managed agent. Bias toward
  recently-active agents so events bind to assets that are actually
  alive in the tenant (analyst dashboards won't suddenly show a
  decommissioned laptop coming back from the dead).
* ``random_identity()`` — pick a random AD identity from
  ``/web/api/v2.1/active-directory/accounts``. Returns ``None`` and
  caches the miss (so the push loop fails-open and doesn't slam the
  API every event) when:
    - the endpoint 404s (POC tenant during v2.2 work),
    - the resolver is unconfigured,
    - the response carries 0 accounts.
* ``sticky_pick(kind, ratio=0.8)`` — sticky-with-jitter picker.
  Operator confirmed 2026-06-25: ``ratio`` of events stick to the
  session's primary asset, ``(1 - ratio)`` re-roll for a different
  asset (lateral-movement-realistic).

The hit shape mirrors ``resolve_endpoint``'s for the endpoint case
(uid, hostname, agent_uuid, ...) plus a new identity hit shape
(``uid``, ``upn``, ``display_name``, ``domain``) so the push-loop
caller can plug the value into ``user.uid`` / ``user.name`` without
branching on which method produced it.
"""
from __future__ import annotations

import json

import httpx

import s1_assets


# ── Test fixtures ───────────────────────────────────────────────────


def _mk_resolver(handler):
    """Helper to build a resolver pinned to a mock transport. Mirrors
    the pattern used by ``tests/test_s1_assets.py``."""
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    return s1_assets.S1AssetResolver(
        console_url="https://example.test",
        api_token="t",
        account_id="acc-1",
        client=client,
    )


# Sample XDR assets list shaped like ``/web/api/v2.1/xdr/assets``.
_FAKE_ASSETS = [
    {
        # Recently active — should be preferred by random pick.
        "id":   "xdr-active-1",
        "name": "ALICE-LAPTOP-1",
        "category": "Workstation",
        "agent": {
            "uuid": "aaaa1111",
            "id":   "11111111",
            "lastActiveAt":  "2026-06-25T10:00:00Z",
            "lastReportedIp": "10.0.0.5",
            "osName": "Windows 11", "osType": "windows",
            "agentVersion": "23.4.1",
            "machineType":  "laptop",
            "computerName": "ALICE-LAPTOP-1",
            "domain": "ACME",
        },
    },
    {
        # Stale (last active months ago) — should be deprioritised.
        "id":   "xdr-stale-1",
        "name": "OLD-SRV-2019",
        "category": "Server",
        "agent": {
            "uuid": "bbbb2222",
            "id":   "22222222",
            "lastActiveAt": "2024-01-01T00:00:00Z",
            "lastReportedIp": "10.0.0.99",
            "osName": "Windows Server 2019", "osType": "windows",
            "agentVersion": "23.4.1",
            "machineType":  "server",
            "computerName": "OLD-SRV-2019",
            "domain": "ACME",
        },
    },
    {
        # No agent — passive discovery record. Must be skipped by
        # random_endpoint just like resolve_endpoint already does.
        "id":   "xdr-passive-1",
        "name": "s3-bucket-finance",
        "agent": None,
    },
]


# ── random_endpoint ────────────────────────────────────────────────


def test_random_endpoint_returns_managed_agent_hit_shape():
    """A populated XDR assets list yields a hit shape compatible with
    the existing ``resolve_endpoint`` output: same keys, same types,
    a real ``uid`` (the XDR Asset ID, not the agent uuid)."""
    def handler(req):
        return httpx.Response(200, json={"data": _FAKE_ASSETS,
                                          "pagination": {}})
    with _mk_resolver(handler) as r:
        hit = r.random_endpoint()
        assert hit is not None
        # Same key set as resolve_endpoint — the push loop must be
        # able to consume either method's output the same way.
        for key in ("uid", "hostname", "agent_uuid",
                    "os_name", "category"):
            assert key in hit, f"random_endpoint hit missing {key!r}"
        # Picked asset must be managed (passive records skipped).
        assert hit["uid"] in {"xdr-active-1", "xdr-stale-1"}
        assert hit["agent_uuid"], "managed agent must carry an agent_uuid"


def test_random_endpoint_skips_passive_discovery_records():
    """Inventory records without an ``agent`` sub-block (S3 buckets,
    ECR repos, …) must NEVER be picked — UAM won't bind alerts to
    them and the event would land as "Unknown Device"."""
    only_passive = [{"id": "xdr-passive-only", "name": "s3-x",
                     "agent": None}]
    def handler(req):
        return httpx.Response(200, json={"data": only_passive,
                                          "pagination": {}})
    with _mk_resolver(handler) as r:
        assert r.random_endpoint() is None


def test_random_endpoint_returns_none_when_unconfigured():
    """Resolver with no console / token / account id MUST fail-open
    and return None — same contract as ``resolve_endpoint``."""
    r = s1_assets.S1AssetResolver(console_url="", api_token="",
                                   account_id="")
    try:
        assert r.random_endpoint() is None
    finally:
        r.close()


def test_random_endpoint_returns_none_on_empty_inventory():
    """A reachable tenant with zero managed agents is a legitimate
    POC state — return None rather than raising."""
    def handler(req):
        return httpx.Response(200, json={"data": [], "pagination": {}})
    with _mk_resolver(handler) as r:
        assert r.random_endpoint() is None


def test_random_endpoint_prefers_recently_active_agents():
    """Bias the pick toward recently-active agents so demos don't
    revive months-old hosts. The active asset must win the majority
    of 200 trials over the stale one — exact ratio doesn't matter
    as long as the recent one is clearly preferred."""
    def handler(req):
        return httpx.Response(200, json={"data": _FAKE_ASSETS,
                                          "pagination": {}})
    with _mk_resolver(handler) as r:
        picks = [r.random_endpoint()["uid"] for _ in range(200)]
        active = picks.count("xdr-active-1")
        stale  = picks.count("xdr-stale-1")
        # Bias must be strict but not deterministic — allow a 60/40
        # split as the lower bound to keep this test stable.
        assert active > stale, (
            f"recent should beat stale, got active={active} stale={stale}")
        assert active >= 120, (
            f"expected >=60% on recent agent, got active={active}/200")


# ── random_identity ────────────────────────────────────────────────


def test_random_identity_returns_hit_shape():
    """The identity endpoint shape matches what the push loop needs
    to fill ``user.uid`` (S1 unified id), ``user.name`` (UPN), and
    ``user.domain``. Test fixture mirrors a subset of the
    ``/active-directory/accounts`` payload."""
    accounts = {"data": [
        {"id": "id-alice", "userPrincipalName": "alice@acme.test",
         "displayName": "Alice Apple", "domain": "ACME"},
        {"id": "id-bob",   "userPrincipalName": "bob@acme.test",
         "displayName": "Bob Banana", "domain": "ACME"},
    ], "pagination": {}}

    def handler(req):
        if "/active-directory/accounts" in str(req.url):
            return httpx.Response(200, json=accounts)
        return httpx.Response(404, json={"errors": ["not used"]})

    with _mk_resolver(handler) as r:
        hit = r.random_identity()
        assert hit is not None
        assert hit["uid"]          in {"id-alice", "id-bob"}
        assert hit["upn"]          in {"alice@acme.test", "bob@acme.test"}
        assert hit["display_name"] in {"Alice Apple", "Bob Banana"}
        assert hit["domain"]       == "ACME"


def test_random_identity_fallback_on_404():
    """``/active-directory/accounts`` was 404 on the v2.2 POC tenant.
    The resolver MUST handle this cleanly: log + return None + cache
    the miss so we don't hammer the endpoint on every event."""
    seen_calls = {"count": 0}
    def handler(req):
        seen_calls["count"] += 1
        return httpx.Response(404, json={"errors": ["not found"]})
    with _mk_resolver(handler) as r:
        assert r.random_identity() is None
        # Second call must hit the cache, not re-issue the HTTP request.
        assert r.random_identity() is None
        assert seen_calls["count"] == 1, (
            "404 must be cached — observed extra HTTP calls "
            f"({seen_calls['count']})")


def test_random_identity_returns_none_when_unconfigured():
    """Mirror random_endpoint contract for unconfigured resolver."""
    r = s1_assets.S1AssetResolver(console_url="", api_token="",
                                   account_id="")
    try:
        assert r.random_identity() is None
    finally:
        r.close()


# ── sticky_pick ────────────────────────────────────────────────────


def test_sticky_pick_returns_same_asset_majority_of_the_time():
    """With ratio=0.8, ~80% of consecutive picks return the same
    asset as the first one — the "primary" asset for the session.
    20% re-roll to a fresh random asset (lateral movement).
    Bounds are wide enough to avoid flakes from RNG."""
    def handler(req):
        return httpx.Response(200, json={"data": _FAKE_ASSETS,
                                          "pagination": {}})
    with _mk_resolver(handler) as r:
        picks = [r.sticky_pick("endpoint", ratio=0.8) for _ in range(200)]
        # All non-None (we have managed agents available)
        assert all(p is not None for p in picks)
        primary = picks[0]["uid"]
        same = sum(1 for p in picks if p["uid"] == primary)
        # Generous bounds: ratio=0.8 ⇒ at least ~140/200 stay sticky.
        assert same >= 140, (
            f"sticky pick should stay on primary >=70% of calls, "
            f"got {same}/200")
        # And NOT 100% — some variation must occur.
        assert same <= 195, (
            f"sticky pick should drift sometimes, got {same}/200 "
            "(too sticky — jitter knob may be unwired)")


def test_sticky_pick_returns_none_for_kind_none():
    """``kind='none'`` is the explicit opt-out from the registry
    (Snyk / Tenable / Wiz). sticky_pick MUST treat it as a no-op
    so callers don't have to guard with an if-check."""
    def handler(req):  # noqa: ARG001 — never called for kind=none
        raise AssertionError("sticky_pick(none) must not hit the API")
    with _mk_resolver(handler) as r:
        assert r.sticky_pick("none") is None


def test_sticky_pick_kind_identity_uses_identity_inventory():
    """``kind='identity'`` routes through random_identity, not
    random_endpoint — the push loop relies on that to fill user.uid
    on identity-shaped sources like Okta."""
    accounts = {"data": [{"id": "id-only", "userPrincipalName": "x@y.z",
                          "displayName": "X", "domain": "Y"}],
                "pagination": {}}
    def handler(req):
        if "/active-directory/accounts" in str(req.url):
            return httpx.Response(200, json=accounts)
        raise AssertionError(
            f"sticky_pick(identity) hit the wrong endpoint: {req.url}")
    with _mk_resolver(handler) as r:
        hit = r.sticky_pick("identity")
        assert hit is not None
        assert hit["uid"] == "id-only"
        assert hit["upn"] == "x@y.z"
