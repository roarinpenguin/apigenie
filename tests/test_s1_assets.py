"""Unit tests for ``s1_assets.S1AssetResolver`` (v2.2).

Coverage in this file:

* Fuzzy ranking — exact, prefix, substring, token-overlap.
* Cache semantics — hits cached, misses cached (shorter TTL), expiry.
* Misconfig / network / HTTP error paths — silent ``None`` return.
* Real-shape S1 ``GET /xdr/assets`` response → hit dict shape.
* The XDR Asset ID (alphanumeric ``id`` field) is what lands in
  ``out["uid"]`` — the field UAM binds on.
* Score-of-zero candidates filtered out (no false-positive correlation).
* Pagination — multi-page asset responses get walked.
* ``/xdr/assets`` returns mixed managed-agent + passive-discovery
  records; only the managed-agent ones (with an ``agent`` sub-record)
  are candidates for binding.

The HTTP layer is stubbed via ``httpx.MockTransport`` so these are pure
unit tests; no socket I/O.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from s1_assets import S1AssetResolver, _score

# ── Helpers ──────────────────────────────────────────────────────────────────

def _xdr_asset(name: str, *, asset_id: str = "abcdef1234567890abcdef1234",
               with_agent: bool = True, uuid: str = "test-uuid",
               agent_id: str = "1234567890", category: str = "Server",
               **agent_extra: Any) -> dict[str, Any]:
    """Build an XDR asset record shaped like the live ``GET /xdr/assets``
    response.

    A managed-agent asset (``with_agent=True``) carries a nested
    ``agent`` block from which the resolver pulls OS/version/IP fields.
    A passive-discovery asset (``with_agent=False``) has no ``agent``
    block — UAM doesn't bind alerts to these and the resolver must
    skip them.
    """
    record: dict[str, Any] = {
        "id":       asset_id,            # ← XDR Asset ID (binding key)
        "name":     name,
        "category": category,
    }
    if with_agent:
        agent: dict[str, Any] = {
            "id":            agent_id,
            "uuid":          uuid,
            "computerName":  name,
            "osName":        "Linux",
            "osType":        "linux",
            "machineType":   "server",
            "agentVersion":  "25.2.6.442",
            "lastReportedIp": "10.0.0.1",
            "externalIp":    "203.0.113.1",
            "domain":        "example.com",
        }
        agent.update(agent_extra)
        record["agent"] = agent
    return record


def _build_resolver(assets: list[dict[str, Any]] | None = None,
                   *,
                   status_code: int = 200,
                   raise_request_error: bool = False,
                   raise_non_json: bool = False,
                   console_url: str = "https://demo.sentinelone.net",
                   api_token: str = "test-token",
                   account_id: str = "9999999999999999999",
                   site_id: str | None = None,
                   call_log: list[dict[str, Any]] | None = None,
                   pages: list[list[dict[str, Any]]] | None = None,
                   **kwargs: Any) -> S1AssetResolver:
    """Wire an ``S1AssetResolver`` to an ``httpx.MockTransport``.

    ``assets`` (the simple case): one-shot list, single page.
    ``pages`` (advanced): list of pages — handler emits cursors between
    them and an empty cursor on the last page so we can verify the
    pagination walk.
    """
    log = call_log if call_log is not None else []
    # Page state outside the handler so the closure can advance.
    page_iter = list(pages) if pages is not None else [assets or []]

    def handler(request: httpx.Request) -> httpx.Response:
        log.append({
            "url": str(request.url),
            "params": dict(request.url.params),
            "auth": request.headers.get("authorization", ""),
        })
        if raise_request_error:
            raise httpx.ConnectError("simulated network error", request=request)
        if raise_non_json:
            return httpx.Response(200, text="<html>not json</html>")
        if status_code != 200:
            return httpx.Response(status_code, json={"errors": ["nope"]})
        # Determine which page to serve based on cursor.
        cursor = request.url.params.get("cursor")
        if cursor is None:
            idx = 0
        else:
            # cursors we emit look like "page-N" — strip the prefix.
            try:
                idx = int(cursor.split("-", 1)[1])
            except Exception:
                idx = 0
        if idx >= len(page_iter):
            return httpx.Response(200, json={"data": [], "pagination": {}})
        page = page_iter[idx]
        next_cursor = f"page-{idx+1}" if idx + 1 < len(page_iter) else None
        body: dict[str, Any] = {"data": page, "pagination": {}}
        if next_cursor:
            body["pagination"]["nextCursor"] = next_cursor
        return httpx.Response(200, json=body)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return S1AssetResolver(
        console_url=console_url,
        api_token=api_token,
        client=client,
        account_id=account_id,
        site_id=site_id,
        **kwargs,
    )


# ── _score() pure-function tests ─────────────────────────────────────────────

class TestScore:
    def test_exact_case_insensitive_wins(self):
        assert _score("webby", "Webby") == 1000

    def test_prefix_beats_substring(self):
        assert _score("web", "webby") > _score("web", "long-web-server")

    def test_substring_beats_no_match(self):
        assert _score("web", "long-web-server") > 0

    def test_token_overlap_picks_up_hyphenated(self):
        assert _score("bridge", "uss-bridge-prod") > 0

    def test_no_overlap_scores_zero(self):
        assert _score("alpha", "RoarinSrv2022") == 0

    def test_empty_inputs_score_zero(self):
        assert _score("", "anything") == 0
        assert _score("anything", "") == 0


# ── Hit / miss / shape ───────────────────────────────────────────────────────

class TestResolveEndpoint:
    def test_hit_returns_xdr_asset_id_and_enrichment(self):
        r = _build_resolver([
            _xdr_asset("webby",
                       asset_id="3d3dp5xbcauhh5hhqa3so46e6y",
                       uuid="6601fcd8-284b-fb8a-5349-f0287fb32b97",
                       agent_id="9988776655443322",
                       agentVersion="25.2.6.442",
                       machineType="laptop"),
        ])
        out = r.resolve_endpoint("webby")
        assert out is not None
        # ── THE binding key — XDR Asset ID (alphanumeric) — lands in
        # resources[].uid. Without this UAM never correlates to the
        # asset tile and ``assets[].agentUuid`` stays None.
        assert out["uid"] == "3d3dp5xbcauhh5hhqa3so46e6y"
        # Hex agent UUID — used by ``device.uid`` for display only.
        assert out["agent_uuid"] == "6601fcd8-284b-fb8a-5349-f0287fb32b97"
        # Numeric agent id — used by ``device.agent.uid`` cosmetic block.
        assert out["agent_id"] == "9988776655443322"
        assert out["agent_version"] == "25.2.6.442"
        assert out["machine_type"] == "laptop"
        assert out["hostname"] == "webby"
        # OCSF normalisation: lowercase 'linux' from S1 -> Pascal label + int enum.
        assert out["os_type"] == "Linux"
        assert out["os_type_id"] == 100
        assert out["ip"] == "10.0.0.1"
        assert out["category"] == "Server"
        r.close()

    def test_empty_hint_returns_none_without_http_call(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver([], call_log=log)
        assert r.resolve_endpoint("") is None
        assert r.resolve_endpoint("   ") is None
        assert log == []

    def test_unconfigured_returns_none_without_http_call(self):
        # No URL → not configured. No HTTP call attempted.
        log: list[dict[str, Any]] = []
        r = _build_resolver([], console_url="", api_token="", call_log=log)
        assert r.resolve_endpoint("webby") is None
        assert log == []

    def test_unconfigured_when_account_id_missing(self):
        # account_id is now required (it's a /xdr/assets filter param).
        log: list[dict[str, Any]] = []
        r = _build_resolver([], account_id="", call_log=log)
        assert r.resolve_endpoint("webby") is None
        assert log == [], "resolver must short-circuit before any HTTP"

    def test_miss_returns_none(self):
        r = _build_resolver([])
        assert r.resolve_endpoint("does-not-exist") is None

    def test_filters_out_score_zero_candidates(self):
        # The mock returns an unrelated record — resolver must NOT pick it.
        r = _build_resolver([
            _xdr_asset("RoarinSrv2022", asset_id="xxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ])
        assert r.resolve_endpoint("alpha") is None

    def test_picks_best_match_by_score(self):
        r = _build_resolver([
            _xdr_asset("long-web-server-2024", asset_id="loseloseloseloseloselose1"),
            _xdr_asset("webby",                asset_id="winwinwinwinwinwinwinwinww"),
            _xdr_asset("another-host",         asset_id="loserlooserlooserlooserloo"),
        ])
        out = r.resolve_endpoint("web")
        assert out is not None
        assert out["uid"] == "winwinwinwinwinwinwinwinww"

    def test_passive_discovery_records_are_skipped(self):
        """``/xdr/assets`` returns passive-discovery records (S3 buckets,
        ECR repos, λs) that share the inventory with managed agents but
        have no ``agent`` sub-record. UAM does not bind alerts to these,
        so the resolver must filter them out — even when the name fuzzy-
        matches."""
        r = _build_resolver([
            # Same-name passive record at the top of the candidate list.
            _xdr_asset("webby", asset_id="passivepassivepassivepass1",
                       with_agent=False, category="Cloud Asset"),
            # The actual managed agent is later in the list.
            _xdr_asset("webby", asset_id="managedmanagedmanagedman2",
                       uuid="6601fcd8-284b-fb8a-5349-f0287fb32b97"),
        ])
        out = r.resolve_endpoint("webby")
        assert out is not None
        # MUST pick the managed-agent one; not the passive-discovery one.
        assert out["uid"] == "managedmanagedmanagedman2"

    def test_xdr_asset_id_required(self):
        """If the matched record carries no ``id`` (server bug), treat
        as a miss rather than poison the alert with an empty string."""
        broken = _xdr_asset("ghost", asset_id="")
        r = _build_resolver([broken])
        assert r.resolve_endpoint("ghost") is None


# ── Pagination ───────────────────────────────────────────────────────────────

class TestPagination:
    """``/xdr/assets`` doesn't filter by name; the resolver pages the
    whole scope and matches in memory. Verify the page walker."""

    def test_walks_multiple_pages_until_target_found(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver(pages=[
            [_xdr_asset("alpha",  asset_id="aaaaaaaaaaaaaaaaaaaaaaaaaa")],
            [_xdr_asset("beta",   asset_id="bbbbbbbbbbbbbbbbbbbbbbbbbb")],
            [_xdr_asset("webby",  asset_id="winwinwinwinwinwinwinwinww")],
        ], call_log=log)
        out = r.resolve_endpoint("webby")
        assert out is not None
        assert out["uid"] == "winwinwinwinwinwinwinwinww"
        # 3 HTTP calls (one per page) — confirms cursor was honoured.
        assert len(log) == 3
        # The 2nd and 3rd calls MUST include the cursor param.
        assert log[1]["params"].get("cursor") == "page-1"
        assert log[2]["params"].get("cursor") == "page-2"

    def test_site_id_param_forwarded_when_set(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver([_xdr_asset("webby", asset_id="winwinwinwinwinwinwinwinww")],
                            site_id="2168724616075133168", call_log=log)
        r.resolve_endpoint("webby")
        assert log[0]["params"].get("accountIds") == "9999999999999999999"
        assert log[0]["params"].get("siteIds") == "2168724616075133168"

    def test_caches_the_asset_list_across_lookups(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver([
            _xdr_asset("alpha", asset_id="aaaaaaaaaaaaaaaaaaaaaaaaaa"),
            _xdr_asset("webby", asset_id="winwinwinwinwinwinwinwinww"),
        ], call_log=log)
        # Two different names — both must resolve, and the second one
        # MUST NOT trigger a second /xdr/assets fetch.
        a = r.resolve_endpoint("alpha")
        b = r.resolve_endpoint("webby")
        assert a is not None and b is not None
        assert a["uid"] == "aaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert b["uid"] == "winwinwinwinwinwinwinwinww"
        assert len(log) == 1, "asset list should be cached after first fetch"


# ── Failure modes ────────────────────────────────────────────────────────────

class TestFailureModes:
    def test_http_401_returns_none(self):
        r = _build_resolver([], status_code=401)
        assert r.resolve_endpoint("webby") is None

    def test_http_500_returns_none(self):
        r = _build_resolver([], status_code=500)
        assert r.resolve_endpoint("webby") is None

    def test_network_error_returns_none(self):
        r = _build_resolver([], raise_request_error=True)
        assert r.resolve_endpoint("webby") is None

    def test_non_json_response_returns_none(self):
        r = _build_resolver([], raise_non_json=True)
        assert r.resolve_endpoint("webby") is None


# ── Cache ────────────────────────────────────────────────────────────────────

class TestCache:
    def test_hit_is_cached_across_calls(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver([_xdr_asset("webby", asset_id="winwinwinwinwinwinwinwinww")],
                            call_log=log)
        a = r.resolve_endpoint("webby")
        b = r.resolve_endpoint("webby")
        assert a == b
        # Exactly one HTTP call — the second resolve hit the cache.
        assert len(log) == 1

    def test_miss_is_cached_across_calls(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver([], call_log=log)
        assert r.resolve_endpoint("nope") is None
        assert r.resolve_endpoint("nope") is None
        # Asset list still only fetched once (cached as an empty list).
        assert len(log) == 1

    def test_case_insensitive_cache_key(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver([_xdr_asset("webby", asset_id="winwinwinwinwinwinwinwinww")],
                            call_log=log)
        r.resolve_endpoint("Webby")
        r.resolve_endpoint("WEBBY")
        r.resolve_endpoint("webby")
        assert len(log) == 1, log

    def test_hit_expires_after_ttl(self):
        log: list[dict[str, Any]] = []
        r = _build_resolver([_xdr_asset("webby", asset_id="winwinwinwinwinwinwinwinww")],
                            call_log=log, hit_ttl=0.05)
        r.resolve_endpoint("webby")
        time.sleep(0.1)
        r.resolve_endpoint("webby")
        # Both the per-name cache AND the asset-list cache expire.
        assert len(log) == 2


# ── OS normalisation ─────────────────────────────────────────────────────────

class TestOSNormalisation:
    """OCSF ``device.os.type_id`` enum: the hit dict must carry both the
    Pascal-cased label and the integer enum so the alert can populate
    both ``os.type`` and ``os.type_id``. Locked-in here so a future
    refactor doesn't silently drop the enum."""

    def test_windows_maps_to_200(self):
        from s1_assets import _normalise_os
        type_id, label, key = _normalise_os("windows")
        assert type_id == 200
        assert label == "Windows"
        assert key == "windows"

    def test_linux_maps_to_100(self):
        from s1_assets import _normalise_os
        assert _normalise_os("linux")[:2] == (100, "Linux")

    def test_macos_maps_to_300(self):
        from s1_assets import _normalise_os
        assert _normalise_os("macos")[:2] == (300, "macOS")

    def test_unknown_os_uses_99_other(self):
        from s1_assets import _normalise_os
        type_id, label, _ = _normalise_os("BeOS")
        assert type_id == 99
        assert label == "BeOS"

    def test_empty_os_returns_zero(self):
        from s1_assets import _normalise_os
        assert _normalise_os("") == (0, "", "")

    def test_hit_dict_emits_pascal_label_and_int_enum(self):
        """The resolver's hit dict must carry both ``os_type`` (label)
        and ``os_type_id`` (int) ready for OCSF injection."""
        r = _build_resolver([
            _xdr_asset("webby", asset_id="winwinwinwinwinwinwinwinww",
                       osType="windows", osName="Windows Server 2022"),
        ])
        out = r.resolve_endpoint("webby")
        assert out is not None
        assert out["os_type"] == "Windows"
        assert out["os_type_id"] == 200
        assert out["os_name"] == "Windows Server 2022"


# ── Lifecycle ────────────────────────────────────────────────────────────────

def test_context_manager_closes_client():
    closed = {"n": 0}

    class _Client:
        def get(self, *a, **kw):
            return httpx.Response(200, json={"data": []},
                                  request=httpx.Request("GET", "http://x"))
        def close(self):
            closed["n"] += 1

    with S1AssetResolver("https://x", "tok", client=_Client(),     # type: ignore[arg-type]
                         account_id="acct"):
        pass
    # We passed in our own client, so the resolver MUST NOT close it.
    assert closed["n"] == 0

    with S1AssetResolver("https://x", "tok", account_id="acct") as r:
        assert r.is_configured()
    # No external client → its own one was closed; no exception is the assertion.


def test_is_configured_requires_account_id():
    """The resolver is only considered configured when it has all three
    of ``console_url`` / ``api_token`` / ``account_id``. Without
    account_id the ``/xdr/assets`` query can't be made."""
    r = S1AssetResolver("https://x", "tok")
    assert r.is_configured() is False
    r = S1AssetResolver("https://x", "tok", account_id="acct")
    assert r.is_configured() is True
