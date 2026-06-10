"""S1 asset resolver — map OCSF entity names to live XDR Asset IDs.

Used by Alert Push to bind synthetic alerts to real assets in the
configured SentinelOne tenant. When the calling user enables
``link_xdr_assets`` on an Alert Push profile, the send path asks this
resolver for each ``device.name`` / ``device.hostname`` /
``resources[].name`` it finds in the prepared alert; if a match is
returned, the send path puts the **XDR Asset ID** into ``resources[].uid``
so UAM correlates the alert to the existing asset card (the tile becomes
"bound" — ``assets[].agentUuid`` is populated in the UAM view).

What the right correlation field actually is
--------------------------------------------
Empirically verified on the connected ``usea1-purple`` tenant on
2026-06-10 by replicating the bind shape that the ``jarvis_coding`` /
HELIOS project uses (``apollo_ransomware_scenario.py`` and
``Backend/api/app/services/alert_service.py``):

* ``GET /web/api/v2.1/xdr/assets`` returns an asset record with a
  **26-character alphanumeric ``id``** (e.g. ``3d3dp5xbcauhh5hhqa3so46e6y``).
  That id is what UAM correlates ``resources[].uid`` against — putting
  it into an alert payload causes UAM to bind to the matching asset
  tile and populate ``assets[].agentUuid`` / ``category`` / ``osType``.
* The numeric ``agent.id`` (e.g. ``2340988466085504773``) and the hex
  ``agent.uuid`` (e.g. ``57c2f3d40cdc4484b216c319aa9eb3c2``) are NOT
  what UAM binds on. Alerts shipped with either of those in
  ``resources[].uid`` either drop silently (when ``S1-Scope`` is also
  group-tight) or land as **unbound synthetic tiles**.

Why a single endpoint (not name-filtered)
-----------------------------------------
``/xdr/assets`` accepts only ``accountIds`` / ``siteIds`` filters — no
``name__like`` / ``query`` / ``nameContains`` is supported (HTTP 400
``Unknown field``). The resolver therefore paginates the asset list
once per batch, caches it in-memory, and does fuzzy matching on the
``name`` field locally. With the typical "Send N" batch shape (one
distinct name) this is cheap: one paginated walk, then O(1) on every
subsequent lookup.

Why we still query ``/agents`` opportunistically
------------------------------------------------
The ``/xdr/assets`` record's ``agent`` sub-block carries everything
useful (uuid, numeric id, OS, version, machine type, IP). We don't
need a second call.

Design properties
-----------------
* **Read-only** — the resolver never mutates anything in S1.
* **Silent on failure** — any network / auth / 404 condition returns
  ``None`` and the alert ships unenriched. The send path never blocks.
* **Per-batch instance** — one resolver per send; the asset-list cache
  + per-name cache make ``Send 100`` exactly one paginated walk for N
  distinct names.
* **Thread-safe cache** — lock held only across dict reads/writes,
  never across HTTP.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Cache TTLs. 5 minutes is long enough to fold a Send-N batch into a
# single asset-list walk without making decommissioned assets linger
# indefinitely. Misses are cached for a shorter window so a freshly-
# onboarded asset becomes discoverable within ~60s.
_HIT_TTL = 300.0
_MISS_TTL = 60.0
_DEFAULT_TIMEOUT = 10.0      # /xdr/assets pagination can be slower than /agents

# Sentinel value distinct from None so the cache can distinguish "we
# looked, found nothing" from "we have never looked".
_MISS = object()

# OCSF ``device.os.type_id`` enum (from the OCSF Device profile). Mapping
# from the case-folded value that an asset's ``agent.osType`` field
# returns. Set both this AND the Pascal-cased ``type`` label on the
# alert; UAM/OCSF schema validators consume the int enum, while a human
# reading the raw alert appreciates the string.
_OCSF_OS_TYPE: dict[str, tuple[int, str]] = {
    "linux":      (100, "Linux"),
    "windows":    (200, "Windows"),
    "macos":      (300, "macOS"),
    "android":    (400, "Android"),
    "ios":        (500, "iOS"),
    "chromeos":   (601, "ChromeOS"),
    "ipados":     (700, "iPadOS"),
    "solaris":    (800, "Solaris"),
    "watchos":    (900, "watchOS"),
    "freebsd":    (1000, "FreeBSD"),
    "aix":        (1100, "AIX"),
    "hp-ux":      (1200, "HP-UX"),
}


def _normalise_os(raw: str) -> tuple[int, str, str]:
    """Return ``(type_id, type_label, lowercased_key)`` for an S1 ``osType``.

    Returns ``(0, "", "")`` when the input is empty or doesn't map. ``0``
    is OCSF's "Unknown" enum so the alert still carries a valid type_id
    field rather than omitting it inconsistently.
    """
    key = (raw or "").strip().lower()
    if not key:
        return (0, "", "")
    if key in _OCSF_OS_TYPE:
        type_id, label = _OCSF_OS_TYPE[key]
        return (type_id, label, key)
    # Unknown OS family — surface the raw string but mark type_id as
    # OCSF's "Other" (99) so consumers can at least filter.
    return (99, raw.strip(), key)


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def _score(hint: str, candidate: str) -> int:
    """Rank a candidate asset name against the hint. Higher == better.

    Heuristic order:

      1. Exact match (case-insensitive)
      2. Candidate starts with the hint
      3. Hint is a substring of the candidate
      4. Token overlap after splitting on ``- _ .``

    Returns 0 when there is no overlap so the caller can drop candidates
    that aren't actually similar to the hint (avoids picking
    ``RoarinSrv2022`` when the user typed ``webby``).
    """
    h, c = _norm(hint), _norm(candidate)
    if not h or not c:
        return 0
    if h == c:
        return 1000
    if c.startswith(h):
        # 500 with a length penalty so a tighter prefix wins.
        return 500 - max(0, len(c) - len(h))
    if h in c:
        return 250 - max(0, len(c) - len(h))
    h_tokens = {t for t in h.replace("-", " ").replace("_", " ").replace(".", " ").split() if t}
    c_tokens = {t for t in c.replace("-", " ").replace("_", " ").replace(".", " ").split() if t}
    common = h_tokens & c_tokens
    if common:
        return 100 + 10 * len(common)
    return 0


class S1AssetResolver:
    """Per-batch resolver — instantiate one, use it for one send, close it.

    The cache is instance-local; closing the resolver disposes the
    underlying ``httpx.Client`` (unless one was passed in by the caller,
    in which case we leave the lifecycle to the caller).

    Pass a custom ``client`` in tests to swap in an ``httpx.MockTransport``.

    The ``account_id`` / ``site_id`` parameters scope the asset-list
    query so a resolver attached to one Alert Push profile only walks
    that profile's relevant inventory (faster + privacy-respecting in
    multi-tenant setups). They are NOT the binding key — the binding
    key is whatever ``id`` the ``/xdr/assets`` endpoint returns for the
    matched asset.
    """

    def __init__(self, console_url: str, api_token: str, *,
                 hit_ttl: float = _HIT_TTL,
                 miss_ttl: float = _MISS_TTL,
                 timeout: float = _DEFAULT_TIMEOUT,
                 client: httpx.Client | None = None,
                 account_id: str | None = None,
                 site_id: str | None = None,
                 asset_list_max_pages: int = 20,
                 asset_list_page_size: int = 100) -> None:
        self.console_url = (console_url or "").rstrip("/")
        self.api_token = api_token or ""
        self.hit_ttl = hit_ttl
        self.miss_ttl = miss_ttl
        self.timeout = timeout
        self._own_client = client is None
        self._client = client or httpx.Client(timeout=timeout)
        self._cache: dict[str, tuple[float, float, Any]] = {}
        self._lock = threading.Lock()
        self.account_id: str | None = (account_id or "").strip() or None
        self.site_id: str | None = (site_id or "").strip() or None
        # Pagination knobs — defaults sized for typical SE-demo tenants
        # (~hundreds of assets per site). Bump max_pages if you have a
        # tenant with thousands of XDR assets at a single scope.
        self._asset_list_max_pages = max(1, int(asset_list_max_pages))
        self._asset_list_page_size = max(10, min(1000, int(asset_list_page_size)))
        # Diagnostics counters — let the send endpoint surface "did the
        # resolver actually do anything?" to the UI so the user doesn't
        # have to grep container logs after each send. The trace list is
        # capped so a Send-100 batch can't balloon the response.
        self.lookups: int = 0
        self.hits: int = 0
        self.misses: int = 0
        self.cache_hits: int = 0
        self.trace: list[dict[str, Any]] = []
        self._trace_cap: int = 20

    # ── Lifecycle ──────────────────────────────────────────────────────────
    def close(self) -> None:
        if self._own_client:
            try:
                self._client.close()
            except Exception:  # pragma: no cover — defensive
                pass

    def __enter__(self) -> "S1AssetResolver":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # ── Configuration helpers ──────────────────────────────────────────────
    def is_configured(self) -> bool:
        """True iff we have enough to make a real API call."""
        return bool(self.console_url and self.api_token and self.account_id)

    # ── Cache ──────────────────────────────────────────────────────────────
    def _cached(self, key: str) -> Any:
        """Return cached value (which may be None) or _MISS if absent/expired."""
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return _MISS
            stored_at, ttl, value = entry
            if time.monotonic() - stored_at > ttl:
                self._cache.pop(key, None)
                return _MISS
            return value

    def _store(self, key: str, value: Any) -> None:
        ttl = self.hit_ttl if value is not _MISS and value is not None else self.miss_ttl
        with self._lock:
            self._cache[key] = (time.monotonic(), ttl, value)

    # ── Public API ─────────────────────────────────────────────────────────
    def resolve_endpoint(self, name_hint: str) -> dict[str, Any] | None:
        """Return the best-matching XDR asset for ``name_hint``, or ``None``.

        Hit shape::

            {
              "uid":            "<XDR asset id (alphanumeric)>",  # binding key
              "agent_uuid":     "<agent uuid (hex)>",             # legacy / display
              "agent_id":       "<numeric agent id>",             # OCSF device.agent.uid
              "agent_version":  "<agent version>",
              "machine_type":   "server" / "desktop" / "laptop",
              "hostname":       "<asset name>",
              "ip":             "<lastReportedIp / externalIp>",
              "os_name":        "<osName>",
              "os_type":        "<Pascal-cased OS label>",
              "os_type_id":     <OCSF os.type_id int>,
              "domain":         "<domain>",
              "category":       "<asset category — e.g. Server, Workstation>",
            }

        Returns ``None`` when:

        * the resolver isn't configured (missing url / token / account_id),
        * the hint is empty,
        * the API errors out or returns 0 assets,
        * no candidate scores above 0,
        * the matched asset isn't tied to a managed agent (no ``agent``
          sub-record — these are passive discovery records that UAM
          won't bind alerts against).
        """
        hint = _norm(name_hint)
        if not hint:
            return None

        cached = self._cached(hint)
        if cached is not _MISS:
            self.cache_hits += 1
            return None if cached is None else cached

        # Past this point we're going to do real work (or refuse to). Count
        # it as a lookup either way so diagnostics show the resolver was
        # consulted, even if it gave up because creds were missing.
        self.lookups += 1

        if not self.is_configured():
            self._record_trace(name_hint, status="unconfigured")
            self.misses += 1
            self._store(hint, None)
            return None

        assets = self._all_assets()
        if not assets:
            self._record_trace(name_hint, status="no_assets", candidates=0)
            self.misses += 1
            self._store(hint, None)
            return None

        # Filter to managed agents first — XDR Assets include lots of
        # passive-discovery records (S3 buckets, ECR repos, lambdas...)
        # that share the inventory but have no ``agent`` sub-record.
        # UAM only binds against managed agents, so we skip the rest.
        ranked: list[tuple[int, dict[str, Any]]] = []
        for a in assets:
            if not a.get("agent"):
                continue
            nm = a.get("name") or ""
            score = _score(name_hint, nm)
            if score > 0:
                ranked.append((score, a))
        if not ranked:
            self._record_trace(name_hint, status="no_score_match",
                               candidates=sum(1 for a in assets if a.get("agent")),
                               returned=[a.get("name") for a in assets
                                         if a.get("agent")][:5])
            self.misses += 1
            self._store(hint, None)
            return None

        ranked.sort(key=lambda t: t[0], reverse=True)
        best = ranked[0][1]
        agent = best.get("agent") or {}
        os_type_id, os_type_label, _ = _normalise_os(agent.get("osType") or "")
        xdr_asset_id = (best.get("id") or "").strip()
        if not xdr_asset_id:
            # Defensive: every XDR asset record carries an ``id``; if
            # something is funny on the server side, treat as a miss
            # rather than poison the alert with an empty string.
            self._record_trace(name_hint, status="hit_but_no_xdr_id",
                               match=best.get("name"))
            self.misses += 1
            self._store(hint, None)
            return None
        out = {
            "uid": xdr_asset_id,                       # ← XDR ASSET ID (binding key)
            "agent_uuid": agent.get("uuid") or "",     # hex form (legacy / display)
            "agent_id": str(agent.get("id") or ""),    # numeric form (OCSF device.agent.uid)
            "agent_version": agent.get("agentVersion") or "",
            "machine_type": (agent.get("machineType") or "").lower(),
            "hostname": best.get("name") or agent.get("computerName") or "",
            "ip": agent.get("lastReportedIp") or agent.get("externalIp") or "",
            "os_name": agent.get("osName") or "",
            "os_type": os_type_label,
            "os_type_id": os_type_id,
            "domain": agent.get("domain") or "",
            "category": best.get("category") or "",   # e.g. "Server", "Workstation"
        }
        self._record_trace(name_hint, status="hit",
                           match=out["hostname"], uid=out["uid"])
        self.hits += 1
        self._store(hint, out)
        return out

    def _record_trace(self, hint: str, **fields: Any) -> None:
        """Append a capped diagnostic record describing a single lookup."""
        if len(self.trace) >= self._trace_cap:
            return
        record: dict[str, Any] = {"hint": hint}
        record.update(fields)
        self.trace.append(record)

    def stats(self) -> dict[str, Any]:
        """Serialisable diagnostics for embedding in API responses.

        The shape is deliberately small + JSON-clean: an enabled flag, four
        counters, and a bounded trace list. Truthful enough to debug a
        misfire ("0 lookups → toggle off?" / "5 lookups, 0 hits → wrong
        creds or stale inventory?") without leaking secrets.
        """
        return {
            "configured": self.is_configured(),
            "lookups": self.lookups,
            "hits": self.hits,
            "misses": self.misses,
            "cache_hits": self.cache_hits,
            "trace": list(self.trace),
        }

    # ── HTTP ──────────────────────────────────────────────────────────────
    def _all_assets(self) -> list[dict[str, Any]]:
        """Fetch every XDR asset record for the resolver's scope. Cached
        across all lookups in one batch under a stable internal key.

        ``/xdr/assets`` does not accept name filters (HTTP 400
        ``Unknown field`` on ``name``/``name__like``/``query``). The
        only filters honoured are ``accountIds`` and ``siteIds``, so we
        page through the full scope and let ``resolve_endpoint``
        in-memory match against ``a["name"]``.
        """
        cache_key = "__asset_list__"
        cached = self._cached(cache_key)
        if cached is not _MISS:
            self.cache_hits += 1
            return cached or []

        out: list[dict[str, Any]] = []
        cursor: str | None = None
        url = f"{self.console_url}/web/api/v2.1/xdr/assets"
        headers = {
            "Authorization": f"ApiToken {self.api_token}",
            "Accept": "application/json",
        }
        for _page in range(self._asset_list_max_pages):
            params: dict[str, Any] = {
                "accountIds": self.account_id,
                "limit": self._asset_list_page_size,
            }
            if self.site_id:
                params["siteIds"] = self.site_id
            if cursor:
                params["cursor"] = cursor
            try:
                r = self._client.get(url, params=params, headers=headers)
            except httpx.RequestError as exc:
                log.info("s1_assets: /xdr/assets request error: %s", exc)
                break
            if r.status_code != 200:
                log.info("s1_assets: /xdr/assets -> HTTP %d (body: %s)",
                         r.status_code, r.text[:200])
                break
            try:
                payload = r.json()
            except ValueError:
                log.info("s1_assets: /xdr/assets returned non-JSON")
                break
            if not isinstance(payload, dict):
                break
            data = payload.get("data") or []
            if isinstance(data, list):
                out.extend(a for a in data if isinstance(a, dict))
            cursor = ((payload.get("pagination") or {}).get("nextCursor")
                      if isinstance(payload.get("pagination"), dict) else None)
            if not cursor:
                break
        self._store(cache_key, out)
        return out
