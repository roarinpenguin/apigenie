"""Request tracing middleware — captures every API call for the admin UI.

Two parallel data structures are populated per request:

  * REQUEST_TRACE — per-source ring buffer of the most recent 100 entries
    (drives the Request Inspector tab; bounded for memory).
  * AGG          — LRU-capped aggregate counters keyed by (client_ip, source)
    (drives the Sankey + GeoMap admin tabs; survives ring eviction so the
    visualisations keep accurate volume totals beyond the 100-entry window).

Both are per-process. A restart resets state — same as before.
"""

import collections
import ipaddress
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

import bans
import request_log
import telemetry

# source_id → deque of trace entries (newest first)
REQUEST_TRACE: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=100)
)


def find_by_attack(attack_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Scan every per-source request trace for entries whose request or
    response payload contains ``attack_id``.

    This is the cross-source view that powers Phase 3.2 of Attack Scenarios:
    given an ``attack.id`` from a scenario card, surface every HTTP call
    that delivered an event tagged with it, regardless of which source
    handled the call. The result merges every source's ring buffer, adds
    the ``source`` key (REQUEST_TRACE uses the source as the dict key, not
    as a field on each entry), and sorts globally newest-first.

    Match is a plain substring scan over ``req_body`` + ``resp_preview``.
    attack.ids have the form ``att-YYYYMMDD-NNNN`` — distinctive enough
    that this is faster and simpler than parsing every JSON payload. The
    only payload bytes we have are ``resp_preview`` (first 500 chars), so
    callers should treat the result as best-effort for very large responses.

    Push-source events do not flow through TraceMiddleware (they are
    outbound), so attack-tagged events pushed via log_pusher are NOT
    visible here. The per-scenario event log (Phase 3.1) catches those.
    """
    if not attack_id:
        return []
    results: list[dict[str, Any]] = []
    needle = attack_id
    # Snapshot the items() so a concurrent middleware write doesn't trip
    # the iteration; the inner buffers are deques (thread-safe append).
    for source, buf in list(REQUEST_TRACE.items()):
        for entry in list(buf):
            hay = (entry.get("resp_preview") or "") + (entry.get("req_body") or "")
            if needle in hay:
                row = dict(entry)
                row["source"] = source
                results.append(row)
    results.sort(key=lambda e: e.get("ts", ""), reverse=True)
    return results[:max(0, int(limit))]

# (client_ip, source_id) → {"count","first_ts","last_ts","statuses":{code:int}}
# OrderedDict gives O(1) LRU behaviour: move_to_end() on update, popitem(last=False)
# on overflow. Cap is generous for a mock server but bounded so a malicious or
# noisy collector can't OOM the process.
_AGG_CAP = int(os.environ.get("APIGENIE_AGG_CAP", "5000"))
AGG: collections.OrderedDict[tuple[str, str], dict[str, Any]] = collections.OrderedDict()
_AGG_LOCK = threading.Lock()

# Ordered list: first matching pattern wins
_SOURCE_PATTERNS: list[tuple[str, list[str]]] = [
    ("okta",       ["/api/v1/logs"]),
    ("netskope",   ["/api/v2/"]),
    ("m365",       ["/activity/feed/", "/api/v1.0/", "/v1.0/security/alerts_v2", "/v1.0/security/alerts"]),
    ("entra_id",   ["/v1.0/auditLogs/", "/v1.0/identityProtection/", "/v1.0/users/"]),
    ("defender",   ["/v1.0/subscriptions/", "/subscriptions/", "/v1.0/security/incidents", "/v1.0/security/recommendations", "/v1.0/security/secureScores", "/v1.0/security/assessments"]),
    ("cisco_duo",  ["/admin/v1/", "/admin/v2/"]),
    ("gcp_audit",  ["/v2/entries"]),
    ("tenable",    ["/vulns/", "/assets/", "/audit-log/", "/api/v1/refresh-access-token"]),
    ("proofpoint", ["/v2/siem/"]),
    ("cisco_duo",  ["/epm/api/auth/epm/logon"]),  # Duo logon flow per §2.3
    ("cloudtrail", ["/v1/cloudtrail/"]),
    ("waf",        ["/v1/waf/"]),
    ("guardduty",  ["/v1/guardduty/", "/detector/"]),
    ("wiz",        ["/graphql"]),
    ("snyk",       ["/v1/org/", "/rest/orgs/"]),
    ("darktrace",         ["/modelbreaches", "/aianalyst/", "/status", "/groups", "/devices"]),
    ("azure_platform",    ["/api/bus/azure"]),
    ("cato",              ["/api/v1/graphql2"]),
    ("cloudflare",        ["/client/v4/"]),
    ("zscaler_zpa",       ["/mgmtconfig/"]),
    ("sentinelone",       ["/web/api/v2.1/"]),
    ("mimecast",          ["/siem/v1/", "/api/ttp/", "/api/audit/", "/oauth/token"]),
]

# Skip the admin UI itself (login/logout/dashboard/admin API) but NOT Cisco Duo,
# which legitimately lives under /admin/v1/... and /admin/v2/... .
_SKIP_EXACT = {"/admin", "/admin/"}
_SKIP_PREFIXES = ("/admin/login", "/admin/logout", "/admin/api/", "/health", "/stats", "/docs", "/openapi", "/listener/")


def get_source(path: str, body: str = "") -> str | None:
    for source, patterns in _SOURCE_PATTERNS:
        for p in patterns:
            if path == p or path.startswith(p):
                return source
    # Tenant-prefixed Microsoft OAuth: /{tenant}/oauth2/v2.0/token
    # Distinguish M365 vs Entra ID vs Defender by checking the scope in the POST body.
    if path.endswith("/oauth2/v2.0/token") or path.endswith("/oauth2/token"):
        body_lower = body.lower()
        if "manage.office.com" in body_lower or "office365" in body_lower or "activityfeed" in body_lower:
            return "m365"
        if "securityevents" in body_lower or "security.read" in body_lower:
            return "defender"
        return "entra_id"
    return None


def _sanitise_headers(headers: Any) -> dict[str, str]:
    sensitive = {"authorization", "cookie", "x-apikeys"}
    return {
        k: ("***" if k.lower() in sensitive else v)
        for k, v in dict(headers).items()
    }


def _real_client(request: Request) -> str:
    """Resolve the upstream client IP, honouring the proxy chain.

    nginx is configured to forward both ``X-Forwarded-For`` (chained) and
    ``X-Real-IP`` (single hop). Without this helper ``request.client.host``
    would always be the nginx-bridge container IP, which makes the Sankey
    and GeoMap tabs useless.

    Trust order:
      1. left-most public IP from X-Forwarded-For
      2. X-Real-IP                                (set by our nginx)
      3. request.client.host                       (worst case)
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # Left-most non-empty token is the original client. Skip private
        # hops so a request that traverses several NATs still attributes
        # to the public origin if one is present.
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for p in parts:
            try:
                if not ipaddress.ip_address(p).is_private:
                    return p
            except ValueError:
                continue
        if parts:
            return parts[0]
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()
    return request.client.host if request.client else "?"


def _agg_observe(ip: str, source: str, status: int, ts_iso: str) -> None:
    """Increment the (ip, source) aggregate, with O(1) LRU eviction."""
    key = (ip, source)
    with _AGG_LOCK:
        bucket = AGG.get(key)
        if bucket is None:
            bucket = {"count": 0, "first_ts": ts_iso, "last_ts": ts_iso, "statuses": {}}
            AGG[key] = bucket
            # Evict oldest if we exceed cap. popitem(last=False) is O(1).
            while len(AGG) > _AGG_CAP:
                AGG.popitem(last=False)
        else:
            AGG.move_to_end(key)
        bucket["count"] += 1
        bucket["last_ts"] = ts_iso
        s = str(status)
        bucket["statuses"][s] = bucket["statuses"].get(s, 0) + 1


class TraceMiddleware(BaseHTTPMiddleware):
    _log_pruner_started = False

    async def dispatch(self, request: Request, call_next):
        if not TraceMiddleware._log_pruner_started:
            request_log.start_pruner()
            telemetry.start()
            TraceMiddleware._log_pruner_started = True

        path = request.url.path
        if path in _SKIP_EXACT or any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        # ── IP ban check (early exit, after admin routes are exempt) ──────
        client_ip = _real_client(request)
        if bans.is_banned(client_ip):
            from starlette.responses import JSONResponse
            return JSONResponse({"error": "forbidden", "reason": "IP banned"}, status_code=403)

        # Read body early so we can use it for source detection (M365 vs Entra ID token)
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8", errors="replace")[:2000] if body_bytes else ""

        source = get_source(path, body_str)
        if source is None:
            # Unrecognised path — capture as intrusion attempt
            try:
                import intrusions
                t0_unk = time.monotonic()
                unk_body = await request.body()
                unk_body_str = unk_body.decode("utf-8", errors="replace")[:500] if unk_body else ""
                response = await call_next(request)
                intrusions.record(
                    ip=client_ip, method=request.method, path=path,
                    query=str(request.query_params) if request.query_params else "",
                    status=response.status_code,
                    headers=_sanitise_headers(request.headers),
                    body=unk_body_str,
                    duration_ms=int((time.monotonic() - t0_unk) * 1000),
                    user_agent=request.headers.get("user-agent", ""),
                )
                return response
            except Exception:
                return await call_next(request)

        t0 = time.monotonic()

        response = await call_next(request)
        duration_ms = int((time.monotonic() - t0) * 1000)
        # client_ip already resolved at the top of dispatch
        ts_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # Capture response body size and preview
        resp_body_bytes = b""
        resp_body_preview = ""
        resp_size = 0
        async for chunk in response.body_iterator:
            resp_body_bytes += chunk if isinstance(chunk, bytes) else chunk.encode()
        resp_size = len(resp_body_bytes)
        resp_body_preview = resp_body_bytes.decode("utf-8", errors="replace")[:500] if resp_body_bytes else ""
        # Re-wrap the response with the consumed body
        from starlette.responses import Response as StarletteResponse
        response = StarletteResponse(
            content=resp_body_bytes,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )

        entry: dict[str, Any] = {
            "ts": ts_iso,
            "method": request.method,
            "path": path,
            "query": str(request.query_params) if request.query_params else "",
            "client": client_ip,
            "status": response.status_code,
            "duration_ms": duration_ms,
            "req_headers": _sanitise_headers(request.headers),
            "req_body": body_str,
            "resp_size": resp_size,
            "resp_preview": resp_body_preview,
        }
        REQUEST_TRACE[source].appendleft(entry)
        _agg_observe(client_ip, source, response.status_code, ts_iso)
        request_log.append({**entry, "source": source})
        telemetry.record(source)
        return response
