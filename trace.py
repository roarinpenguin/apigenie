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

# source_id → deque of trace entries (newest first)
REQUEST_TRACE: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=100)
)

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
    ("entra_id",   ["/v1.0/auditLogs/", "/v1.0/identityProtection/", "/v2.0/token", "/oauth2/"]),
    ("defender",   ["/v1.0/subscriptions/", "/subscriptions/", "/v1.0/security/", "/security/alerts", "/security/incidents", "/security/secureScores", "/security/assessments", "/auditLogs/directoryAudits", "/auditLogs/signIns"]),
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
    ("darktrace",  ["/modelbreaches", "/aianalyst/", "/status", "/groups", "/devices"]),
]

# Skip the admin UI itself (login/logout/dashboard/admin API) but NOT Cisco Duo,
# which legitimately lives under /admin/v1/... and /admin/v2/... .
_SKIP_EXACT = {"/admin", "/admin/"}
_SKIP_PREFIXES = ("/admin/login", "/admin/logout", "/admin/api/", "/health", "/docs", "/openapi")


def get_source(path: str) -> str | None:
    for source, patterns in _SOURCE_PATTERNS:
        for p in patterns:
            if path == p or path.startswith(p):
                return source
    # Tenant-prefixed Microsoft OAuth: /{tenant}/oauth2/v2.0/token
    # The tenant id can be a UUID or a named tenant (e.g. "my-roarin-tenant-id"),
    # so match on the suffix rather than the tenant format.
    if path.endswith("/oauth2/v2.0/token") or path.endswith("/oauth2/token"):
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
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _SKIP_EXACT or any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        source = get_source(path)
        if source is None:
            return await call_next(request)

        t0 = time.monotonic()
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8", errors="replace")[:2000] if body_bytes else ""

        response = await call_next(request)
        duration_ms = int((time.monotonic() - t0) * 1000)
        client_ip = _real_client(request)
        ts_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

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
        }
        REQUEST_TRACE[source].appendleft(entry)
        _agg_observe(client_ip, source, response.status_code, ts_iso)
        return response
