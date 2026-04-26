"""Request tracing middleware — captures every API call for the admin UI."""

import collections
import time
from datetime import datetime, timezone
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# source_id → deque of trace entries (newest first)
REQUEST_TRACE: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=100)
)

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
    ("cloudtrail", ["/v1/cloudtrail/", "/aws/sqs/", "/aws/s3/", "/aws/"]),
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

        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "method": request.method,
            "path": path,
            "query": str(request.query_params) if request.query_params else "",
            "client": request.client.host if request.client else "?",
            "status": response.status_code,
            "duration_ms": duration_ms,
            "req_headers": _sanitise_headers(request.headers),
            "req_body": body_str,
        }
        REQUEST_TRACE[source].appendleft(entry)
        return response
