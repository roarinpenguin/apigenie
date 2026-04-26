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
    ("entra_id",   ["/v1.0/auditLogs/", "/v2.0/token", "/oauth2/"]),
    ("defender",   ["/v1.0/subscriptions/", "/subscriptions/"]),
    ("cisco_duo",  ["/admin/v1/", "/admin/v2/"]),
    ("gcp_audit",  ["/v2/entries"]),
    ("tenable",    ["/vulns/", "/assets/", "/audit-log/"]),
    ("proofpoint", ["/v2/siem/"]),
    ("cloudtrail", ["/v1/cloudtrail/"]),
    ("waf",        ["/v1/waf/"]),
    ("guardduty",  ["/v1/guardduty/", "/detector/"]),
    ("wiz",        ["/graphql"]),
    ("snyk",       ["/v1/org/", "/rest/orgs/"]),
    ("darktrace",  ["/modelbreaches", "/aianalyst/", "/status", "/groups", "/devices"]),
]

_SKIP_PREFIXES = ("/admin", "/health", "/docs", "/openapi")


def get_source(path: str) -> str | None:
    for source, patterns in _SOURCE_PATTERNS:
        for p in patterns:
            if path == p or path.startswith(p):
                return source
    # tenant-prefixed Microsoft paths: /{uuid}/oauth2/...
    parts = path.lstrip("/").split("/", 1)
    if len(parts) == 2 and len(parts[0]) == 36 and parts[0].count("-") == 4:
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
        if any(path.startswith(p) for p in _SKIP_PREFIXES):
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
