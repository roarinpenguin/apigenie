"""ApiGenie — standalone HTTP mock server for 14 security platform APIs.

Routes mirror the real platform API paths so Observo Site telemetry collector
can connect without any URL rewriting.
"""

import logging
import os
import random
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from admin import router as admin_router
from auth import BearerAuth, BasicAuth, DuoAuth, XApiKeysAuth
from trace import TraceMiddleware
from state import (
    tenable_export_exists,
    tenable_get_chunks,
    tenable_store_export,
)

# Source data generators
from sources.aws_cloudtrail import get_events_response as cloudtrail_events
from sources.aws_guardduty import get_findings_response as guardduty_findings
from sources.aws_waf import get_logs_response as waf_logs
from sources.azure_ad import get_audit_logs_response as entra_audit, get_signin_logs_response as entra_signin
from sources.cisco_duo import get_admin_logs_response as duo_admin, get_auth_logs_response as duo_auth
from sources.darktrace import get_analyst_incidents, get_model_breaches, get_status as darktrace_status
from sources.gcp_audit import get_audit_logs_response as gcp_audit
from sources.microsoft_defender import get_alerts_response as defender_alerts, get_recommendations_response as defender_recs
from sources.netskope import get_alerts_response as netskope_alerts, get_audit_events_response as netskope_audit
from sources.okta import get_logs_response as okta_logs
from sources.proofpoint import get_logs_response as proofpoint_logs
from sources.snyk import get_audit_logs_response as snyk_audit, get_issues_response as snyk_issues, get_projects_response as snyk_projects
from sources.tenable import generate_asset_chunks, generate_vuln_chunks, get_audit_logs_response as tenable_audit
from sources.wiz import get_issues_response as wiz_issues

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

_publishers_enabled = os.environ.get("PUBLISHERS_ENABLED", "true").lower() == "true"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if _publishers_enabled:
        try:
            from publishers import kafka_publisher, pubsub_publisher
            kafka_publisher.start()
            pubsub_publisher.start()
            logger.info("Background publishers started")
        except Exception as exc:
            logger.warning(f"Could not start background publishers: {exc}")
    yield
    if _publishers_enabled:
        try:
            from publishers import kafka_publisher, pubsub_publisher
            kafka_publisher.stop()
            pubsub_publisher.stop()
        except Exception:
            pass


app = FastAPI(
    title="ApiGenie",
    description="Mock HTTP server for 14 security platform APIs",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(TraceMiddleware)
app.include_router(admin_router)


# =============================================================================
# Health
# =============================================================================


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "apigenie"}


# =============================================================================
# Okta  —  Bearer / SSWS token auth
# =============================================================================


@app.get("/api/v1/logs")
async def okta_system_logs(
    _auth: BearerAuth,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(100, le=1000),
) -> Response:
    logs, next_url = okta_logs(since=since, limit=limit)
    headers = {}
    if next_url:
        headers["Link"] = f'<{next_url}>; rel="next"'
    return JSONResponse(content=logs, headers=headers)


# =============================================================================
# Netskope  —  Bearer token auth
# =============================================================================


@app.get("/api/v2/events/data/alert")
async def netskope_alerts_endpoint(_auth: BearerAuth, limit: int = Query(100, le=10000)) -> dict[str, Any]:
    return netskope_alerts(limit=limit)


@app.get("/api/v2/events/data/audit")
async def netskope_audit_endpoint(_auth: BearerAuth, limit: int = Query(50, le=10000)) -> dict[str, Any]:
    return netskope_audit(limit=limit)


# =============================================================================
# Microsoft Entra ID (Azure AD)  —  Bearer token auth
# =============================================================================


@app.get("/v1.0/auditLogs/directoryAudits")
async def entra_directory_audits(
    _auth: BearerAuth,
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
) -> dict[str, Any]:
    return entra_audit(limit=top, skip=skip)


@app.get("/v1.0/auditLogs/signIns")
async def entra_signin_logs(
    _auth: BearerAuth,
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
) -> dict[str, Any]:
    return entra_signin(limit=top, skip=skip)


# =============================================================================
# Microsoft Defender for Cloud  —  Bearer token auth
# =============================================================================


@app.get("/v1.0/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts")
async def defender_security_alerts(_auth: BearerAuth, subscription_id: str, top: int = Query(50, le=500)) -> dict[str, Any]:
    return defender_alerts(limit=top)


@app.get("/v1.0/subscriptions/{subscription_id}/providers/Microsoft.Security/recommendations")
async def defender_recommendations(_auth: BearerAuth, subscription_id: str, top: int = Query(25, le=500)) -> dict[str, Any]:
    return defender_recs(limit=top)


# Alternative shorter paths used by some collectors
@app.get("/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts")
async def defender_security_alerts_v2(_auth: BearerAuth, subscription_id: str, top: int = Query(50, le=500)) -> dict[str, Any]:
    return defender_alerts(limit=top)


@app.get("/subscriptions/{subscription_id}/providers/Microsoft.Security/recommendations")
async def defender_recommendations_v2(_auth: BearerAuth, subscription_id: str, top: int = Query(25, le=500)) -> dict[str, Any]:
    return defender_recs(limit=top)


# =============================================================================
# Cisco Duo  —  HMAC auth
# =============================================================================


@app.get("/admin/v1/logs/authentication")
async def duo_auth_logs_v1(
    _auth: DuoAuth,
    mintime: int | None = None,
    maxtime: int | None = None,
    limit: int = Query(100, le=1000),
) -> dict[str, Any]:
    return duo_auth(limit=limit, mintime=mintime, maxtime=maxtime)


@app.get("/admin/v2/logs/authentication")
async def duo_auth_logs_v2_endpoint(
    _auth: DuoAuth,
    mintime: int | None = None,
    maxtime: int | None = None,
    limit: int = Query(100, le=1000),
) -> dict[str, Any]:
    mintime_s = mintime // 1000 if mintime else None
    maxtime_s = maxtime // 1000 if maxtime else None
    return duo_auth(limit=limit, mintime=mintime_s, maxtime=maxtime_s)


@app.get("/admin/v1/logs/administrator")
async def duo_admin_logs_endpoint(
    _auth: DuoAuth,
    mintime: int | None = None,
    limit: int = Query(100, le=1000),
) -> dict[str, Any]:
    return duo_admin(limit=limit, mintime=mintime)


@app.get("/admin/v1/info/summary")
async def duo_summary() -> dict[str, Any]:
    return {"stat": "OK", "response": {"admin_count": 5, "integration_count": 12, "user_count": 1547}}


# =============================================================================
# GCP Audit Logs via Cloud Logging API  —  Bearer token auth
# (Pub/Sub path handled by background publisher + emulator)
# =============================================================================


@app.post("/v2/entries:list")
async def gcp_log_entries(_auth: BearerAuth, request: Request) -> dict[str, Any]:
    body = await request.json()
    limit = body.get("pageSize", 50)
    project_ids = body.get("resourceNames", [])
    project = project_ids[0].replace("projects/", "") if project_ids else None
    return gcp_audit(limit=limit, project=project)


# =============================================================================
# Tenable  —  X-ApiKeys header auth  (stateful async export)
# =============================================================================


@app.post("/vulns/export")
async def tenable_vulns_export_start(_auth: XApiKeysAuth) -> dict[str, Any]:
    import uuid
    export_uuid = str(uuid.uuid4())
    chunks = generate_vuln_chunks()
    tenable_store_export("vulns", export_uuid, chunks)
    return {"export_uuid": export_uuid}


@app.get("/vulns/export/{export_uuid}/status")
async def tenable_vulns_export_status(_auth: XApiKeysAuth, export_uuid: str) -> dict[str, Any]:
    chunks = tenable_get_chunks("vulns", export_uuid)
    if chunks is None:
        raise HTTPException(status_code=404, detail="Export not found")
    return {
        "status": "FINISHED",
        "chunks_available": list(range(1, len(chunks) + 1)),
        "num_assets_per_chunk": 50,
        "total_chunks": len(chunks),
        "export_uuid": export_uuid,
        "created": 0,
        "finished": 0,
        "filters": {},
        "num_assets_exported": sum(len(c) for c in chunks),
    }


@app.get("/vulns/export/{export_uuid}/chunks/{chunk_id}")
async def tenable_vulns_export_chunk(_auth: XApiKeysAuth, export_uuid: str, chunk_id: int) -> list[dict[str, Any]]:
    chunks = tenable_get_chunks("vulns", export_uuid)
    if chunks is None:
        raise HTTPException(status_code=404, detail="Export not found")
    idx = chunk_id - 1
    if idx < 0 or idx >= len(chunks):
        raise HTTPException(status_code=404, detail="Chunk not found")
    return chunks[idx]


@app.post("/assets/export")
async def tenable_assets_export_start(_auth: XApiKeysAuth) -> dict[str, Any]:
    import uuid
    export_uuid = str(uuid.uuid4())
    chunks = generate_asset_chunks()
    tenable_store_export("assets", export_uuid, chunks)
    return {"export_uuid": export_uuid}


@app.get("/assets/export/{export_uuid}/status")
async def tenable_assets_export_status(_auth: XApiKeysAuth, export_uuid: str) -> dict[str, Any]:
    chunks = tenable_get_chunks("assets", export_uuid)
    if chunks is None:
        raise HTTPException(status_code=404, detail="Export not found")
    return {
        "status": "FINISHED",
        "chunks_available": list(range(1, len(chunks) + 1)),
        "num_assets_per_chunk": 25,
        "total_chunks": len(chunks),
        "export_uuid": export_uuid,
        "created": 0,
        "finished": 0,
        "filters": {},
        "num_assets_exported": sum(len(c) for c in chunks),
    }


@app.get("/assets/export/{export_uuid}/chunks/{chunk_id}")
async def tenable_assets_export_chunk(_auth: XApiKeysAuth, export_uuid: str, chunk_id: int) -> list[dict[str, Any]]:
    chunks = tenable_get_chunks("assets", export_uuid)
    if chunks is None:
        raise HTTPException(status_code=404, detail="Export not found")
    idx = chunk_id - 1
    if idx < 0 or idx >= len(chunks):
        raise HTTPException(status_code=404, detail="Chunk not found")
    return chunks[idx]


@app.get("/audit-log/v1/events")
async def tenable_audit_logs(
    _auth: XApiKeysAuth,
    limit: int = Query(100, le=5000),
    offset: int = Query(0),
) -> dict[str, Any]:
    return tenable_audit(limit=limit, offset=offset)


# =============================================================================
# Proofpoint TAP  —  Basic Auth
# =============================================================================


@app.get("/v2/siem/all")
async def proofpoint_siem_all(_auth: BasicAuth, sinceSeconds: int = Query(3600, alias="sinceSeconds")) -> dict[str, Any]:
    return proofpoint_logs(since_seconds=sinceSeconds)


@app.get("/v2/siem/clicks/blocked")
async def proofpoint_clicks_blocked(_auth: BasicAuth, sinceSeconds: int = Query(3600, alias="sinceSeconds")) -> dict[str, Any]:
    return {"clicksBlocked": [], "clicksPermitted": [], "queryEndTime": "", "queryStartTime": ""}


@app.get("/v2/siem/messages/blocked")
async def proofpoint_messages_blocked(_auth: BasicAuth, sinceSeconds: int = Query(3600, alias="sinceSeconds")) -> dict[str, Any]:
    data = proofpoint_logs(since_seconds=sinceSeconds)
    return {
        "messagesBlocked": data["messagesBlocked"],
        "queryEndTime": data["queryEndTime"],
        "queryStartTime": data["queryStartTime"],
    }


# =============================================================================
# AWS CloudTrail  —  Bearer / AWS SigV4 (we accept any Bearer for simplicity)
# =============================================================================


@app.get("/v1/cloudtrail/events")
async def aws_cloudtrail_events(_auth: BearerAuth, MaxResults: int = Query(50, le=50)) -> dict[str, Any]:
    return cloudtrail_events(limit=MaxResults)


@app.post("/v1/cloudtrail/events")
async def aws_cloudtrail_events_post(_auth: BearerAuth, request: Request) -> dict[str, Any]:
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    limit = body.get("MaxResults", 50) if isinstance(body, dict) else 50
    return cloudtrail_events(limit=min(limit, 50))


# =============================================================================
# AWS WAF  —  Bearer auth
# =============================================================================


@app.get("/v1/waf/logs")
async def aws_waf_logs(_auth: BearerAuth, limit: int = Query(100, le=1000)) -> list[dict[str, Any]]:
    return waf_logs(limit=limit)


@app.post("/v1/waf/logs")
async def aws_waf_logs_post(_auth: BearerAuth, request: Request) -> list[dict[str, Any]]:
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    limit = body.get("limit", 100) if isinstance(body, dict) else 100
    return waf_logs(limit=min(limit, 1000))


# =============================================================================
# AWS GuardDuty  —  Bearer auth
# =============================================================================


@app.get("/v1/guardduty/findings")
async def aws_guardduty_findings_endpoint(_auth: BearerAuth, MaxResults: int = Query(50, le=50)) -> dict[str, Any]:
    return guardduty_findings(limit=MaxResults)


@app.post("/detector/{detector_id}/findings/get")
async def aws_guardduty_get_findings(_auth: BearerAuth, detector_id: str, request: Request) -> dict[str, Any]:
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    limit = len(body.get("FindingIds", [])) or 50
    return guardduty_findings(limit=min(limit, 50))


# =============================================================================
# Wiz  —  Bearer token auth (GraphQL)
# =============================================================================


@app.post("/graphql")
async def wiz_graphql(_auth: BearerAuth, request: Request) -> dict[str, Any]:
    body = await request.json()
    variables = body.get("variables", {})
    first = variables.get("first", 100)
    after = variables.get("after")
    return wiz_issues(first=first, after=after)


# =============================================================================
# Snyk  —  Bearer token auth
# =============================================================================


@app.get("/v1/org/{org_id}/issues")
async def snyk_org_issues(
    _auth: BearerAuth,
    org_id: str,
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
) -> dict[str, Any]:
    return snyk_issues(org=org_id, limit=limit, offset=offset)


@app.get("/v1/org/{org_id}/projects")
async def snyk_org_projects(_auth: BearerAuth, org_id: str) -> dict[str, Any]:
    return snyk_projects(org=org_id)


@app.get("/v1/org/{org_id}/audit")
async def snyk_org_audit(
    _auth: BearerAuth,
    org_id: str,
    limit: int = Query(100, le=1000),
    page: int = Query(1),
) -> list[dict[str, Any]]:
    return snyk_audit(org=org_id, limit=limit, page=page)


@app.get("/rest/orgs/{org_id}/issues")
async def snyk_rest_issues(
    _auth: BearerAuth,
    org_id: str,
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
) -> dict[str, Any]:
    return snyk_issues(org=org_id, limit=limit, offset=offset)


# =============================================================================
# Darktrace  —  HMAC auth (signature in Authorization header)
# =============================================================================


@app.get("/modelbreaches")
async def darktrace_model_breaches(
    request: Request,
    starttime: int | None = None,
    endtime: int | None = None,
    minscore: float = Query(0.0),
    limit: int = Query(50, le=200),
) -> list[dict[str, Any]]:
    # Darktrace uses a custom HMAC — for the mock we accept without verification
    return get_model_breaches(limit=limit, minscore=minscore)


@app.get("/aianalyst/incident/log")
async def darktrace_ai_analyst_log(
    request: Request,
    starttime: int | None = None,
    endtime: int | None = None,
    limit: int = Query(20, le=100),
) -> list[dict[str, Any]]:
    return get_analyst_incidents(limit=limit)


@app.get("/status")
async def darktrace_status_endpoint() -> dict[str, Any]:
    return darktrace_status()


# =============================================================================
# OAuth2 token endpoint  —  returns a mock access token for platforms that need it
# =============================================================================


@app.post("/oauth2/v1/token")
@app.post("/oauth2/token")
@app.post("/v2.0/token")
@app.post("/oauth2/v2.0/token")
async def oauth_token(request: Request) -> dict[str, Any]:
    return {
        "access_token": "apigenie-valid-token-001",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read:logs read:events",
    }


# Tenant-prefixed Microsoft token endpoint: /{tenant-id}/oauth2/v2.0/token
@app.post("/{tenant_id}/oauth2/v2.0/token")
async def oauth_token_tenant(tenant_id: str, request: Request) -> dict[str, Any]:
    return {
        "access_token": "apigenie-valid-token-001",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "https://graph.microsoft.com/.default",
    }


# =============================================================================
# Darktrace — additional endpoints
# =============================================================================


@app.get("/groups")
async def darktrace_groups(request: Request) -> list[dict[str, Any]]:
    return [
        {"id": i, "name": f"Device Group {i}", "size": random.randint(5, 150),
         "type": random.choice(["Client", "Server", "IoT", "Network"]),
         "score": round(random.uniform(0.0, 1.0), 3)}
        for i in range(1, random.randint(4, 8))
    ]


@app.get("/devices")
async def darktrace_devices(
    request: Request,
    count: int = Query(50, le=500),
) -> list[dict[str, Any]]:
    return [
        {"did": i, "ip": f"10.0.{i // 256}.{i % 256}",
         "hostname": f"host-{i:04d}.internal",
         "os": random.choice(["Windows", "Linux", "macOS", "iOS", "Android"]),
         "score": round(random.uniform(0.0, 1.0), 3)}
        for i in range(1, min(count, 50) + 1)
    ]
