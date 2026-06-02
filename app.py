"""ApiGenie — standalone HTTP mock server for 17 security platform APIs + 16 push sources.

Routes mirror the real platform API paths so Observo Site telemetry collector
can connect without any URL rewriting.
"""

import json
import logging
import os
import random
import time as _time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime as _dt, timezone as _tz
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from admin import router as admin_router
from auth import BearerAuth, BasicAuth, DuoAuth, XApiKeysAuth
from trace import TraceMiddleware
import listeners as _listeners
from state import (
    tenable_export_exists,
    tenable_get_chunks,
    tenable_store_export,
)

# Source data generators
# NOTE: AWS sources (CloudTrail, WAF, GuardDuty) intentionally not imported here.
# Real Observo collectors fetch them via SQS-notified S3 polling, which apigenie
# cannot emulate with HTTP endpoints. The generators in sources/aws_*.py are
# preserved for a future LocalStack-based stack (see docs/LOCALSTACK_PLAN.md).
from sources.azure_ad import get_audit_logs_response as entra_audit, get_signin_logs_response as entra_signin
from sources.cisco_duo import get_admin_logs_response as duo_admin, get_auth_logs_response as duo_auth
from sources.darktrace import get_analyst_incidents, get_model_breaches, get_status as darktrace_status
from sources.gcp_audit import get_audit_logs_response as gcp_audit
from sources.m365 import get_content_response as m365_content, get_subscriptions_response as m365_subscriptions
from sources.microsoft_defender import get_alerts_response as defender_alerts, get_recommendations_response as defender_recs
from sources.netskope import get_alerts_response as netskope_alerts, get_audit_events_response as netskope_audit
from sources.okta import get_logs_response as okta_logs
from sources.proofpoint import get_logs_response as proofpoint_logs
from sources.snyk import (
    get_audit_logs_response as snyk_audit,
    get_issues_response as snyk_issues,
    get_issues_response_jsonapi as snyk_issues_jsonapi,
    get_projects_response as snyk_projects,
)
from sources.tenable import generate_asset_chunks, generate_vuln_chunks, get_audit_logs_response as tenable_audit
from sources.wiz import get_issues_response as wiz_issues
from sources.cato import generate_events as cato_events
from sources.cloudflare import generate_events as cloudflare_events
from sources.zscaler_zpa import generate_events as zpa_events
from sources.sentinelone import generate_threats as s1_threats, generate_activities as s1_activities, generate_agents as s1_agents
from sources.mimecast import generate_siem_response as mimecast_siem, generate_ttp_impersonation_response as mimecast_ttp_impersonation

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

_publishers_enabled = os.environ.get("PUBLISHERS_ENABLED", "true").lower() == "true"

# Public-facing hostname for URLs returned in payloads (e.g. EPM ManagerURL).
DOMAIN = os.environ.get("APIGENIE_DOMAIN", "apigenie.example.com")


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
    try:
        import bus_monitor
        bus_monitor.start()
    except Exception as exc:
        logger.warning(f"Could not start bus monitor: {exc}")
    try:
        import sysmon
        sysmon.start()
    except Exception as exc:
        logger.warning(f"Could not start sysmon: {exc}")
    yield
    if _publishers_enabled:
        try:
            from publishers import kafka_publisher, pubsub_publisher
            kafka_publisher.stop()
            pubsub_publisher.stop()
        except Exception:
            pass
    try:
        import bus_monitor
        bus_monitor.stop()
    except Exception:
        pass
    try:
        import sysmon
        sysmon.stop()
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


# Lightweight bus-source probe — allows seed-fake-traffic.sh and the bus
# monitor to inject traceable azure_platform entries via HTTP.
@app.get("/api/bus/azure")
async def bus_azure_probe() -> dict[str, str]:
    return {"status": "ok", "source": "azure_platform", "transport": "kafka"}


@app.get("/stats")
async def public_stats() -> dict[str, Any]:
    """Public (no auth) stats for the landing page."""
    enabled = sum(1 for l in _listeners.LISTENERS.values() if l.enabled)
    return {
        "http_sources": 11 + enabled,
        "streaming_sources": 2,
        "auth_schemes": 5,
        "custom_listeners": enabled,
    }


# =============================================================================
# Fake Google OAuth2 token endpoint
#
# Some collectors do not honour PUBSUB_EMULATOR_HOST and will run the full
# RFC 7523 service-account flow: sign a JWT with the SA private key and POST
# it to the SA JSON's "token_uri". Real Google then rejects the assertion
# with "Invalid grant: account not found" because our mock SA does not exist.
#
# We point token_uri at this endpoint (in /admin/gcp-sa.json) and return a
# synthetic access token so the collector proceeds to the data-plane Pub/Sub
# call, which it then sends to our emulator on port 8085.
# =============================================================================


@app.post("/oauth2/token")
@app.post("/token")  # alias — some clients hit /token directly
async def oauth2_token(request: Request) -> JSONResponse:
    # We accept anything — no JWT validation, no grant_type check. The mock's
    # job is to keep the collector moving past the OAuth step.
    try:
        await request.body()  # drain
    except Exception:
        pass
    return JSONResponse({
        "access_token": "apigenie-fake-oauth-access-token",
        "token_type":   "Bearer",
        "expires_in":   3600,
        "scope":        "https://www.googleapis.com/auth/pubsub https://www.googleapis.com/auth/cloud-platform",
    })


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
async def netskope_alerts_endpoint(
    _auth: BearerAuth,
    limit: int = Query(100, le=10000),
    type: str | None = Query(None, description="Netskope alert_type filter, e.g. DLP, Malware, anomaly"),
) -> dict[str, Any]:
    return netskope_alerts(limit=limit, alert_type=type)


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
# Microsoft 365 Management Activity API  —  Bearer token auth
# =============================================================================
# Mimics the O365 Management Activity API used by collectors to pull audit logs.
# Same OAuth2 tenant token flow as Entra ID.


@app.get("/v1.0/security/alerts_v2")
async def graph_security_alerts_v2(
    _auth: BearerAuth,
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
    filter: str = Query("", alias="$filter"),
    orderby: str = Query("", alias="$orderby"),
    skiptoken: str = Query("", alias="$skiptoken"),
) -> dict[str, Any]:
    """Graph API security alerts (v2) — used by M365 collectors with INGEST_SECURITY_ALERTS=true."""
    data = m365_content(content_type="Audit.General", limit=min(top, 50))
    # Wrap events as Graph security alerts format
    alerts = []
    for ev in data["events"]:
        alerts.append({
            "id": ev.get("Id", str(uuid.uuid4())),
            "title": ev.get("Operation", "Security Event"),
            "description": f"{ev.get('Workload', 'M365')} - {ev.get('Operation', 'event')}",
            "severity": ev.get("severity", "medium"),
            "status": "new",
            "createdDateTime": ev.get("CreationTime", _dt.now(_tz.utc).isoformat()),
            "lastUpdateDateTime": ev.get("CreationTime", _dt.now(_tz.utc).isoformat()),
            "category": ev.get("Workload", "General"),
            "userStates": [{"userPrincipalName": ev.get("UserId", ""), "accountName": ev.get("UserId", "").split("@")[0] if "@" in ev.get("UserId", "") else ""}],
            "hostStates": [{"netBiosName": "", "publicIpAddress": ev.get("ClientIP", "")}],
            "vendorInformation": {"provider": "Microsoft", "vendor": "Microsoft", "subProvider": ev.get("Workload", "")},
            "rawEvent": ev,
        })
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2", "value": alerts}


@app.get("/api/v1.0/{tenant_id}/activity/feed/subscriptions/list")
async def m365_subscriptions_list(_auth: BearerAuth, tenant_id: str) -> list[dict[str, Any]]:
    return m365_subscriptions()


@app.post("/api/v1.0/{tenant_id}/activity/feed/subscriptions/start")
async def m365_subscriptions_start(
    _auth: BearerAuth, tenant_id: str,
    contentType: str = Query("Audit.General"),
) -> dict[str, Any]:
    return {"contentType": contentType, "status": "enabled", "webhook": None}


@app.get("/api/v1.0/{tenant_id}/activity/feed/subscriptions/content")
async def m365_content_feed(
    _auth: BearerAuth, tenant_id: str,
    contentType: str = Query("Audit.General"),
    PublisherIdentifier: str = Query(""),
) -> list[dict[str, Any]]:
    data = m365_content(content_type=contentType)
    return data["blobs"]


@app.get("/api/v1.0/{tenant_id}/activity/feed/audit/{content_id}")
async def m365_content_blob(
    _auth: BearerAuth, tenant_id: str, content_id: str,
    contentType: str = Query("Audit.General"),
) -> list[dict[str, Any]]:
    data = m365_content(content_type=contentType, limit=10)
    return data["events"]


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


# Microsoft Defender XDR / Graph Security API paths.
# Many collectors integrate with Defender via graph.microsoft.com/v1.0/security/...
# rather than the Azure Resource Manager /subscriptions/... routes.
@app.get("/v1.0/security/alerts_v2")
@app.get("/v1.0/security/alerts")
async def defender_graph_alerts(_auth: BearerAuth, top: int = Query(50, alias="$top", le=500)) -> dict[str, Any]:
    return defender_alerts(limit=top)


@app.get("/v1.0/security/incidents")
async def defender_graph_incidents(_auth: BearerAuth, top: int = Query(50, alias="$top", le=500)) -> dict[str, Any]:
    return defender_alerts(limit=top)


@app.get("/v1.0/security/recommendations")
async def defender_graph_recommendations(_auth: BearerAuth, top: int = Query(25, alias="$top", le=500)) -> dict[str, Any]:
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


async def _duo_telephony_response(
    limit: int,
    mintime: int | None,
    maxtime: int | None,
) -> dict[str, Any]:
    # Reuse auth-log generator with telephony-flavoured contexts. Real Duo telephony
    # rows include phone/voice fields; we synthesise a representative subset here.
    base = duo_auth(limit=limit, mintime=mintime, maxtime=maxtime)
    resp = base.get("response", [])
    # duo_auth returns {"response": [...]} as a flat list; older code looked for
    # {"response": {"authlogs": [...]}} which yielded an empty telephony array.
    if isinstance(resp, dict):
        rows = resp.get("authlogs", [])
    elif isinstance(resp, list):
        rows = resp
    else:
        rows = []
    telephony = [
        {
            "timestamp": r.get("timestamp"),
            "context": random.choice(["administrator login", "authentication", "enrollment"]),
            "credits": random.randint(1, 5),
            "phone": f"+1555{random.randint(1000000, 9999999)}",
            "type": random.choice(["sms", "phone"]),
            "eventtype": "telephony",
        }
        for r in rows
    ]
    return {"stat": "OK", "response": telephony, "metadata": {"total_objects": len(telephony)}}


@app.get("/admin/v1/logs/telephony")
async def duo_telephony_logs_v1(
    _auth: DuoAuth,
    mintime: int | None = None,
    maxtime: int | None = None,
    limit: int = Query(100, le=1000),
) -> dict[str, Any]:
    # Duo v1 telephony API uses seconds — pass through as-is.
    return await _duo_telephony_response(limit, mintime, maxtime)


@app.get("/admin/v2/logs/telephony")
async def duo_telephony_logs_v2(
    _auth: DuoAuth,
    mintime: int | None = None,
    maxtime: int | None = None,
    limit: int = Query(100, le=1000),
) -> dict[str, Any]:
    # Duo v2 telephony API uses milliseconds — convert before passing to the
    # generator, which uses seconds internally (matches /admin/v2/logs/authentication).
    mintime_s = mintime // 1000 if mintime else None
    maxtime_s = maxtime // 1000 if maxtime else None
    return await _duo_telephony_response(limit, mintime_s, maxtime_s)


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
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    f: str | None = Query(None),       # Tenable filter, e.g. f=date.gt:2026-04-08T00:44:33.000Z
    next: str | None = Query(None),    # Tenable cursor pagination token
) -> dict[str, Any]:
    # Real Tenable supports cursor pagination via 'next'; for the mock we treat
    # 'next' as a numeric offset when parseable, otherwise ignore.
    if next:
        try:
            offset = max(offset, int(next))
        except (TypeError, ValueError):
            pass
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
# AWS sources (CloudTrail, WAF, GuardDuty) — NOT EXPOSED via HTTP
#
# All three are delivered to customers via S3 (CloudTrail / WAF) or SQS-notified
# S3 (GuardDuty). Real Observo collectors poll those AWS services directly using
# the AWS SDK, with hostnames hardcoded to *.amazonaws.com and SigV4 host-header
# binding. Without an S3-compatible mock + SQS mock (see docs/LOCALSTACK_PLAN.md)
# there is no useful HTTP shape to expose here. The sources/aws_*.py data
# generators remain in the tree for that future integration.
# =============================================================================


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


# Some collectors (Observo's Wiz source included) probe the GraphQL endpoint
# with GET before issuing the first POST query. Real Wiz returns 405 here, but
# the probe treats anything non-200 as 'service unreachable' and never
# proceeds to authenticate. Return a minimal GraphQL handshake instead.
@app.get("/graphql")
async def wiz_graphql_probe() -> dict[str, Any]:
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"name": "Issue"}, {"name": "CloudResource"}, {"name": "User"}],
            }
        }
    }


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
    version: str | None = Query(None),     # required by real Snyk REST API
    limit: int = Query(100, le=1000),
    starting_after: str | None = Query(None),
) -> dict[str, Any]:
    # Snyk REST API speaks JSON:API; the response wraps issues under 'data'.
    return snyk_issues_jsonapi(org=org_id, limit=limit, starting_after=starting_after)


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
@app.get("/aianalyst/incidentevents")
async def darktrace_ai_analyst_log(
    request: Request,
    starttime: int | None = None,
    endtime: int | None = None,
    includeallpinned: bool | None = None,
    limit: int = Query(20, le=100),
) -> list[dict[str, Any]]:
    return get_analyst_incidents(limit=limit)


@app.get("/status")
async def darktrace_status_endpoint() -> dict[str, Any]:
    return darktrace_status()


# =============================================================================
# OAuth2 / login / token-exchange endpoints
# Every flow below returns a mock bearer that the rest of the API will accept.
# Multiple field-name synonyms are emitted so different collector libraries
# (httpx, Vector, Cribl, Azure SDK, vendor SDKs) can pick the one they expect.
# =============================================================================


def _token_payload(scope: str = "read:logs read:events") -> dict[str, Any]:
    """Standard OAuth2 + vendor-synonym token payload."""
    tok = "apigenie-valid-token-001"
    return {
        "access_token": tok,
        "accessToken": tok,   # Cyera, BigID camelCase
        "token": tok,         # Tenable, Cyera login response
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": scope,
    }


def _make_unsecured_jwt(sub: str = "apigenie", scope: str = "kafka") -> str:
    """Create an unsecured JWT (alg: none) for Kafka SASL/OAUTHBEARER.

    Kafka's built-in OAuthBearerUnsecuredValidatorCallbackHandler accepts
    tokens with {"alg":"none"} in the header and checks for a "sub" claim
    plus non-expired "exp". No signature verification is performed.
    """
    import base64 as _b64
    now = int(_time.time())
    header = '{"alg":"none"}'
    payload = json.dumps({
        "sub": sub,
        "iat": now,
        "exp": now + 3600,
        "scope": scope,
    }, separators=(",", ":"))
    h = _b64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
    p = _b64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()
    return f"{h}.{p}."


def _oauthbearer_token_payload(scope: str = "kafka") -> dict[str, Any]:
    """Token response suitable for librdkafka OIDC OAUTHBEARER flow."""
    tok = _make_unsecured_jwt(sub="apigenie-kafka-client", scope=scope)
    return {
        "access_token": tok,
        "token_type": "Bearer",
        "expires_in": 3600,
    }


# Generic OAuth2 client-credentials  —  used by Wiz, Cato, CyberArk EPM and any
# collector configured with a bare /token URL.
@app.post("/token")
@app.post("/oauth/token")
@app.post("/oauth2/v1/token")
@app.post("/oauth2/token")
@app.post("/v2.0/token")
@app.post("/oauth2/v2.0/token")
async def oauth_token(request: Request) -> dict[str, Any]:
    return _token_payload()


# Tenant-prefixed Microsoft token endpoints — Defender + Entra ID + O365 Mgmt.
# POST is the spec; GET is what some Azure SDKs use when impersonating cached
# refresh tokens (and what COLLECTOR_CONFIG.md §2.3 documents).
#
# When the scope contains ".servicebus.windows.net" or the grant is for Event
# Hubs, this is a Kafka OAUTHBEARER token request from librdkafka — return an
# unsecured JWT that Kafka's built-in validator will accept.
@app.post("/{tenant_id}/oauth2/v2.0/token")
@app.get("/{tenant_id}/oauth2/v2.0/token")
@app.post("/{tenant_id}/oauth2/token")
@app.get("/{tenant_id}/oauth2/token")
async def oauth_token_tenant(tenant_id: str, request: Request) -> dict[str, Any]:
    # Detect Event Hubs OAUTHBEARER request from librdkafka
    try:
        form = await request.form()
        scope = str(form.get("scope", ""))
    except Exception:
        scope = ""
    # Kafka OAUTHBEARER: only for Event Hubs (servicebus.windows.net)
    if "servicebus.windows.net" in scope or "eventhubs" in scope.lower():
        logger.info("OAUTHBEARER token request from tenant %s (scope: %s)", tenant_id, scope)
        return _oauthbearer_token_payload(scope=scope or "kafka")
    # M365 / Graph / other Microsoft services: return a JWT with proper claims
    effective_scope = scope or "https://graph.microsoft.com/.default"
    all_permissions = "ActivityFeed.Read ActivityFeed.ReadDlp SecurityEvents.Read.All ServiceHealth.Read.All"
    import base64 as _b64
    now = int(_time.time())
    header = '{"alg":"RS256","typ":"JWT","kid":"apigenie-mock-key"}'
    payload_obj = {
        "aud": effective_scope.replace("/.default", ""),
        "iss": f"https://sts.windows.net/{tenant_id}/",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "sub": "apigenie-client",
        "appid": "apigenie-client",
        "tid": tenant_id,
        "roles": ["ActivityFeed.Read", "ActivityFeed.ReadDlp", "SecurityEvents.Read.All",
                   "ServiceHealth.Read.All", "User.Read.All", "Directory.Read.All",
                   "Mail.Read", "AuditLog.Read.All"],
        "scp": all_permissions,
    }
    payload_str = json.dumps(payload_obj, separators=(",", ":"))
    h = _b64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
    p = _b64.urlsafe_b64encode(payload_str.encode()).rstrip(b"=").decode()
    # Fake signature (not validated by our endpoints)
    fake_sig = _b64.urlsafe_b64encode(b"apigenie-mock-signature-not-validated").rstrip(b"=").decode()
    jwt_token = f"{h}.{p}.{fake_sig}"
    return {
        "access_token": jwt_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": f"{effective_scope} {all_permissions}",
        "ext_expires_in": 3600,
        "resource": effective_scope.replace("/.default", ""),
    }


# Tenable refresh-access-token (GET, no body) — collector calls this with its
# X-ApiKeys credentials and uses the returned bearer for subsequent calls.
@app.get("/api/v1/refresh-access-token")
async def tenable_refresh_token(request: Request) -> dict[str, Any]:
    return _token_payload(scope="tenable:read")


# Cyera login / refresh
@app.post("/v1/login")
@app.post("/v1/refresh")
async def cyera_login(request: Request) -> dict[str, Any]:
    return _token_payload(scope="cyera:read")


# CyberArk EPM / Cisco Duo logon — returns a session token in EPM-flavoured
# fields plus the standard OAuth synonyms so generic collectors can extract it.
@app.post("/epm/api/auth/epm/logon")
async def epm_logon(request: Request) -> dict[str, Any]:
    payload = _token_payload(scope="epm:read")
    payload["SessionId"] = payload["access_token"]
    payload["ManagerURL"] = f"https://{DOMAIN}"
    return payload


# Mimecast discover-authentication — the gateway URI the collector should hit
# for subsequent calls (we point it back at ourselves).
@app.post("/api/login/discover-authentication")
async def mimecast_discover(request: Request) -> dict[str, Any]:
    return {
        "fail": [],
        "data": [{
            "region": "eu",
            "authenticate": [{
                "uri": f"https://{DOMAIN}",
                "name": "TOTPAuthentication",
            }],
            "emailToken": "apigenie-valid-token-001",
        }],
    }


# =============================================================================
# Darktrace — additional endpoints
# =============================================================================


@app.get("/groups")
@app.get("/aianalyst/groups")
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


# =============================================================================
# Cato Networks  —  GraphQL API, x-api-key header auth
# =============================================================================


@app.post("/api/v1/graphql2")
async def cato_graphql(request: Request) -> dict[str, Any]:
    api_key = request.headers.get("x-api-key", "")
    if not api_key:
        raise HTTPException(401, "Missing x-api-key header")
    body = await request.json()
    query_str = body.get("query", "")
    variables = body.get("variables", {})
    count = variables.get("first", variables.get("last", 20))
    if "eventsFeed" in query_str:
        events = cato_events(count=min(count, 100))
        marker = events[-1].get("time", "") if events else ""
        return {"data": {"eventsFeed": {"marker": marker, "fetchedCount": len(events), "accounts": [
            {"id": "12345", "records": events}
        ]}}}
    elif "auditFeed" in query_str:
        events = [e for e in cato_events(count=min(count, 50)) if e.get("event_type") == "Audit"]
        if not events:
            events = cato_events(count=5)
        marker = events[-1].get("time", "") if events else ""
        return {"data": {"auditFeed": {"marker": marker, "fetchedCount": len(events), "accounts": [
            {"id": "12345", "records": events}
        ]}}}
    elif "accountMetrics" in query_str or "accountSnapshot" in query_str:
        return {"data": {"accountSnapshot": {"sites": [
            {"id": "100", "name": "HQ-NewYork", "connState": "connected"},
            {"id": "101", "name": "Branch-London", "connState": "connected"},
        ]}}}
    else:
        return {"data": {}, "errors": [{"message": "Unknown query"}]}


# =============================================================================
# Cloudflare  —  Logpull REST API + GraphQL Analytics
# =============================================================================


@app.get("/client/v4/zones/{zone_id}/logs/received")
async def cloudflare_logpull(_auth: BearerAuth, zone_id: str,
                              count: int = Query(20, le=1000)) -> JSONResponse:
    events = cloudflare_events(count=min(count, 200))
    # Cloudflare Logpull returns newline-delimited JSON
    import json as _json
    ndjson = "\n".join(_json.dumps(e) for e in events) + "\n"
    return JSONResponse(content=events)


@app.get("/client/v4/zones/{zone_id}/dns_analytics/report")
async def cloudflare_dns_analytics(_auth: BearerAuth, zone_id: str) -> dict[str, Any]:
    events = [e for e in cloudflare_events(count=30) if e.get("event_type") == "dns_event"]
    if not events:
        events = cloudflare_events(count=5)
    return {"result": {"rows": events, "totals": {"queryCount": len(events)}},
            "success": True, "errors": [], "messages": []}


@app.get("/client/v4/zones/{zone_id}/firewall/events")
async def cloudflare_firewall_events(_auth: BearerAuth, zone_id: str,
                                       per_page: int = Query(20, le=200)) -> dict[str, Any]:
    events = [e for e in cloudflare_events(count=per_page)
              if e.get("event_type") in ("firewall_event", "waf_event")]
    if not events:
        events = cloudflare_events(count=5)
    return {"result": events, "success": True, "result_info": {
        "page": 1, "per_page": per_page, "total_count": len(events), "count": len(events)
    }}


@app.get("/client/v4/accounts/{account_id}/access/logs/access_requests")
async def cloudflare_access_logs(_auth: BearerAuth, account_id: str,
                                   limit: int = Query(20)) -> dict[str, Any]:
    events = [e for e in cloudflare_events(count=limit) if e.get("event_type") == "access_event"]
    if not events:
        events = cloudflare_events(count=5)
    return {"result": events, "success": True, "result_info": {"count": len(events)}}


@app.get("/client/v4/accounts/{account_id}/gateway/audit_logs")
async def cloudflare_gateway_logs(_auth: BearerAuth, account_id: str,
                                    limit: int = Query(20)) -> dict[str, Any]:
    events = [e for e in cloudflare_events(count=limit) if e.get("event_type") == "gateway_event"]
    if not events:
        events = cloudflare_events(count=5)
    return {"result": events, "success": True}


# =============================================================================
# Zscaler ZPA  —  REST API, Bearer token auth
# =============================================================================


@app.get("/mgmtconfig/v1/admin/customers/{customer_id}/auditLogEntryReport")
async def zpa_audit_logs(_auth: BearerAuth, customer_id: str,
                          page: int = Query(1), pagesize: int = Query(20)) -> dict[str, Any]:
    events = zpa_events(count=min(pagesize, 100))
    return {"list": events, "totalPages": 1, "totalCount": len(events)}


@app.get("/mgmtconfig/v2/admin/customers/{customer_id}/userActivity")
async def zpa_user_activity(_auth: BearerAuth, customer_id: str,
                             page: int = Query(1), pagesize: int = Query(20)) -> dict[str, Any]:
    events = [e for e in zpa_events(count=min(pagesize, 100)) if e.get("event_type") == "user_activity"]
    if not events:
        events = zpa_events(count=10)
    return {"list": events, "totalPages": 1, "totalCount": len(events)}


@app.get("/mgmtconfig/v1/admin/customers/{customer_id}/connectorStatus")
async def zpa_connector_status(_auth: BearerAuth, customer_id: str) -> dict[str, Any]:
    events = [e for e in zpa_events(count=10) if e.get("event_type") == "connector_status"]
    if not events:
        events = zpa_events(count=5)
    return {"list": events, "totalCount": len(events)}


@app.get("/mgmtconfig/v1/admin/customers/{customer_id}/healthStatus")
async def zpa_health_status(_auth: BearerAuth, customer_id: str) -> dict[str, Any]:
    events = [e for e in zpa_events(count=10) if e.get("event_type") == "health"]
    if not events:
        events = zpa_events(count=5)
    return {"list": events, "totalCount": len(events)}


# =============================================================================
# Mimecast  —  API 2.0, OAuth2 client credentials + SIEM events
# =============================================================================


@app.post("/oauth/token")
async def mimecast_oauth_token(request: Request) -> dict[str, Any]:
    """Mimecast OAuth2 client_credentials token endpoint."""
    form = await request.form()
    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret", "")
    if grant_type != "client_credentials" or not client_id or not client_secret:
        return JSONResponse({"error": "invalid_request",
                             "error_description": "grant_type must be client_credentials with client_id and client_secret"},
                            status_code=400)
    # Generate a mock Bearer token
    import base64 as _b64, json as _json, time as _time
    payload = {"client_id": client_id, "exp": int(_time.time()) + 1800, "scope": "siem.events.read"}
    token = _b64.b64encode(_json.dumps(payload).encode()).decode()
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 1800,
        "scope": "siem.events.read",
    }


@app.get("/siem/v1/events/cg")
async def mimecast_siem_events(request: Request,
                                type: str = Query("", description="Event type filter"),
                                limit: int = Query(100, le=500),
                                token: str = Query("", description="Pagination token")) -> JSONResponse:
    """Mimecast SIEM API 2.0 — Cloud Gateway events stream."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return JSONResponse({"fail": [{"errors": [{"code": "err_xdk_client_unauthorized",
                             "message": "Authorization header missing or invalid"}]}]},
                            status_code=401)
    resp = mimecast_siem(count=min(limit, 200), event_type=type, token=token)
    # Set mc-siem-token in response header (real Mimecast does this)
    next_token = resp.get("meta", {}).get("pagination", {}).get("next", "")
    headers = {}
    if next_token:
        headers["mc-siem-token"] = next_token
    return JSONResponse(content=resp, headers=headers)


@app.get("/siem/v1/batch/events/cg")
async def mimecast_siem_batch(request: Request,
                               type: str = Query("", description="Event type filter"),
                               limit: int = Query(500, le=5000),
                               token: str = Query("", description="Pagination token")) -> JSONResponse:
    """Mimecast SIEM API 2.0 — Cloud Gateway batch events (larger page size)."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return JSONResponse({"fail": [{"errors": [{"code": "err_xdk_client_unauthorized",
                             "message": "Authorization header missing or invalid"}]}]},
                            status_code=401)
    resp = mimecast_siem(count=min(limit, 500), event_type=type, token=token)
    next_token = resp.get("meta", {}).get("pagination", {}).get("next", "")
    headers = {}
    if next_token:
        headers["mc-siem-token"] = next_token
    return JSONResponse(content=resp, headers=headers)


@app.post("/api/ttp/impersonation/get-logs")
async def mimecast_ttp_impersonation_logs(request: Request) -> dict[str, Any]:
    """Mimecast TTP Impersonation Protect logs — dedicated endpoint.

    Matches the real Mimecast POST /api/ttp/impersonation/get-logs API.
    Auth: MC (HMAC-SHA1) or Bearer token (mock accepts any Authorization header).
    """
    auth = request.headers.get("authorization", "")
    if not auth:
        return JSONResponse({"fail": [{"errors": [{"code": "err_xdk_client_unauthorized",
                             "message": "Authorization header missing"}]}]},
                            status_code=401)
    # Parse optional pagination from request body
    page_size = 25
    page_token = ""
    try:
        body = await request.json()
        meta = body.get("meta", {})
        pag = meta.get("pagination", {})
        page_size = min(pag.get("pageSize", 25), 500)
        page_token = pag.get("pageToken", "")
    except Exception:
        pass
    return mimecast_ttp_impersonation(count=page_size, page_token=page_token)


# =============================================================================
# SentinelOne Singularity  —  Management Console API v2.1, ApiToken auth
# =============================================================================


@app.get("/web/api/v2.1/threats")
async def s1_threats_list(request: Request,
                          limit: int = Query(10, le=1000)) -> dict[str, Any]:
    token = request.headers.get("authorization", "")
    if not token:
        return JSONResponse({"errors": [{"code": 4010011, "detail": "Unauthorized", "title": "Unauthorized"}]}, 401)
    return s1_threats(count=min(limit, 200))


@app.get("/web/api/v2.1/activities")
async def s1_activities_list(request: Request,
                              limit: int = Query(10, le=1000)) -> dict[str, Any]:
    token = request.headers.get("authorization", "")
    if not token:
        return JSONResponse({"errors": [{"code": 4010011, "detail": "Unauthorized", "title": "Unauthorized"}]}, 401)
    return s1_activities(count=min(limit, 200))


@app.get("/web/api/v2.1/agents")
async def s1_agents_list(request: Request,
                          limit: int = Query(10, le=200)) -> dict[str, Any]:
    token = request.headers.get("authorization", "")
    if not token:
        return JSONResponse({"errors": [{"code": 4010011, "detail": "Unauthorized", "title": "Unauthorized"}]}, 401)
    return s1_agents(count=min(limit, 50))


# See docs/CUSTOM_LISTENERS.md
#
# A single catch-all route handles ALL configured listeners. We resolve the
# config from the in-memory LISTENERS dict, run auth + chaos + rate-limit,
# record the hit, and return a stub response. TraceMiddleware skips this
# prefix (listener traffic has its own per-listener trace pane in admin).
# =============================================================================

@app.api_route(
    "/listener/{lid}/{rest:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"],
)
async def listener_dispatch(lid: str, rest: str, request: Request):
    listener = _listeners.LISTENERS.get(lid)
    t0 = _time.monotonic()
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""

    # Helper: record + return. Centralised so every code path emits a hit.
    def _finish(status: int, body: Any, content_type: str,
                identity: str = "anon", extra_headers: dict[str, str] | None = None):
        ts_iso = _dt.now(_tz.utc).isoformat(timespec="seconds")
        duration_ms = int((_time.monotonic() - t0) * 1000)
        client_ip = request.client.host if request.client else "?"
        # Prefer X-Forwarded-For if nginx forwarded one
        xff = request.headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",", 1)[0].strip() or client_ip
        if listener is not None:
            import json as _json
            resp_str = body if isinstance(body, str) else _json.dumps(body, default=str)
            entry = _listeners.make_hit(
                ts=ts_iso, method=request.method, path="/" + rest,
                query=str(request.query_params) if request.query_params else "",
                client=client_ip, status=status, identity=identity,
                headers=dict(request.headers), body=body_str,
                duration_ms=duration_ms,
                resp_body=resp_str, resp_size=len(resp_str),
            )
            _listeners.record_hit(lid, entry)
        if isinstance(body, str):
            resp = PlainTextResponse(body, status_code=status, media_type=content_type)
        else:
            resp = JSONResponse(body, status_code=status, media_type=content_type)
        if extra_headers:
            for k, v in extra_headers.items():
                resp.headers[k] = v
        return resp

    if listener is None or not listener.enabled:
        return _finish(404, {"error": "listener_not_found", "id": lid}, "application/json")

    # Path/method match. The configured listener.path is treated as the prefix
    # under /listener/<id>/...
    expected = listener.path.lstrip("/")
    if rest != expected and not rest.startswith(expected + "/"):
        return _finish(404, {
            "error": "path_mismatch", "expected": "/" + expected, "got": "/" + rest,
        }, "application/json")
    if request.method != listener.method and request.method != "HEAD":
        return _finish(405, {
            "error": "method_not_allowed", "expected": listener.method, "got": request.method,
        }, "application/json")

    # Auth
    ok, identity = _listeners.check_auth(listener.auth, dict(request.headers))
    if not ok:
        return _finish(401, {"error": "unauthorized", "reason": identity}, "application/json", identity)

    # Rate-limit / chaos
    injected = _listeners.maybe_inject_status(listener)
    if injected is not None:
        return _finish(injected, {"error": "injected", "status": injected}, "application/json", identity)

    body, ctype, extra = _listeners.build_response(listener, dict(request.query_params))
    return _finish(200, body, ctype, identity, extra)
