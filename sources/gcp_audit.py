"""GCP Audit Logs mock data generator (for Pub/Sub publishing).

Event catalog grounded in the Cloud Audit Logs taxonomy
(``cloud.google.com/logging/docs/audit``). The four log types match
GCP's Activity / Data Access / Policy Denied / System Event categories.
"""

import json
import random
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    generate_email,
    generate_ip,
    generate_uuid,
    now_iso,
    weighted_choice,
)

_PROJECTS = ["my-project-123", "prod-project-456", "staging-project-789"]
_SERVICES = [
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
    "compute.googleapis.com",
    "bigquery.googleapis.com",
]
_METHODS = {
    "cloudresourcemanager.googleapis.com": ["CreateProject", "DeleteProject", "SetIamPolicy", "GetIamPolicy"],
    "iam.googleapis.com": ["CreateServiceAccount", "DeleteServiceAccount", "SetIamPolicy", "CreateRole"],
    "storage.googleapis.com": ["storage.buckets.create", "storage.objects.get", "storage.objects.create"],
    "compute.googleapis.com": ["compute.instances.insert", "compute.instances.delete", "compute.firewalls.insert"],
    "bigquery.googleapis.com": ["google.cloud.bigquery.v2.TableService.InsertTable", "jobservice.query"],
}

# ── Event catalog ──────────────────────────────────────────────────────
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "admin_activity", "label": "Admin Activity (mutations)",
     "default_weight": 0.50,
     "docs_anchor": "cloud.google.com/logging/docs/audit#admin-activity"},
    {"id": "data_access", "label": "Data Access (reads / queries)",
     "default_weight": 0.25,
     "docs_anchor": "cloud.google.com/logging/docs/audit#data-access"},
    {"id": "iam_policy_change", "label": "IAM policy change (SetIamPolicy)",
     "default_weight": 0.15,
     "docs_anchor": "cloud.google.com/iam/docs/audit-logging"},
    {"id": "system_event", "label": "System event (GCP-initiated)",
     "default_weight": 0.10,
     "docs_anchor": "cloud.google.com/logging/docs/audit#system-event"},
]

_LOG_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "admin_activity": ({"logName": "cloudaudit.googleapis.com%2Factivity", "severity": "NOTICE"}, 0.50),
    "data_access": ({"logName": "cloudaudit.googleapis.com%2Fdata_access", "severity": "INFO"}, 0.25),
    "iam_policy_change": ({"logName": "cloudaudit.googleapis.com%2Factivity", "severity": "WARNING"}, 0.15),
    "system_event": ({"logName": "cloudaudit.googleapis.com%2Fsystem_event", "severity": "INFO"}, 0.10),
}


def generate_audit_log(project: str | None = None, ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    template = weighted_choice(event_mix.apply(_LOG_TEMPLATES, "gcp_audit"))
    project = project or random.choice(_PROJECTS)
    service = random.choice(_SERVICES)
    method = random.choice(_METHODS.get(service, ["unknownMethod"]))
    pu = ctx.pick_user() if ctx else None
    if pu:
        principal = pu.get("email") or f"{pu.get('username', 'user')}@{pu.get('domain', 'example.com').lower()}.com"
        caller_ip = pu.get("workstation_ip") or generate_ip()
    else:
        principal = generate_email()
        caller_ip = generate_ip()
    log_id = generate_uuid()

    return {
        "insertId": log_id,
        "logName": f"projects/{project}/logs/{template['logName']}",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "authenticationInfo": {
                "principalEmail": principal,
                "principalSubject": f"user:{principal}",
            },
            "authorizationInfo": [
                {
                    "granted": True,
                    "permission": f"{service.split('.')[0]}.{method.lower()}",
                    "resource": f"projects/{project}",
                    "resourceAttributes": {},
                }
            ],
            "methodName": method,
            "requestMetadata": {
                "callerIp": caller_ip,
                "callerSuppliedUserAgent": "google-cloud-sdk/453.0.0",
            },
            "resourceName": f"projects/{project}",
            "serviceName": service,
            "status": {},
        },
        "receiveTimestamp": now_iso(),
        "resource": {
            "labels": {"project_id": project},
            "type": "project",
        },
        "severity": template["severity"],
        "timestamp": now_iso(),
    }


def get_audit_logs_response(limit: int = 50, project: str | None = None) -> dict[str, Any]:
    ctx = profiles.get_context("gcp_audit")
    count = profiles.scale_count("gcp_audit", min(limit, 50))
    entries = [generate_audit_log(project, ctx) for _ in range(count)]
    entries = detection_rules.inject_detection_events("gcp_audit", entries)
    return {"entries": entries}


def generate_pubsub_message(project: str | None = None) -> bytes:
    """Generate a Pub/Sub message payload (JSON-encoded audit log)."""
    ctx = profiles.get_context("gcp_audit")
    log = generate_audit_log(project, ctx)
    return json.dumps(log).encode("utf-8")
