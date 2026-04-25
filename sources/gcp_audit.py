"""GCP Audit Logs mock data generator (for Pub/Sub publishing)."""

import json
import random
from typing import Any

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

_LOG_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "admin_activity": ({"logName": "cloudaudit.googleapis.com%2Factivity", "severity": "NOTICE"}, 0.50),
    "data_access": ({"logName": "cloudaudit.googleapis.com%2Fdata_access", "severity": "INFO"}, 0.25),
    "iam_policy_change": ({"logName": "cloudaudit.googleapis.com%2Factivity", "severity": "WARNING"}, 0.15),
    "system_event": ({"logName": "cloudaudit.googleapis.com%2Fsystem_event", "severity": "INFO"}, 0.10),
}


def generate_audit_log(project: str | None = None) -> dict[str, Any]:
    template = weighted_choice(_LOG_TEMPLATES)
    project = project or random.choice(_PROJECTS)
    service = random.choice(_SERVICES)
    method = random.choice(_METHODS.get(service, ["unknownMethod"]))
    principal = generate_email()
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
                "callerIp": generate_ip(),
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
    count = min(limit, 50)
    entries = [generate_audit_log(project) for _ in range(count)]
    return {"entries": entries}


def generate_pubsub_message(project: str | None = None) -> bytes:
    """Generate a Pub/Sub message payload (JSON-encoded audit log)."""
    log = generate_audit_log(project)
    return json.dumps(log).encode("utf-8")
