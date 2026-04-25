"""Wiz Security mock data generator (GraphQL API)."""

import random
from typing import Any

from generators import (
    generate_ip,
    generate_uuid,
    now_iso,
    weighted_choice,
)

_RESOURCE_TYPES = ["VirtualMachine", "Bucket", "ContainerImage", "KubernetesCluster", "DatabaseInstance", "LoadBalancer"]
_ENVIRONMENTS = ["Production", "Staging", "Development", "Testing"]
_CLOUDS = ["AWS", "Azure", "GCP", "OCI"]
_PROJECTS = ["prod-infra", "staging", "dev-team", "security"]

_ISSUE_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "issue": (
        {
            "type": "TOXIC_COMBINATION",
            "status": "OPEN",
            "severity": "MEDIUM",
            "title": "Exposed service running as root",
            "description": "A publicly exposed service is running as root with a critical vulnerability.",
        },
        0.40,
    ),
    "critical_vulnerability": (
        {
            "type": "VULNERABILITY",
            "status": "OPEN",
            "severity": "CRITICAL",
            "title": "Critical Remote Code Execution Vulnerability",
            "description": "A critical RCE vulnerability was found in the workload.",
        },
        0.20,
    ),
    "open_security_group": (
        {
            "type": "MISCONFIGURATION",
            "status": "OPEN",
            "severity": "HIGH",
            "title": "Security group allows unrestricted inbound access",
            "description": "Inbound security group rule allows unrestricted access (0.0.0.0/0) on sensitive port.",
        },
        0.15,
    ),
    "exposed_secret": (
        {
            "type": "SECRET_IN_CODE",
            "status": "OPEN",
            "severity": "CRITICAL",
            "title": "Secret exposed in repository",
            "description": "A hardcoded secret or API key was found in source code or configuration.",
        },
        0.10,
    ),
    "iam_misconfiguration": (
        {
            "type": "IAM_MISCONFIGURATION",
            "status": "OPEN",
            "severity": "HIGH",
            "title": "Overly permissive IAM role",
            "description": "An IAM role grants excessive permissions that violate least privilege principle.",
        },
        0.08,
    ),
    "container_vulnerability": (
        {
            "type": "VULNERABILITY",
            "status": "IN_PROGRESS",
            "severity": "HIGH",
            "title": "Vulnerable container image in production",
            "description": "A container image with known high-severity CVEs is running in production.",
        },
        0.05,
    ),
    "k8s_misconfiguration": (
        {
            "type": "MISCONFIGURATION",
            "status": "OPEN",
            "severity": "MEDIUM",
            "title": "Kubernetes pod running as root",
            "description": "A Kubernetes pod is running as root without read-only filesystem.",
        },
        0.02,
    ),
}


def _generate_issue() -> dict[str, Any]:
    template = weighted_choice(_ISSUE_TEMPLATES)
    resource_type = random.choice(_RESOURCE_TYPES)
    cloud = random.choice(_CLOUDS)
    project = random.choice(_PROJECTS)
    issue_id = generate_uuid()
    resource_id = generate_uuid()

    return {
        "id": issue_id,
        "type": template["type"],
        "status": template["status"],
        "severity": template["severity"],
        "createdAt": now_iso(),
        "updatedAt": now_iso(),
        "resolvedAt": None,
        "dueAt": None,
        "projects": [{"id": generate_uuid(), "name": project, "slug": project}],
        "entity": {
            "id": resource_id,
            "name": f"{resource_type.lower()}-{generate_uuid()[:8]}",
            "type": resource_type,
        },
        "entitySnapshot": {
            "id": resource_id,
            "type": resource_type,
            "nativeType": resource_type,
            "name": f"{resource_type.lower()}-{generate_uuid()[:8]}",
            "status": "Active",
            "cloudPlatform": cloud,
            "cloudProviderURL": f"https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#Instances:instanceId={resource_id}",
            "providerId": f"{cloud.lower()}-{generate_uuid()[:12]}",
            "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "subscription": {
                "id": generate_uuid(),
                "name": f"{project}-account",
                "externalId": f"{random.randint(100000000000, 999999999999)}",
            },
            "tags": {
                "Environment": random.choice(_ENVIRONMENTS),
                "Team": random.choice(["Platform", "Security", "DevOps", "Backend"]),
            },
        },
        "control": {
            "id": generate_uuid(),
            "name": template["title"],
            "description": template["description"],
            "severity": template["severity"],
            "type": template["type"],
        },
        "sourceRules": [],
        "note": None,
        "ticket": None,
    }


def get_issues_response(first: int = 100, after: str | None = None) -> dict[str, Any]:
    count = min(first, 100)
    nodes = [_generate_issue() for _ in range(count)]
    end_cursor = generate_uuid() if count == first else None
    return {
        "data": {
            "issues": {
                "nodes": nodes,
                "pageInfo": {
                    "hasNextPage": count == first,
                    "endCursor": end_cursor,
                },
                "totalCount": count + random.randint(0, 500),
            }
        }
    }
