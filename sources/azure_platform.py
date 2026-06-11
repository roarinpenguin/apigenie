"""Azure Platform (Event Hubs) event generator + mix catalog.

This module owns the template catalog for events streamed via the
Event Hubs / Kafka topic ``azure-platform-logs``. Historically the
generator lived inside ``publishers/kafka_publisher.py``; moving it here
lets the source participate in the Event Mix admin surface alongside the
other ``sources/<vendor>.py`` modules.

The Kafka publisher imports :func:`generate_azure_event` from this module
so the batch loop in the publisher stays untouched — this file is now the
single source of truth for the templates, the catalog ids, and the mix
wiring.

Event-mix axis: ``category × operationName``. The 14 templates cover both
the Azure Monitor diagnostic-settings stream (Administrative / Security /
Policy / ServiceHealth) and the Entra ID activity logs (SignInLogs /
AuditLogs / RiskyUsers) that flow into the same Event Hubs topic in real
deployments. Default weights are uniform (1/14) so the legacy
``random.choice`` distribution is preserved until an admin overrides it.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any

import event_mix
from generators import weighted_choice


# ── Event catalog (admin UI) ────────────────────────────────────────────────
# Each entry maps to one ``_AZURE_TEMPLATES`` key 1:1 so the catalog-template
# alignment test in ``tests/test_event_mix_sources.py`` stays exhaustive.
EVENT_CATALOG: list[dict[str, Any]] = [
    # Administrative / infrastructure plane
    {
        "id": "admin_vm_write",
        "label": "Administrative · VM write",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log",
    },
    {
        "id": "security_alert_activate",
        "label": "Security · alert activated",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/azure/defender-for-cloud/alerts-overview",
    },
    {
        "id": "policy_assignment_write",
        "label": "Policy · assignment write",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/azure/governance/policy/concepts/effects",
    },
    {
        "id": "service_health_activity",
        "label": "ServiceHealth · activity log",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/azure/service-health/service-health-overview",
    },
    # Entra ID — Sign-in logs
    {
        "id": "signin_success",
        "label": "SignInLogs · success",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins",
    },
    {
        "id": "signin_risky",
        "label": "SignInLogs · risky sign-in",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks",
    },
    # Entra ID — Audit logs (user lifecycle + entitlements)
    {
        "id": "audit_user_add",
        "label": "AuditLogs · Add user",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs",
    },
    {
        "id": "audit_user_update",
        "label": "AuditLogs · Update user",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs",
    },
    {
        "id": "audit_user_delete",
        "label": "AuditLogs · Delete user",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs",
    },
    {
        "id": "audit_group_member_add",
        "label": "AuditLogs · Add member to group",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs",
    },
    {
        "id": "audit_user_password_reset",
        "label": "AuditLogs · Reset password",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs",
    },
    # Entra ID — Identity Protection
    {
        "id": "risky_user_detected",
        "label": "RiskyUsers · risky user detected",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk",
    },
    # Entra ID — app / service-principal entitlements
    {
        "id": "audit_app_consent",
        "label": "AuditLogs · Consent to app",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent",
    },
    {
        "id": "audit_service_principal_add",
        "label": "AuditLogs · Add service principal",
        "default_weight": 1 / 14,
        "docs": "https://learn.microsoft.com/entra/identity-platform/app-objects-and-service-principals",
    },
]


# ── Internal templates keyed by catalog id ──────────────────────────────────
# Shape: ``{event_id: (payload, default_weight)}``. The optional ``_entra``
# and ``_risk`` flags branch the generator below into the Entra ID
# SignIn/Audit log envelope vs. the plain resource activity-log envelope.
_AZURE_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "admin_vm_write": ({
        "category": "Administrative",
        "operationName": "Microsoft.Compute/virtualMachines/write",
        "level": "Informational",
        "resourceType": "VIRTUAL MACHINES",
    }, 1 / 14),
    "security_alert_activate": ({
        "category": "Security",
        "operationName": "Microsoft.Security/securityAlerts/activate/action",
        "level": "Warning",
        "resourceType": "SECURITY ALERTS",
    }, 1 / 14),
    "policy_assignment_write": ({
        "category": "Policy",
        "operationName": "Microsoft.Authorization/policyAssignments/write",
        "level": "Informational",
        "resourceType": "POLICY ASSIGNMENTS",
    }, 1 / 14),
    "service_health_activity": ({
        "category": "ServiceHealth",
        "operationName": "Microsoft.Insights/activityLogs/write",
        "level": "Informational",
        "resourceType": "ACTIVITY LOGS",
    }, 1 / 14),
    "signin_success": ({
        "category": "SignInLogs",
        "operationName": "Sign-in activity",
        "level": "Informational",
        "resourceType": "SIGN-IN LOGS",
        "_entra": True,
    }, 1 / 14),
    "signin_risky": ({
        "category": "SignInLogs",
        "operationName": "Sign-in activity",
        "level": "Warning",
        "resourceType": "SIGN-IN LOGS",
        "_entra": True,
        "_risk": True,
    }, 1 / 14),
    "audit_user_add": ({
        "category": "AuditLogs",
        "operationName": "Add user",
        "level": "Informational",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    }, 1 / 14),
    "audit_user_update": ({
        "category": "AuditLogs",
        "operationName": "Update user",
        "level": "Informational",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    }, 1 / 14),
    "audit_user_delete": ({
        "category": "AuditLogs",
        "operationName": "Delete user",
        "level": "Warning",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    }, 1 / 14),
    "audit_group_member_add": ({
        "category": "AuditLogs",
        "operationName": "Add member to group",
        "level": "Informational",
        "resourceType": "GROUP MANAGEMENT",
        "_entra": True,
    }, 1 / 14),
    "audit_user_password_reset": ({
        "category": "AuditLogs",
        "operationName": "Reset user password",
        "level": "Informational",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    }, 1 / 14),
    "risky_user_detected": ({
        "category": "RiskyUsers",
        "operationName": "Risky user detected",
        "level": "Warning",
        "resourceType": "IDENTITY PROTECTION",
        "_entra": True,
        "_risk": True,
    }, 1 / 14),
    "audit_app_consent": ({
        "category": "AuditLogs",
        "operationName": "Consent to application",
        "level": "Informational",
        "resourceType": "APPLICATION MANAGEMENT",
        "_entra": True,
    }, 1 / 14),
    "audit_service_principal_add": ({
        "category": "AuditLogs",
        "operationName": "Add service principal",
        "level": "Informational",
        "resourceType": "SERVICE PRINCIPAL",
        "_entra": True,
    }, 1 / 14),
}


_ENTRA_USERS = [
    "jsmith@corp.onmicrosoft.com", "agarcia@corp.onmicrosoft.com",
    "mchen@corp.onmicrosoft.com", "kwilson@corp.onmicrosoft.com",
    "rbrown@corp.onmicrosoft.com", "ljohnson@corp.onmicrosoft.com",
    "tlee@corp.onmicrosoft.com", "nkowalski@corp.onmicrosoft.com",
]
_ENTRA_APPS = [
    "Microsoft Office 365", "Salesforce", "Slack", "AWS Console",
    "GitHub", "Zoom", "ServiceNow",
]
_ENTRA_LOCATIONS = [
    {"city": "New York", "state": "NY", "countryOrRegion": "US"},
    {"city": "London", "countryOrRegion": "GB"},
    {"city": "Berlin", "countryOrRegion": "DE"},
    {"city": "Tokyo", "countryOrRegion": "JP"},
    {"city": "São Paulo", "countryOrRegion": "BR"},
]


def generate_azure_event() -> dict[str, Any]:
    """Generate one Azure Platform event with the active event mix applied.

    Mix-eligibility is the *category × operationName* axis. Once the
    template is chosen the generator branches on ``_entra`` to emit the
    Sign-in / Audit log shape for Entra ID flows, or the plain resource
    activity-log shape for infra / security / policy flows. The Kafka
    publisher calls this once per message in a batch.
    """
    templates = event_mix.apply(_AZURE_TEMPLATES, "azure_platform")
    template = weighted_choice(templates)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    sub_id = "12345678-1234-1234-1234-123456789012"
    tenant_id = "a5a18162-7e4d-4b85-8f5b-b1e4c8d73d25"

    # ── Entra ID user-activity events (SignInLogs / AuditLogs / RiskyUsers) ──
    if template.get("_entra"):
        user = random.choice(_ENTRA_USERS)
        user_id = str(uuid.uuid4())
        location = random.choice(_ENTRA_LOCATIONS)
        is_risk = template.get("_risk", False)

        event = {
            "time": now,
            "tenantId": tenant_id,
            "category": template["category"],
            "operationName": template["operationName"],
            "operationVersion": "1.0",
            "resultType": "failure" if is_risk else random.choice(["success", "failure"]),
            "resultSignature": "None" if is_risk else "None",
            "correlationId": str(uuid.uuid4()),
            "level": template["level"],
            "callerIpAddress": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "identity": user,
            "properties": {
                "id": str(uuid.uuid4()),
                "userDisplayName": user.split("@")[0].replace(".", " ").title(),
                "userPrincipalName": user,
                "userId": user_id,
                "appId": str(uuid.uuid4()),
                "appDisplayName": random.choice(_ENTRA_APPS),
                "ipAddress": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "location": location,
                "clientAppUsed": random.choice([
                    "Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync",
                ]),
                "deviceDetail": {
                    "deviceId": str(uuid.uuid4()),
                    "operatingSystem": random.choice([
                        "Windows 10", "macOS", "iOS", "Android", "Linux",
                    ]),
                    "browser": random.choice([
                        "Chrome 130", "Safari 17", "Edge 130", "Firefox 128",
                    ]),
                    "isCompliant": random.choice([True, False]),
                    "isManaged": random.choice([True, False]),
                },
                "status": {
                    "errorCode": 50126 if is_risk else 0,
                    "failureReason": "Invalid username or password" if is_risk else None,
                },
                "resourceType": template["resourceType"],
            },
        }
        if is_risk:
            event["properties"]["riskDetail"] = random.choice([
                "unfamiliarFeatures", "anonymizedIPAddress", "impossibleTravel",
                "maliciousIPAddress", "leakedCredentials",
            ])
            event["properties"]["riskLevelDuringSignIn"] = random.choice([
                "low", "medium", "high",
            ])
        return event

    # ── Standard Azure platform event (infra / policy / security) ───────────
    return {
        "time": now,
        "resourceId": (
            f"/subscriptions/{sub_id}/resourceGroups/rg-prod/providers/"
            f"Microsoft.Compute/virtualMachines/vm-{uuid.uuid4().hex[:8]}"
        ),
        "operationName": template["operationName"],
        "category": template["category"],
        "level": template["level"],
        "resultType": random.choice(["Success", "Start", "Failed"]),
        "correlationId": str(uuid.uuid4()),
        "identity": {
            "authorization": {
                "scope": f"/subscriptions/{sub_id}",
                "action": template["operationName"],
            },
            "claims": {"appid": str(uuid.uuid4()), "name": "AzurePortal"},
        },
        "properties": {
            "statusCode": random.choice([
                "Created", "OK", "Accepted", "BadRequest",
            ]),
            "serviceRequestId": str(uuid.uuid4()),
            "resourceType": template["resourceType"],
        },
    }
