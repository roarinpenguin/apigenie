"""Microsoft Entra ID (Azure AD) mock data generator.

Event catalog grounded in the Microsoft Graph audit + signin schemas
(``learn.microsoft.com/en-us/graph/api/resources/directoryaudit`` and
``learn.microsoft.com/en-us/graph/api/resources/signin``). Like cisco_duo,
the catalogue spans two endpoint families — each entry carries an
``endpoint`` key so the catalog-coverage test sums weights per family.
"""

import random
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    generate_country_code,
    generate_email,
    generate_ip,
    generate_uuid,
    now_iso,
    weighted_choice,
)

_USERS = [
    ("john.doe", "John Doe"),
    ("jane.smith", "Jane Smith"),
    ("admin", "Global Administrator"),
    ("svc-account", "Service Account"),
    ("mike.jones", "Mike Jones"),
]

# ── Event catalog ──────────────────────────────────────────────────────
EVENT_CATALOG: list[dict[str, Any]] = [
    # /v1.0/auditLogs/directoryAudits
    {"id": "audit", "label": "User update (directory audit)",
     "endpoint": "directoryAudits", "default_weight": 0.40,
     "docs_anchor": "learn.microsoft.com/en-us/graph/api/resources/directoryaudit"},
    {"id": "mfa_required", "label": "MFA registration",
     "endpoint": "directoryAudits", "default_weight": 0.20,
     "docs_anchor": "learn.microsoft.com/en-us/graph/api/resources/directoryaudit"},
    {"id": "conditional_access_block", "label": "Conditional Access block (add member to role)",
     "endpoint": "directoryAudits", "default_weight": 0.15,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policies"},
    {"id": "risky_signin", "label": "Risky user confirmed safe (Identity Protection)",
     "endpoint": "directoryAudits", "default_weight": 0.10,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks"},
    {"id": "service_principal_auth", "label": "Service principal added",
     "endpoint": "directoryAudits", "default_weight": 0.10,
     "docs_anchor": "learn.microsoft.com/en-us/graph/api/resources/serviceprincipal"},
    {"id": "impossible_travel", "label": "Impossible travel detected",
     "endpoint": "directoryAudits", "default_weight": 0.05,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#impossible-travel"},
    # /v1.0/auditLogs/signIns
    {"id": "success", "label": "Sign-in success",
     "endpoint": "signIns", "default_weight": 0.65,
     "docs_anchor": "learn.microsoft.com/en-us/graph/api/resources/signin"},
    {"id": "mfa_interrupted", "label": "Sign-in interrupted by MFA (errorCode 50074)",
     "endpoint": "signIns", "default_weight": 0.15,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes"},
    {"id": "ca_block", "label": "Sign-in blocked by Conditional Access (53003)",
     "endpoint": "signIns", "default_weight": 0.10,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes"},
    {"id": "invalid_password", "label": "Invalid username or password (50126)",
     "endpoint": "signIns", "default_weight": 0.07,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes"},
    {"id": "risky", "label": "Risky sign-in (atRisk)",
     "endpoint": "signIns", "default_weight": 0.03,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks"},
]

_AUDIT_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "audit": (
        {
            "operationType": "Update",
            "result": "success",
            "activityDisplayName": "Update user",
            "category": "UserManagement",
            "loggedByService": "Core Directory",
        },
        0.40,
    ),
    "mfa_required": (
        {
            "operationType": "Add",
            "result": "success",
            "activityDisplayName": "User registered security info",
            "category": "UserManagement",
            "loggedByService": "MFA",
        },
        0.20,
    ),
    "conditional_access_block": (
        {
            "operationType": "Add",
            "result": "failure",
            "activityDisplayName": "Add member to role",
            "category": "RoleManagement",
            "loggedByService": "Conditional Access",
        },
        0.15,
    ),
    "risky_signin": (
        {
            "operationType": "Update",
            "result": "success",
            "activityDisplayName": "Risky user confirmed safe",
            "category": "IdentityProtection",
            "loggedByService": "Identity Protection",
        },
        0.10,
    ),
    "service_principal_auth": (
        {
            "operationType": "Add",
            "result": "success",
            "activityDisplayName": "Add service principal",
            "category": "ApplicationManagement",
            "loggedByService": "Core Directory",
        },
        0.10,
    ),
    "impossible_travel": (
        {
            "operationType": "Update",
            "result": "failure",
            "activityDisplayName": "Impossible travel detected",
            "category": "IdentityProtection",
            "loggedByService": "Identity Protection",
        },
        0.05,
    ),
}

_SIGNIN_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "success": ({"status": {"errorCode": 0, "failureReason": None}, "conditionalAccessStatus": "success"}, 0.65),
    "mfa_interrupted": (
        {"status": {"errorCode": 50074, "failureReason": "Strong Authentication required."}, "conditionalAccessStatus": "failure"},
        0.15,
    ),
    "ca_block": (
        {"status": {"errorCode": 53003, "failureReason": "Blocked by Conditional Access."}, "conditionalAccessStatus": "failure"},
        0.10,
    ),
    "invalid_password": (
        {"status": {"errorCode": 50126, "failureReason": "Invalid username or password."}, "conditionalAccessStatus": "notApplied"},
        0.07,
    ),
    "risky": (
        {"status": {"errorCode": 0, "failureReason": None}, "conditionalAccessStatus": "success", "riskState": "atRisk"},
        0.03,
    ),
}


def _make_user_principal(login: str) -> str:
    domain = random.choice(["contoso.com", "example.org", "acme.onmicrosoft.com"])
    return f"{login}@{domain}"


def get_audit_logs_response(limit: int = 50, skip: int = 0) -> dict[str, Any]:
    ctx = profiles.get_context("azure_ad")
    count = profiles.scale_count("azure_ad", min(limit, 50))
    logs = []
    audit_templates = event_mix.apply(_AUDIT_TEMPLATES, "azure_ad")
    for _ in range(count):
        template = weighted_choice(audit_templates)
        pu = ctx.pick_user() if ctx else None
        if pu:
            user_login = pu.get("username", "user")
            user_name = pu.get("name", user_login)
            user_ip = pu.get("workstation_ip") or generate_ip()
        else:
            user_login, user_name = random.choice(_USERS)
            user_ip = generate_ip()
        logs.append(
            {
                "id": generate_uuid(),
                "category": template["category"],
                "correlationId": generate_uuid(),
                "result": template["result"],
                "resultReason": "",
                "activityDisplayName": template["activityDisplayName"],
                "activityDateTime": now_iso(),
                "loggedByService": template["loggedByService"],
                "operationType": template["operationType"],
                "initiatedBy": {
                    "user": {
                        "id": generate_uuid(),
                        "displayName": user_name,
                        "userPrincipalName": _make_user_principal(user_login),
                        "ipAddress": user_ip,
                    }
                },
                "targetResources": [
                    {
                        "id": generate_uuid(),
                        "displayName": user_name,
                        "type": "User",
                        "userPrincipalName": _make_user_principal(user_login),
                    }
                ],
                "additionalDetails": [],
            }
        )
    logs = detection_rules.inject_detection_events("azure_ad", logs)
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/directoryAudits", "value": logs}


def get_signin_logs_response(limit: int = 50, skip: int = 0) -> dict[str, Any]:
    ctx = profiles.get_context("azure_ad")
    count = min(limit, 50)
    logs = []
    signin_templates = event_mix.apply(_SIGNIN_TEMPLATES, "azure_ad")
    for _ in range(count):
        template = weighted_choice(signin_templates)
        pu = ctx.pick_user() if ctx else None
        if pu:
            user_login = pu.get("username", "user")
            user_name = pu.get("name", user_login)
            signin_ip = pu.get("workstation_ip") or generate_ip()
            signin_city = pu.get("city", "Seattle")
        else:
            user_login, user_name = random.choice(_USERS)
            signin_ip = generate_ip()
            signin_city = random.choice(["Seattle", "London", "Tokyo", "Paris", "Sydney"])
        log = {
            "id": generate_uuid(),
            "createdDateTime": now_iso(),
            "userDisplayName": user_name,
            "userPrincipalName": _make_user_principal(user_login),
            "userId": generate_uuid(),
            "appId": generate_uuid(),
            "appDisplayName": random.choice(["Microsoft Azure Portal", "Microsoft Teams", "Office 365"]),
            "ipAddress": signin_ip,
            "clientAppUsed": random.choice(["Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync"]),
            "correlationId": generate_uuid(),
            "conditionalAccessStatus": template["conditionalAccessStatus"],
            "isInteractive": random.random() < 0.8,
            "riskDetail": "none",
            "riskLevelAggregated": "none",
            "riskLevelDuringSignIn": "none",
            "riskState": template.get("riskState", "none"),
            "status": template["status"],
            "deviceDetail": {
                "deviceId": "",
                "displayName": "",
                "operatingSystem": random.choice(["Windows 10", "macOS", "iOS", "Android"]),
                "browser": random.choice(["Chrome 120.0.0", "Firefox 121.0", "Safari 17.0"]),
            },
            "location": {
                "city": signin_city,
                "state": "",
                "countryOrRegion": generate_country_code(),
                "geoCoordinates": {},
            },
        }
        logs.append(log)
    logs = detection_rules.inject_detection_events("azure_ad", logs)
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", "value": logs}
