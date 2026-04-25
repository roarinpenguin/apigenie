"""Microsoft Entra ID (Azure AD) mock data generator."""

import random
from typing import Any

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
    count = min(limit, 50)
    logs = []
    for _ in range(count):
        template = weighted_choice(_AUDIT_TEMPLATES)
        user_login, user_name = random.choice(_USERS)
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
                        "ipAddress": generate_ip(),
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
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/directoryAudits", "value": logs}


def get_signin_logs_response(limit: int = 50, skip: int = 0) -> dict[str, Any]:
    count = min(limit, 50)
    logs = []
    for _ in range(count):
        template = weighted_choice(_SIGNIN_TEMPLATES)
        user_login, user_name = random.choice(_USERS)
        log = {
            "id": generate_uuid(),
            "createdDateTime": now_iso(),
            "userDisplayName": user_name,
            "userPrincipalName": _make_user_principal(user_login),
            "userId": generate_uuid(),
            "appId": generate_uuid(),
            "appDisplayName": random.choice(["Microsoft Azure Portal", "Microsoft Teams", "Office 365"]),
            "ipAddress": generate_ip(),
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
                "city": random.choice(["Seattle", "London", "Tokyo", "Paris", "Sydney"]),
                "state": "",
                "countryOrRegion": generate_country_code(),
                "geoCoordinates": {},
            },
        }
        logs.append(log)
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", "value": logs}
