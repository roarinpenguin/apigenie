"""Cisco Duo mock data generator."""

import random
from typing import Any

from generators import (
    generate_country_code,
    generate_email,
    generate_ip,
    generate_uuid,
    now_epoch,
    now_epoch_ms,
    weighted_choice,
)

_USERS = ["john.doe@example.com", "jane.smith@corp.com", "admin@acme.org", "service.account@example.com"]
_FACTORS = ["duo_push", "phone_call", "passcode", "hardware_token", "bypass_code"]
_REASONS = {
    "SUCCESS": ["user_approved", "valid_passcode", "remembered_device"],
    "FAILURE": ["user_denied", "no_response", "invalid_passcode", "factor_disabled"],
    "FRAUD": ["user_marked_fraud"],
    "ERROR": ["user_not_enrolled", "locked_out", "no_active_auth_methods"],
}

_AUTH_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "success": ({"result": "SUCCESS"}, 0.70),
    "failure": ({"result": "FAILURE"}, 0.15),
    "fraud": ({"result": "FRAUD"}, 0.10),
    "error": ({"result": "ERROR"}, 0.05),
}

_ADMIN_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "admin_login": ({"action": "admin_login", "description": "Administrator logged in"}, 0.40),
    "user_create": ({"action": "user_create", "description": "User created"}, 0.25),
    "policy_update": ({"action": "update_policy", "description": "Policy updated"}, 0.20),
    "integration_update": ({"action": "update_integration", "description": "Integration updated"}, 0.10),
    "group_create": ({"action": "group_create", "description": "Group created"}, 0.05),
}


def _make_auth_log(mintime: int | None = None, maxtime: int | None = None) -> dict[str, Any]:
    template = weighted_choice(_AUTH_TEMPLATES)
    result = template["result"]
    reason = random.choice(_REASONS[result])
    ts = now_epoch() - random.randint(0, 3600)
    if mintime:
        ts = max(ts, mintime)
    if maxtime:
        ts = min(ts, maxtime)

    return {
        "access_device": {
            "browser": random.choice(["Chrome", "Firefox", "Safari"]),
            "browser_version": "120.0",
            "flash_version": "uninstalled",
            "hostname": None,
            "ip": generate_ip(),
            "is_encryption_enabled": True,
            "is_firewall_enabled": True,
            "is_password_set": True,
            "java_version": "uninstalled",
            "location": {
                "city": random.choice(["New York", "London", "Tokyo", "Berlin"]),
                "country": generate_country_code(),
                "state": "",
            },
            "os": random.choice(["Windows", "Mac OS X", "iOS", "Android"]),
            "os_version": "10.0",
            "security_agents": [],
        },
        "alias": "",
        "application": {
            "key": f"DI{generate_uuid()[:18].upper()}",
            "name": random.choice(["VPN", "AWS Console", "Corporate Portal", "Jira"]),
        },
        "auth_device": {
            "ip": generate_ip(),
            "key": f"DP{generate_uuid()[:18].upper()}",
            "location": {
                "city": random.choice(["Seattle", "Chicago", "Austin"]),
                "country": generate_country_code(),
                "state": "",
            },
            "name": f"iPhone {random.randint(12, 15)} ({random.choice(_USERS).split('@')[0]})",
            "type": "Apple iOS",
        },
        "email": random.choice(_USERS),
        "event_type": "authentication",
        "factor": random.choice(_FACTORS),
        "isotimestamp": f"{ts}",
        "ood_software": None,
        "reason": reason,
        "result": result,
        "timestamp": ts,
        "trusted_endpoint_status": "not trusted",
        "txid": generate_uuid(),
        "user": {
            "groups": [random.choice(["Engineering", "Sales", "HR", "Executives", "IT"])],
            "key": f"DU{generate_uuid()[:18].upper()}",
            "name": random.choice(_USERS),
        },
    }


def get_auth_logs_response(limit: int = 100, mintime: int | None = None, maxtime: int | None = None) -> dict[str, Any]:
    count = min(limit, 100)
    logs = [_make_auth_log(mintime, maxtime) for _ in range(count)]
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    next_offset = None
    if count == limit:
        next_offset = [logs[-1]["timestamp"] * 1000 + 1, generate_uuid()]
    return {
        "stat": "OK",
        "response": logs,
        "metadata": {
            "next_offset": next_offset,
            "total_objects": count,
        },
    }


def get_admin_logs_response(limit: int = 100, mintime: int | None = None) -> dict[str, Any]:
    count = min(limit, 50)
    logs = []
    for _ in range(count):
        template = weighted_choice(_ADMIN_TEMPLATES)
        ts = now_epoch() - random.randint(0, 7200)
        if mintime:
            ts = max(ts, mintime)
        logs.append(
            {
                "action": template["action"],
                "description": template["description"],
                "isotimestamp": f"{ts}",
                "object": random.choice(_USERS),
                "timestamp": ts,
                "username": "admin@example.com",
            }
        )
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return {
        "stat": "OK",
        "response": logs,
        "metadata": {"next_offset": None, "total_objects": count},
    }
