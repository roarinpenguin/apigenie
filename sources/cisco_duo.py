"""Cisco Duo mock data generator.

Event catalog sourced from the Cisco Duo Admin API docs
(``duo.com/docs/adminapi``). Two endpoint families ship today:

* ``/admin/v1/logs/authentication`` — ``auth.*`` events.
* ``/admin/v1/logs/administrator`` — ``admin.*`` events.

The per-template dicts (``_AUTH_TEMPLATES`` / ``_ADMIN_TEMPLATES``) key on
the same ids declared in ``EVENT_CATALOG`` so an admin can toggle and
reweight them via ``event_mix``.
"""

import random
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    epoch_to_iso,
    generate_country_code,
    generate_email,
    generate_ip,
    generate_uuid,
    now_epoch,
    now_epoch_ms,
    weighted_choice,
)

# ── Event catalog ────────────────────────────────────────────────────────────
# Mapped to the Duo Admin API event taxonomy (``duo.com/docs/adminapi``).
# Defaults match the historical weights so existing callers see no behaviour
# change until an admin opts in to a custom mix.
EVENT_CATALOG: list[dict[str, Any]] = [
    # ── /admin/v1/logs/authentication ──
    {"id": "auth.success", "label": "Authentication success",
     "endpoint": "authentication", "default_weight": 0.70,
     "docs_anchor": "duo.com/docs/adminapi#authentication-logs"},
    {"id": "auth.failure", "label": "Authentication failure",
     "endpoint": "authentication", "default_weight": 0.15,
     "docs_anchor": "duo.com/docs/adminapi#authentication-logs"},
    {"id": "auth.fraud", "label": "Marked fraud by user",
     "endpoint": "authentication", "default_weight": 0.10,
     "docs_anchor": "duo.com/docs/adminapi#authentication-logs"},
    {"id": "auth.error", "label": "Authentication error",
     "endpoint": "authentication", "default_weight": 0.05,
     "docs_anchor": "duo.com/docs/adminapi#authentication-logs"},
    # ── /admin/v1/logs/administrator ──
    {"id": "admin.admin_login", "label": "Administrator logged in",
     "endpoint": "administrator", "default_weight": 0.40,
     "docs_anchor": "duo.com/docs/adminapi#retrieve-administrator-logs"},
    {"id": "admin.user_create", "label": "User created",
     "endpoint": "administrator", "default_weight": 0.25,
     "docs_anchor": "duo.com/docs/adminapi#retrieve-administrator-logs"},
    {"id": "admin.policy_update", "label": "Policy updated",
     "endpoint": "administrator", "default_weight": 0.20,
     "docs_anchor": "duo.com/docs/adminapi#retrieve-administrator-logs"},
    {"id": "admin.integration_update", "label": "Integration updated",
     "endpoint": "administrator", "default_weight": 0.10,
     "docs_anchor": "duo.com/docs/adminapi#retrieve-administrator-logs"},
    {"id": "admin.group_create", "label": "Group created",
     "endpoint": "administrator", "default_weight": 0.05,
     "docs_anchor": "duo.com/docs/adminapi#retrieve-administrator-logs"},
]

_USERS = ["john.doe@example.com", "jane.smith@corp.com", "admin@acme.org", "service.account@example.com"]
_FACTORS = ["duo_push", "phone_call", "passcode", "hardware_token", "bypass_code"]
_REASONS = {
    "SUCCESS": ["user_approved", "valid_passcode", "remembered_device"],
    "FAILURE": ["user_denied", "no_response", "invalid_passcode", "factor_disabled"],
    "FRAUD": ["user_marked_fraud"],
    "ERROR": ["user_not_enrolled", "locked_out", "no_active_auth_methods"],
}

# Keys deliberately match the EVENT_CATALOG ids so event_mix overrides apply
# 1:1. Renaming a key here without updating the catalog (or vice versa) will
# fail the catalog-coverage test in tests/test_event_mix.py.
# ── Persona projection ────────────────────────────────────────────────
# Duo authentication logs nest the principal under ``user.name`` (the
# Duo username, typically a UPN-shape email) and the access device's
# IP under ``access_device.ip``. ``email`` is a top-level alias Duo
# keeps for backwards-compatibility — projecting both keeps every
# consumer in sync. The country lives under
# ``access_device.location.country`` (2-letter ISO).
PERSONA_PROJECTION: dict[str, str] = {
    "email":                            "victim_user.email",
    "user.name":                        "victim_user.email",
    "access_device.ip":                 "attacker.ip",
    "access_device.location.country":   "attacker.country",
}


_AUTH_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "auth.success": ({"result": "SUCCESS"}, 0.70),
    "auth.failure": ({"result": "FAILURE"}, 0.15),
    "auth.fraud":   ({"result": "FRAUD"},   0.10),
    "auth.error":   ({"result": "ERROR"},   0.05),
}

_ADMIN_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "admin.admin_login":         ({"action": "admin_login",         "description": "Administrator logged in"}, 0.40),
    "admin.user_create":         ({"action": "user_create",         "description": "User created"},          0.25),
    "admin.policy_update":       ({"action": "update_policy",       "description": "Policy updated"},        0.20),
    "admin.integration_update":  ({"action": "update_integration",  "description": "Integration updated"},   0.10),
    "admin.group_create":        ({"action": "group_create",        "description": "Group created"},         0.05),
}


def _make_auth_log(mintime: int | None = None, maxtime: int | None = None, ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    template = weighted_choice(event_mix.apply(_AUTH_TEMPLATES, "cisco_duo"))
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
        "email": _duo_email(ctx),
        "event_type": "authentication",
        "factor": random.choice(_FACTORS),
        "isotimestamp": epoch_to_iso(ts),
        "ood_software": None,
        "reason": reason,
        "result": result,
        "timestamp": ts,
        "trusted_endpoint_status": "not trusted",
        "txid": generate_uuid(),
        "user": {
            "groups": [random.choice(["Engineering", "Sales", "HR", "Executives", "IT"])],
            "key": f"DU{generate_uuid()[:18].upper()}",
            "name": _duo_email(ctx),
        },
    }


def _duo_email(ctx: profiles.ProfileContext | None) -> str:
    pu = ctx.pick_user() if ctx else None
    if pu:
        return pu.get("email") or f"{pu.get('username', 'user')}@{pu.get('domain', 'example.com').lower()}.com"
    return random.choice(_USERS)


def get_auth_logs_response(limit: int = 100, mintime: int | None = None, maxtime: int | None = None) -> dict[str, Any]:
    ctx = profiles.get_context("cisco_duo")
    count = profiles.scale_count("cisco_duo", min(limit, 100))
    logs = [_make_auth_log(mintime, maxtime, ctx) for _ in range(count)]
    logs = detection_rules.inject_detection_events("cisco_duo", logs)
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
    admin_templates = event_mix.apply(_ADMIN_TEMPLATES, "cisco_duo")
    for _ in range(count):
        template = weighted_choice(admin_templates)
        ts = now_epoch() - random.randint(0, 7200)
        if mintime:
            ts = max(ts, mintime)
        logs.append(
            {
                "action": template["action"],
                "description": template["description"],
                "isotimestamp": epoch_to_iso(ts),
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
