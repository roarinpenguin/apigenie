"""Netskope Alerts and Audit Events mock data generator."""

import random
from typing import Any

from generators import (
    generate_country_code,
    generate_email,
    generate_hostname,
    generate_ip,
    generate_uuid,
    now_epoch,
    weighted_choice,
)

_USERS = ["alice@example.com", "bob@corp.com", "charlie@acme.org", "diana@testco.io", "evan@sample.net"]
_APPS = ["Dropbox", "Google Drive", "OneDrive", "Box", "Slack", "Zoom", "Office 365"]
_CATEGORIES = ["Cloud Storage", "Collaboration", "Social Media", "Email", "Productivity"]

_ALERT_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "alert": (
        {
            "alert_type": "policy",
            "alert_name": "Sensitive Data Upload Detected",
            "action": "alert",
            "category": "Cloud Storage",
            "severity": "low",
        },
        0.55,
    ),
    "dlp_violation": (
        {
            "alert_type": "dlp",
            "alert_name": "DLP Policy Violation - Credit Card Numbers",
            "action": "block",
            "category": "Cloud Storage",
            "severity": "high",
        },
        0.20,
    ),
    "malware_detection": (
        {
            "alert_type": "malware",
            "alert_name": "Malware Detected in Upload",
            "action": "block",
            "category": "Cloud Storage",
            "severity": "critical",
        },
        0.12,
    ),
    "anomalous_activity": (
        {
            "alert_type": "anomaly",
            "alert_name": "Anomalous Upload Volume Detected",
            "action": "alert",
            "category": "Collaboration",
            "severity": "medium",
        },
        0.08,
    ),
    "shadow_it": (
        {
            "alert_type": "policy",
            "alert_name": "Unsanctioned Cloud App Usage",
            "action": "alert",
            "category": "Cloud Storage",
            "severity": "low",
        },
        0.03,
    ),
    "insider_threat": (
        {
            "alert_type": "uba",
            "alert_name": "Insider Threat: Mass Download Before Resignation",
            "action": "block",
            "category": "Cloud Storage",
            "severity": "critical",
        },
        0.02,
    ),
}


def _generate_alert() -> dict[str, Any]:
    template = weighted_choice(_ALERT_TEMPLATES)
    app = random.choice(_APPS)
    user = random.choice(_USERS)
    ts = now_epoch() - random.randint(0, 3600)

    return {
        "_id": generate_uuid(),
        "timestamp": ts,
        "type": "alert",
        "alert_type": template["alert_type"],
        "alert_name": template["alert_name"],
        "action": template["action"],
        "app": app,
        "appcategory": template["category"],
        "category": template["category"],
        "severity": template["severity"],
        "user": user,
        "srcip": generate_ip(),
        "dstip": generate_ip(),
        "hostname": generate_hostname(),
        "device": random.choice(["Windows Device", "Mac Device", "iOS Device", "Android Device"]),
        "os": random.choice(["Windows 10", "macOS 12", "iOS 16", "Android 12"]),
        "browser": random.choice(["Chrome", "Firefox", "Safari", "Edge"]),
        "country": generate_country_code(),
        "object": f"file_{generate_uuid()[:8]}.pdf",
        "object_type": "File",
        "file_size": random.randint(1024, 10485760),
        "file_type": random.choice(["pdf", "docx", "xlsx", "csv", "zip"]),
        "policy": "Corporate DLP Policy",
        "instance": f"{app.lower().replace(' ', '-')}-instance-01",
        "site": app,
        "ur_normalized": user,
    }


def get_alerts_response(limit: int = 100) -> dict[str, Any]:
    count = min(limit, 100)
    alerts = [_generate_alert() for _ in range(count)]
    return {
        "ok": 1,
        "data": alerts,
        "wait": 0,
    }


def get_audit_events_response(limit: int = 50) -> dict[str, Any]:
    count = min(limit, 50)
    events = []
    for _ in range(count):
        ts = now_epoch() - random.randint(0, 7200)
        events.append(
            {
                "_id": generate_uuid(),
                "timestamp": ts,
                "type": "audit",
                "audit_log_event": random.choice(
                    ["login", "logout", "admin_update_policy", "admin_add_user", "api_token_created"]
                ),
                "supporting_data": {
                    "data_type": "user",
                    "data_values": [generate_email()],
                },
                "user": generate_email(),
                "ur_normalized": generate_email(),
                "organization_unit": random.choice(["Engineering", "Sales", "HR", "Finance", "IT"]),
            }
        )
    return {"ok": 1, "data": events, "wait": 0}
