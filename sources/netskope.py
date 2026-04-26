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

# Netskope /api/v2/events/data/alert exposes one alert_type per request via the
# "type" query param. Values match Netskope's documented alert_types. Each
# template defines the alert_type-specific fields the collector enriches on.
_ALERT_TEMPLATES: dict[str, dict[str, Any]] = {
    "policy": {
        "alert_type": "policy",
        "alert_name": "Sensitive Data Upload Detected",
        "action": "alert",
        "category": "Cloud Storage",
        "severity": "low",
        "policy": "Corporate DLP Policy",
    },
    "DLP": {
        "alert_type": "DLP",
        "alert_name": "DLP Policy Violation - Credit Card Numbers",
        "action": "block",
        "category": "Cloud Storage",
        "severity": "high",
        "dlp_profile": "PCI-DSS",
        "dlp_rule_count": 3,
    },
    "Malware": {
        "alert_type": "Malware",
        "alert_name": "Malware Detected in Upload",
        "action": "block",
        "category": "Cloud Storage",
        "severity": "critical",
        "malware_name": "Trojan.Generic.KD.123",
        "malware_type": "trojan",
        "malware_severity": "high",
    },
    "anomaly": {
        "alert_type": "anomaly",
        "alert_name": "Anomalous Upload Volume Detected",
        "action": "alert",
        "category": "Collaboration",
        "severity": "medium",
        "anomaly_type": "data_exfil",
    },
    "Compromised Credential": {
        "alert_type": "Compromised Credential",
        "alert_name": "Credential Exposed in Public Breach",
        "action": "alert",
        "category": "Identity",
        "severity": "high",
        "breach_id": "haveibeenpwned-2025",
    },
    "watchlist": {
        "alert_type": "watchlist",
        "alert_name": "Watchlisted User Activity",
        "action": "alert",
        "category": "UEBA",
        "severity": "medium",
    },
    "malsite": {
        "alert_type": "malsite",
        "alert_name": "Connection to Known Malicious Site",
        "action": "block",
        "category": "Web",
        "severity": "high",
        "malsite_category": "phishing",
    },
    "Security Assessment": {
        "alert_type": "Security Assessment",
        "alert_name": "Misconfiguration Detected",
        "action": "alert",
        "category": "CSPM",
        "severity": "medium",
    },
    "quarantine": {
        "alert_type": "quarantine",
        "alert_name": "File Quarantined",
        "action": "quarantine",
        "category": "Cloud Storage",
        "severity": "low",
    },
    "Remediation": {
        "alert_type": "Remediation",
        "alert_name": "Remediation Action Executed",
        "action": "remediate",
        "category": "Cloud Storage",
        "severity": "low",
    },
    "uba": {
        "alert_type": "uba",
        "alert_name": "Insider Threat: Mass Download Before Resignation",
        "action": "block",
        "category": "UEBA",
        "severity": "critical",
    },
}


def _generate_alert(alert_type: str | None = None) -> dict[str, Any]:
    if alert_type and alert_type in _ALERT_TEMPLATES:
        template = _ALERT_TEMPLATES[alert_type]
    else:
        template = random.choice(list(_ALERT_TEMPLATES.values()))
    app = random.choice(_APPS)
    user = random.choice(_USERS)
    ts = now_epoch() - random.randint(0, 3600)

    base = {
        "_id": generate_uuid(),
        "_insertion_epoch_timestamp": ts,
        "timestamp": ts,
        "alert": "yes",
        "alert_id": generate_uuid(),
        "type": "alert",
        "app": app,
        "appcategory": template["category"],
        "category": template["category"],
        "user": user,
        "src_country": generate_country_code(),
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
        "instance": f"{app.lower().replace(' ', '-')}-instance-01",
        "site": app,
        "ur_normalized": user,
        "userip": generate_ip(),
        "organization_unit": random.choice(["Engineering", "Sales", "HR", "Finance", "IT"]),
        "connection_id": generate_uuid(),
    }
    base.update(template)
    return base


def get_alerts_response(limit: int = 100, alert_type: str | None = None) -> dict[str, Any]:
    """Return alerts in the Netskope v2 envelope: {result, status, total}."""
    count = min(limit, 100)
    alerts = [_generate_alert(alert_type=alert_type) for _ in range(count)]
    return {
        "result": alerts,
        "status": "success",
        "total": count,
    }


def get_audit_events_response(limit: int = 50) -> dict[str, Any]:
    count = min(limit, 50)
    events = []
    for _ in range(count):
        ts = now_epoch() - random.randint(0, 7200)
        events.append(
            {
                "_id": generate_uuid(),
                "_insertion_epoch_timestamp": ts,
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
    return {"result": events, "status": "success", "total": count}
