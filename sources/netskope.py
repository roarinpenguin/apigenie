"""Netskope Alerts and Audit Events mock data generator."""

import random
from typing import Any

import profiles
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


_TYPE_ALIASES = {
    "anomaly": "uba",
    "watchlist": "policy",
    "Compromised Credential": "Compromised Credential",
    "dlp": "DLP",
    "malware": "Malware",
    "malsite": "Malsite",
    "policy": "policy",
    "quarantine": "quarantine",
    "uba": "uba",
    "Security Assessment": "Security Assessment",
    "Remediation": "Remediation",
}


def _generate_alert(alert_type: str | None = None, ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    try:
        return _generate_alert_inner(alert_type, ctx)
    except Exception:
        import logging, traceback
        logging.getLogger("netskope.gen").error("ALERT GEN FAILED:\n%s", traceback.format_exc())
        ts = now_epoch()
        return {
            "_id": generate_uuid(), "_insertion_epoch_timestamp": ts,
            "timestamp": ts, "alert": "yes", "alert_id": generate_uuid(),
            "type": "alert", "alert_type": alert_type or "policy",
            "alert_name": "Security Alert", "action": "alert",
            "severity": "medium", "category": "Security",
            "user": "admin@corp.local", "srcip": "10.0.0.1",
            "dstip": "10.0.0.2", "hostname": "host-01",
            "app": "Unknown", "appcategory": "Security",
        }


def _generate_alert_inner(alert_type: str | None = None, ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    resolved_type = _TYPE_ALIASES.get(alert_type, alert_type) if alert_type else None
    if resolved_type and resolved_type in _ALERT_TEMPLATES:
        template = dict(_ALERT_TEMPLATES[resolved_type])
    else:
        template = dict(random.choice(list(_ALERT_TEMPLATES.values())))
    app = random.choice(_APPS)

    # Safely extract profile entities — every pick can return None, str, or dict
    user = random.choice(_USERS)
    srcip = generate_ip()
    hostname = generate_hostname()
    dstip = generate_ip()
    malware_name = None

    if ctx:
        try:
            pu = ctx.pick_user()
            if isinstance(pu, dict):
                user = pu.get("email", user)
        except Exception:
            pass
        try:
            pm = ctx.pick_machine()
            if isinstance(pm, dict):
                srcip = pm.get("ip", srcip)
                hostname = pm.get("primary_workstation", hostname)
        except Exception:
            pass
        try:
            pc2 = ctx.pick_c2()
            if isinstance(pc2, dict):
                dstip = pc2.get("ip_c2", dstip)
        except Exception:
            pass
        try:
            pmal = ctx.pick_malware()
            if isinstance(pmal, dict):
                malware_name = pmal.get("filename")
        except Exception:
            pass

    ts = now_epoch() - random.randint(0, 3600)

    alert = {
        "_id": generate_uuid(),
        "_insertion_epoch_timestamp": ts,
        "timestamp": ts,
        "alert": "yes",
        "alert_id": generate_uuid(),
        "type": "alert",
        "alert_type": template.get("alert_type", "policy"),
        "alert_name": template.get("alert_name", "Security Alert"),
        "action": template.get("action", "alert"),
        "severity": template.get("severity", "medium"),
        "app": app,
        "appcategory": template.get("category", "Security"),
        "category": template.get("category", "Security"),
        "user": user,
        "src_country": generate_country_code(),
        "srcip": srcip,
        "dstip": dstip,
        "hostname": hostname,
        "os": random.choice(["Windows 10", "macOS 12", "iOS 16", "Android 12"]),
        "os_version": random.choice(["22H2", "14.1", "17.0", "13"]),
        "browser": random.choice(["Chrome", "Firefox", "Safari", "Edge"]),
        "browser_version": f"{random.randint(90,130)}.0.{random.randint(1000,9999)}.{random.randint(10,99)}",
        "device_classification": random.choice(["managed", "unmanaged"]),
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
    if malware_name:
        alert["malware_name"] = malware_name
    return alert


def get_alerts_response(limit: int = 100, alert_type: str | None = None) -> dict[str, Any]:
    """Return alerts in the real Netskope v2 API format: {ok, result, data}."""
    ctx = profiles.get_context("netskope")
    count = min(limit, 100)
    alerts = [_generate_alert(alert_type=alert_type, ctx=ctx) for _ in range(count)]
    return {
        "ok": 1,
        "result": "success",
        "status": "success",
        "data": alerts,
        "total": count,
        "wait_time": 0,
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
