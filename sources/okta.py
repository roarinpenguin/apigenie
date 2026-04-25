"""Okta System Log mock data generator."""

import random
from typing import Any

from generators import (
    generate_country_code,
    generate_email,
    generate_hostname,
    generate_ip,
    generate_uuid,
    now_iso,
    now_minus_minutes_iso,
    weighted_choice,
)

_ACTORS = [
    ("john.doe", "John Doe"),
    ("jane.smith", "Jane Smith"),
    ("mike.johnson", "Mike Johnson"),
    ("sarah.williams", "Sarah Williams"),
    ("tom.brown", "Tom Brown"),
]

_APPS = ["Salesforce", "Slack", "GitHub", "AWS Console", "Okta Dashboard", "Zoom", "Jira"]

_LOG_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "raw_log": (
        {
            "eventType": "user.session.start",
            "outcome": {"result": "SUCCESS"},
            "severity": "INFO",
            "displayMessage": "User login to Okta",
        },
        0.70,
    ),
    "mfa_failure": (
        {
            "eventType": "user.mfa.factor.activate",
            "outcome": {"result": "FAILURE", "reason": "MFA factor activation failed"},
            "severity": "WARN",
            "displayMessage": "MFA factor activation failed",
        },
        0.10,
    ),
    "rate_limited": (
        {
            "eventType": "system.api_token.create",
            "outcome": {"result": "FAILURE", "reason": "Rate limit exceeded"},
            "severity": "ERROR",
            "displayMessage": "Rate limit exceeded",
        },
        0.10,
    ),
    "suspicious_activity": (
        {
            "eventType": "user.account.update_password",
            "outcome": {"result": "SUCCESS"},
            "severity": "WARN",
            "displayMessage": "Suspicious activity detected: password changed from new location",
        },
        0.05,
    ),
    "account_lockout": (
        {
            "eventType": "user.account.lock",
            "outcome": {"result": "SUCCESS"},
            "severity": "ERROR",
            "displayMessage": "User account locked due to multiple failed login attempts",
        },
        0.05,
    ),
}


def _generate_log() -> dict[str, Any]:
    template = weighted_choice(_LOG_TEMPLATES)
    actor_login, actor_name = random.choice(_ACTORS)
    domain = random.choice(["example.com", "acme.corp", "testorg.io"])
    actor_login = f"{actor_login}@{domain}"

    return {
        "uuid": generate_uuid(),
        "published": now_iso(),
        "eventType": template["eventType"],
        "version": "0",
        "severity": template["severity"],
        "displayMessage": template["displayMessage"],
        "actor": {
            "id": f"00u{generate_uuid()[:16]}",
            "type": "User",
            "alternateId": actor_login,
            "displayName": actor_name,
        },
        "client": {
            "ipAddress": generate_ip(),
            "geographicalContext": {
                "country": generate_country_code(),
                "city": random.choice(["New York", "London", "Tokyo", "Berlin", "Sydney"]),
            },
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "os": random.choice(["Windows", "Mac OS X", "Linux", "iOS", "Android"]),
                "browser": random.choice(["Chrome", "Firefox", "Safari", "Edge"]),
            },
            "device": random.choice(["Computer", "Mobile", "Tablet"]),
        },
        "outcome": template["outcome"],
        "target": [
            {
                "id": f"00u{generate_uuid()[:16]}",
                "type": "AppUser",
                "label": random.choice(_APPS),
            }
        ],
        "transaction": {"type": "WEB", "id": generate_uuid()},
        "authenticationContext": {
            "authenticationStep": 0,
            "externalSessionId": f"idx{generate_uuid()[:20]}",
        },
        "securityContext": {
            "isProxy": random.random() < 0.05,
            "isTor": random.random() < 0.02,
        },
    }


def get_logs_response(since: str | None = None, limit: int = 100) -> tuple[list[dict[str, Any]], str | None]:
    count = min(limit, 100)
    logs = [_generate_log() for _ in range(count)]
    logs.sort(key=lambda x: x["published"], reverse=True)
    # Return a Link header next URL hint (caller decides full URL)
    next_url = f"?since={now_minus_minutes_iso(0)}&limit={limit}" if count == limit else None
    return logs, next_url
