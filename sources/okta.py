"""Okta System Log mock data generator.

Event catalog grounded in the Okta System Log API event-type taxonomy
(``developer.okta.com/docs/reference/api/event-types``). The ids in
``EVENT_CATALOG`` and ``_LOG_TEMPLATES`` match exactly so an admin's
event-mix override binds 1:1 — changing one side without the other will
fail the catalog-coverage test in ``tests/test_event_mix_sources.py``.
"""

import random
from typing import Any

import detection_rules
import event_mix
import profiles
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

# ── Event catalog ──────────────────────────────────────────────────────
# Sourced from the Okta System Log event-type catalog. Default weights mirror
# the historical ones so existing callers see no behaviour change until an
# admin opts in to a custom mix.
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "raw_log", "label": "User session start (login)",
     "default_weight": 0.70,
     "docs_anchor": "developer.okta.com/docs/reference/api/event-types/#user-session-start"},
    {"id": "mfa_failure", "label": "MFA factor activation failure",
     "default_weight": 0.10,
     "docs_anchor": "developer.okta.com/docs/reference/api/event-types/#user-mfa-factor-activate"},
    {"id": "rate_limited", "label": "API token rate-limit hit",
     "default_weight": 0.10,
     "docs_anchor": "developer.okta.com/docs/reference/api/event-types/#system-api-token-create"},
    {"id": "suspicious_activity", "label": "Suspicious password change",
     "default_weight": 0.05,
     "docs_anchor": "developer.okta.com/docs/reference/api/event-types/#user-account-update-password"},
    {"id": "account_lockout", "label": "Account locked (repeated failed logins)",
     "default_weight": 0.05,
     "docs_anchor": "developer.okta.com/docs/reference/api/event-types/#user-account-lock"},
]

# ── Persona projection ────────────────────────────────────────────────
# Maps Okta System Log dotted field paths ⇒ canonical persona slot paths
# (see ``personas.CANONICAL_SCHEMA``). The scenario engine reads this when
# stamping a phase's temp detection rule for source ``okta`` so the
# generated event is anchored to the scenario's actors instead of a
# fresh ``random.choice(_ACTORS)``. Field paths track the wire shape
# emitted by ``_generate_log`` above — keep both sides in sync when a
# new field is added.
PERSONA_PROJECTION: dict[str, str] = {
    # Victim identity — Okta's principal is ``actor.alternateId`` (the
    # login string the analyst sees in the System Log UI) plus
    # ``actor.displayName``.
    "actor.alternateId": "victim_user.email",
    "actor.displayName": "victim_user.name",
    # The IP from which the user connected. In a real attack story
    # this is the *attacker's* IP (compromised credential used from
    # external infrastructure), so we project the attacker slot here —
    # otherwise the SOC analyst sees a clean internal address and the
    # geo-enrichment doesn't fire.
    "client.ipAddress":  "attacker.ip",
    "client.geographicalContext.country": "attacker.country",
}

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


def _generate_log(ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    template = weighted_choice(event_mix.apply(_LOG_TEMPLATES, "okta"))
    pu = ctx.pick_user() if ctx else None
    if pu:
        actor_login = pu.get("email") or f"{pu.get('username', 'user')}@{pu.get('domain', 'example.com').lower()}.com"
        actor_name = pu.get("name", pu.get("username", "Unknown"))
        client_ip = pu.get("workstation_ip") or generate_ip()
        city = pu.get("city", "New York")
    else:
        actor_login, actor_name = random.choice(_ACTORS)
        domain = random.choice(["example.com", "acme.corp", "testorg.io"])
        actor_login = f"{actor_login}@{domain}"
        client_ip = generate_ip()
        city = random.choice(["New York", "London", "Tokyo", "Berlin", "Sydney"])

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
            "ipAddress": client_ip,
            "geographicalContext": {
                "country": generate_country_code(),
                "city": city,
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
    ctx = profiles.get_context("okta")
    count = profiles.scale_count("okta", min(limit, 100))
    logs = [_generate_log(ctx) for _ in range(count)]
    logs = detection_rules.inject_detection_events("okta", logs)
    logs.sort(key=lambda x: x["published"], reverse=True)
    # Return a Link header next URL hint (caller decides full URL)
    next_url = f"?since={now_minus_minutes_iso(0)}&limit={limit}" if count == limit else None
    return logs, next_url
