"""Okta alert adapter — covers 8 supported event types."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "okta"
VENDOR_NAME = "Okta"
PRODUCT_NAME = "Okta Identity Platform"

VARIANTS = [
    {"name": "Policy Sign-On Evaluation",                "eventType": "policy.evaluate_sign_on",                                  "severity": "medium", "weight": 20},
    {"name": "Security Attack Detected",                 "eventType": "security.attack.start",                                    "severity": "high",   "weight": 15},
    {"name": "Security Attack Ended",                    "eventType": "security.attack.end",                                      "severity": "medium", "weight": 10},
    {"name": "Client Roaming Detected",                  "eventType": "security.session.detect_client_roaming",                   "severity": "medium", "weight": 15},
    {"name": "Threat Detected",                          "eventType": "security.threat.detected",                                 "severity": "high",   "weight": 15},
    {"name": "Suspicious Activity Reported by User",     "eventType": "user.account.report_suspicious_activity_by_enduser",       "severity": "medium", "weight": 10},
    {"name": "Zone Deactivated",                         "eventType": "zone.deactivate",                                          "severity": "low",    "weight": 8},
    {"name": "Zone Deleted",                             "eventType": "zone.delete",                                              "severity": "low",    "weight": 7},
]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        user = ctx.pick_user() if ctx else None
        email = user.get("email", "jsmith@corp.local") if user else "jsmith@corp.local"
        display = user.get("name", "John Smith") if user else "John Smith"
        ip = _pick_ip(ctx)

        alerts.append({
            "finding_uid": f"tev{uuid.uuid4().hex[:20]}",
            "title": f"[Okta] {v['name']} — {display}",
            "description": f"Okta event {v['eventType']}: {v['name']}. Actor: {display} ({email}), IP: {ip}.",
            "severity": v["severity"],
            "finding_types": [v["eventType"], "Identity Security"],
            "resources": [{"uid": email, "name": display, "type": "user"}],
            "observables": [
                {"name": email, "type": "user"},
                {"name": ip, "type": "ip"},
            ],
            "unmapped": {
                "eventType": v["eventType"],
                "actor": {"id": f"00u{uuid.uuid4().hex[:16]}", "alternateId": email, "displayName": display},
                "outcome": {"result": random.choice(["SUCCESS", "FAILURE", "SKIPPED"])},
            },
        })
    return alerts


def _pick_ip(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"198.51.100.{random.randint(1,254)}")
    return f"198.51.100.{random.randint(1,254)}"
