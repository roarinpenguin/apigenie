"""Microsoft Entra ID Identity Protection alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "microsoft_entra_id"
VENDOR_NAME = "Microsoft"
PRODUCT_NAME = "Microsoft Entra ID Protection"

VARIANTS = [
    {"name": "Impossible Travel",              "riskType": "anomalousSignIn",            "severity": "medium", "weight": 25},
    {"name": "Unfamiliar Sign-in Properties",  "riskType": "unfamiliarFeatures",         "severity": "medium", "weight": 25},
    {"name": "Leaked Credentials",             "riskType": "leakedCredentials",          "severity": "high",   "weight": 15},
    {"name": "Malicious IP Address Sign-in",   "riskType": "maliciousIPAddress",         "severity": "high",   "weight": 15},
    {"name": "Password Spray Attack",          "riskType": "passwordSpray",              "severity": "high",   "weight": 10},
    {"name": "Anonymous IP Address Login",     "riskType": "anonymousIPAddress",         "severity": "medium", "weight": 10},
]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        user = ctx.pick_user() if ctx else None
        upn = user.get("email", "jsmith@corp.onmicrosoft.com") if user else "jsmith@corp.onmicrosoft.com"
        display = user.get("name", "John Smith") if user else "John Smith"
        ip = _pick_ip(ctx)

        alerts.append({
            "finding_uid": str(uuid.uuid4()),
            "title": f"[Entra ID] {v['name']} — {display}",
            "description": f"Identity risk detection: {v['name']} for user {upn} from IP {ip}.",
            "severity": v["severity"],
            "finding_types": [v["riskType"], "Identity Protection"],
            "resources": [{"uid": upn, "name": display, "type": "user"}],
            "observables": [
                {"name": upn, "type": "user"},
                {"name": ip, "type": "ip"},
            ],
            "unmapped": {
                "riskEventType": v["riskType"],
                "riskState": "atRisk",
                "riskLevel": v["severity"],
                "userPrincipalName": upn,
            },
        })
    return alerts


def _pick_ip(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"198.51.100.{random.randint(1,254)}")
    return f"198.51.100.{random.randint(1,254)}"
