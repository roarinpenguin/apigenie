"""Netskope alert adapter — covers all 8 alert families."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "netskope"
VENDOR_NAME = "Netskope"
PRODUCT_NAME = "Netskope Security Cloud"

VARIANTS = [
    {"name": "DLP Policy Violation",         "type": "dlp",                     "severity": "high",     "weight": 20},
    {"name": "Malware Detected",             "type": "malware",                 "severity": "critical", "weight": 15},
    {"name": "UBA Anomaly Detected",         "type": "uba",                     "severity": "medium",   "weight": 15},
    {"name": "Compromised Credentials",      "type": "compromised_credential",  "severity": "high",     "weight": 10},
    {"name": "Malicious Site Access",        "type": "malsite",                 "severity": "high",     "weight": 10},
    {"name": "Policy Violation",             "type": "policy",                  "severity": "medium",   "weight": 10},
    {"name": "Quarantine Action",            "type": "quarantine",              "severity": "medium",   "weight": 10},
    {"name": "Security Assessment Finding",  "type": "security_assessment",     "severity": "low",      "weight": 10},
]

_APPS = ["Slack", "Google Drive", "OneDrive", "Dropbox", "Salesforce", "Box", "GitHub"]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        user = ctx.pick_user() if ctx else None
        email = user.get("email", "user@corp.local") if user else "user@corp.local"
        username = user.get("username", "jsmith") if user else "jsmith"
        machine = ctx.pick_machine() if ctx else None
        device = machine.get("primary_workstation", "LAPTOP-01") if machine else "LAPTOP-01"
        app = random.choice(_APPS)
        malware = ctx.pick_malware() if ctx else None

        observables = [
            {"name": email, "type": "user"},
            {"name": device, "type": "hostname"},
        ]
        if v["type"] in ("malware", "malsite"):
            c2 = _pick_c2(ctx)
            observables.append({"name": c2, "type": "ip"})
            if malware:
                observables.append({"name": malware.get("filename", "malware.exe"), "type": "file"})

        alerts.append({
            "finding_uid": f"netskope_{uuid.uuid4().hex[:16]}",
            "title": f"[Netskope] {v['name']} — {app}",
            "description": f"Netskope {v['type']} alert: {v['name']} by {email} on {device} using {app}.",
            "severity": v["severity"],
            "finding_types": [v["type"], "Cloud Security"],
            "resources": [{"uid": device, "name": device, "type": "computer"}],
            "observables": observables,
            "unmapped": {
                "alert_type": v["type"],
                "app": app,
                "user_email": email,
                "policy_name": f"{v['type'].upper()}_Policy",
            },
        })
    return alerts


def _pick_c2(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"185.220.101.{random.randint(1,254)}")
    return f"185.220.101.{random.randint(1,254)}"
