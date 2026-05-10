"""Vectra AI alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "vectra_ai"
VENDOR_NAME = "Vectra AI"
PRODUCT_NAME = "Vectra AI Platform"

VARIANTS = [
    {"name": "Lateral Movement via SMB",       "category": "lateral_movement",    "severity": "high",     "weight": 25},
    {"name": "C2 Beaconing Detected",          "category": "command_and_control",  "severity": "critical", "weight": 20},
    {"name": "Internal Reconnaissance",        "category": "reconnaissance",       "severity": "medium",   "weight": 20},
    {"name": "Data Smuggler Activity",         "category": "exfiltration",         "severity": "high",     "weight": 15},
    {"name": "Kerberoasting Attempt",          "category": "credential_access",    "severity": "high",     "weight": 10},
    {"name": "RDP Brute Force",                "category": "brute_force",          "severity": "medium",   "weight": 10},
]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        machine = ctx.pick_machine() if ctx else None
        hostname = machine.get("primary_workstation", f"host-{random.randint(1,99):02d}") if machine else f"host-{random.randint(1,99):02d}"
        src_ip = machine.get("ip", f"10.20.{random.randint(1,254)}.{random.randint(1,254)}") if machine else f"10.20.{random.randint(1,254)}.{random.randint(1,254)}"
        dst_ip = _pick_c2(ctx)
        user = ctx.pick_user() if ctx else None
        username = user.get("username", "analyst") if user else "analyst"

        alerts.append({
            "finding_uid": f"vectra_{uuid.uuid4().hex[:16]}",
            "title": f"[Vectra] {v['name']}",
            "description": f"Vectra AI detection: {v['name']}. Host: {hostname} ({src_ip}), User: {username}.",
            "severity": v["severity"],
            "finding_types": [v["category"], "Network Detection"],
            "resources": [{"uid": hostname, "name": hostname, "type": "computer"}],
            "observables": [
                {"name": src_ip, "type": "ip"},
                {"name": dst_ip, "type": "ip"},
                {"name": username, "type": "user"},
            ],
            "unmapped": {
                "detection_category": v["category"],
                "threat_score": random.randint(50, 100),
                "certainty_score": random.randint(60, 99),
            },
        })
    return alerts


def _pick_c2(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"185.220.101.{random.randint(1,254)}")
    return f"185.220.101.{random.randint(1,254)}"
