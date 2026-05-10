"""ExtraHop RevealX alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "extrahop_revealx"
VENDOR_NAME = "ExtraHop"
PRODUCT_NAME = "ExtraHop RevealX"

VARIANTS = [
    {"name": "Data Exfiltration Detected",       "category": "data_loss",           "severity": "high",     "weight": 20},
    {"name": "Lateral Movement Detected",        "category": "lateral_movement",    "severity": "high",     "weight": 20},
    {"name": "C2 Beaconing Activity",            "category": "command_and_control",  "severity": "critical", "weight": 15},
    {"name": "Suspicious DNS Activity",          "category": "dns_anomaly",          "severity": "medium",   "weight": 20},
    {"name": "Unauthorized Protocol Usage",      "category": "policy_violation",     "severity": "low",      "weight": 15},
    {"name": "Cryptomining Activity Detected",   "category": "cryptomining",         "severity": "medium",   "weight": 10},
]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        machine = ctx.pick_machine() if ctx else None
        hostname = machine.get("primary_workstation", f"server-{random.randint(1,50):02d}") if machine else f"server-{random.randint(1,50):02d}"
        src_ip = machine.get("ip", f"10.10.{random.randint(1,254)}.{random.randint(1,254)}") if machine else f"10.10.{random.randint(1,254)}.{random.randint(1,254)}"
        dst_ip = _pick_c2(ctx)

        alerts.append({
            "finding_uid": f"extrahop_{uuid.uuid4().hex[:16]}",
            "title": f"[RevealX] {v['name']}",
            "description": f"ExtraHop RevealX detection: {v['name']}. Source: {hostname} ({src_ip}) → {dst_ip}.",
            "severity": v["severity"],
            "finding_types": [v["category"], "Network Detection"],
            "resources": [{"uid": hostname, "name": hostname, "type": "computer"}],
            "observables": [
                {"name": src_ip, "type": "ip"},
                {"name": dst_ip, "type": "ip"},
                {"name": hostname, "type": "hostname"},
            ],
            "unmapped": {
                "detection_type": "anomaly_detection",
                "threat_category": v["category"],
                "risk_score": random.randint(60, 99),
                "confidence_score": random.randint(70, 98),
            },
        })
    return alerts


def _pick_c2(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"185.220.101.{random.randint(1,254)}")
    return f"185.220.101.{random.randint(1,254)}"
