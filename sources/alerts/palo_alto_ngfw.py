"""Palo Alto Networks Firewall alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "palo_alto_ngfw"
VENDOR_NAME = "Palo Alto Networks"
PRODUCT_NAME = "Palo Alto Networks Firewall"

VARIANTS = [
    {"name": "Exploit Detection - CVE-2024-3400", "severity": "critical",      "weight": 15},
    {"name": "Spyware C2 Communication",          "severity": "high",          "weight": 20},
    {"name": "Vulnerability Exploit Attempt",     "severity": "high",          "weight": 20},
    {"name": "Wildfire Malware Detected",         "severity": "critical",      "weight": 15},
    {"name": "DNS Tunneling Detected",            "severity": "medium",        "weight": 15},
    {"name": "Brute Force Login Attempt",         "severity": "informational", "weight": 15},
]

_SUBTYPES = ["spyware", "vulnerability", "virus", "wildfire", "url"]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        src_ip = _pick_c2(ctx)
        dst_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        machine = ctx.pick_machine() if ctx else None
        fw_host = machine.get("primary_workstation", "PA-5220-DMZ") if machine else "PA-5220-DMZ"

        alerts.append({
            "finding_uid": f"palofw_{uuid.uuid4().hex[:16]}",
            "title": f"[PAN Firewall] {v['name']}",
            "description": f"Palo Alto Firewall threat log: {v['name']}. {src_ip} → {dst_ip}.",
            "severity": v["severity"],
            "finding_types": [random.choice(_SUBTYPES), "Threat"],
            "resources": [{"uid": fw_host, "name": fw_host, "type": "Firewall"}],
            "observables": [
                {"name": src_ip, "type": "ip"},
                {"name": dst_ip, "type": "ip"},
            ],
            "unmapped": {
                "subtype": random.choice(_SUBTYPES),
                "action": random.choice(["alert", "drop", "reset-both", "block-url"]),
                "rule_name": "Threat_Prevention_Rule",
                "device_name": fw_host,
            },
        })
    return alerts


def _pick_c2(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"203.0.113.{random.randint(1,254)}")
    return f"203.0.113.{random.randint(1,254)}"
