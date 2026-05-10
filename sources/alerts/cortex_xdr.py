"""Palo Alto Cortex XDR alert adapter (incident-centric)."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "cortex_xdr"
VENDOR_NAME = "Palo Alto Networks"
PRODUCT_NAME = "Cortex XDR"

VARIANTS = [
    {"name": "Malware Process Execution",           "category": "malware_detection",  "severity": "critical", "weight": 20},
    {"name": "Suspicious PowerShell Activity",      "category": "execution",          "severity": "high",     "weight": 25},
    {"name": "Credential Theft Attempt",            "category": "credential_access",  "severity": "high",     "weight": 20},
    {"name": "Lateral Movement via PsExec",         "category": "lateral_movement",   "severity": "medium",   "weight": 15},
    {"name": "Ransomware Behavior Detected",        "category": "impact",             "severity": "critical", "weight": 10},
    {"name": "Suspicious Network Connection",       "category": "command_and_control","severity": "medium",   "weight": 10},
]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        machine = ctx.pick_machine() if ctx else None
        user = ctx.pick_user() if ctx else None
        hostname = machine.get("primary_workstation", "WORKSTATION-01") if machine else f"HOST-{random.randint(1,99):02d}"
        username = user.get("username", "admin") if user else "admin_service"
        src_ip = machine.get("ip", f"10.50.60.{random.randint(1,254)}") if machine else f"10.50.60.{random.randint(1,254)}"
        dst_ip = _pick_c2(ctx)

        alerts.append({
            "finding_uid": f"xdr_{uuid.uuid4().hex[:16]}",
            "title": f"[Cortex XDR] {v['name']}",
            "description": f"Cortex XDR incident: {v['name']} on host {hostname} by user {username}.",
            "severity": v["severity"],
            "finding_types": [v["category"], "Incident"],
            "resources": [{"uid": hostname, "name": hostname, "type": "computer"}],
            "observables": [
                {"name": src_ip, "type": "ip"},
                {"name": dst_ip, "type": "ip"},
                {"name": username, "type": "user"},
            ],
            "evidences": [{
                "process": {
                    "name": random.choice(["powershell.exe", "cmd.exe", "psexec.exe", "wmic.exe"]),
                    "cmd_line": f"{v['name'].lower().replace(' ', '_')} --exec",
                }
            }],
            "unmapped": {
                "incident_id": random.randint(100000, 999999),
                "alert_category": v["category"],
                "confidence_score": random.randint(70, 99),
            },
        })
    return alerts


def _pick_c2(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"185.220.101.{random.randint(1,254)}")
    return f"185.220.101.{random.randint(1,254)}"
