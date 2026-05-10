"""Check Point Next Generation Firewall alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "checkpoint_ngfw"
VENDOR_NAME = "Check Point"
PRODUCT_NAME = "Check Point NGFW"

VARIANTS = [
    {"name": "Threat Emulation - Malware Detected",  "blade": "Threat Emulation", "severity": "critical", "weight": 15},
    {"name": "Anti-Bot - C2 Communication Blocked",  "blade": "Anti-Bot",         "severity": "high",     "weight": 20},
    {"name": "IPS - Exploit Attempt Detected",       "blade": "IPS",              "severity": "high",     "weight": 25},
    {"name": "Anti-Virus - Malicious File Blocked",  "blade": "Anti-Virus",       "severity": "medium",   "weight": 20},
    {"name": "Threat Extraction - Content Removed",  "blade": "Threat Extraction","severity": "low",      "weight": 20},
]

_ACTIONS = ["block", "detect", "quarantine", "allow"]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        src_ip = _pick_ip(ctx, "c2")
        dst_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        machine = _pick_machine(ctx)
        gw = machine.get("primary_workstation", "fw-dmz-01.corp.local") if machine else "fw-dmz-01.corp.local"

        alerts.append({
            "finding_uid": f"chkp_{uuid.uuid4().hex[:16]}",
            "title": f"[CheckPoint] {v['name']}",
            "description": f"{v['blade']} blade detected: {v['name']}. Source: {src_ip} → Dest: {dst_ip}",
            "severity": v["severity"],
            "finding_types": [v["blade"], "Threat Prevention"],
            "resources": [{"uid": gw, "name": gw, "type": "Firewall"}],
            "observables": [
                {"name": src_ip, "type": "ip"},
                {"name": dst_ip, "type": "ip"},
            ],
            "unmapped": {
                "blade": v["blade"],
                "action": random.choice(_ACTIONS),
                "policy_name": "Production_DMZ_Policy",
                "gateway": gw,
            },
        })
    return alerts


def _pick_ip(ctx: Any, kind: str = "c2") -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"203.0.113.{random.randint(1,254)}")
    return f"203.0.113.{random.randint(1,254)}"


def _pick_machine(ctx: Any) -> dict | None:
    return ctx.pick_machine() if ctx else None
