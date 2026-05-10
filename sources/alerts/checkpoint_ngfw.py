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


_THREAT_NAMES = {
    "Threat Emulation": ["Trojan.Win32.Generic", "Ransomware.Locky", "Worm.Win32.Conficker"],
    "Anti-Bot": ["Bot.Win32.ZeuS", "Bot.Linux.Mirai", "Bot.Win32.Emotet"],
    "IPS": ["CVE-2024-3400", "CVE-2023-44228", "Apache Struts2 RCE"],
    "Anti-Virus": ["Trojan.Win32.Generic", "Adware.Win32.Agent", "Exploit.PDF.CVE-2017-0199"],
    "Threat Extraction": ["Macro.Office.Downloader", "Script.JS.Obfuscated", "PDF.Exploit"],
}

_COUNTRIES = ["CN", "RU", "KP", "IR", "US", "DE", "BR", "IN", "NG", "UA"]


def generate_native(n: int, ctx: Any = None) -> list[dict]:
    """Return Check Point native log format matching the real CP show-logs API."""
    import time as _time
    weights = [v["weight"] for v in VARIANTS]
    logs = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        src_ip = _pick_ip(ctx, "c2")
        dst_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        machine = _pick_machine(ctx)
        gw = machine.get("primary_workstation", "fw-dmz-01.corp.local") if machine else "fw-dmz-01.corp.local"
        malware = ctx.pick_malware() if ctx else None
        threat = malware.get("filename", random.choice(_THREAT_NAMES[v["blade"]])) if malware else random.choice(_THREAT_NAMES[v["blade"]])
        action = random.choice(_ACTIONS)
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 300))
        time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        logs.append({
            "id": random.randint(100000, 999999),
            "time": time_iso,
            "type": "Log",
            "action": action.capitalize(),
            "origin": gw,
            "origin_sic_name": f"CN={gw},O=apigenie.roarinpenguin.com",
            "ifdir": random.choice(["inbound", "outbound"]),
            "ifname": random.choice(["eth0", "eth1", "bond0"]),
            "logid": random.randint(1, 99999),
            "loguid": f"{{0x{uuid.uuid4().hex[:8]},0x{uuid.uuid4().hex[:4]},0x{uuid.uuid4().hex[:8]},0x{uuid.uuid4().hex[:16]}}}",
            "sequencenum": random.randint(1, 100),
            "version": "5",
            "src": src_ip,
            "dst": dst_ip,
            "proto": random.choice(["6", "17"]),
            "service": str(random.choice([80, 443, 8080, 22, 53])),
            "s_port": str(random.randint(30000, 65000)),
            "product": v["blade"],
            "blade_name": v["blade"],
            "attack": threat,
            "attack_info": v["name"],
            "severity": v["severity"],
            "confidence_level": random.choice(["Low", "Medium", "High", "Critical"]),
            "protection_name": threat,
            "protection_type": "anomaly" if v["blade"] == "IPS" else "signature",
            "policy_name": "Production_DMZ_Policy",
            "policy_date": "2026-01-15",
            "rule_name": f"Rule_{random.randint(1,50)}",
            "rule_uid": f"{{0x{uuid.uuid4().hex[:8]}}}",
            "rule": str(random.randint(1, 100)),
            "src_country": random.choice(_COUNTRIES),
            "dst_country": "US",
            "message": f"{v['blade']}: {v['name']} - {threat}",
        })
    return logs


def _pick_ip(ctx: Any, kind: str = "c2") -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"203.0.113.{random.randint(1,254)}")
    return f"203.0.113.{random.randint(1,254)}"


def _pick_machine(ctx: Any) -> dict | None:
    return ctx.pick_machine() if ctx else None
