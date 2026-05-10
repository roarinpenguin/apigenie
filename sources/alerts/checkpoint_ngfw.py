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


_SEV_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def generate_native(n: int, ctx: Any = None) -> list[dict]:
    """Return Check Point native log format matching S1's exact field mapping.

    Field names and value types are taken from S1's internal CP→OCSF mapping doc.
    """
    import time as _time
    weights = [v["weight"] for v in VARIANTS]
    logs = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        src_ip = _pick_ip(ctx, "c2")
        dst_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        machine = _pick_machine(ctx)
        gw_name = machine.get("primary_workstation", "Checkpoint-GW") if machine else "Checkpoint-GW"
        gw_ip = machine.get("ip", "10.1.1.200") if machine else "10.1.1.200"
        malware = ctx.pick_malware() if ctx else None
        threat = malware.get("filename", random.choice(_THREAT_NAMES[v["blade"]])) if malware else random.choice(_THREAT_NAMES[v["blade"]])
        action = random.choice(_ACTIONS)
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 300))
        time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        loguid = f"{{0x{uuid.uuid4().hex[:8]},0x{uuid.uuid4().hex[:4]},0x{uuid.uuid4().hex[:8]},0x{uuid.uuid4().hex[:16]}}}"
        sev_num = _SEV_MAP.get(v["severity"], 2)

        log = {
            # Core fields S1 maps (web_api mapper, NOT syslog mapper)
            "id": str(random.randint(100000, 999999)),  # → finding_info.uid (web_api uses 'id', syslog uses 'loguid')
            "loguid": loguid,                     # kept for completeness
            "origin": gw_ip,                      # → device.ip / finding_info.src_url
            "originsicname": f"CN={gw_name},O=Checkpoint-MGMT..apigenie",  # → device.name
            "sequencenum": str(random.randint(1, 100)),  # → metadata.sequence
            "time": time_iso,                     # → metadata.original_time (ISO for web_api)
            "version": "5",                       # → metadata.product.version
            "product": v["blade"],                # → metadata.product.feature.name + activity_name
            "severity": str(sev_num),             # → severity_id (0→1,1→2,2→3,3→4,4→5)
            "ifdir": random.choice(["inbound", "outbound"]),  # → evidences[0].connection_info.direction
            "flags": "166216",                    # → unmapped.flags

            # Description/title fields
            "description": f"{v['name']} — {threat}. Source: {src_ip}, Destination: {dst_ip}",  # → finding_info.desc
            "contract_name": v["name"],           # → finding_info.title

            # Network fields (VPN-1 & FireWall-1 type)
            "src": src_ip,                        # → evidences[0].src_endpoint.ip
            "dst": dst_ip,                        # → evidences[0].dst_endpoint.ip
            "s_port": str(random.randint(30000, 65000)),  # → evidences[0].src_endpoint.port
            "service": str(random.choice([80, 443, 8080, 22, 53])),  # → evidences[0].src_endpoint.svc_name
            "proto": random.choice(["6", "17"]),  # → evidences[0].connection_info.protocol_num

            # Geo fields
            "src_country": random.choice(_COUNTRIES),  # → evidences[0].src_endpoint.location.country
            "dst_country": "US",                  # → evidences[0].dst_endpoint.location.country

            # Policy/rule
            "policy_name": "Production_DMZ_Policy",  # → actor.authorizations[0].policy.name
            "rule_name": f"Rule_{random.randint(1,50)}",
            "rule_uid": f"{{0x{uuid.uuid4().hex[:8]}}}",

            # Threat details
            "attack": threat,
            "attack_info": v["name"],
            "confidence_level": random.choice(["Low", "Medium", "High", "Critical"]),  # → confidence_score
            "protection_name": threat,
            "protection_type": "anomaly" if v["blade"] == "IPS" else "signature",

            # Action
            "action": action.capitalize(),

            # Log metadata
            "type": "Log",
            "log_id": str(random.randint(1, 9999)),  # → metadata.uid
            "ifname": random.choice(["eth0", "eth1", "bond0"]),

            # CP Management API resolves objects inline (not in syslog, only in show-logs)
            # S1 maps these resolved objects to OCSF resources[]
            "origin_object": {
                "uid": str(uuid.uuid4()),
                "name": gw_name,
                "type": "simple-gateway",
                "ipv4-address": gw_ip,
                "domain": {"domain-type": "local domain", "name": "SMC User", "uid": str(uuid.uuid4())},
                "sic-name": f"CN={gw_name},O=Checkpoint-MGMT..apigenie",
            },
            "src_machine_object": {
                "uid": str(uuid.uuid4()),
                "name": f"host-{random.randint(1,99):02d}",
                "type": "host",
                "ipv4-address": src_ip,
            },
            "dst_machine_object": {
                "uid": str(uuid.uuid4()),
                "name": f"server-{random.randint(1,99):02d}",
                "type": "host",
                "ipv4-address": dst_ip,
            },
            "originsicname": f"CN={gw_name},O=Checkpoint-MGMT..apigenie",
            "inzone": "External",
            "outzone": "Internal",
        }
        logs.append(log)
    return logs


def _pick_ip(ctx: Any, kind: str = "c2") -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"203.0.113.{random.randint(1,254)}")
    return f"203.0.113.{random.randint(1,254)}"


def _pick_machine(ctx: Any) -> dict | None:
    return ctx.pick_machine() if ctx else None
