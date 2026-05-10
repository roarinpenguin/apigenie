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
    """Return Check Point native log in the REAL Management API show-logs format.

    Based on actual CP Management API response — uses orig (not origin),
    i_f_dir (not ifdir), and _attr arrays for resolved objects.
    """
    weights = [v["weight"] for v in VARIANTS]
    logs = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        src_ip = _pick_ip(ctx, "c2")
        dst_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        machine = _pick_machine(ctx)
        gw_name = machine.get("primary_workstation", "fw-gw-01") if machine else "fw-gw-01"
        gw_ip = machine.get("ip", "10.1.1.200") if machine else "10.1.1.200"
        malware = ctx.pick_malware() if ctx else None
        threat = malware.get("filename", random.choice(_THREAT_NAMES[v["blade"]])) if malware else random.choice(_THREAT_NAMES[v["blade"]])
        action = random.choice(["Accept", "Drop", "Reject", "Block"])
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 300))
        time_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        src_host = f"host-{random.randint(1,99):02d}.corp.local"
        dst_host = f"server-{random.randint(1,99):02d}.corp.local"
        log_server_name = "mgmt-logserver-01"
        log_server_ip = gw_ip
        log_server_uid = str(uuid.uuid4())
        src_uid = str(uuid.uuid4())
        dst_uid = str(uuid.uuid4())
        rule_uid = str(uuid.uuid4())
        svc_port = str(random.choice([53, 80, 443, 8080, 22]))
        svc_name = {"53": "domain-udp", "80": "http", "443": "https", "8080": "http-alt", "22": "ssh"}[svc_port]
        direction = random.choice(["inbound", "outbound"])
        conn_dir = "Incoming" if direction == "inbound" else "Outgoing"
        iface = random.choice(["eth0", "eth1", "bond0", "bond80.100"])

        log = {
            "id": str(uuid.uuid4()),
            "time": time_iso,
            "type": "Connection",
            "action": action,
            "conn_direction": conn_dir,
            "i_f_dir": direction,
            "i_f_name": iface,
            "__interface": iface,
            "first": "true",
            "sequencenum": str(random.randint(1, 9999)),

            # Origin (gateway)
            "orig": gw_name,
            "orig_log_server": log_server_ip,
            "orig_log_server_attr": [
                {"isCHKPObject": "true", "resolved": log_server_name, "uuid": log_server_uid},
            ],

            # Source
            "src": src_ip,
            "src_attr": [
                {"isCHKPObject": "true", "resolved": src_host, "uuid": src_uid},
            ],
            "s_port": str(random.randint(30000, 65000)),

            # Destination
            "dst": dst_ip,
            "dst_attr": [
                {"isCHKPObject": "true", "resolved": dst_host, "uuid": dst_uid},
            ],
            "service": svc_port,
            "service_id": svc_name,
            "fservice": svc_name,

            # Protocol
            "proto": random.choice(["6", "17"]),
            "proto_attr": [
                {"isCHKPObject": "false", "resolved": "TCP (6)" if "6" else "UDP (17)"},
            ],

            # Policy / rule
            "policy_name": "Production_Policy",
            "policy_mgmt": "fwm1-mgmt",
            "policy_date": "2026-01-15T12:00:00Z",
            "rule": f"{random.randint(1,50)}.{random.randint(1,9)}",
            "rule_uid": rule_uid,
            "match_table": [
                {
                    "layer_name": "Production Network",
                    "layer_uuid": str(uuid.uuid4()),
                    "match_id": str(random.randint(1, 100)),
                    "parent_rule": "0",
                    "rule": f"{random.randint(1,50)}.{random.randint(1,9)}",
                    "rule_action": action,
                    "rule_uid": rule_uid,
                },
            ],
            "layer_name": "Production Network",

            # Product / blade
            "product": v["blade"],
            "product_family": "Threat" if "Threat" in v["blade"] else "Access",

            # Threat details
            "attack": threat,
            "attack_info": v["name"],
            "severity": str(_SEV_MAP.get(v["severity"], 2)),
            "confidence_level": random.choice(["Low", "Medium", "High", "Critical"]),
            "protection_name": threat,
            "protection_type": "anomaly" if v["blade"] == "IPS" else "signature",
            "description": f"{v['name']} — {threat}",

            # Metadata
            "domain": "Global",
            "db_tag": f"{{{str(uuid.uuid4())}}}",
            "logid": "0",
            "marker": f"@A@@B@{int(datetime.now(timezone.utc).timestamp())}@C@{random.randint(1000000,9999999)}",
            "id_generated_by_indexer": "false",
            "log_delay": str(int(datetime.now(timezone.utc).timestamp())),
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
