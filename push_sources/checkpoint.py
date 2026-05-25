"""Check Point NGFW log generator — realistic Log Exporter / SmartEvent format.

Covers: firewall (accept/drop/reject), IPS blade, anti-bot, anti-virus,
threat emulation, URL filtering, application control, identity awareness.
Fields match Check Point R81.20 Log Exporter LEEF/CEF/syslog output.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid, generate_country_code

_GATEWAYS = ["CPGW-HQ-01", "CPGW-DC-02", "CPGW-DMZ-03", "CPGW-BRANCH-04"]
_MGMT = ["CPMGMT-01", "SmartCenter-01"]
_ORIGINS = ["10.0.1.1", "10.0.2.1", "172.16.1.1"]
_BLADES = ["Firewall", "IPS", "Anti-Bot", "Anti-Virus", "Threat Emulation",
           "URL Filtering", "Application Control", "Identity Awareness"]
_ACTIONS = ["Accept", "Drop", "Reject", "Prevent", "Detect", "Ask"]
_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
_USERS = ["jsmith@corp.local", "admin", "agarcia", "mwilson", "svc-monitor"]
_SERVICES = ["https", "http", "dns", "ssh", "rdp", "smtp", "ntp", "ftp", "ms-sql", "oracle"]
_RULES = ["Cleanup Rule", "Outbound Allow", "Inbound Web", "Block Malicious", "VPN Access",
          "DMZ to Internal", "Guest Internet", "Block Tor", "Allow DNS"]
_APPS = ["Facebook", "YouTube", "Google Drive", "Dropbox", "BitTorrent", "Tor", "Skype",
         "Microsoft Teams", "Zoom", "LinkedIn", "Twitter", "Salesforce", "AWS Console"]
_URL_CATS = ["Business / Economy", "Search Engines", "Social Networking", "Streaming Media",
             "Phishing", "Malware", "Spyware / Adware", "Anonymizer", "Gambling"]
_PROTECTION_NAMES = [
    "Apache Log4j Remote Code Execution", "Microsoft Exchange ProxyShell",
    "Suspicious DNS Query", "Cobalt Strike Beacon Activity",
    "SQL Injection Attempt", "Cross-Site Scripting", "Brute Force Attack",
    "Known C&C Communication", "Ransomware Activity Detected",
    "Credential Phishing Page", "Malicious File Download",
]
_MALWARE = ["Emotet", "TrickBot", "QakBot", "IcedID", "Dridex", "Agent.Tesla", "AsyncRAT", "Remcos"]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _base(ctx=None) -> dict[str, Any]:
    gw = random.choice(_GATEWAYS)
    return {
        "time": _now(), "hostname": gw, "origin": random.choice(_ORIGINS),
        "origin_sic_name": f"CN={gw},O={random.choice(_MGMT)}",
        "product": "VPN-1 & FireWall-1", "vendor": "Check Point",
        "device_version": random.choice(["R81.20", "R81.10", "R80.40"]),
        "log_uid": f"{{{generate_uuid()}}}", "sequencenum": random.randint(1, 999999),
    }

def _fw_log(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    pu = ctx.pick_user() if ctx else None
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src = pm.get("ip") if pm else generate_ip()
    dst = pc2.get("ip_c2") if pc2 else generate_ip()
    user = pu.get("email", random.choice(_USERS)) if pu else random.choice(_USERS)
    action = random.choices(_ACTIONS[:3], weights=[60, 25, 15])[0]
    return {**b, "type": "Log", "blade": "Firewall", "action": action,
            "severity": "Low" if action == "Accept" else "Medium",
            "src": src, "dst": dst, "s_port": random.randint(1024, 65535),
            "service": random.choice(_SERVICES), "proto": random.choice(["tcp", "udp", "icmp"]),
            "rule": random.choice(_RULES), "rule_uid": f"{{{generate_uuid()}}}",
            "src_user_name": user, "src_machine_name": generate_hostname(),
            "xlatesrc": generate_ip() if random.random() < 0.5 else "",
            "bytes": random.randint(100, 5000000), "packets": random.randint(1, 5000),
            "ifname": random.choice(["eth0", "eth1", "eth2", "bond0"]),
            "inzone": random.choice(["Internal", "External", "DMZ"]),
            "outzone": random.choice(["Internal", "External", "DMZ"]),
            "matched_category": random.choice(_URL_CATS[:5]),
            "smartdefense_profile": "Optimized"}

def _ips_log(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    return {**b, "type": "Log", "blade": "IPS", "action": random.choice(["Prevent", "Detect"]),
            "severity": random.choices(_SEVERITIES[:4], weights=[5, 20, 50, 25])[0],
            "src": pm.get("ip") if pm else generate_ip(),
            "dst": pc2.get("ip_c2") if pc2 else generate_ip(),
            "protection_name": random.choice(_PROTECTION_NAMES),
            "protection_id": f"ips_{random.randint(10000, 99999)}",
            "confidence_level": random.choice(["High", "Medium", "Low"]),
            "performance_impact": random.choice(["Low", "Medium", "High"]),
            "attack_info": random.choice(_PROTECTION_NAMES),
            "reference": f"https://www.checkpoint.com/defense/advisories/public/{random.randint(2020,2026)}/cpai-{random.randint(1000,9999)}.html"}

def _av_log(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    pmal = ctx.pick_malware() if ctx else None
    mal = pmal.get("filename", random.choice(_MALWARE)) if pmal else random.choice(_MALWARE)
    return {**b, "type": "Log", "blade": "Anti-Virus",
            "action": random.choice(["Prevent", "Detect"]),
            "severity": "High", "malware_name": mal,
            "malware_family": random.choice(["Trojan", "Worm", "Ransomware", "RAT", "Infostealer"]),
            "src": generate_ip(), "dst": generate_ip(),
            "resource": f"https://{generate_hostname()}/{random.choice(['update.exe', 'doc.pdf', 'script.js'])}",
            "protection_type": "AV"}

def _bot_log(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    pc2 = ctx.pick_c2() if ctx else None
    return {**b, "type": "Log", "blade": "Anti-Bot",
            "action": random.choice(["Prevent", "Detect"]),
            "severity": "Critical", "src": generate_ip(),
            "dst": pc2.get("ip_c2") if pc2 else generate_ip(),
            "protection_name": random.choice(["Operator.CobaltStrike", "Backdoor.Emotet", "Trojan.TrickBot", "C2.Generic"]),
            "malware_action": "Communication with C&C",
            "confidence_level": "High"}

def _urlf_log(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    cat = random.choice(_URL_CATS)
    action = "Block" if cat in ["Phishing", "Malware", "Spyware / Adware", "Anonymizer"] else random.choice(["Allow", "Monitor"])
    return {**b, "type": "Log", "blade": "URL Filtering", "action": action,
            "severity": "Medium" if action == "Block" else "Informational",
            "resource": f"https://{generate_hostname()}/{random.choice(['', 'login', 'index.html'])}",
            "matched_category": cat, "src": generate_ip(), "dst": generate_ip(),
            "src_user_name": random.choice(_USERS)}

def _appctrl_log(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    app = random.choice(_APPS)
    return {**b, "type": "Log", "blade": "Application Control",
            "action": random.choice(["Accept", "Drop", "Inform"]),
            "severity": "Informational",
            "appi_name": app, "app_risk": random.choice(["Critical", "High", "Medium", "Low", "Very Low"]),
            "src": generate_ip(), "dst": generate_ip(), "src_user_name": random.choice(_USERS)}

_GENERATORS = [
    (_fw_log, 40), (_ips_log, 15), (_av_log, 10), (_bot_log, 8),
    (_urlf_log, 12), (_appctrl_log, 10), (_fw_log, 5),  # extra traffic weight
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
