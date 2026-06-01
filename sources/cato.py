"""Cato Networks SASE — mock GraphQL eventsFeed and auditFeed.

Matches the Cato Networks GraphQL API (api.catonetworks.com/api/v1/graphql2).
Auth: x-api-key header.
Event types: Security (IPS, anti-malware, firewall), Internet Access, WAN, Audit.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid
from detection_rules import inject_detection_events
import profiles

_ACCOUNT_IDS = ["12345", "67890"]
_SITES = [
    {"id": "100", "name": "HQ-NewYork"},
    {"id": "101", "name": "Branch-London"},
    {"id": "102", "name": "DC-Frankfurt"},
    {"id": "103", "name": "Remote-Tokyo"},
]
_USERS = ["jsmith@corp.com", "agarcia@corp.com", "mwilson@corp.com",
          "lchen@corp.com", "admin@corp.com", "svc-vpn@corp.com"]
_RULE_NAMES = ["Allow-Web", "Block-Malware", "Allow-SaaS", "Block-Gambling",
               "IPS-Default", "Allow-VPN", "Block-TOR", "Allow-O365"]
_APP_CATEGORIES = ["Web Browsing", "Cloud Storage", "Email", "Social Media",
                    "Streaming", "Business Apps", "Security", "Malware"]
_APPS = ["Microsoft 365", "Google Workspace", "Salesforce", "Slack", "Zoom",
         "AWS Console", "GitHub", "Dropbox", "Box", "ServiceNow"]
_THREAT_TYPES = ["Malware", "Phishing", "Command & Control", "Exploit",
                  "Ransomware", "Spyware", "Trojan", "Worm"]
_IPS_SIGNATURES = [
    "CVE-2021-44228 Log4Shell", "CVE-2023-34362 MOVEit SQL Injection",
    "CVE-2024-3400 PAN-OS Command Injection", "Emotet C2 Communication",
    "Cobalt Strike Beacon", "Brute Force SSH", "DNS Tunneling Detected",
    "TOR Exit Node Communication", "Cryptominer Detected",
]
_ACTIONS = ["Allow", "Block", "Monitor", "Alert"]
_OS_TYPES = ["Windows", "macOS", "Linux", "iOS", "Android"]
_DEVICE_TYPES = ["Laptop", "Desktop", "Mobile", "Server", "Virtual"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


def _marker() -> str:
    return generate_uuid()[:16]


def _security_event(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    subtypes = [
        ("IPS", "ips"),
        ("Anti Malware", "anti_malware"),
        ("Firewall", "firewall"),
    ]
    event_type, subtype = random.choice(subtypes)
    site = random.choice(_SITES)
    action = random.choice(_ACTIONS)
    ev = {
        "event_type": "Security",
        "event_sub_type": event_type,
        "time": _now_iso(),
        "account_id": random.choice(_ACCOUNT_IDS),
        "site_id": site["id"],
        "site_name": site["name"],
        "source_ip": generate_ip(),
        "source_port": random.randint(1024, 65535),
        "destination_ip": pc2.get("ip_c2", generate_ip()) if pc2 else generate_ip(),
        "destination_port": random.choice([80, 443, 22, 25, 53, 8080]),
        "protocol": random.choice(["TCP", "UDP"]),
        "action": action,
        "rule_name": random.choice(_RULE_NAMES),
        "user_name": random.choice(_USERS),
        "os_type": random.choice(_OS_TYPES),
        "device_type": random.choice(_DEVICE_TYPES),
        "src_country": random.choice(["US", "GB", "DE", "JP", "FR"]),
        "dst_country": random.choice(["US", "NL", "RU", "CN", "DE", "IR"]),
        "risk_score": random.randint(0, 100),
        "severity": random.choices(["Critical", "High", "Medium", "Low", "Info"],
                                    weights=[5, 15, 30, 30, 20])[0],
    }
    if subtype == "ips":
        ev["signature"] = random.choice(_IPS_SIGNATURES)
        ev["threat_type"] = random.choice(_THREAT_TYPES)
        ev["cve"] = random.choice(["CVE-2021-44228", "CVE-2023-34362", "CVE-2024-3400", ""])
    elif subtype == "anti_malware":
        ev["threat_name"] = random.choice(["Win32/Emotet", "Trojan.GenericKD", "JS/Downloader",
                                            "Ransom.WannaCry", "HEUR:Trojan.Script"])
        ev["threat_type"] = random.choice(_THREAT_TYPES[:5])
        ev["file_name"] = random.choice(["invoice.exe", "update.dll", "doc.pdf.exe", "setup.msi"])
        ev["file_hash"] = generate_uuid().replace("-", "") * 2
    else:
        ev["application"] = random.choice(_APPS)
        ev["application_category"] = random.choice(_APP_CATEGORIES)
    return ev


def _internet_access_event(ctx=None) -> dict[str, Any]:
    site = random.choice(_SITES)
    return {
        "event_type": "Internet Access",
        "event_sub_type": random.choice(["Internet Firewall", "URL Filtering", "SaaS Security"]),
        "time": _now_iso(),
        "account_id": random.choice(_ACCOUNT_IDS),
        "site_id": site["id"],
        "site_name": site["name"],
        "source_ip": generate_ip(),
        "destination_ip": generate_ip(),
        "destination_port": random.choice([80, 443]),
        "protocol": "TCP",
        "action": random.choice(["Allow", "Block", "Monitor"]),
        "rule_name": random.choice(_RULE_NAMES),
        "user_name": random.choice(_USERS),
        "application": random.choice(_APPS),
        "application_category": random.choice(_APP_CATEGORIES),
        "url": f"https://{random.choice(['example.com','corp-app.com','docs.google.com'])}/path",
        "domain": random.choice(["example.com", "corp-app.com", "docs.google.com"]),
        "bytes_uploaded": random.randint(100, 500000),
        "bytes_downloaded": random.randint(100, 5000000),
        "duration_ms": random.randint(10, 30000),
        "os_type": random.choice(_OS_TYPES),
        "severity": "Info",
    }


def _wan_event(ctx=None) -> dict[str, Any]:
    sites = random.sample(_SITES, 2)
    return {
        "event_type": "WAN",
        "event_sub_type": random.choice(["SD-WAN", "Connectivity", "Link Health"]),
        "time": _now_iso(),
        "account_id": random.choice(_ACCOUNT_IDS),
        "src_site_id": sites[0]["id"],
        "src_site_name": sites[0]["name"],
        "dst_site_id": sites[1]["id"],
        "dst_site_name": sites[1]["name"],
        "tunnel_type": random.choice(["IPSec", "DTLS", "GRE"]),
        "pop_name": random.choice(["New York", "London", "Frankfurt", "Singapore"]),
        "link_type": random.choice(["Primary", "Secondary", "Backup"]),
        "latency_ms": round(random.uniform(5, 200), 1),
        "jitter_ms": round(random.uniform(0.5, 50), 1),
        "packet_loss_pct": round(random.uniform(0, 5), 2),
        "bandwidth_up_mbps": round(random.uniform(10, 1000), 1),
        "bandwidth_down_mbps": round(random.uniform(10, 1000), 1),
        "severity": "Info" if random.random() > 0.1 else random.choice(["Warning", "Error"]),
    }


def _audit_event(ctx=None) -> dict[str, Any]:
    actions = [
        ("admin_login", "Admin Login", "Admin logged in to management console"),
        ("policy_update", "Policy Update", "Firewall policy updated"),
        ("site_config", "Site Configuration", "Site settings modified"),
        ("user_add", "User Management", "New admin user created"),
        ("rule_change", "Rule Change", "Security rule modified"),
        ("certificate_update", "Certificate", "TLS certificate updated"),
        ("license_update", "License", "License updated"),
        ("api_key_created", "API Key", "New API key created"),
    ]
    action, category, desc = random.choice(actions)
    return {
        "event_type": "Audit",
        "event_sub_type": category,
        "time": _now_iso(),
        "account_id": random.choice(_ACCOUNT_IDS),
        "admin_user": random.choice(["admin@corp.com", "netops@corp.com", "secops@corp.com"]),
        "admin_ip": generate_ip(),
        "action": action,
        "object_type": category,
        "description": desc,
        "result": random.choice(["Success", "Success", "Success", "Failure"]),
        "severity": "Info",
    }


_GENERATORS = [
    (_security_event, 30), (_internet_access_event, 30),
    (_wan_event, 20), (_audit_event, 20),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]


def generate_events(count: int = 20) -> list[dict[str, Any]]:
    ctx = profiles.get_context("cato")
    count = profiles.scale_count("cato", count)
    events = [random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0](ctx) for _ in range(count)]
    events = inject_detection_events("cato", events)
    return events
