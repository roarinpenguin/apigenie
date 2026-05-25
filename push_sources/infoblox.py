"""Infoblox DDI log generator — DNS queries, DHCP, RPZ, threat intelligence.

Matches Infoblox NIOS syslog and BloxOne Threat Defense JSON format.
Covers: DNS query/response, DHCP lease events, RPZ (Response Policy Zone)
hits, DNS tunneling, data exfiltration, DGA detection, threat feeds.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_DEVICE_NAMES = ["infoblox-dc1", "infoblox-dc2", "infoblox-branch1", "bloxone-cloud"]
_MEMBERS = ["10.0.1.10", "10.0.1.11", "172.16.1.10"]
_VIEWS = ["default", "internal", "external"]
_ZONES = ["corp.local", "example.com", "10.in-addr.arpa", "168.192.in-addr.arpa"]
_QUERY_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "SOA", "NS", "ANY"]
_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "slack.com", "zoom.us",
    "evil-c2-server.xyz", "dga-domain-abc123.org", "phishing-bank.com",
    "malware-payload.ru", "crypto-miner.io", "suspicious-tunnel.net",
    "cdn.cloudflare.com", "api.amazonaws.com", "login.microsoftonline.com",
]
_RPZ_FEEDS = ["Infoblox-Base", "Infoblox-Malware", "Infoblox-C2", "Infoblox-Phishing",
              "Custom-Blocklist", "ThreatIntel-Feed-1"]
_RPZ_ACTIONS = ["NXDOMAIN", "NODATA", "PASSTHRU", "REDIRECT", "DROP"]
_DHCP_TYPES = ["DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPACK", "DHCPNAK",
               "DHCPRELEASE", "DHCPDECLINE", "DHCPINFORM"]
_THREAT_TYPES = ["C2", "Malware", "Phishing", "DGA", "DNS Tunneling",
                 "Data Exfiltration", "Cryptomining", "Fast Flux"]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _syslog_ts() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

def _dns_query(ctx=None) -> dict[str, Any]:
    pm = ctx.pick_machine() if ctx else None
    client = pm.get("ip") if pm else generate_ip()
    domain = random.choice(_DOMAINS)
    qtype = random.choices(_QUERY_TYPES[:6], weights=[50, 10, 15, 5, 10, 10])[0]
    return {
        "type": "dns_query", "subtype": "query",
        "timestamp": _now(), "device_name": random.choice(_DEVICE_NAMES),
        "member": random.choice(_MEMBERS),
        "client_ip": client, "query_name": domain, "query_type": qtype,
        "view": random.choice(_VIEWS),
        "response_code": random.choices(["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"],
                                         weights=[80, 10, 5, 5])[0],
        "response_ip": generate_ip() if random.random() < 0.8 else "",
        "response_time_ms": random.randint(1, 500),
        "flags": random.choice(["QR RD RA", "QR AA RD RA", "QR RD"]),
        "recursion": random.choice(["yes", "no"]),
        "severity": "informational",
        "vendor": "Infoblox", "product": "NIOS",
    }

def _rpz_hit(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    malicious_domains = ["evil-c2-server.xyz", "dga-domain-abc123.org", "phishing-bank.com",
                         "malware-payload.ru", "crypto-miner.io", "suspicious-tunnel.net"]
    domain = pc2.get("fqdn", random.choice(malicious_domains)) if pc2 else random.choice(malicious_domains)
    feed = random.choice(_RPZ_FEEDS)
    action = random.choices(_RPZ_ACTIONS[:3], weights=[60, 20, 20])[0]
    threat = random.choice(_THREAT_TYPES)
    return {
        "type": "rpz", "subtype": "rpz_hit",
        "timestamp": _now(), "device_name": random.choice(_DEVICE_NAMES),
        "client_ip": generate_ip(), "query_name": domain,
        "query_type": "A",
        "rpz_feed": feed, "rpz_action": action,
        "rpz_policy": f"{feed}-policy",
        "threat_type": threat,
        "threat_level": random.choice(["High", "Medium", "Critical"]),
        "confidence": random.randint(70, 100),
        "severity": "high" if threat in ["C2", "Malware", "Data Exfiltration"] else "medium",
        "vendor": "Infoblox", "product": "NIOS",
    }

def _dhcp_event(ctx=None) -> dict[str, Any]:
    pm = ctx.pick_machine() if ctx else None
    ip = pm.get("ip") if pm else f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
    hostname = pm.get("primary_workstation", generate_hostname().split(".")[0]) if pm else generate_hostname().split(".")[0]
    msg_type = random.choices(_DHCP_TYPES, weights=[10, 10, 20, 30, 2, 10, 2, 16])[0]
    return {
        "type": "dhcp", "subtype": msg_type.lower(),
        "timestamp": _now(), "device_name": random.choice(_DEVICE_NAMES),
        "message_type": msg_type,
        "client_ip": ip, "client_mac": mac, "client_hostname": hostname,
        "lease_time": random.choice([3600, 7200, 14400, 28800, 86400]),
        "subnet": f"10.{random.randint(0,255)}.{random.randint(0,255)}.0/24",
        "scope": random.choice(["corp-workstations", "servers", "guest-wifi", "iot-devices"]),
        "severity": "informational",
        "vendor": "Infoblox", "product": "NIOS",
    }

def _threat_event(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    threat = random.choice(_THREAT_TYPES)
    domain = pc2.get("fqdn", random.choice(_DOMAINS[-6:])) if pc2 else random.choice(_DOMAINS[-6:])
    return {
        "type": "threat", "subtype": threat.lower().replace(" ", "_"),
        "timestamp": _now(), "device_name": random.choice(_DEVICE_NAMES),
        "client_ip": generate_ip(),
        "query_name": domain, "threat_type": threat,
        "threat_level": random.choice(["High", "Critical", "Medium"]),
        "confidence": random.randint(75, 100),
        "threat_indicator": domain,
        "feed": random.choice(_RPZ_FEEDS),
        "action": random.choice(["Block", "Log", "Redirect"]),
        "tld": domain.split(".")[-1],
        "description": f"{threat} activity detected for {domain}",
        "severity": "critical" if threat in ["C2", "Data Exfiltration", "Malware"] else "high",
        "vendor": "Infoblox", "product": "BloxOne Threat Defense",
    }

_GENERATORS = [(_dns_query, 50), (_rpz_hit, 15), (_dhcp_event, 20), (_threat_event, 15)]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
