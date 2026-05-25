"""Zscaler Internet Access (ZIA) log generator — web, firewall, DNS, tunnel logs.

Matches ZIA Nanolog Streaming Service (NSS) JSON/CEF output format.
Covers: web transactions, firewall logs, DNS logs, tunnel events.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid, generate_country_code

_DEPARTMENTS = ["Engineering", "Sales", "Marketing", "Finance", "IT", "HR", "Legal", "Executive"]
_LOCATIONS = ["HQ-SFO", "Office-NYC", "Branch-LON", "Branch-TYO", "Remote-Users"]
_USERS = ["jsmith@corp.com", "agarcia@corp.com", "mwilson@corp.com", "lchen@corp.com", "admin@corp.com"]
_APPS = ["Microsoft 365", "Salesforce", "Slack", "Zoom", "Google Workspace", "Box",
         "Dropbox", "GitHub", "AWS Console", "ServiceNow", "Jira", "BitTorrent", "Tor"]
_URL_CATS = ["Business Use", "Web Search", "Streaming Media", "Social Networking",
             "Adult Content", "Malware", "Phishing", "Advanced Security Risk",
             "Newly Registered Domains", "Unauthorized Communication", "Peer-to-Peer"]
_URL_SUPER_CATS = ["Business & Economy", "Information Technology", "Entertainment", "Adult", "Security"]
_ACTIONS = ["Allowed", "Blocked", "Cautioned", "Isolated"]
_DLP_DICTS = ["SSN", "Credit Card", "HIPAA", "PCI", "Custom Sensitive Data"]
_THREAT_NAMES = ["Malicious URL", "Phishing Page", "Adware", "Cryptominer", "C2 Communication",
                 "Known Malware Host", "Suspicious Content", "Browser Exploit"]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())

def _web_log(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    user = pu.get("email", random.choice(_USERS)) if pu else random.choice(_USERS)
    clientip = pm.get("ip") if pm else generate_ip()
    serverip = pc2.get("ip_c2") if pc2 else generate_ip()
    cat = random.choice(_URL_CATS)
    action = "Blocked" if cat in ["Malware", "Phishing", "Advanced Security Risk", "Adult Content"] else random.choice(["Allowed", "Cautioned"])
    host = generate_hostname()
    return {
        "sourcetype": "zscalernss-web", "event": {
            "datetime": _now(), "timestamp": _epoch(),
            "login": user, "department": random.choice(_DEPARTMENTS),
            "location": random.choice(_LOCATIONS), "clientip": clientip,
            "clientpublicIP": generate_ip(), "serverip": serverip,
            "hostname": host, "url": f"https://{host}/{random.choice(['', 'login', 'api', 'download'])}",
            "urlcategory": cat, "urlsupercategory": random.choice(_URL_SUPER_CATS),
            "action": action, "reason": cat if action == "Blocked" else "",
            "requestmethod": random.choice(["GET", "POST", "GET", "GET"]),
            "requestsize": random.randint(200, 5000),
            "responsesize": random.randint(500, 500000),
            "statuscode": 200 if action == "Allowed" else 403,
            "useragent": random.choice(["Mozilla/5.0 Chrome/124", "Mozilla/5.0 Firefox/126", "curl/8.7"]),
            "contenttype": random.choice(["text/html", "application/json", "image/png", "application/pdf"]),
            "threatname": random.choice(_THREAT_NAMES) if action == "Blocked" else "",
            "dlpdictnames": random.choice(_DLP_DICTS) if random.random() < 0.1 else "",
            "appname": random.choice(_APPS),
        },
        "type": "web", "severity": "high" if action == "Blocked" else "informational",
        "vendor": "Zscaler", "product": "ZIA",
    }

def _fw_log(ctx=None) -> dict[str, Any]:
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    return {
        "sourcetype": "zscalernss-fw", "event": {
            "datetime": _now(), "timestamp": _epoch(),
            "csrcip": pm.get("ip") if pm else generate_ip(),
            "cdstip": pc2.get("ip_c2") if pc2 else generate_ip(),
            "csrcport": random.randint(1024, 65535),
            "cdstport": random.choice([80, 443, 22, 3389, 53, 25]),
            "proto": random.choice(["TCP", "UDP", "ICMP"]),
            "action": random.choice(["Allow", "Drop", "Reset"]),
            "department": random.choice(_DEPARTMENTS),
            "location": random.choice(_LOCATIONS),
            "nwapp": random.choice(_APPS[:8]),
            "rulelabel": random.choice(["Allow-Outbound", "Block-Tor", "Block-P2P", "Default-Allow"]),
            "aggregate": random.choice(["No", "Yes"]),
            "durationms": random.randint(0, 60000),
            "avgduration": random.randint(0, 1000),
            "csrcbytes": random.randint(100, 500000),
            "cdstbytes": random.randint(100, 800000),
        },
        "type": "firewall", "severity": "informational",
        "vendor": "Zscaler", "product": "ZIA",
    }

def _dns_log(ctx=None) -> dict[str, Any]:
    domains = ["example.com", "google.com", "evil-c2.xyz", "phishing-site.org",
               "cdn.cloudflare.com", "api.github.com", "malware-payload.ru"]
    dom = random.choice(domains)
    action = "Blocked" if dom in ["evil-c2.xyz", "phishing-site.org", "malware-payload.ru"] else "Allowed"
    return {
        "sourcetype": "zscalernss-dns", "event": {
            "datetime": _now(), "timestamp": _epoch(),
            "login": random.choice(_USERS),
            "department": random.choice(_DEPARTMENTS),
            "location": random.choice(_LOCATIONS),
            "dns_req": dom, "dns_reqtype": random.choice(["A", "AAAA", "CNAME", "MX", "TXT"]),
            "dns_resp": generate_ip() if action == "Allowed" else "0.0.0.0",
            "action": action, "category": random.choice(_URL_CATS[:5]),
            "durationms": random.randint(1, 500),
        },
        "type": "dns", "severity": "high" if action == "Blocked" else "informational",
        "vendor": "Zscaler", "product": "ZIA",
    }

def _tunnel_log(ctx=None) -> dict[str, Any]:
    return {
        "sourcetype": "zscalernss-tunnel", "event": {
            "datetime": _now(), "Ession": generate_uuid(),
            "location": random.choice(_LOCATIONS),
            "sourceip": generate_ip(), "destinationip": generate_ip(),
            "event": random.choice(["PHASE1_UP", "PHASE1_DOWN", "PHASE2_UP", "PHASE2_DOWN", "REKEY"]),
            "eventreason": random.choice(["Normal", "Timeout", "Peer Reset", "DPD Failure", ""]),
            "tunneltype": random.choice(["GRE", "IPSec", "ZTunnel 2.0"]),
            "txbytes": random.randint(0, 50000000), "rxbytes": random.randint(0, 80000000),
            "dpdrec": random.randint(0, 100),
        },
        "type": "tunnel", "severity": "informational",
        "vendor": "Zscaler", "product": "ZIA",
    }

_GENERATORS = [(_web_log, 50), (_fw_log, 20), (_dns_log, 20), (_tunnel_log, 10)]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
