"""Imperva WAF log generator — security events, access violations, bot detection.

Matches Imperva Cloud WAF (Incapsula) CEF/JSON log format.
Covers: WAF security events, access control violations, bot mitigation,
DDoS, API security, account takeover.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid, generate_country_code

_SITE_IDS = ["12345678", "23456789", "34567890"]
_SITE_NAMES = ["www.example.com", "api.example.com", "app.example.com", "portal.example.com"]
_POP = ["iad", "sjc", "fra", "nrt", "lhr", "sin", "syd"]
_ACTIONS = ["REQ_PASSED", "REQ_BLOCKED", "REQ_CHALLENGED", "REQ_BAD_BOT"]
_ATTACK_TYPES = ["SQL Injection", "Cross Site Scripting", "Remote File Inclusion",
                 "Illegal Resource Access", "Bot Access Control", "Protocol Violation",
                 "Command Injection", "Directory Traversal", "DDoS", "Account Takeover",
                 "API Violation", "Backdoor Protection"]
_BOT_TYPES = ["Bad Bot", "Good Bot", "Search Engine", "Unknown", "Human"]
_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
_PATHS = ["/login", "/api/v1/users", "/api/v2/data", "/admin", "/wp-admin/",
          "/search", "/checkout", "/api/graphql", "/.env", "/etc/passwd",
          "/api/v1/transactions", "/reset-password"]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1",
    "python-requests/2.31.0", "curl/8.7.1", "Googlebot/2.1",
    "sqlmap/1.7", "Nikto/2.5.0", "Mozilla/5.0 (compatible; bot)",
]
_RESPONSE_CODES = [200, 200, 200, 301, 302, 400, 403, 404, 429, 500, 503]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def _epoch_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def _waf_event(ctx=None) -> dict[str, Any]:
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src = pc2.get("ip_c2") if pc2 else generate_ip()
    attack = random.choice(_ATTACK_TYPES[:8])
    blocked = attack in ["SQL Injection", "Cross Site Scripting", "Command Injection",
                         "Remote File Inclusion", "Directory Traversal", "Backdoor Protection"]
    path = random.choice(_PATHS)
    return {
        "type": "WAF", "event_id": str(random.randint(100000000, 999999999)),
        "time": _epoch_ms(), "datetime": _now(),
        "site_id": random.choice(_SITE_IDS), "site_name": random.choice(_SITE_NAMES),
        "pop": random.choice(_POP),
        "src_ip": src, "src_port": random.randint(1024, 65535),
        "country_code": generate_country_code(),
        "dst_ip": generate_ip(), "dst_port": random.choice([80, 443]),
        "request_url": f"https://{random.choice(_SITE_NAMES)}{path}",
        "request_method": random.choice(_HTTP_METHODS[:4]),
        "user_agent": random.choice(_USER_AGENTS),
        "response_code": 403 if blocked else random.choice([200, 200, 200, 301]),
        "action": "REQ_BLOCKED" if blocked else "REQ_PASSED",
        "attack_type": attack, "attack_id": f"att-{random.randint(10000,99999)}",
        "rule_name": f"WAF-{attack.replace(' ', '-')}-{random.randint(1,99):02d}",
        "severity": "high" if blocked else "medium",
        "additional_info": {"violated_directive": f"rule {random.randint(100000, 999999)}"},
        "vendor": "Imperva", "product": "Cloud WAF",
    }

def _bot_event(ctx=None) -> dict[str, Any]:
    bot_type = random.choices(_BOT_TYPES, weights=[40, 15, 10, 25, 10])[0]
    action = "REQ_BAD_BOT" if bot_type in ["Bad Bot", "Unknown"] else "REQ_PASSED"
    return {
        "type": "BOT", "event_id": str(random.randint(100000000, 999999999)),
        "time": _epoch_ms(), "datetime": _now(),
        "site_id": random.choice(_SITE_IDS), "site_name": random.choice(_SITE_NAMES),
        "src_ip": generate_ip(), "country_code": generate_country_code(),
        "request_url": f"https://{random.choice(_SITE_NAMES)}{random.choice(_PATHS[:6])}",
        "user_agent": random.choice(_USER_AGENTS),
        "bot_type": bot_type, "action": action,
        "bot_classification": random.choice(["Scraper", "Scanner", "Spammer", "Click Bot", "Credential Stuffer", "SEO Bot"]),
        "challenge_type": random.choice(["CAPTCHA", "JS Challenge", "Fingerprint", "None"]) if action == "REQ_BAD_BOT" else "None",
        "severity": "medium" if action == "REQ_BAD_BOT" else "informational",
        "vendor": "Imperva", "product": "Cloud WAF",
    }

def _acl_event(ctx=None) -> dict[str, Any]:
    return {
        "type": "ACL", "event_id": str(random.randint(100000000, 999999999)),
        "time": _epoch_ms(), "datetime": _now(),
        "site_id": random.choice(_SITE_IDS), "site_name": random.choice(_SITE_NAMES),
        "src_ip": generate_ip(), "country_code": generate_country_code(),
        "request_url": f"https://{random.choice(_SITE_NAMES)}{random.choice(_PATHS)}",
        "action": random.choice(["REQ_BLOCKED", "REQ_CHALLENGED"]),
        "rule_name": random.choice(["GeoBlock-CN", "GeoBlock-RU", "IP-Blacklist", "Rate-Limit-Exceeded",
                                     "Country-Block", "IP-Reputation-Block"]),
        "severity": "medium",
        "vendor": "Imperva", "product": "Cloud WAF",
    }

def _ddos_event(ctx=None) -> dict[str, Any]:
    return {
        "type": "DDOS", "event_id": str(random.randint(100000000, 999999999)),
        "time": _epoch_ms(), "datetime": _now(),
        "site_id": random.choice(_SITE_IDS), "site_name": random.choice(_SITE_NAMES),
        "action": "REQ_BLOCKED",
        "attack_type": random.choice(["HTTP Flood", "Slowloris", "RUDY", "Application DDoS"]),
        "requests_per_second": random.randint(1000, 100000),
        "total_requests": random.randint(50000, 5000000),
        "mitigation": random.choice(["Rate Limiting", "JS Challenge", "CAPTCHA", "Block"]),
        "severity": "critical",
        "vendor": "Imperva", "product": "Cloud WAF",
    }

_GENERATORS = [(_waf_event, 45), (_bot_event, 25), (_acl_event, 20), (_ddos_event, 10)]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
