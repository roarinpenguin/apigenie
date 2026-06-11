"""Cloudflare log generator — HTTP, Firewall, WAF, DNS, Bot, Access, Gateway events.

Matches Cloudflare Logpull REST API (GET /zones/{zone_id}/logs/received)
and GraphQL Analytics API (POST /graphql).
Auth: Bearer token or X-Auth-Email + X-Auth-Key.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid, weighted_choice
from detection_rules import inject_detection_events
import event_mix
import profiles

_ZONES = [
    {"id": "zone_abc123", "name": "example.com"},
    {"id": "zone_def456", "name": "api.corp.com"},
    {"id": "zone_ghi789", "name": "app.company.io"},
]
_EDGE_LOCATIONS = ["EWR", "LAX", "LHR", "FRA", "NRT", "SIN", "SYD", "CDG", "AMS", "ORD"]
_COUNTRIES = ["US", "GB", "DE", "JP", "FR", "NL", "CN", "RU", "BR", "IN"]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "curl/8.7.1", "python-requests/2.32", "Go-http-client/2.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]
_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
_HTTP_VERSIONS = ["HTTP/1.1", "HTTP/2", "HTTP/3"]
_CACHE_STATUSES = ["hit", "miss", "expired", "dynamic", "bypass", "revalidated"]
_WAF_ACTIONS = ["block", "challenge", "simulate", "allow", "log"]
_WAF_RULES = [
    ("100001", "SQLi - UNION SELECT", "SQLi"),
    ("100002", "XSS - Script Injection", "XSS"),
    ("100003", "RFI - Remote File Inclusion", "RFI"),
    ("100004", "LFI - Local File Inclusion", "LFI"),
    ("100005", "Command Injection", "CMDi"),
    ("100006", "Directory Traversal", "Traversal"),
    ("100007", "Log4j Exploit Attempt", "CVE"),
]
_FW_ACTIONS = ["allow", "block", "challenge", "js_challenge", "managed_challenge"]
_BOT_SCORES = list(range(1, 100))
_BOT_SOURCES = ["Not Computed", "Machine Learning", "Heuristics", "Behavioral Analysis", "JS Fingerprinting"]
_ACCESS_DECISIONS = ["Allow", "Deny", "Bypass"]
_GATEWAY_ACTIONS = ["allow", "block", "isolate", "override"]
_DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
_PATHS = ["/", "/api/v1/users", "/login", "/admin", "/wp-admin/", "/.env",
          "/api/graphql", "/health", "/static/main.js", "/robots.txt"]
_STATUS_CODES = [200, 200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 429, 500, 502, 503]


def _ray_id() -> str:
    return generate_uuid().replace("-", "")[:16]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


def _http_request_event(ctx=None) -> dict[str, Any]:
    zone = random.choice(_ZONES)
    status = random.choice(_STATUS_CODES)
    return {
        "event_type": "http_request",
        "RayID": _ray_id(),
        "ZoneName": zone["name"],
        "ZoneID": zone["id"],
        "EdgeStartTimestamp": _now_iso(),
        "EdgeEndTimestamp": _now_iso(),
        "EdgeResponseStatus": status,
        "EdgeColoCode": random.choice(_EDGE_LOCATIONS),
        "EdgeColoID": random.randint(1, 300),
        "ClientIP": generate_ip(),
        "ClientCountry": random.choice(_COUNTRIES),
        "ClientRequestMethod": random.choice(_HTTP_METHODS),
        "ClientRequestURI": random.choice(_PATHS),
        "ClientRequestHost": zone["name"],
        "ClientRequestProtocol": random.choice(_HTTP_VERSIONS),
        "ClientRequestUserAgent": random.choice(_USER_AGENTS),
        "ClientRequestBytes": random.randint(100, 50000),
        "EdgeResponseBytes": random.randint(100, 500000),
        "OriginResponseStatus": status,
        "OriginResponseTime": random.randint(1, 5000),
        "CacheCacheStatus": random.choice(_CACHE_STATUSES),
        "CacheResponseBytes": random.randint(0, 500000),
        "SecurityLevel": random.choice(["low", "medium", "high", "essentially_off"]),
        "WAFAction": "none",
        "WAFProfile": "low",
        "BotScore": random.choice(_BOT_SCORES),
        "BotScoreSrc": random.choice(_BOT_SOURCES),
        "WorkerStatus": random.choice(["ok", "unknown", ""]),
        "EdgeRateLimitAction": "",
        "EdgeRateLimitID": 0,
        "OriginIP": generate_ip(),
        "UpperTierColoID": 0,
    }


def _firewall_event(ctx=None) -> dict[str, Any]:
    zone = random.choice(_ZONES)
    action = random.choice(_FW_ACTIONS)
    return {
        "event_type": "firewall_event",
        "RayID": _ray_id(),
        "ZoneName": zone["name"],
        "Datetime": _now_iso(),
        "Action": action,
        "ClientIP": generate_ip(),
        "ClientCountry": random.choice(_COUNTRIES),
        "ClientRequestMethod": random.choice(_HTTP_METHODS),
        "ClientRequestPath": random.choice(_PATHS),
        "ClientRequestHost": zone["name"],
        "ClientRequestUserAgent": random.choice(_USER_AGENTS),
        "Source": random.choice(["firewallRules", "rateLimit", "securityLevel",
                                  "l7ddos", "ipAccessRules", "bic", "hot"]),
        "RuleID": generate_uuid()[:8],
        "EdgeColoCode": random.choice(_EDGE_LOCATIONS),
        "OriginResponseStatus": random.choice(_STATUS_CODES),
        "Kind": random.choice(["firewall", "managed", "rate_limit"]),
        "Description": f"Firewall rule triggered: {action}",
    }


def _waf_event(ctx=None) -> dict[str, Any]:
    rule_id, rule_desc, rule_group = random.choice(_WAF_RULES)
    action = random.choice(_WAF_ACTIONS)
    return {
        "event_type": "waf_event",
        "RayID": _ray_id(),
        "ZoneName": random.choice(_ZONES)["name"],
        "Datetime": _now_iso(),
        "Action": action,
        "ClientIP": generate_ip(),
        "ClientCountry": random.choice(_COUNTRIES),
        "ClientRequestMethod": random.choice(["GET", "POST", "PUT"]),
        "ClientRequestPath": random.choice(["/login", "/api/v1/query", "/admin",
                                             "/wp-admin/admin-ajax.php", "/search"]),
        "WAFRuleID": rule_id,
        "WAFRuleMessage": rule_desc,
        "WAFGroup": rule_group,
        "WAFAction": action,
        "WAFFlags": random.choice(["0", "1", "2"]),
        "EdgeColoCode": random.choice(_EDGE_LOCATIONS),
        "MatchedData": random.choice(["UNION SELECT", "<script>", "../../../etc/passwd",
                                       "${jndi:ldap://", "'; DROP TABLE"]),
    }


def _dns_event(ctx=None) -> dict[str, Any]:
    zone = random.choice(_ZONES)
    return {
        "event_type": "dns_event",
        "ZoneName": zone["name"],
        "Datetime": _now_iso(),
        "QueryName": zone["name"],
        "QueryType": random.choice(_DNS_TYPES),
        "ResponseCode": random.choice([0, 0, 0, 3, 2]),  # NOERROR, NXDOMAIN, SERVFAIL
        "SourceIP": generate_ip(),
        "ColoCode": random.choice(_EDGE_LOCATIONS),
        "EDNSSubnet": f"{generate_ip()}/24",
        "EDNSSubnetLength": 24,
        "ResponseCached": random.choice([True, False]),
        "StaleCount": 0,
    }


def _bot_management_event(ctx=None) -> dict[str, Any]:
    score = random.randint(1, 99)
    return {
        "event_type": "bot_management",
        "RayID": _ray_id(),
        "ZoneName": random.choice(_ZONES)["name"],
        "Datetime": _now_iso(),
        "BotScore": score,
        "BotScoreSrc": random.choice(_BOT_SOURCES),
        "BotDetectionIDs": [random.randint(1, 50)] if score < 30 else [],
        "Verified": random.choice([True, False]),
        "Action": "block" if score < 10 else ("challenge" if score < 30 else "allow"),
        "ClientIP": generate_ip(),
        "ClientRequestUserAgent": random.choice(_USER_AGENTS),
        "JA3Hash": generate_uuid().replace("-", "")[:32],
        "ClientRequestPath": random.choice(_PATHS),
    }


def _access_event(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    user = pu.get("email", f"user{random.randint(1,20)}@corp.com") if pu else f"user{random.randint(1,20)}@corp.com"
    return {
        "event_type": "access_event",
        "Datetime": _now_iso(),
        "UserEmail": user,
        "UserUID": generate_uuid(),
        "IPAddress": generate_ip(),
        "Country": random.choice(_COUNTRIES),
        "AppDomain": random.choice(["app.corp.com", "dashboard.internal.io", "admin.company.com"]),
        "AppName": random.choice(["Internal Dashboard", "Admin Portal", "Dev Tools", "HR System"]),
        "Action": random.choice(_ACCESS_DECISIONS),
        "Connection": random.choice(["warp", "browser", "api"]),
        "PolicyName": random.choice(["Corp SSO", "Admin Only", "Engineering Team", "Default Deny"]),
        "DevicePostureCheck": random.choice(["pass", "pass", "fail"]),
        "SessionDuration": random.randint(60, 28800),
        "DeviceID": generate_uuid(),
    }


def _gateway_event(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    return {
        "event_type": "gateway_event",
        "Datetime": _now_iso(),
        "UserEmail": f"user{random.randint(1,20)}@corp.com",
        "SourceIP": generate_ip(),
        "DestinationIP": pc2.get("ip_c2", generate_ip()) if pc2 else generate_ip(),
        "DestinationPort": random.choice([80, 443, 22, 53, 8080]),
        "Protocol": random.choice(["TCP", "UDP"]),
        "Action": random.choice(_GATEWAY_ACTIONS),
        "PolicyName": random.choice(["Block Malware", "Allow SaaS", "Block Social", "Monitor All"]),
        "SNI": pc2.get("fqdn", random.choice(["example.com", "malware-c2.xyz"])) if pc2 else random.choice(["example.com", "legit.com"]),
        "HTTPHost": random.choice(["example.com", "api.corp.com"]),
        "Categories": random.sample(["Malware", "Phishing", "Business", "Technology",
                                      "Social Media", "Gambling", "Adult"], k=random.randint(1, 3)),
        "Location": random.choice(["HQ", "Branch-London", "Remote"]),
        "DeviceID": generate_uuid(),
        "DeviceName": generate_hostname(),
    }


def _audit_event(ctx=None) -> dict[str, Any]:
    actions = [
        ("zone.setting.changed", "Zone setting modified"),
        ("user.login", "User logged in"),
        ("firewall.rule.created", "Firewall rule created"),
        ("dns.record.created", "DNS record added"),
        ("access.policy.updated", "Access policy updated"),
        ("api_token.created", "API token created"),
        ("page_rule.created", "Page rule created"),
        ("waf.rule_group.updated", "WAF rule group updated"),
    ]
    action_type, desc = random.choice(actions)
    return {
        "event_type": "audit_event",
        "Datetime": _now_iso(),
        "ActorEmail": f"admin{random.randint(1,5)}@corp.com",
        "ActorIP": generate_ip(),
        "ActorType": random.choice(["user", "user", "token"]),
        "ActionType": action_type,
        "ActionResult": random.choice([True, True, True, False]),
        "ResourceType": action_type.split(".")[0],
        "ResourceID": generate_uuid()[:12],
        "Description": desc,
        "ZoneName": random.choice(_ZONES)["name"],
        "Interface": random.choice(["UI", "API", "Terraform"]),
    }


# ── Event catalog ──────────────────────────────────────────────────────
# Eight top-level Cloudflare log streams exposed by Logpull / Logpush /
# GraphQL Analytics. Each one corresponds to a distinct Logpush dataset.
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "http_request", "label": "HTTP request log (edge access)",
     "default_weight": 0.25,
     "docs_anchor": "developers.cloudflare.com/logs/reference/log-fields/zone/http_requests"},
    {"id": "firewall_event", "label": "Firewall event (IP / country / ASN rules)",
     "default_weight": 0.15,
     "docs_anchor": "developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events"},
    {"id": "waf_event", "label": "WAF event (managed / OWASP / custom rules)",
     "default_weight": 0.10,
     "docs_anchor": "developers.cloudflare.com/waf/"},
    {"id": "dns_event", "label": "DNS query log",
     "default_weight": 0.12,
     "docs_anchor": "developers.cloudflare.com/logs/reference/log-fields/zone/dns_logs"},
    {"id": "bot_management", "label": "Bot Management score",
     "default_weight": 0.08,
     "docs_anchor": "developers.cloudflare.com/bots/concepts/bot-score/"},
    {"id": "access_event", "label": "Cloudflare Access (Zero Trust SSO)",
     "default_weight": 0.10,
     "docs_anchor": "developers.cloudflare.com/cloudflare-one/policies/access/"},
    {"id": "gateway_event", "label": "Gateway DNS/HTTP/Network (Zero Trust SWG)",
     "default_weight": 0.12,
     "docs_anchor": "developers.cloudflare.com/cloudflare-one/policies/gateway/"},
    {"id": "audit_event", "label": "Account audit log (admin actions)",
     "default_weight": 0.08,
     "docs_anchor": "developers.cloudflare.com/fundamentals/setup/account/account-security/review-audit-logs/"},
]

# Catalogue ids → (generator callable, default weight). Keys MUST match
# EVENT_CATALOG ids exactly so admin overrides bind 1:1.
_EVENT_TEMPLATES: dict[str, tuple[Any, float]] = {
    "http_request":    (_http_request_event,    0.25),
    "firewall_event":  (_firewall_event,        0.15),
    "waf_event":       (_waf_event,             0.10),
    "dns_event":       (_dns_event,             0.12),
    "bot_management":  (_bot_management_event,  0.08),
    "access_event":    (_access_event,          0.10),
    "gateway_event":   (_gateway_event,         0.12),
    "audit_event":     (_audit_event,           0.08),
}


def generate_events(count: int = 20) -> list[dict[str, Any]]:
    ctx = profiles.get_context("cloudflare")
    count = profiles.scale_count("cloudflare", count)
    templates = event_mix.apply(_EVENT_TEMPLATES, "cloudflare")
    events = [weighted_choice(templates)(ctx) for _ in range(count)]
    events = inject_detection_events("cloudflare", events)
    return events
