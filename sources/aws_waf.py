"""AWS WAF mock data generator (logs in millisecond timestamps)."""

import random
from typing import Any

from generators import (
    generate_ip,
    generate_uuid,
    now_epoch_ms,
    weighted_choice,
)

_WEB_ACLS = [
    "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/production-waf/abc123",
    "arn:aws:wafv2:us-west-2:123456789012:regional/webacl/staging-waf/def456",
]
_RULE_GROUPS = ["AWS-AWSManagedRulesCommonRuleSet", "AWS-AWSManagedRulesSQLiRuleSet", "AWS-AWSManagedRulesKnownBadInputsRuleSet"]
_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"]
_PATHS = ["/api/v1/users", "/api/v1/login", "/api/v1/data", "/admin", "/wp-admin", "/api/search", "/"]

_LOG_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "allowed_request": ({"action": "ALLOW", "terminatingRuleType": "REGULAR", "ruleId": "AllowRule"}, 0.40),
    "xss_block": (
        {"action": "BLOCK", "terminatingRuleType": "MANAGED_RULE_GROUP", "ruleId": "CrossSiteScripting_BODY"},
        0.25,
    ),
    "sql_injection_block": (
        {"action": "BLOCK", "terminatingRuleType": "MANAGED_RULE_GROUP", "ruleId": "SQLi_BODY"},
        0.15,
    ),
    "rate_limit_block": (
        {"action": "BLOCK", "terminatingRuleType": "RATE_BASED", "ruleId": "RateBasedRule-1000"},
        0.10,
    ),
    "bot_block": (
        {"action": "BLOCK", "terminatingRuleType": "MANAGED_RULE_GROUP", "ruleId": "SignalNonBrowserUserAgent"},
        0.05,
    ),
    "captcha_challenge": (
        {"action": "CAPTCHA", "terminatingRuleType": "REGULAR", "ruleId": "CaptchaRule"},
        0.03,
    ),
    "lfi_block": (
        {"action": "BLOCK", "terminatingRuleType": "MANAGED_RULE_GROUP", "ruleId": "LFI_URIPATH"},
        0.02,
    ),
}


def _generate_log() -> dict[str, Any]:
    template = weighted_choice(_LOG_TEMPLATES)
    ts_ms = now_epoch_ms() - random.randint(0, 3600000)
    web_acl = random.choice(_WEB_ACLS)
    path = random.choice(_PATHS)
    method = random.choice(_HTTP_METHODS)
    src_ip = generate_ip()

    # Inject attack payloads for blocked requests
    query_string = ""
    if template["action"] == "BLOCK":
        if "SQLi" in template["ruleId"]:
            query_string = "id=1+OR+1=1--&pass=password"
        elif "CrossSite" in template["ruleId"]:
            query_string = "q=<script>alert('xss')</script>"
        elif "LFI" in template["ruleId"]:
            query_string = "file=../../../../etc/passwd"

    return {
        "timestamp": ts_ms,
        "formatVersion": 1,
        "webaclId": web_acl,
        "terminatingRuleId": template["ruleId"],
        "terminatingRuleType": template["terminatingRuleType"],
        "action": template["action"],
        "terminatingRuleMatchDetails": [],
        "httpSourceName": "ALB",
        "httpSourceId": f"123456789012-app/prod-alb/{generate_uuid()[:16]}",
        "ruleGroupList": [
            {
                "ruleGroupId": random.choice(_RULE_GROUPS),
                "terminatingRule": None,
                "nonTerminatingMatchingRules": [],
                "excludedRules": None,
            }
        ],
        "rateBasedRuleList": [],
        "nonTerminatingMatchingRules": [],
        "requestHeadersInserted": None,
        "responseCodeSent": None,
        "httpRequest": {
            "clientIp": src_ip,
            "country": random.choice(["US", "CN", "RU", "DE", "GB", "BR", "IN"]),
            "headers": [
                {"name": "Host", "value": "api.example.com"},
                {"name": "User-Agent", "value": random.choice(["Mozilla/5.0", "curl/7.68.0", "python-requests/2.28.0", "sqlmap/1.7"])},
                {"name": "Accept", "value": "application/json"},
            ],
            "uri": path,
            "args": query_string,
            "httpVersion": random.choice(["HTTP/1.1", "HTTP/2.0"]),
            "httpMethod": method,
            "requestId": generate_uuid(),
        },
        "labels": [],
        "captchaResponse": None,
    }


def get_logs_response(limit: int = 100) -> list[dict[str, Any]]:
    count = min(limit, 100)
    logs = [_generate_log() for _ in range(count)]
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return logs
