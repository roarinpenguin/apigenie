"""SentinelOne Detection Library client — queries and manages platform detection rules.

Connects to a SentinelOne console via the Management API to:
- List detection library rules filtered by source, MITRE tactic, severity
- Get data sources available in the library
- Enable/disable managed platform rules

Settings (console URL + API token) are stored in /var/lib/apigenie/s1_settings.json.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
_SETTINGS_FILE = _DATA_ROOT / "s1_settings.json"

# Map ApiGenie source keys to S1 detection library data source names
SOURCE_KEY_TO_S1 = {
    "okta": "Okta",
    "entra_id": "Microsoft Entra ID",
    "m365": "Microsoft O365",
    "proofpoint": "Proofpoint",
    "netskope": "Netskope",
    "cisco_duo": "Cisco Duo",
    "darktrace": "Darktrace",
    "wiz": "Wiz",
    "paloalto": "Palo Alto Networks Firewall",
    "fortigate": "FortiGate",
    "checkpoint": "Check Point Next Generation Firewall",
    "cisco_asa": "Cisco Firewall Threat Defense",
    "zscaler": "Zscaler Internet Access",
    "sentinelone": "SentinelOne",
    "gcp_audit": "GCP Audit",
    "azure_platform": "Azure Platform",
}


# ── Settings ─────────────────────────────────────────────────────────────────

def get_settings() -> dict[str, Any]:
    try:
        if _SETTINGS_FILE.is_file():
            return json.loads(_SETTINGS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def save_settings(data: dict[str, Any]) -> None:
    _DATA_ROOT.mkdir(parents=True, exist_ok=True)
    current = get_settings()
    current.update(data)
    tmp = _SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2))
    tmp.replace(_SETTINGS_FILE)


def is_configured() -> bool:
    s = get_settings()
    return bool(s.get("console_url") and s.get("api_token"))


# ── API client ───────────────────────────────────────────────────────────────

def _api_get(path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    """Make a GET request to the S1 Management API."""
    settings = get_settings()
    base = settings.get("console_url", "").rstrip("/")
    token = settings.get("api_token", "")
    if not base or not token:
        return {"error": "S1 console not configured"}

    url = f"{base}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True)

    req = urllib.request.Request(url, headers={
        "Authorization": f"ApiToken {token}",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        log.warning("S1 API error %s %s: %s", e.code, path, body)
        return {"error": f"HTTP {e.code}", "detail": body}
    except Exception as e:
        log.warning("S1 API connection error: %s", e)
        return {"error": str(e)}


def _api_put(path: str, body: dict[str, Any]) -> dict[str, Any]:
    """Make a PUT request to the S1 Management API."""
    settings = get_settings()
    base = settings.get("console_url", "").rstrip("/")
    token = settings.get("api_token", "")
    if not base or not token:
        return {"error": "S1 console not configured"}

    url = f"{base}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="PUT", headers={
        "Authorization": f"ApiToken {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        log.warning("S1 API PUT error %s %s: %s", e.code, path, body)
        return {"error": f"HTTP {e.code}", "detail": body}
    except Exception as e:
        return {"error": str(e)}


# ── Detection Library queries ────────────────────────────────────────────────

def get_data_sources() -> list[dict[str, str]]:
    """Get available data sources from the S1 detection library."""
    resp = _api_get("/web/api/v2.1/detection-library/data-sources")
    if "error" in resp:
        return []
    return resp.get("data", {}).get("dataSources", [])


def get_account_id() -> str | None:
    """Get the account ID from settings or auto-discover it."""
    settings = get_settings()
    acct = settings.get("account_id")
    if acct:
        return acct
    # Auto-discover from /accounts
    resp = _api_get("/web/api/v2.1/accounts", {"limit": "1"})
    if "error" not in resp:
        accounts = resp.get("data", [])
        if accounts:
            acct = str(accounts[0].get("id", ""))
            # Cache it
            save_settings({"account_id": acct})
            return acct
    return None


def query_rules(source: str | None = None, mitre_tactic: str | None = None,
                severity: str | None = None, status: str | None = None,
                query: str | None = None, limit: int = 20) -> dict[str, Any]:
    """Query the detection library catalog rules.
    
    Args:
        source: ApiGenie source key (e.g. 'okta') — mapped to S1 data source name
        mitre_tactic: MITRE tactic name (e.g. 'Credential Access')
        severity: 'Low', 'Medium', 'High', 'Critical'
        status: 'Enabled', 'Disabled'
        query: Free-text search across name, description, query content
        limit: Max rules to return (1-1000)
    """
    acct = get_account_id()
    if not acct:
        return {"error": "Could not determine S1 account ID", "rules": [], "total": 0}

    params: dict[str, str] = {"accountIds": acct, "limit": str(limit)}

    if source:
        s1_source = SOURCE_KEY_TO_S1.get(source, source)
        params["sources"] = s1_source

    if mitre_tactic:
        params["mitreTactics"] = mitre_tactic

    if severity:
        params["severities"] = severity

    if status:
        params["statuses"] = status

    if query:
        params["query"] = query

    resp = _api_get("/web/api/v2.1/detection-library/rules", params)
    if "error" in resp:
        return {"error": resp["error"], "rules": [], "total": 0}

    rules = resp.get("data", [])
    total = resp.get("pagination", {}).get("totalItems", len(rules))

    return {"rules": rules, "total": total}


def query_rules_for_phase(source: str, mitre_tactic: str, limit: int = 10) -> dict[str, Any]:
    """Query rules matching a scenario phase (source + MITRE tactic)."""
    return query_rules(source=source, mitre_tactic=mitre_tactic, limit=limit)


def get_platform_rule(rule_id: str) -> dict[str, Any] | None:
    """Get a single platform rule by ID."""
    acct = get_account_id()
    if not acct:
        return None
    resp = _api_get("/web/api/v2.1/detection-library/platform-rules", {
        "platformRuleIds": rule_id,
        "scopeLevel": "account",
        "scopeId": acct,
    })
    if "error" not in resp:
        data = resp.get("data", [])
        return data[0] if data else None
    return None


def enable_rule(rule_id: str) -> dict[str, Any]:
    """Enable a platform detection rule."""
    acct = get_account_id()
    if not acct:
        return {"error": "Could not determine account ID"}
    return _api_put("/web/api/v2.1/detection-library/platform-rules/enable", {
        "data": {"platformRuleId": rule_id},
        "filter": {"scopeLevel": "account", "scopeId": acct},
    })


def disable_rule(rule_id: str) -> dict[str, Any]:
    """Disable a platform detection rule."""
    acct = get_account_id()
    if not acct:
        return {"error": "Could not determine account ID"}
    return _api_put("/web/api/v2.1/detection-library/platform-rules/disable", {
        "data": {"platformRuleId": rule_id},
        "filter": {"scopeLevel": "account", "scopeId": acct},
    })


def test_connection() -> dict[str, Any]:
    """Test the S1 console connection and return summary info."""
    resp = _api_get("/web/api/v2.1/system/info")
    if "error" in resp:
        return {"connected": False, "error": resp["error"]}
    info = resp.get("data", {})
    # Also get rule count
    acct = get_account_id()
    rule_count = 0
    if acct:
        count_resp = _api_get("/web/api/v2.1/detection-library/rules", {
            "accountIds": acct, "countOnly": "true"})
        rule_count = count_resp.get("pagination", {}).get("totalItems", 0)
    return {
        "connected": True,
        "console_url": get_settings().get("console_url", ""),
        "deployment": info.get("deployment", ""),
        "version": info.get("latestAgentVersion", ""),
        "account_id": acct,
        "detection_rules_count": rule_count,
    }
