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
    "cato": "Cato Networks",
    "corelight": "Corelight",
    "cyberark": "CyberArk EPM",
    "stamus": "Stamus Networks",
}


# ── Settings ─────────────────────────────────────────────────────────────────

def get_settings() -> dict[str, Any]:
    """Read the admin-global S1 settings, transparently decrypting the
    ``api_token`` field.

    v5.1 Phase B: ``api_token`` is stored as a Fernet token at rest. Legacy
    plaintext blobs are auto-detected and returned as-is; the next call to
    :func:`save_settings` will re-encrypt them (silent migration). If the
    stored ciphertext fails to decrypt (e.g. ``APIGENIE_SECRET_KEY`` was
    rotated incorrectly), the caller sees an empty token and is prompted
    to re-enter — never a 500.
    """
    try:
        if _SETTINGS_FILE.is_file():
            raw = json.loads(_SETTINGS_FILE.read_text())
        else:
            return {}
    except (json.JSONDecodeError, OSError):
        return {}
    token = raw.get("api_token") or ""
    if token:
        import crypto                   # lazy import to keep import-time light
        raw["api_token"] = crypto.try_decrypt(token)
    return raw


def save_settings(data: dict[str, Any]) -> None:
    """Persist the admin-global S1 settings, encrypting ``api_token`` at
    rest with the server-side Fernet key (see :mod:`crypto`)."""
    _DATA_ROOT.mkdir(parents=True, exist_ok=True)
    current = get_settings()             # returns plaintext token (or "")
    current.update(data)
    # Re-encrypt the token on every save — covers the silent-migration
    # case where the previously-read token was legacy plaintext.
    token = current.get("api_token") or ""
    if token:
        import crypto
        current["api_token"] = crypto.encrypt(token)
    tmp = _SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2))
    tmp.replace(_SETTINGS_FILE)


# ── Per-request S1 console override (v5.1 Phase A) ──────────────────────────
#
# The per-user S1 console URL + API token live in the browser's localStorage
# and ride every fetch() as X-S1-Console-URL / X-S1-Console-Token headers.
# A FastAPI middleware (see app.py) reads those headers and calls
# ``set_request_override()`` so handlers downstream — and any
# ``s1_detection_library`` call originating from this request — see the
# per-user values without the server ever persisting them.
#
# The override is a ``contextvars.ContextVar`` so concurrent requests on
# the same worker don't bleed into each other (FastAPI runs each request
# in its own task with its own context copy).

import contextvars as _contextvars
import hashlib as _hashlib

_REQUEST_OVERRIDE: _contextvars.ContextVar[dict[str, str] | None] = (
    _contextvars.ContextVar("apigenie_s1_request_override", default=None)
)


def set_request_override(
    console_url: str,
    api_token: str,
    *,
    account_id: str = "",
    site_id: str = "",
) -> _contextvars.Token:
    """Install a per-request S1 console override.

    Called by the FastAPI middleware on each incoming request that
    carries the ``X-S1-Console-URL`` + ``X-S1-Console-Token`` headers.
    Returns a token that the middleware should pass to
    :func:`clear_request_override` once the response is dispatched.

    *Partial* overrides (URL but no token, or vice versa) are ignored —
    falling back to the global blob is safer than pairing the admin's
    token with an unrelated tenant URL.

    The ``account_id`` / ``site_id`` kwargs are optional and exist for
    site-scoped tokens (format ``<account_id>:<site_id>``): the S1
    console exposes a token whose ``/accounts`` access is denied, so
    the caller can supply the scope explicitly. When omitted, the
    downstream :func:`discover_token_scope` helper queries
    ``/web/api/v2.1/user`` (which any scope can call) to infer them.
    Old call sites that pass only two positional arguments are
    unaffected.
    """
    if not (console_url and api_token):
        return _REQUEST_OVERRIDE.set(None)
    return _REQUEST_OVERRIDE.set({
        "console_url": console_url.rstrip("/"),
        "api_token":   api_token,
        "account_id":  (account_id or "").strip(),
        "site_id":     (site_id or "").strip(),
    })


def clear_request_override(token: _contextvars.Token) -> None:
    """Restore the override variable to its previous state."""
    _REQUEST_OVERRIDE.reset(token)


def _resolved_settings() -> dict[str, Any]:
    """Return the active S1 console settings for the current request.

    Resolution order:

    1. Per-request browser override (``X-S1-Console-URL`` +
       ``X-S1-Console-Token`` headers, installed by app.py middleware).
       The override now also carries its own ``account_id`` / ``site_id``
       so a per-user request never inherits the admin's saved scope
       (the cross-tenant leak that affected the pre-fix codebase).
    2. Admin global ``s1_settings.json`` (encrypted at rest via
       :mod:`crypto`), used as a fallback when no browser override is
       present — typically the built-in admin or a user who hasn't
       configured their own console yet.
    """
    override = _REQUEST_OVERRIDE.get()
    if override:
        return {
            "console_url": override["console_url"],
            "api_token":   override["api_token"],
            # Scope hints belong to the override itself — NOT to the
            # admin-global blob (cross-tenant leak fix). Empty when the
            # browser didn't ship them; discover_token_scope is the
            # downstream fallback.
            "account_id":  override.get("account_id", ""),
            "site_id":     override.get("site_id", ""),
            "_source":     "browser_override",
        }
    s = get_settings()
    return {**s, "_source": "global"}


# ── Token scope discovery (site-scoped fix) ─────────────────────────────────
#
# The S1 ``/web/api/v2.1/user`` endpoint is the only one guaranteed to
# accept any token — Global / Account / Site. Its response carries the
# token's own scope plus an array of ``scopeRoles`` from which we derive
# the parent account ID and (for site-scoped tokens) the site ID.
#
# The result is memoised by ``(console_url, sha256(api_token)[:16])`` so a
# single request that calls ``get_account_id`` + ``get_site_id`` +
# ``_resolve_scope_for_write`` doesn't hit the S1 console three times.
# The token hash is keyed on the prefix to avoid storing the full
# secret in memory — collision risk is negligible for the cache size.

_SCOPE_CACHE: dict[tuple[str, str], dict[str, str]] = {}


def _scope_cache_key() -> tuple[str, str] | None:
    resolved = _resolved_settings()
    url = (resolved.get("console_url") or "").rstrip("/")
    tok = resolved.get("api_token") or ""
    if not (url and tok):
        return None
    digest = _hashlib.sha256(tok.encode("utf-8")).hexdigest()[:16]
    return (url, digest)


def discover_token_scope() -> dict[str, str]:
    """Call ``GET /web/api/v2.1/user`` and return ``{scope, account_id,
    site_id}``.

    The returned dict is normalised:

    - ``scope`` is one of ``"global"`` / ``"account"`` / ``"site"`` /
      ``""`` (empty when the call errored or the response was
      unparseable).
    - ``account_id`` / ``site_id`` are always strings, empty when the
      token's scope doesn't carry them (e.g. ``site_id`` for a global
      token).

    Memoised per ``(console_url, token-hash)`` so multiple resolutions
    inside the same request hit the S1 console at most once.
    """
    key = _scope_cache_key()
    if key and key in _SCOPE_CACHE:
        return dict(_SCOPE_CACHE[key])
    resp = _api_get("/web/api/v2.1/user")
    if "error" in resp:
        return {"scope": "", "account_id": "", "site_id": ""}
    data = resp.get("data") or {}
    scope = (data.get("scope") or "").lower()
    # S1 sometimes uses "tenant" as the spelling for global — normalise.
    if scope == "tenant":
        scope = "global"
    roles = data.get("scopeRoles") or []
    first = roles[0] if roles else {}
    out = {
        "scope":       scope,
        "account_id":  str(first.get("accountId") or ""),
        "site_id":     str(first.get("siteId") or ""),
    }
    if key:
        _SCOPE_CACHE[key] = out
    return dict(out)


def is_configured() -> bool:
    s = _resolved_settings()
    return bool(s.get("console_url") and s.get("api_token"))


# ── API client ───────────────────────────────────────────────────────────────

def _api_get(path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    """Make a GET request to the S1 Management API."""
    settings = _resolved_settings()
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
    settings = _resolved_settings()
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
    """Resolve the account ID for the current request, scope-aware.

    Resolution order:

    1. ``_resolved_settings().account_id`` — the override's pinned value
       or the global blob's saved value.
    2. :func:`discover_token_scope` — ``/web/api/v2.1/user`` works for
       any scope, including site-scoped tokens that can't list
       ``/accounts``.
    3. Legacy ``/web/api/v2.1/accounts`` — kept as a last resort for
       installs whose token can call it (Global / Account scope).

    The discovered value is persisted into the admin-global blob
    **only** when the request is operating on that blob (no override
    active). When a per-user override drives the discovery, the
    discovered value stays in the in-memory scope cache and never
    touches ``s1_settings.json`` — preventing the cross-tenant leak
    where tenant A's account_id was getting cached for tenant B.
    """
    resolved = _resolved_settings()
    acct = (resolved.get("account_id") or "").strip()
    if acct:
        return acct

    # Scope-aware discovery via /user (works for any token scope).
    scope = discover_token_scope()
    acct = (scope.get("account_id") or "").strip()
    if acct:
        # Cache to disk only when the resolution belongs to the
        # admin-global blob; a per-user override has its own context
        # and must not bleed into the shared file.
        if resolved.get("_source") == "global":
            save_settings({"account_id": acct})
        return acct

    # Legacy fallback — the historical behaviour. Global / account tokens
    # whose /user response is missing scopeRoles (rare, mostly very old
    # consoles) still resolve through /accounts.
    resp = _api_get("/web/api/v2.1/accounts", {"limit": "1"})
    if "error" not in resp:
        accounts = resp.get("data", [])
        if accounts:
            acct = str(accounts[0].get("id", ""))
            if resolved.get("_source") == "global":
                save_settings({"account_id": acct})
            return acct
    return None


def get_site_id() -> str | None:
    """Resolve the site ID for the current request, scope-aware.

    Mirror of :func:`get_account_id` but for the (optional) site
    component of the token's scope. Returns ``None`` when the token
    operates at Account or Global scope, where the concept doesn't
    apply.

    Never persists to disk — site IDs are inherently per-tenant and
    the admin-global blob is shared. Callers that want to pin a site
    can pass it explicitly via :func:`set_request_override`'s
    ``site_id`` kwarg or save it through :func:`save_settings`.
    """
    resolved = _resolved_settings()
    sid = (resolved.get("site_id") or "").strip()
    if sid:
        return sid
    scope = discover_token_scope()
    sid = (scope.get("site_id") or "").strip()
    return sid or None


def _resolve_scope_for_write() -> tuple[str, str] | None:
    """Return ``(scope_level, scope_id)`` for platform-rule writes.

    Preference order: site > account. A site-scoped token cannot write
    at account level (HTTP 403), so we pick the most specific scope
    the token can operate on. Returns ``None`` when neither can be
    resolved — the caller surfaces a clean error instead of issuing a
    request that would fail server-side.
    """
    sid = get_site_id()
    if sid:
        return ("site", sid)
    acct = get_account_id()
    if acct:
        return ("account", acct)
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
    """Get a single platform rule by ID.

    Uses :func:`_resolve_scope_for_write` so site-scoped tokens query
    the rule at ``scopeLevel=site`` instead of ``account`` (which would
    HTTP 403).
    """
    scope = _resolve_scope_for_write()
    if not scope:
        return None
    scope_level, scope_id = scope
    resp = _api_get("/web/api/v2.1/detection-library/platform-rules", {
        "platformRuleIds": rule_id,
        "scopeLevel": scope_level,
        "scopeId":    scope_id,
    })
    if "error" not in resp:
        data = resp.get("data", [])
        return data[0] if data else None
    return None


def enable_rule(rule_id: str) -> dict[str, Any]:
    """Enable a platform detection rule.

    Targets the most specific scope the token can write to (site for
    site-scoped tokens, account otherwise).
    """
    scope = _resolve_scope_for_write()
    if not scope:
        return {"error": "Could not determine S1 scope (no account/site available)"}
    scope_level, scope_id = scope
    return _api_put("/web/api/v2.1/detection-library/platform-rules/enable", {
        "data":   {"platformRuleId": rule_id},
        "filter": {"scopeLevel": scope_level, "scopeId": scope_id},
    })


def disable_rule(rule_id: str) -> dict[str, Any]:
    """Disable a platform detection rule. See :func:`enable_rule`."""
    scope = _resolve_scope_for_write()
    if not scope:
        return {"error": "Could not determine S1 scope (no account/site available)"}
    scope_level, scope_id = scope
    return _api_put("/web/api/v2.1/detection-library/platform-rules/disable", {
        "data":   {"platformRuleId": rule_id},
        "filter": {"scopeLevel": scope_level, "scopeId": scope_id},
    })


def test_connection() -> dict[str, Any]:
    """Test the S1 console connection and return summary info.

    Adds ``scope`` and ``site_id`` to the response so the admin UI can
    surface the token's scope alongside its account — useful for the
    operator to verify they hit the right tenant.
    """
    resp = _api_get("/web/api/v2.1/system/info")
    if "error" in resp:
        return {"connected": False, "error": resp["error"]}
    info = resp.get("data", {})
    # Resolve scope FIRST so the rule-count query targets the right
    # account regardless of whether it was pinned or auto-discovered.
    acct = get_account_id()
    sid = get_site_id()
    scope = discover_token_scope().get("scope", "")
    rule_count = 0
    if acct:
        count_resp = _api_get("/web/api/v2.1/detection-library/rules", {
            "accountIds": acct, "countOnly": "true"})
        rule_count = count_resp.get("pagination", {}).get("totalItems", 0)
    return {
        "connected":             True,
        "console_url":           _resolved_settings().get("console_url", ""),
        "deployment":            info.get("deployment", ""),
        "version":               info.get("latestAgentVersion", ""),
        "account_id":            acct,
        "site_id":               sid,
        "scope":                 scope,
        "detection_rules_count": rule_count,
    }
