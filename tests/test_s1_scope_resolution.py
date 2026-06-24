"""Scope-aware S1 detection-library resolution (fix for site-scoped tokens).

The pre-fix behaviour: ``s1_detection_library.get_account_id()`` always tried
``GET /web/api/v2.1/accounts?limit=1`` to auto-discover the account ID, and
``enable_rule`` / ``disable_rule`` / ``get_platform_rule`` always issued the
``filter`` with ``scopeLevel="account"``. Both assumptions break when the
operator's S1 API token is scoped to a Site (the format the console exposes
as ``<account_id>:<site_id>``): ``/accounts`` returns 401/empty and the
scope-level write fails with 403.

This suite locks in the new behaviour:

- ``set_request_override`` accepts optional ``account_id`` / ``site_id`` kwargs
  carrying the per-request override scope (so site-scoped tokens supplied via
  browser headers never need ``/accounts``).
- ``_resolved_settings`` returns ``account_id`` / ``site_id`` from the override
  itself, NOT from the admin-global blob (multi-tenant leak fix).
- ``discover_token_scope`` calls ``/web/api/v2.1/user`` (which works for any
  scope) and returns a normalised ``{scope, account_id, site_id}`` dict.
- ``get_account_id`` prefers the resolved/discovered value over the legacy
  ``/accounts`` path, AND only caches a discovered value into
  ``s1_settings.json`` when the request is operating on the global blob
  (cross-tenant leak through caching was the second bug).
- ``get_site_id`` parallels get_account_id for site-scoped tokens.
- ``_resolve_scope_for_write`` returns ``(scope_level, scope_id)`` with
  preference site > account, so platform-rule writes target the
  most-specific scope the token can operate on.
"""
from __future__ import annotations

import json
from typing import Any

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def s1(tmp_path, monkeypatch):
    """Redirect the global settings file to a tmp_path and drop any stale
    process-level state (scope cache + request override) so each test starts
    from a clean slate."""
    import s1_detection_library as mod
    monkeypatch.setattr(mod, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(mod, "_SETTINGS_FILE", tmp_path / "s1_settings.json")
    # In-memory scope cache must not leak between tests.
    if hasattr(mod, "_SCOPE_CACHE"):
        mod._SCOPE_CACHE.clear()
    # Defensive: the contextvar should be at its default already, but a
    # previously failing test might have leaked one in.
    yield mod


@pytest.fixture
def fake_api(monkeypatch):
    """Replace ``_api_get`` / ``_api_put`` with deterministic stubs.

    Returns a 2-tuple ``(routes, calls)`` where ``routes`` is a mutable dict
    the test populates with ``{path: response}`` and ``calls`` is a list the
    stub appends ``(method, path, params_or_body)`` to for assertions.
    """
    import s1_detection_library as mod
    routes: dict[str, Any] = {}
    calls: list[tuple[str, str, Any]] = []

    def fake_get(path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        calls.append(("GET", path, params or {}))
        if path in routes:
            r = routes[path]
            return r(params) if callable(r) else dict(r)
        return {"error": "HTTP 404", "detail": "no stub"}

    def fake_put(path: str, body: dict[str, Any]) -> dict[str, Any]:
        calls.append(("PUT", path, body))
        if path in routes:
            r = routes[path]
            return r(body) if callable(r) else dict(r)
        return {"error": "HTTP 404", "detail": "no stub"}

    monkeypatch.setattr(mod, "_api_get", fake_get)
    monkeypatch.setattr(mod, "_api_put", fake_put)
    return routes, calls


# ── set_request_override: scope kwargs ────────────────────────────────

class TestRequestOverrideAcceptsScope:
    """The browser middleware (or any internal caller) can now ship the
    token's scope alongside the credentials so downstream queries don't
    have to auto-discover it. Backwards compatible: the two original
    positional arguments still work, and the kwargs default to "" so the
    legacy callsite ``set_request_override(url, token)`` is unchanged."""

    def test_override_carries_account_and_site(self, s1):
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="1234567890", site_id="9876543210",
        )
        try:
            out = s1._resolved_settings()
            assert out["console_url"] == "https://alice.sentinelone.net"
            assert out["api_token"] == "alice-token"
            assert out["account_id"] == "1234567890"
            assert out["site_id"] == "9876543210"
            assert out["_source"] == "browser_override"
        finally:
            s1.clear_request_override(tok)

    def test_override_without_scope_kwargs_is_backwards_compatible(self, s1):
        """Legacy call form must still work, with the new scope fields
        defaulting to "" (which means "discover at first use")."""
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
        )
        try:
            out = s1._resolved_settings()
            assert out["account_id"] == ""
            assert out["site_id"] == ""
            assert out["_source"] == "browser_override"
        finally:
            s1.clear_request_override(tok)

    def test_override_does_not_leak_global_account_id(self, s1):
        """*Pre-fix bug.* The old ``_resolved_settings`` filled ``account_id``
        from the admin-global blob whenever the override was active — leaking
        tenant A's account into tenant B's request. The fix returns the
        override's own account_id (possibly empty) so a per-user request
        never inherits the admin's saved value."""
        s1.save_settings({"console_url": "https://global.sentinelone.net",
                          "api_token": "global-token",
                          "account_id": "GLOBAL-ACCT"})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            # No scope supplied — must NOT inherit GLOBAL-ACCT.
        )
        try:
            out = s1._resolved_settings()
            assert out["account_id"] == "", (
                "override request must not inherit account_id from the "
                "admin-global blob")
        finally:
            s1.clear_request_override(tok)


# ── discover_token_scope ──────────────────────────────────────────────

class TestDiscoverTokenScope:
    """``discover_token_scope`` calls ``GET /web/api/v2.1/user`` because that
    endpoint is the only one the S1 API guarantees to accept regardless of
    the token's scope — ``/accounts`` is account/global-only."""

    def test_site_scoped_token_returns_account_and_site_ids(self, s1, fake_api):
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "site",
            "scopeRoles": [{
                "accountId": "1111", "siteId": "2222",
                "scope": "site",
            }],
        }}
        out = s1.discover_token_scope()
        assert out == {"scope": "site", "account_id": "1111", "site_id": "2222"}

    def test_account_scoped_token_returns_account_only(self, s1, fake_api):
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "account",
            "scopeRoles": [{"accountId": "3333", "scope": "account"}],
        }}
        out = s1.discover_token_scope()
        assert out["scope"] == "account"
        assert out["account_id"] == "3333"
        assert out["site_id"] == ""

    def test_global_scoped_token_returns_empty_ids(self, s1, fake_api):
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "global",
            "scopeRoles": [],
        }}
        out = s1.discover_token_scope()
        assert out["scope"] == "global"
        assert out["account_id"] == ""
        assert out["site_id"] == ""

    def test_user_endpoint_error_returns_empty_scope(self, s1, fake_api):
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"error": "HTTP 401"}
        out = s1.discover_token_scope()
        assert out == {"scope": "", "account_id": "", "site_id": ""}

    def test_discover_is_cached_per_token(self, s1, fake_api):
        """A second call with the same (console_url, api_token) must NOT
        hit ``/user`` again — production code can call get_account_id +
        get_site_id + _resolve_scope_for_write in the same request and we
        don't want three round-trips to the S1 console."""
        routes, calls = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "site",
            "scopeRoles": [{"accountId": "A", "siteId": "S"}],
        }}
        s1.save_settings({"console_url": "https://t.sentinelone.net",
                          "api_token": "tok"})
        s1.discover_token_scope()
        s1.discover_token_scope()
        s1.discover_token_scope()
        user_calls = [c for c in calls if c[1] == "/web/api/v2.1/user"]
        assert len(user_calls) == 1, (
            "discover_token_scope must memoise per (url, token)")


# ── get_account_id: scope-aware resolution ────────────────────────────

class TestGetAccountIdScopeAware:
    """Resolution order after the fix:

    1. ``_resolved_settings().account_id`` — the override's own field, or
       the global blob's value when no override is active.
    2. ``discover_token_scope()`` — the universal ``/user`` lookup.
    3. ``/accounts`` legacy fallback — only useful for global tokens but
       kept for backwards compatibility with installs that don't have a
       saved account_id and run with a global token (no behaviour change
       for that case).
    """

    def test_uses_override_account_id_when_set(self, s1, fake_api):
        """Override carries a pinned account_id → use it, no API calls."""
        _, calls = fake_api
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="OVERRIDE-ACCT",
        )
        try:
            assert s1.get_account_id() == "OVERRIDE-ACCT"
        finally:
            s1.clear_request_override(tok)
        # No /accounts and no /user call needed.
        assert all(c[1] != "/web/api/v2.1/accounts" for c in calls)
        assert all(c[1] != "/web/api/v2.1/user" for c in calls)

    def test_falls_back_to_user_endpoint_for_site_scoped_token(self, s1, fake_api):
        """Site-scoped token, no pinned account_id anywhere → /user must
        be the discovery path, NOT /accounts (which would 401)."""
        routes, calls = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "site",
            "scopeRoles": [{"accountId": "FROM-USER", "siteId": "S1"}],
        }}
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
        )
        try:
            assert s1.get_account_id() == "FROM-USER"
        finally:
            s1.clear_request_override(tok)
        assert any(c[1] == "/web/api/v2.1/user" for c in calls)

    def test_does_not_persist_override_discovery_to_global_blob(self, s1, fake_api):
        """*Pre-fix bug.* The old ``get_account_id`` ran
        ``save_settings({"account_id": acct})`` even when the discovery
        happened inside a per-user override — leaking the override
        tenant's account into the admin-global blob. The fix only caches
        when the resolution is operating on the global blob."""
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "site",
            "scopeRoles": [{"accountId": "TENANT-A", "siteId": "S1"}],
        }}
        # Pre-existing admin-global blob (no account_id pinned).
        s1.save_settings({"console_url": "https://admin.sentinelone.net",
                          "api_token": "admin-token"})

        tok = s1.set_request_override(
            "https://tenant-a.sentinelone.net", "tenant-a-token",
        )
        try:
            assert s1.get_account_id() == "TENANT-A"
        finally:
            s1.clear_request_override(tok)

        # The discovered TENANT-A must NOT have been written to the
        # admin-global blob — tenant B's later request (without override)
        # would otherwise inherit it.
        post = s1.get_settings()
        assert post.get("account_id", "") == "", (
            "discovered override account_id must not leak into the "
            "admin-global blob")

    def test_caches_discovery_into_global_blob_when_no_override(self, s1, fake_api):
        """When the resolution happens against the global blob (no
        override active), caching the discovered account_id back into the
        blob is fine — that's the same tenant. Keeps the legacy behaviour
        for the simple "single-tenant admin" install."""
        routes, _ = fake_api
        # /user returns the answer first; we still expect it to be cached.
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "account",
            "scopeRoles": [{"accountId": "GLOBAL-FROM-USER"}],
        }}
        s1.save_settings({"console_url": "https://admin.sentinelone.net",
                          "api_token": "admin-token"})
        assert s1.get_account_id() == "GLOBAL-FROM-USER"
        assert s1.get_settings().get("account_id") == "GLOBAL-FROM-USER", (
            "global-blob resolution must persist the discovered value so "
            "subsequent requests don't re-hit /user")

    def test_legacy_accounts_fallback_when_user_returns_empty(self, s1, fake_api):
        """A very old console (or a token that doesn't have /user access
        for some odd reason) falls back to the legacy /accounts call so
        nobody regresses."""
        routes, _ = fake_api
        # /user replies "no scope info" — pre-fix global tokens still
        # got their account from /accounts.
        routes["/web/api/v2.1/user"] = {"data": {"scope": "global",
                                                  "scopeRoles": []}}
        routes["/web/api/v2.1/accounts"] = {"data": [{"id": "LEGACY-ACCT"}]}
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "x-token"})
        assert s1.get_account_id() == "LEGACY-ACCT"


# ── get_site_id ───────────────────────────────────────────────────────

class TestGetSiteId:
    """New helper. Used by ``_resolve_scope_for_write`` to prefer site
    scope over account scope for ``enable_rule`` / ``disable_rule``."""

    def test_returns_override_site_id_when_pinned(self, s1):
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            site_id="PINNED-SITE",
        )
        try:
            assert s1.get_site_id() == "PINNED-SITE"
        finally:
            s1.clear_request_override(tok)

    def test_discovers_from_user_endpoint(self, s1, fake_api):
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "site",
            "scopeRoles": [{"accountId": "A", "siteId": "DISC-SITE"}],
        }}
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "x-token"})
        assert s1.get_site_id() == "DISC-SITE"

    def test_returns_none_for_global_token(self, s1, fake_api):
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"data": {
            "scope": "global", "scopeRoles": [],
        }}
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "x-token"})
        assert s1.get_site_id() is None


# ── _resolve_scope_for_write ──────────────────────────────────────────

class TestResolveScopeForWrite:
    """Returns the most-specific (scope_level, scope_id) the token can
    write to. enable_rule/disable_rule use this so a site-scoped token
    gets ``filter.scopeLevel=site`` instead of the old hard-coded
    ``account`` (which produced 403)."""

    def test_site_preferred_when_site_id_available(self, s1):
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            assert s1._resolve_scope_for_write() == ("site", "SITE")
        finally:
            s1.clear_request_override(tok)

    def test_falls_back_to_account_when_no_site(self, s1):
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT",
        )
        try:
            assert s1._resolve_scope_for_write() == ("account", "ACCT")
        finally:
            s1.clear_request_override(tok)

    def test_returns_none_when_no_scope_resolvable(self, s1, fake_api):
        """Nothing pinned, /user errors, /accounts empty → caller must
        surface a clean error instead of pretending the request succeeded."""
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"error": "HTTP 401"}
        routes["/web/api/v2.1/accounts"] = {"data": []}
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "x-token"})
        assert s1._resolve_scope_for_write() is None


# ── enable_rule / disable_rule / get_platform_rule ────────────────────

class TestPlatformRuleScopeAware:
    """The three call sites that used to hard-code ``scopeLevel=account``
    must now use the resolver's value. This is the test that locks down
    the user-visible bug: site-scoped operator hits Enable on a rule →
    the PUT body now carries ``filter.scopeLevel=site`` and the request
    actually succeeds."""

    def test_enable_rule_uses_site_scope_when_site_scoped(self, s1, fake_api):
        """PUT body must match the FLAT PlatformRuleSchemaWithValidation
        shape (top-level scopeLevel + scopeId + platformRuleIds), NOT the
        nested data/filter shape — the latter is silently accepted by S1
        (200 OK) but doesn't enable anything, which is the user-visible
        'enable bounces back to disabled' bug."""
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/platform-rules/enable"] = (
            {"data": {"affected": 1}})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.enable_rule("rule-xyz")
            assert "error" not in out
        finally:
            s1.clear_request_override(tok)
        # Locate the PUT call.
        puts = [c for c in calls if c[0] == "PUT"]
        assert len(puts) == 1
        _, _, body = puts[0]
        # Flat shape per swagger schema (verified live 2026-06-24).
        assert body.get("scopeLevel") == "site"
        assert body.get("scopeId") == "SITE"
        assert body.get("platformRuleIds") == ["rule-xyz"]
        # The legacy nested envelope must not be present — S1 ignores it
        # silently and never enables the rule.
        assert "data" not in body
        assert "filter" not in body

    def test_disable_rule_uses_account_scope_when_no_site(self, s1, fake_api):
        """Same flat-body contract for the disable endpoint, account scope."""
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/platform-rules/disable"] = (
            {"data": {"affected": 1}})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT-ONLY",
        )
        try:
            s1.disable_rule("rule-abc")
        finally:
            s1.clear_request_override(tok)
        puts = [c for c in calls if c[0] == "PUT"]
        assert len(puts) == 1
        _, _, body = puts[0]
        assert body.get("scopeLevel") == "account"
        assert body.get("scopeId") == "ACCT-ONLY"
        assert body.get("platformRuleIds") == ["rule-abc"]
        assert "data" not in body
        assert "filter" not in body

    def test_get_platform_rule_uses_site_scope_when_site_scoped(self, s1, fake_api):
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/platform-rules"] = (
            {"data": [{"id": "rule-xyz", "name": "..."}]})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            r = s1.get_platform_rule("rule-xyz")
            assert r and r["id"] == "rule-xyz"
        finally:
            s1.clear_request_override(tok)
        gets = [c for c in calls
                if c[0] == "GET" and "platform-rules" in c[1]
                and "rules/" not in c[1]]
        assert gets, "expected one /platform-rules GET"
        _, _, params = gets[0]
        assert params.get("scopeLevel") == "site"
        assert params.get("scopeId") == "SITE"

    def test_enable_returns_clear_error_when_scope_unknown(self, s1, fake_api):
        """If neither account nor site can be resolved, the error message
        must be specific — not the old generic 'Could not determine
        account ID' which is misleading for a site-scoped operator."""
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"error": "HTTP 401"}
        routes["/web/api/v2.1/accounts"] = {"data": []}
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "x-token"})
        out = s1.enable_rule("rule-anything")
        assert "error" in out
        # The message must reference 'scope' so the operator can act on it.
        assert "scope" in out["error"].lower()


# ── query_rules / detection-library reads ────────────────────────────

class TestQueryRulesScopeAware:
    """The detection-library /rules listing endpoint enforces the same
    scope discipline as the platform-rule writes: a site-scoped token
    that filters with ``accountIds=<acct>`` is rejected by S1 with HTTP
    400 / code 4000010 ('User <uid>:site can not create rule with
    higher scope <acct>:account'). The fix uses ``siteIds=<site_id>``
    for site-scoped tokens and keeps ``accountIds=<acct>`` for
    account/global ones."""

    def test_uses_siteIds_filter_for_site_scoped_token(self, s1, fake_api):
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/rules"] = (
            {"data": [{"id": "rule-1", "name": "..."}], "pagination": {"totalItems": 1}})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.query_rules(limit=5)
            assert "error" not in out
            assert out["total"] == 1
        finally:
            s1.clear_request_override(tok)
        gets = [c for c in calls
                if c[0] == "GET" and c[1] == "/web/api/v2.1/detection-library/rules"]
        assert len(gets) == 1
        _, _, params = gets[0]
        assert params.get("siteIds") == "SITE", (
            "site-scoped token must filter by siteIds, not accountIds")
        assert "accountIds" not in params, (
            "passing accountIds for a site-scoped token triggers HTTP 400 "
            "code 4000010 'higher scope' on the S1 console")

    def test_uses_accountIds_filter_when_no_site(self, s1, fake_api):
        """Account-scoped (or global) token: keep the legacy accountIds
        filter so we don't regress consoles that have always worked."""
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/rules"] = (
            {"data": [], "pagination": {"totalItems": 0}})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT-ONLY",
        )
        try:
            s1.query_rules(limit=5)
        finally:
            s1.clear_request_override(tok)
        gets = [c for c in calls
                if c[0] == "GET" and c[1] == "/web/api/v2.1/detection-library/rules"]
        assert len(gets) == 1
        _, _, params = gets[0]
        assert params.get("accountIds") == "ACCT-ONLY"
        assert "siteIds" not in params

    def test_returns_clear_error_when_no_scope(self, s1, fake_api):
        """Same error contract as enable_rule when the resolver can't
        produce any scope."""
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"error": "HTTP 401"}
        routes["/web/api/v2.1/accounts"] = {"data": []}
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "x-token"})
        out = s1.query_rules(limit=5)
        assert "error" in out
        assert "scope" in out["error"].lower()
        assert out["rules"] == []
        assert out["total"] == 0


# ── platform-rule settings: inheritance lock ─────────────────────────

class TestPlatformSettingsInheritance:
    """Bug discovered live 2026-06-24: S1 returns an opaque HTTP 500
    ``code 5000010 'Server could not process the request.'`` when a
    site-scoped operator tries to enable/disable a rule that inherits
    its activation state from the parent account scope.

    The S1 console exposes this as an "inheritance lock" — the site
    scope must explicitly opt out of parent inheritance
    (``disableInheritance=true`` on
    ``PUT /web/api/v2.1/detection-library/platform-rules/settings``)
    before any per-rule write at site level can succeed.

    The fix gives the operator a clean signal: a pre-flight GET on
    ``/platform-rules/settings`` for the current scope, and a
    structured error code ``inheritance_locked`` (with the parent
    scope visible) instead of letting the 500 leak through. Pairs
    with a settings-write helper so the UI can offer "Unlock at this
    scope" without falling back to raw curl."""

    def test_get_platform_settings_passes_scope(self, s1, fake_api):
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/platform-rules/settings"] = {
            "data": {
                "scopeLevel":         "site",
                "scopeId":            "SITE",
                "disableInheritance": True,
            }
        }
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.get_platform_settings()
            assert out["disableInheritance"] is True
            assert out["scopeLevel"] == "site"
            assert out["scopeId"] == "SITE"
        finally:
            s1.clear_request_override(tok)
        gets = [c for c in calls
                if c[0] == "GET"
                and c[1] == "/web/api/v2.1/detection-library/platform-rules/settings"]
        assert len(gets) == 1
        _, _, params = gets[0]
        # The settings endpoint takes scopeLevel + scopeId as query params,
        # not as a body — this is unlike the platform-rules/enable PUT.
        assert params.get("scopeLevel") == "site"
        assert params.get("scopeId") == "SITE"

    def test_get_platform_settings_returns_clear_error_when_no_scope(self, s1, fake_api):
        routes, _ = fake_api
        routes["/web/api/v2.1/user"] = {"error": "HTTP 401"}
        routes["/web/api/v2.1/accounts"] = {"data": []}
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "x-token"})
        out = s1.get_platform_settings()
        assert "error" in out
        assert "scope" in out["error"].lower()

    def test_set_platform_inheritance_sends_correct_body(self, s1, fake_api):
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/platform-rules/settings"] = {
            "data": {
                "scopeLevel":         "site",
                "scopeId":            "SITE",
                "disableInheritance": True,
            }
        }
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.set_platform_inheritance(disable_inheritance=True)
            assert "error" not in out
        finally:
            s1.clear_request_override(tok)
        puts = [c for c in calls
                if c[0] == "PUT"
                and c[1] == "/web/api/v2.1/detection-library/platform-rules/settings"]
        assert len(puts) == 1
        _, _, body = puts[0]
        # disableInheritance + scopeLevel are required per the swagger
        # PlatformSettingsSchema; scopeId is required at site/account.
        assert body.get("disableInheritance") is True
        assert body.get("scopeLevel") == "site"
        assert body.get("scopeId") == "SITE"

    def test_enable_rule_short_circuits_when_inheritance_locked(self, s1, fake_api):
        """When disableInheritance is False at the operator's scope, the
        rule activation actually happens at the parent scope, and a per-rule
        write at the child scope returns S1's opaque HTTP 500 with no useful
        detail. We must catch this *before* calling /enable and return a
        structured, actionable error so the UI can offer 'unlock'."""
        routes, calls = fake_api
        # Parent inheritance is still active for this site:
        routes["/web/api/v2.1/detection-library/platform-rules/settings"] = {
            "data": {
                "scopeLevel":         "site",
                "scopeId":            "SITE",
                "disableInheritance": False,
            }
        }
        # If the pre-flight check is missing or wrong, the test catches
        # the PUT going out and fails — the platform-rules/enable route
        # is deliberately NOT stubbed.
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.enable_rule("rule-xyz")
        finally:
            s1.clear_request_override(tok)
        assert "error" in out
        assert out.get("code") == "inheritance_locked"
        # The error message must name the scope so the operator knows
        # where to act.
        msg = out["error"].lower()
        assert "inherit" in msg
        # The pre-flight GET on /settings must have happened, and the
        # PUT on /enable must NOT have happened.
        assert any(c[0] == "GET" and c[1].endswith("/platform-rules/settings")
                   for c in calls)
        assert not any(c[0] == "PUT" and c[1].endswith("/platform-rules/enable")
                       for c in calls)

    def test_disable_rule_short_circuits_when_inheritance_locked(self, s1, fake_api):
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/platform-rules/settings"] = {
            "data": {
                "scopeLevel":         "site",
                "scopeId":            "SITE",
                "disableInheritance": False,
            }
        }
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.disable_rule("rule-xyz")
        finally:
            s1.clear_request_override(tok)
        assert out.get("code") == "inheritance_locked"
        assert not any(c[0] == "PUT" and c[1].endswith("/platform-rules/disable")
                       for c in calls)

    def test_enable_rule_proceeds_when_inheritance_unlocked(self, s1, fake_api):
        """Happy path: site has opted out of parent inheritance, the
        pre-flight check confirms it, and the PUT on /enable goes
        through unchanged."""
        routes, calls = fake_api
        routes["/web/api/v2.1/detection-library/platform-rules/settings"] = {
            "data": {
                "scopeLevel":         "site",
                "scopeId":            "SITE",
                "disableInheritance": True,
            }
        }
        routes["/web/api/v2.1/detection-library/platform-rules/enable"] = (
            {"data": {"affected": 1}})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.enable_rule("rule-xyz")
            assert "error" not in out
        finally:
            s1.clear_request_override(tok)
        puts = [c for c in calls
                if c[0] == "PUT" and c[1].endswith("/platform-rules/enable")]
        assert len(puts) == 1, (
            "the /enable PUT must still fire when inheritance is unlocked")

    def test_enable_rule_proceeds_when_settings_lookup_fails(self, s1, fake_api):
        """If the settings GET itself fails (e.g. transient 5xx, token
        without ``platform-rules.settings.view``), the pre-flight check
        must NOT block the write — fall through to the original behaviour
        rather than fabricating a false 'locked' state."""
        routes, _ = fake_api
        # /settings is intentionally NOT stubbed -> fake_api returns HTTP 404.
        routes["/web/api/v2.1/detection-library/platform-rules/enable"] = (
            {"data": {"affected": 1}})
        tok = s1.set_request_override(
            "https://alice.sentinelone.net", "alice-token",
            account_id="ACCT", site_id="SITE",
        )
        try:
            out = s1.enable_rule("rule-xyz")
            assert "error" not in out, (
                "settings-lookup failures must not block the write — "
                f"got: {out}")
        finally:
            s1.clear_request_override(tok)
