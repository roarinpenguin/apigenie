"""RBAC Phase 3.5 + v5.1 Phase A — self-service account settings (TDD).

Three pieces ship together:

  1. `accounts.change_password(uid, current, new)` — verifies the *current*
     password and atomically replaces it with *new*. Returns True on success;
     raises ValueError on any input failure. Underpins the per-user portal
     "Change password" form.

  2. `accounts.update_user(uid, email=..., ...)` — self-service writes for
     the email + admin-managed flags only. The legacy `console_url` /
     `console_token` columns were dropped in v5.1 Phase A; the per-user S1
     console URL + token now live exclusively in browser localStorage and
     ride every request as `X-S1-Console-URL` / `X-S1-Console-Token`
     headers — never persisted on the server.

  3. `s1_detection_library._resolved_settings()` — returns the **per-request
     browser override** (installed by `set_request_override()` from the
     middleware) when both URL and token are set, otherwise falls back to
     the global `s1_settings.json` blob written by the admin
     "System Settings" page.
"""
from __future__ import annotations

import pytest


# ── accounts.change_password ─────────────────────────────────────────────────

class TestAccountsChangePassword:
    def test_happy_path_replaces_hash(self, make_user):
        import accounts

        u = make_user("alice")          # password = "testpassw0rd"
        ok = accounts.change_password(u["id"], "testpassw0rd", "n3wPassw0rd!")
        assert ok is True

        # New password works, old one no longer does
        assert accounts.verify_login("alice", "n3wPassw0rd!") is not None
        assert accounts.verify_login("alice", "testpassw0rd") is None

    def test_wrong_current_rejected(self, make_user):
        import accounts

        u = make_user("alice")
        with pytest.raises(ValueError) as ex:
            accounts.change_password(u["id"], "WRONG", "n3wPassw0rd!")
        assert "current" in str(ex.value).lower()
        # And the old password still works
        assert accounts.verify_login("alice", "testpassw0rd") is not None

    def test_short_new_rejected(self, make_user):
        import accounts

        u = make_user("alice")
        with pytest.raises(ValueError):
            accounts.change_password(u["id"], "testpassw0rd", "short")
        assert accounts.verify_login("alice", "testpassw0rd") is not None

    def test_unknown_user_returns_false(self):
        import accounts

        # No raise — a missing user is just "no rows updated"
        assert accounts.change_password("usr_does_not_exist", "x", "longenough1") is False

    def test_disabled_user_cannot_change_password(self, make_user):
        import accounts

        u = make_user("alice")
        accounts.update_user(u["id"], disabled=True)
        with pytest.raises(ValueError) as ex:
            accounts.change_password(u["id"], "testpassw0rd", "n3wPassw0rd!")
        assert "disabled" in str(ex.value).lower() or "current" in str(ex.value).lower()


# ── accounts.update_user — self-service-relevant fields ──────────────────────

class TestAccountsSelfServiceFields:
    def test_email_round_trip(self, make_user):
        import accounts

        u = make_user("alice")
        upd = accounts.update_user(u["id"], email="alice@new.example.com")
        assert upd["email"] == "alice@new.example.com"

    def test_email_validation_rejects_garbage(self, make_user):
        import accounts

        u = make_user("alice")
        with pytest.raises(ValueError):
            accounts.update_user(u["id"], email="not-an-email")

    def test_per_user_s1_console_columns_are_gone(self, make_user):
        """v5.1 Phase A — the per-user S1 console URL + token used to live on
        the `users` row (`console_url` / `console_token`) and round-tripped
        through `accounts.update_user(...)`. They now live exclusively in
        browser localStorage. This regression test pins the contract that:

        a) `update_user()` no longer accepts those kwargs (TypeError);
        b) `get_user(..., with_secrets=True)` no longer surfaces the columns.
        """
        import accounts

        u = make_user("alice")
        # (a) the kwargs are gone from the signature.
        with pytest.raises(TypeError):
            accounts.update_user(
                u["id"],
                console_url="https://alice-tenant.sentinelone.net",
                console_token="alice-token",
            )
        # (b) and the dropped columns must not leak even with secrets.
        secret = accounts.get_user(u["id"], with_secrets=True)
        assert "console_url" not in secret
        assert "console_token" not in secret
        assert "has_console_token" not in secret


# ── s1_detection_library._resolved_settings ──────────────────────────────────

class TestS1ResolvedSettings:
    """v5.1 Phase A — the S1 client reads its console URL + API token from
    a per-request override installed by the FastAPI middleware (which itself
    pulls them off the `X-S1-Console-URL` / `X-S1-Console-Token` headers
    stamped by the browser from localStorage). When the override is absent
    or partial, we fall back to the admin-global `s1_settings.json` blob.
    """

    def _set_global(self, tmp_path, monkeypatch, url="https://global.sentinelone.net",
                    token="global-token"):
        import s1_detection_library as s1
        monkeypatch.setattr(s1, "_DATA_ROOT", tmp_path)
        monkeypatch.setattr(s1, "_SETTINGS_FILE", tmp_path / "s1_settings.json")
        s1.save_settings({"console_url": url, "api_token": token})

    def test_no_override_falls_back_to_global(self, tmp_path, monkeypatch):
        import s1_detection_library as s1

        self._set_global(tmp_path, monkeypatch)
        # No middleware has installed an override on this context.
        out = s1._resolved_settings()
        assert out["console_url"] == "https://global.sentinelone.net"
        assert out["api_token"] == "global-token"
        assert out["_source"] == "global"

    def test_request_override_wins_over_global(self, tmp_path, monkeypatch):
        import s1_detection_library as s1

        self._set_global(tmp_path, monkeypatch)
        tok = s1.set_request_override(
            "https://alice-tenant.sentinelone.net",
            "alice-browser-token",
        )
        try:
            out = s1._resolved_settings()
            assert out["console_url"] == "https://alice-tenant.sentinelone.net"
            assert out["api_token"] == "alice-browser-token"
            assert out["_source"] == "browser_override"
        finally:
            s1.clear_request_override(tok)

    def test_partial_override_falls_back_to_global(self, tmp_path, monkeypatch):
        """A browser that sent the URL but not the token (or vice versa) must
        NOT be mixed with the global token — that would leak the admin's
        credentials against an unrelated tenant. Fall back cleanly to global.
        """
        import s1_detection_library as s1

        self._set_global(tmp_path, monkeypatch)
        # URL only — no token.
        tok = s1.set_request_override("https://alice-tenant.sentinelone.net", "")
        try:
            out = s1._resolved_settings()
            assert out["console_url"] == "https://global.sentinelone.net"
            assert out["api_token"] == "global-token"
            assert out["_source"] == "global"
        finally:
            s1.clear_request_override(tok)

        # Token only — no URL.
        tok = s1.set_request_override("", "orphan-token")
        try:
            out = s1._resolved_settings()
            assert out["console_url"] == "https://global.sentinelone.net"
            assert out["api_token"] == "global-token"
        finally:
            s1.clear_request_override(tok)

    def test_override_is_reset_correctly(self, tmp_path, monkeypatch):
        """clear_request_override must restore the previous context state so
        per-request values can't leak across requests on the same worker."""
        import s1_detection_library as s1

        self._set_global(tmp_path, monkeypatch)
        tok = s1.set_request_override("https://x.sentinelone.net", "x-token")
        assert s1._resolved_settings()["_source"] == "browser_override"
        s1.clear_request_override(tok)
        assert s1._resolved_settings()["_source"] == "global"

    def test_is_configured_reflects_resolved_settings(self, tmp_path, monkeypatch):
        """If global is empty and a request-scoped override is installed,
        is_configured() must say True."""
        import s1_detection_library as s1

        # Empty global.
        monkeypatch.setattr(s1, "_DATA_ROOT", tmp_path)
        monkeypatch.setattr(s1, "_SETTINGS_FILE", tmp_path / "s1_settings.json")
        s1.save_settings({"console_url": "", "api_token": ""})

        assert s1.is_configured() is False
        tok = s1.set_request_override("https://alice.sentinelone.net", "alice-tok")
        try:
            assert s1.is_configured() is True
        finally:
            s1.clear_request_override(tok)
        assert s1.is_configured() is False
