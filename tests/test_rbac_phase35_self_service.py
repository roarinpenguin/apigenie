"""RBAC Phase 3.5 — self-service account settings (TDD).

Three pieces ship together:

  1. `accounts.change_password(uid, current, new)` — verifies the *current*
     password and atomically replaces it with *new*. Returns True on success;
     raises ValueError on any input failure. Underpins the per-user portal
     "Change password" form.

  2. `accounts.update_user(uid, email=..., console_url=..., console_token=...)`
     — already exists; this file pins the contract for the self-service
     wrappers in admin.py.

  3. `s1_detection_library._resolved_settings()` — returns the **per-user**
     S1 console URL + token if the resolved caller (via
     `profiles.set_current_user`) has both set, otherwise falls back to the
     global `s1_settings.json` blob written by the admin "System Settings"
     page. Wires per-user S1 access for the Detection Library browser.
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

    def test_per_user_s1_console_url_and_token_round_trip(self, make_user):
        import accounts

        u = make_user("alice")
        upd = accounts.update_user(
            u["id"],
            console_url="https://alice-tenant.sentinelone.net",
            console_token="alice-s1-mgmt-token-xyz",
        )
        assert upd["console_url"] == "https://alice-tenant.sentinelone.net"
        assert upd["has_console_token"] is True

        # Token is not echoed back without secrets=True
        public = accounts.get_user(u["id"])
        assert "console_token" not in public

        # With secrets it is
        secret = accounts.get_user(u["id"], with_secrets=True)
        assert secret["console_token"] == "alice-s1-mgmt-token-xyz"

    def test_per_user_s1_console_can_be_cleared(self, make_user):
        import accounts

        u = make_user("alice")
        accounts.update_user(
            u["id"], console_url="https://x.sentinelone.net", console_token="t"
        )
        accounts.update_user(u["id"], console_url="", console_token="")
        fresh = accounts.get_user(u["id"], with_secrets=True)
        assert fresh["console_url"] == ""
        assert fresh["console_token"] == ""


# ── s1_detection_library._resolved_settings ──────────────────────────────────

class TestS1ResolvedSettings:
    """The S1 client must read per-user override when the caller-context (set
    by auth.py from a matched identifier, OR by an admin/portal endpoint from
    the session) points to a user with a configured per-user console."""

    def _set_global(self, tmp_path, monkeypatch, url="https://global.sentinelone.net",
                    token="global-token"):
        import s1_detection_library as s1
        monkeypatch.setattr(s1, "_DATA_ROOT", tmp_path)
        monkeypatch.setattr(s1, "_SETTINGS_FILE", tmp_path / "s1_settings.json")
        s1.save_settings({"console_url": url, "api_token": token})

    def test_no_caller_falls_back_to_global(self, tmp_path, monkeypatch):
        import s1_detection_library as s1
        import profiles

        self._set_global(tmp_path, monkeypatch)
        profiles.set_current_user(None)

        out = s1._resolved_settings()
        assert out["console_url"] == "https://global.sentinelone.net"
        assert out["api_token"] == "global-token"

    def test_caller_with_per_user_override_uses_per_user(
        self, tmp_path, monkeypatch, make_user
    ):
        import s1_detection_library as s1
        import accounts
        import profiles

        self._set_global(tmp_path, monkeypatch)
        u = make_user("alice")
        accounts.update_user(
            u["id"],
            console_url="https://alice-tenant.sentinelone.net",
            console_token="alice-token",
        )

        profiles.set_current_user(u["id"])
        out = s1._resolved_settings()
        assert out["console_url"] == "https://alice-tenant.sentinelone.net"
        assert out["api_token"] == "alice-token"

    def test_partial_override_falls_back_to_global(
        self, tmp_path, monkeypatch, make_user
    ):
        """A user who set the URL but not the token (or vice versa) must NOT be
        mixed with the global token — that would leak the admin's credentials
        against an unrelated tenant. Fall back cleanly to global."""
        import s1_detection_library as s1
        import accounts
        import profiles

        self._set_global(tmp_path, monkeypatch)
        u = make_user("alice")
        accounts.update_user(u["id"], console_url="https://alice-tenant.sentinelone.net")
        # No console_token set.

        profiles.set_current_user(u["id"])
        out = s1._resolved_settings()
        assert out["console_url"] == "https://global.sentinelone.net"
        assert out["api_token"] == "global-token"

    def test_unknown_caller_uid_falls_back_to_global(self, tmp_path, monkeypatch):
        import s1_detection_library as s1
        import profiles

        self._set_global(tmp_path, monkeypatch)
        profiles.set_current_user("usr_does_not_exist")
        out = s1._resolved_settings()
        assert out["console_url"] == "https://global.sentinelone.net"
        assert out["api_token"] == "global-token"

    def test_is_configured_reflects_resolved_settings(
        self, tmp_path, monkeypatch, make_user
    ):
        """If global is empty and the resolved caller has a per-user setup,
        is_configured() must say True."""
        import s1_detection_library as s1
        import accounts
        import profiles

        # Empty global.
        monkeypatch.setattr(s1, "_DATA_ROOT", tmp_path)
        monkeypatch.setattr(s1, "_SETTINGS_FILE", tmp_path / "s1_settings.json")
        s1.save_settings({"console_url": "", "api_token": ""})

        u = make_user("alice")
        accounts.update_user(
            u["id"],
            console_url="https://alice-tenant.sentinelone.net",
            console_token="alice-token",
        )

        profiles.set_current_user(None)
        assert s1.is_configured() is False

        profiles.set_current_user(u["id"])
        assert s1.is_configured() is True
