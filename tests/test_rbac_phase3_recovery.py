"""RBAC Phase 3 — admin handoff / password-recovery link coverage.

The no-SMTP handoff flow was already shipped:

  POST /admin/api/rbac/users (no password)  → returns one-time setup_link
  POST /admin/api/rbac/users/{uid}/reset-link → returns one-time reset_link
  GET  /portal/set-password?token=…  → renders the form
  POST /portal/set-password           → consumes the token, sets the password

These tests pin the underlying account-token lifecycle (issue / peek / consume
/ TTL / wrong-kind) so future refactors don't silently break the handoff.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


class TestAccountTokenLifecycle:
    def test_issue_then_consume_returns_user_id(self, make_user):
        import accounts
        u = make_user("alice")
        tok = accounts.issue_token(u["id"], "confirm")
        assert tok and len(tok) > 20
        assert accounts.consume_token(tok, "confirm") == u["id"]

    def test_consume_is_one_shot(self, make_user):
        import accounts
        u = make_user("alice")
        tok = accounts.issue_token(u["id"], "confirm")
        accounts.consume_token(tok, "confirm")
        assert accounts.consume_token(tok, "confirm") is None

    def test_peek_does_not_consume(self, make_user):
        import accounts
        u = make_user("alice")
        tok = accounts.issue_token(u["id"], "recovery")
        info = accounts.peek_token(tok)
        assert info is not None
        assert info["user_id"] == u["id"]
        assert info["kind"] == "recovery"
        # Still consumable afterwards
        assert accounts.consume_token(tok) == u["id"]

    def test_wrong_kind_rejected_and_deleted(self, make_user):
        import accounts
        u = make_user("alice")
        tok = accounts.issue_token(u["id"], "confirm")
        assert accounts.consume_token(tok, "recovery") is None
        # Implementation deletes mismatched tokens to prevent reuse
        assert accounts.consume_token(tok, "confirm") is None

    def test_invalid_kind_rejected_at_issue(self, make_user):
        import accounts
        u = make_user("alice")
        with pytest.raises(ValueError, match="Invalid token kind"):
            accounts.issue_token(u["id"], "not_a_kind")

    def test_unknown_user_rejected_at_issue(self):
        import accounts
        with pytest.raises(ValueError, match="Unknown user"):
            accounts.issue_token("usr_nope", "confirm")

    def test_blank_token_returns_none(self):
        import accounts
        assert accounts.consume_token("") is None
        assert accounts.consume_token(None) is None  # type: ignore[arg-type]
        assert accounts.peek_token("") is None

    def test_expired_token_rejected_and_cleaned_up(self, make_user, monkeypatch):
        import accounts
        u = make_user("alice")
        tok = accounts.issue_token(u["id"], "confirm")
        # Backdate the expiry to simulate an old token.
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        conn = accounts._get_conn()
        conn.execute("UPDATE account_tokens SET expires_iso=? WHERE token=?", (past, tok))
        conn.commit()
        assert accounts.peek_token(tok) is None
        assert accounts.consume_token(tok) is None


class TestSetPasswordWorkflow:
    """Verifies the end-to-end flow: token → password set → token gone."""

    def test_set_password_via_token_workflow(self, make_user):
        import accounts
        u = make_user("alice")
        tok = accounts.issue_token(u["id"], "confirm")
        # peek (form render) keeps token alive
        info = accounts.peek_token(tok)
        assert info and info["user_id"] == u["id"]
        # consume → user_id; then admin/portal sets the password
        uid = accounts.consume_token(tok)
        assert uid == u["id"]
        ok = accounts.set_password(uid, "n3w-strong-pw")
        assert ok is True
        # Token is dead; user can log in with the new password
        assert accounts.verify_login(u["username"], "n3w-strong-pw") is not None

    def test_recovery_kind_resets_existing_password(self, make_user):
        import accounts
        u = make_user("alice")
        accounts.set_password(u["id"], "original-pw-12345")
        tok = accounts.issue_token(u["id"], "recovery")
        uid = accounts.consume_token(tok, "recovery")
        assert uid == u["id"]
        accounts.set_password(uid, "replacement-pw-67890")
        assert accounts.verify_login(u["username"], "original-pw-12345") is None
        assert accounts.verify_login(u["username"], "replacement-pw-67890") is not None
