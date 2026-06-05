"""Backfill tests for RBAC Phase 2.2 / 2.3 / 2.4.

These cover the multi-user log-profiling work added on top of the Phase 1
accounts/sessions baseline:

* 2.2 — per-user source identifiers (registration, collision guards, matching).
* 2.3 — Source Details placeholder masking for user portal.
* 2.4 — admin "Viewing as" user-switcher (_session_identity acting-as).

Storage is redirected to a tmp dir by conftest.py — no production data touched.
"""
from __future__ import annotations

import pytest


# ────────────────────────────────────────────────────────────────────────────
# Phase 2.2 — identifiers & matching
# ────────────────────────────────────────────────────────────────────────────

class TestIdentifierRegistration:
    def test_add_and_list(self, make_user):
        import accounts
        u = make_user("alice")
        ident = accounts.add_identifier(u["id"], "okta", "bearer_token", "tok-alice-001")
        assert ident["id_value"] == "tok-alice-001"
        assert ident["user_id"] == u["id"]
        assert accounts.list_identifiers(u["id"]) == [ident]

    def test_same_value_same_source_rejected(self, make_user):
        import accounts
        u1 = make_user("alice")
        accounts.add_identifier(u1["id"], "okta", "bearer_token", "shared-val")
        with pytest.raises(ValueError, match="already in use"):
            accounts.add_identifier(u1["id"], "okta", "bearer_token", "shared-val")

    def test_same_value_different_source_different_user_rejected(self, make_user):
        """Phase 2.2 global-uniqueness guard — the main collision risk fix."""
        import accounts
        u1 = make_user("alice")
        u2 = make_user("bob")
        accounts.add_identifier(u1["id"], "okta", "bearer_token", "collide-xyz")
        with pytest.raises(ValueError, match="already in use"):
            accounts.add_identifier(u2["id"], "netskope", "bearer_token", "collide-xyz")

    def test_invalid_kind_rejected(self, make_user):
        import accounts
        u = make_user("alice")
        with pytest.raises(ValueError, match="Invalid identifier kind"):
            accounts.add_identifier(u["id"], "okta", "not_a_kind", "v")

    def test_blank_value_rejected(self, make_user):
        import accounts
        u = make_user("alice")
        with pytest.raises(ValueError, match="required"):
            accounts.add_identifier(u["id"], "okta", "bearer_token", "   ")


class TestIdentifierMatching:
    def test_match_returns_owner(self, make_user):
        import accounts
        u = make_user("alice")
        accounts.add_identifier(u["id"], "okta", "bearer_token", "tok-001")
        assert accounts.match_user_by_identifier("tok-001") == u["id"]

    def test_match_with_source_hint(self, make_user):
        import accounts
        u = make_user("alice")
        accounts.add_identifier(u["id"], "okta", "bearer_token", "tok-002")
        assert accounts.match_user_by_identifier("tok-002", source="okta") == u["id"]

    def test_unknown_value_returns_none(self):
        import accounts
        assert accounts.match_user_by_identifier("nope") is None

    def test_blank_returns_none(self):
        import accounts
        assert accounts.match_user_by_identifier("") is None
        assert accounts.match_user_by_identifier("   ") is None


class TestReservedCredentials:
    """Phase 2.2 — built-in shared mock tokens must not be hijackable."""

    @pytest.mark.parametrize("val", [
        "apigenie-valid-token-001",
        "apigenie-ak-001",
        "apigenie-sk-001",
        "apigenie-principal-001",
        "apigenie-secret-001",
    ])
    def test_known_shared_secrets_are_reserved(self, val):
        import auth
        assert auth.is_reserved_credential(val) is True

    def test_custom_value_not_reserved(self):
        import auth
        assert auth.is_reserved_credential("a-value-that-no-one-uses-12345") is False

    def test_blank_not_reserved(self):
        import auth
        assert auth.is_reserved_credential("") is False
        assert auth.is_reserved_credential("   ") is False


# ────────────────────────────────────────────────────────────────────────────
# Phase 2.3 — Source Details placeholders
# ────────────────────────────────────────────────────────────────────────────

class TestUserPortalMasking:
    def test_mask_table_covers_known_shared_secrets(self):
        import admin
        table = admin._user_mask_table()
        assert "apigenie-valid-token-001" in table
        assert table["apigenie-valid-token-001"] == "<YOUR_BEARER_TOKEN>"
        assert "apigenie-ak-001" in table

    def test_mask_text_substitutes_known_values(self):
        import admin
        s = 'Authorization: Bearer apigenie-valid-token-001'
        assert admin._mask_text_for_user(s) == 'Authorization: Bearer <YOUR_BEARER_TOKEN>'

    def test_mask_text_leaves_unknown_untouched(self):
        import admin
        s = "hello world without any secrets"
        assert admin._mask_text_for_user(s) == s

    def test_mask_text_handles_empty(self):
        import admin
        assert admin._mask_text_for_user("") == ""
        assert admin._mask_text_for_user(None) is None  # type: ignore[arg-type]


class TestIdentifierKindsPerSource:
    def test_bearer_source_offers_only_bearer(self):
        import admin
        v = {"auth_type": "Bearer token", "credentials": {"token": "x"}}
        assert admin._source_identifier_kinds(v) == ["bearer_token"]

    def test_oauth_tenant_offers_bearer_client_tenant(self):
        import admin
        v = {"auth_type": "OAuth2 Bearer (tenant token endpoint)",
             "credentials": {"client_id": "x", "client_secret": "y"}}
        kinds = admin._source_identifier_kinds(v)
        assert set(kinds) == {"bearer_token", "client_id", "tenant_id"}

    def test_x_apikeys_source_offers_api_key(self):
        import admin
        v = {"auth_type": "X-ApiKeys header (accessKey + secretKey)",
             "credentials": {"accessKey": "x", "secretKey": "y"}}
        assert admin._source_identifier_kinds(v) == ["api_key"]

    def test_basic_auth_source_offers_basic_user(self):
        import admin
        v = {"auth_type": "HTTP Basic auth",
             "credentials": {"username": "x", "password": "y"}}
        assert admin._source_identifier_kinds(v) == ["basic_user"]

    def test_kafka_source_offers_consumer_group(self):
        import admin
        v = {"auth_type": "Kafka SASL/PLAIN", "credentials": {}}
        assert admin._source_identifier_kinds(v) == ["consumer_group"]

    def test_pubsub_source_offers_subscription(self):
        import admin
        v = {"auth_type": "Service-account JSON or PUBSUB_EMULATOR_HOST", "credentials": {}}
        assert admin._source_identifier_kinds(v) == ["subscription"]

    def test_unknown_falls_back_to_all_kinds(self):
        import accounts
        import admin
        v = {"auth_type": "completely unknown scheme", "credentials": {"foo": "bar"}}
        assert admin._source_identifier_kinds(v) == list(accounts.IDENTIFIER_KINDS)


# ────────────────────────────────────────────────────────────────────────────
# Phase 2.4 — admin "Viewing as" user-switcher
# ────────────────────────────────────────────────────────────────────────────

class TestSessionIdentityActingAs:
    def _admin_session(self):
        import admin
        return admin._new_session(role="admin", user_id=None, username="admin", is_admin=True)

    def _user_session(self, uid: str, username: str):
        import admin
        return admin._new_session(role="user", user_id=uid, username=username, is_admin=False)

    def test_pure_admin_resolves_to_none_admin(self):
        import admin
        tok = self._admin_session()
        assert admin._session_identity(tok) == (None, True)

    def test_admin_acting_as_resolves_to_target_with_admin_true(self, make_user):
        import admin
        u = make_user("alice")
        tok = self._admin_session()
        admin._sessions[tok]["acting_as_user_id"] = u["id"]
        assert admin._session_identity(tok) == (u["id"], True)

    def test_regular_user_resolves_to_self_not_admin(self, make_user):
        import admin
        u = make_user("alice")
        tok = self._user_session(u["id"], u["username"])
        assert admin._session_identity(tok) == (u["id"], False)

    def test_unknown_token_resolves_to_none_not_admin(self):
        import admin
        assert admin._session_identity("not-a-real-token") == (None, False)

    def test_blank_token_resolves_to_none_not_admin(self):
        import admin
        assert admin._session_identity(None) == (None, False)
        assert admin._session_identity("") == (None, False)
