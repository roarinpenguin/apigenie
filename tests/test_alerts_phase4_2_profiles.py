"""Alert Push Phase 4.2 — module-level CRUD + serialisation tests.

Pure module tests (no router). Covers:

* create_profile builds a complete, default-populated profile shape
* round-trip storage (create -> get / list / update / delete) survives
  the JSON file on disk
* to_public_dict redacts the UAM service token and exposes
  has_uam_service_token instead — the same redaction pattern the
  Phase 3.5 console_token uses
* update_profile preserves the saved token when caller sends "" /
  omits the field (so a user can edit URL / account_id without
  re-pasting the secret)
* update_profile clears the token on explicit "__clear__" sentinel
* clone_profile drops the source token (so secrets don't propagate
  between owners) and resets runtime state

Router-level enforcement (login, owner stamping via _owner_stamp,
visibility filtering via _can_see_obj) is exercised in
``test_alerts_phase4_2_api.py``.
"""
from __future__ import annotations


class TestCreateProfile:
    def test_creates_profile_with_defaults(self):
        import alert_push
        p = alert_push.create_profile({
            "name": "BEC inbox rule",
            "template_id": "o365_bec_inbox_rule",
            "owner_id": "alice-uid",
            "visibility": "private",
        })
        assert p["id"]
        assert p["name"] == "BEC inbox rule"
        assert p["template_id"] == "o365_bec_inbox_rule"
        assert p["owner_id"] == "alice-uid"
        assert p["visibility"] == "private"
        # Defaults
        assert p["status"] == "stopped"
        assert p["alerts_sent"] == 0
        assert p["uam_ingest_url"] == "https://ingest.us1.sentinelone.net"
        assert p["mode"] == "oneshot"
        assert p["rate"] == 1
        assert p["duration"] == {"value": 5, "unit": "minutes"}
        assert p["overrides"] == {}
        assert p["link_xdr_assets"] is False

    def test_creates_profile_persists_to_disk(self):
        import alert_push
        alert_push.create_profile({
            "name": "P1", "template_id": "default_alert",
            "owner_id": "alice", "visibility": "private",
        })
        # A fresh load_profiles call (different in-memory state) sees it.
        assert any(p["name"] == "P1" for p in alert_push._load_profiles())

    def test_create_strips_trailing_slash_on_ingest_url(self):
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "uam_ingest_url": "https://ingest.example.com/",
        })
        assert p["uam_ingest_url"] == "https://ingest.example.com"

    def test_create_clamps_rate(self):
        import alert_push
        p_high = alert_push.create_profile({
            "name": "H", "template_id": "default_alert", "rate": 9999,
        })
        p_low = alert_push.create_profile({
            "name": "L", "template_id": "default_alert", "rate": 0,
        })
        assert p_high["rate"] == 100
        assert p_low["rate"] == 1


class TestRoundTrip:
    def test_get_by_id(self):
        import alert_push
        a = alert_push.create_profile({
            "name": "A", "template_id": "default_alert",
        })
        b = alert_push.get_profile(a["id"])
        assert b is not None
        assert b["id"] == a["id"]
        assert b["name"] == "A"

    def test_get_unknown_returns_none(self):
        import alert_push
        assert alert_push.get_profile("does-not-exist") is None

    def test_list_returns_all(self):
        import alert_push
        alert_push.create_profile({"name": "A", "template_id": "default_alert"})
        alert_push.create_profile({"name": "B", "template_id": "default_alert"})
        assert {p["name"] for p in alert_push.list_profiles()} == {"A", "B"}

    def test_delete_removes(self):
        import alert_push
        p = alert_push.create_profile({"name": "D", "template_id": "default_alert"})
        assert alert_push.delete_profile(p["id"]) is True
        assert alert_push.get_profile(p["id"]) is None

    def test_delete_unknown_returns_false(self):
        import alert_push
        assert alert_push.delete_profile("not-there") is False


class TestUpdateProfile:
    def test_update_name_and_template(self):
        import alert_push
        p = alert_push.create_profile({"name": "P", "template_id": "default_alert"})
        out = alert_push.update_profile(p["id"], {"name": "Renamed",
                                                  "template_id": "o365_bec_inbox_rule"})
        assert out["name"] == "Renamed"
        assert out["template_id"] == "o365_bec_inbox_rule"

    def test_update_strips_trailing_slash_on_ingest_url(self):
        import alert_push
        p = alert_push.create_profile({"name": "P", "template_id": "default_alert"})
        out = alert_push.update_profile(p["id"], {
            "uam_ingest_url": "https://eu1.sentinelone.net/",
        })
        assert out["uam_ingest_url"] == "https://eu1.sentinelone.net"

    def test_update_unknown_returns_none(self):
        import alert_push
        assert alert_push.update_profile("nope", {"name": "x"}) is None

    def test_owner_id_cannot_be_smuggled_in_via_update(self):
        """The router strips owner_id before calling update_profile, so the
        module should ignore it even if someone calls it directly (defence
        in depth). update_profile only touches keys in _UPDATABLE_KEYS."""
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "owner_id": "alice",
        })
        out = alert_push.update_profile(p["id"], {"owner_id": "mallory"})
        assert out["owner_id"] == "alice", "owner_id must be immutable via update_profile"

    def test_update_rate_is_clamped(self):
        import alert_push
        p = alert_push.create_profile({"name": "P", "template_id": "default_alert"})
        out = alert_push.update_profile(p["id"], {"rate": 9999})
        assert out["rate"] == 100


class TestTokenLifecycle:
    """The UAM service token is the most security-sensitive field. These
    tests pin down the storage/redaction/preservation contract."""

    def test_token_stored_verbatim(self):
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "uam_service_token": "svc-tok-abc",
        })
        raw = alert_push.get_profile(p["id"])
        assert raw["uam_service_token"] == "svc-tok-abc"

    def test_to_public_dict_redacts_token(self):
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "uam_service_token": "svc-tok-abc",
        })
        pub = alert_push.to_public_dict(p)
        assert "uam_service_token" not in pub
        assert pub["has_uam_service_token"] is True

    def test_to_public_dict_empty_token(self):
        import alert_push
        p = alert_push.create_profile({"name": "P", "template_id": "default_alert"})
        pub = alert_push.to_public_dict(p)
        assert pub["has_uam_service_token"] is False

    def test_to_public_dict_handles_none(self):
        import alert_push
        assert alert_push.to_public_dict(None) is None

    def test_update_with_empty_token_preserves_saved(self):
        """Same UX as Phase 3.5 console_token — empty input must NOT clear."""
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "uam_service_token": "original",
        })
        alert_push.update_profile(p["id"], {"uam_service_token": "",
                                            "name": "Renamed"})
        assert alert_push.get_profile(p["id"])["uam_service_token"] == "original"

    def test_update_with_new_token_overwrites(self):
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "uam_service_token": "original",
        })
        alert_push.update_profile(p["id"], {"uam_service_token": "replacement"})
        assert alert_push.get_profile(p["id"])["uam_service_token"] == "replacement"

    def test_update_with_clear_sentinel_wipes_token(self):
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "uam_service_token": "original",
        })
        alert_push.update_profile(p["id"], {"uam_service_token": "__clear__"})
        assert alert_push.get_profile(p["id"])["uam_service_token"] == ""

    def test_get_uam_token_resolver(self):
        import alert_push
        p = alert_push.create_profile({
            "name": "P", "template_id": "default_alert",
            "uam_service_token": "tok-123",
        })
        assert alert_push.get_uam_token(p["id"]) == "tok-123"
        # Empty / missing slot returns None (not "")
        p2 = alert_push.create_profile({"name": "Q", "template_id": "default_alert"})
        assert alert_push.get_uam_token(p2["id"]) is None
        assert alert_push.get_uam_token("not-a-profile") is None


class TestClone:
    def test_clone_drops_secrets(self):
        """A cloned profile must NOT carry the original owner's UAM token —
        otherwise cloning a public profile would silently leak the source
        owner's S1 credentials to the cloner."""
        import alert_push
        src = alert_push.create_profile({
            "name": "Public BEC", "template_id": "o365_bec_inbox_rule",
            "owner_id": "alice", "visibility": "public",
            "uam_service_token": "alice-secret",
            "uam_account_id": "acct-alice",
        })
        clone = alert_push.clone_profile(src, owner_id="bob")
        # Token is wiped, but non-secret config (account_id, ingest URL) carries.
        assert clone["uam_service_token"] == ""
        assert clone["uam_account_id"] == "acct-alice"
        assert clone["owner_id"] == "bob"
        assert clone["visibility"] == "private"
        assert clone["id"] != src["id"]
        assert clone["name"] == "Copy of Public BEC"

    def test_clone_custom_name(self):
        import alert_push
        src = alert_push.create_profile({
            "name": "Src", "template_id": "default_alert", "owner_id": "alice",
        })
        clone = alert_push.clone_profile(src, owner_id="bob", new_name="My BEC")
        assert clone["name"] == "My BEC"

    def test_clone_resets_runtime_state(self):
        import alert_push
        src = alert_push.create_profile({
            "name": "Src", "template_id": "default_alert",
        })
        # Simulate a profile that had been fired before
        src_loaded = alert_push.get_profile(src["id"])
        src_loaded["alerts_sent"] = 42
        src_loaded["status"] = "completed"
        clone = alert_push.clone_profile(src_loaded, owner_id="bob")
        assert clone["alerts_sent"] == 0
        assert clone["status"] == "stopped"


class TestRbacCategoryRegistered:
    def test_alert_push_in_all_categories(self):
        import accounts
        assert "alert_push" in accounts.ALL_CATEGORIES
        assert accounts.Category.ALERT_PUSH == "alert_push"
        assert accounts.CATEGORY_LABELS["alert_push"] == "Alert Push Profiles"
