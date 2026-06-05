"""RBAC Phase 3 — Log Push detection-rule customisation (TDD).

The push worker (log_pusher._push_loop) calls
detection_rules.inject_detection_events for every generated event. Phase 2.5
gave that function per-user filtering via the profiles caller contextvar — but
the push worker never sets the contextvar, so only admin/public rules fire.

This phase wires the push worker's thread caller-context to the owner of the
push profile so a user's own detection rules show up in their pushed traffic.
"""
from __future__ import annotations


def _make_rule(name: str, *, owner_id=None, visibility="public", source="okta"):
    import detection_rules
    return detection_rules.create_rule({
        "name": name, "source": source, "owner_id": owner_id,
        "visibility": visibility, "periodicity": 10,
        "field_overrides": {"marker": name},
    })


def _fired(logs):
    return {ev["_detection_rule"] for ev in logs if "_detection_rule" in ev}


class TestPushCallerContext:
    def test_set_caller_for_loop_sets_contextvar_to_owner(self, make_user):
        import log_pusher
        import profiles

        alice = make_user("alice")
        prof = log_pusher.create_profile({
            "name": "alice_push", "source_type": "okta",
            "owner_id": alice["id"], "visibility": "private",
        })
        log_pusher._set_caller_for_loop(prof["id"])
        assert profiles.get_current_user() == alice["id"]

    def test_unknown_profile_clears_caller(self):
        import log_pusher
        import profiles

        profiles.set_current_user("someone")
        log_pusher._set_caller_for_loop("not-a-real-profile-id")
        assert profiles.get_current_user() is None

    def test_admin_owned_profile_keeps_caller_none(self):
        """Admin-created (owner_id=None) push profiles must remain anonymous."""
        import log_pusher
        import profiles

        prof = log_pusher.create_profile({
            "name": "admin_push", "source_type": "okta", "owner_id": None,
        })
        log_pusher._set_caller_for_loop(prof["id"])
        assert profiles.get_current_user() is None


class TestPushInjectionIntegration:
    """End-to-end: a push profile owned by alice gets her private rules injected."""

    def test_alice_push_sees_only_her_private_plus_public(self, make_user):
        import detection_rules
        import log_pusher
        import profiles

        alice = make_user("alice")
        bob = make_user("bob")
        _make_rule("admin_rule", owner_id=None, visibility="public")
        _make_rule("alice_private", owner_id=alice["id"], visibility="private")
        _make_rule("bob_private", owner_id=bob["id"], visibility="private")
        prof = log_pusher.create_profile({
            "name": "alice_push", "source_type": "okta",
            "owner_id": alice["id"], "visibility": "private",
        })

        # Simulate one tick of the push loop: bind caller, then inject.
        log_pusher._set_caller_for_loop(prof["id"])
        events = [{"event": "noop", "i": i} for i in range(10)]
        batch = detection_rules.inject_detection_events("okta", events)

        fired = _fired(batch)
        assert "alice_private" in fired
        assert "admin_rule" in fired
        assert "bob_private" not in fired

    def test_admin_push_sees_only_admin_and_public(self, make_user):
        import detection_rules
        import log_pusher
        import profiles

        alice = make_user("alice")
        _make_rule("admin_rule", owner_id=None, visibility="public")
        _make_rule("alice_private", owner_id=alice["id"], visibility="private")
        prof = log_pusher.create_profile({
            "name": "admin_push", "source_type": "okta", "owner_id": None,
        })

        log_pusher._set_caller_for_loop(prof["id"])
        events = [{"event": "noop", "i": i} for i in range(10)]
        batch = detection_rules.inject_detection_events("okta", events)

        fired = _fired(batch)
        assert "admin_rule" in fired
        assert "alice_private" not in fired
