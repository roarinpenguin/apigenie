"""RBAC Phase 2.5 — per-user detection-rule injection (TDD).

inject_detection_events() should only fire rules the *resolved caller* is
allowed to see. The resolved caller is set on the profiles.set_current_user()
contextvar by auth.py when a request's credential matches a registered
identifier. Visibility semantics mirror _can_see_obj in admin.py:

  - owner_id is None        → admin/global rule  → fires for everyone
  - visibility == "public"  → shared rule         → fires for everyone
  - owner_id == caller      → user's own rule     → fires only for that user
  - else (other user's private rule) → never fires for this caller

When no caller is resolved (kafka pubsub, anonymous, or unmatched credential),
only admin/public rules fire — never another user's private rule.
"""
from __future__ import annotations


# Helpers ──────────────────────────────────────────────────────────────────────

def _logs(n: int = 10) -> list[dict]:
    return [{"event": "noop", "i": i} for i in range(n)]


def _fired(logs: list[dict]) -> set[str]:
    return {ev["_detection_rule"] for ev in logs if "_detection_rule" in ev}


def _make_rule(name: str, *, owner_id=None, visibility="public",
               source="okta", periodicity=10):
    import detection_rules
    return detection_rules.create_rule({
        "name": name,
        "source": source,
        "owner_id": owner_id,
        "visibility": visibility,
        "periodicity": periodicity,
        "field_overrides": {"marker": name},
    })


# Tests ────────────────────────────────────────────────────────────────────────

class TestInjectionScoping:
    def test_no_caller_fires_only_admin_and_public(self, make_user):
        import detection_rules
        import profiles

        alice = make_user("alice")
        bob = make_user("bob")
        _make_rule("admin_rule", owner_id=None, visibility="public")
        _make_rule("alice_private", owner_id=alice["id"], visibility="private")
        _make_rule("bob_private", owner_id=bob["id"], visibility="private")
        _make_rule("bob_public", owner_id=bob["id"], visibility="public")

        profiles.set_current_user(None)
        fired = _fired(detection_rules.inject_detection_events("okta", _logs()))
        assert "admin_rule" in fired
        assert "bob_public" in fired
        assert "alice_private" not in fired
        assert "bob_private" not in fired

    def test_alice_caller_sees_her_private_plus_public_and_admin(self, make_user):
        import detection_rules
        import profiles

        alice = make_user("alice")
        bob = make_user("bob")
        _make_rule("admin_rule", owner_id=None, visibility="public")
        _make_rule("alice_private", owner_id=alice["id"], visibility="private")
        _make_rule("bob_private", owner_id=bob["id"], visibility="private")
        _make_rule("bob_public", owner_id=bob["id"], visibility="public")

        profiles.set_current_user(alice["id"])
        fired = _fired(detection_rules.inject_detection_events("okta", _logs()))
        assert "alice_private" in fired
        assert "admin_rule" in fired
        assert "bob_public" in fired
        assert "bob_private" not in fired

    def test_bob_caller_sees_his_private_not_alices(self, make_user):
        import detection_rules
        import profiles

        alice = make_user("alice")
        bob = make_user("bob")
        _make_rule("alice_private", owner_id=alice["id"], visibility="private")
        _make_rule("bob_private", owner_id=bob["id"], visibility="private")

        profiles.set_current_user(bob["id"])
        fired = _fired(detection_rules.inject_detection_events("okta", _logs()))
        assert "bob_private" in fired
        assert "alice_private" not in fired

    def test_legacy_rule_without_owner_treated_as_public(self):
        """Rules saved before Phase 2 have no owner_id/visibility keys."""
        import detection_rules
        import profiles

        # Bypass create_rule's defaults to simulate a legacy on-disk rule.
        legacy = {
            "id": "legacy-1",
            "name": "legacy_rule",
            "source": "okta",
            "enabled": True,
            "periodicity": 10,
            "field_overrides": {"marker": "legacy"},
        }
        detection_rules._save_rules([legacy])

        profiles.set_current_user(None)
        fired = _fired(detection_rules.inject_detection_events("okta", _logs()))
        assert "legacy_rule" in fired

    def test_disabled_rule_never_fires_regardless_of_caller(self, make_user):
        import detection_rules
        import profiles

        alice = make_user("alice")
        detection_rules.create_rule({
            "name": "disabled_rule",
            "source": "okta",
            "owner_id": alice["id"],
            "visibility": "private",
            "enabled": False,
            "periodicity": 10,
            "field_overrides": {"marker": "x"},
        })

        profiles.set_current_user(alice["id"])
        fired = _fired(detection_rules.inject_detection_events("okta", _logs()))
        assert "disabled_rule" not in fired

    def test_rule_from_other_source_never_fires(self, make_user):
        import detection_rules
        import profiles

        alice = make_user("alice")
        _make_rule("for_netskope", owner_id=alice["id"], visibility="private",
                   source="netskope")

        profiles.set_current_user(alice["id"])
        fired = _fired(detection_rules.inject_detection_events("okta", _logs()))
        assert "for_netskope" not in fired
