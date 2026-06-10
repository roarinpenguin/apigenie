"""Unit tests for ``alerts._apply_overrides`` and ``alerts._tokenize_path``.

These cover the dot-path / bracket-index override syntax surfaced by the
Alert Push editor modal. The bracket form (e.g. ``resources[0].name``)
was broken in P4.2 (silently creating a phantom top-level key
``"resources[0]"``) and only got noticed during the P4.6 send-endpoint
e2e tests — so locking it in with focused tests prevents a regression.
"""
from __future__ import annotations

from typing import Any

import alerts

# ── Tokeniser ────────────────────────────────────────────────────────────────

class TestTokenizePath:
    def test_simple_dot_path(self):
        assert alerts._tokenize_path("device.name") == ["device", "name"]

    def test_three_levels(self):
        assert alerts._tokenize_path("actor.user.uid") == ["actor", "user", "uid"]

    def test_bracket_index(self):
        assert alerts._tokenize_path("resources[0].name") == ["resources", 0, "name"]

    def test_bracket_index_no_subkey(self):
        assert alerts._tokenize_path("resources[2]") == ["resources", 2]

    def test_chained_indices(self):
        assert alerts._tokenize_path("matrix[0][1].x") == ["matrix", 0, 1, "x"]

    def test_double_dot_doesnt_blow_up(self):
        assert alerts._tokenize_path("a..b") == ["a", "b"]

    def test_single_key(self):
        assert alerts._tokenize_path("severity_id") == ["severity_id"]


# ── Override application: dict paths (P4.1 originals) ────────────────────────

class TestOverridesDictPaths:
    def test_top_level_string_key(self):
        alert: dict[str, Any] = {}
        alerts._apply_overrides(alert, {"severity_id": 4})
        assert alert == {"severity_id": 4}

    def test_nested_dict_path_creates_missing_parents(self):
        alert: dict[str, Any] = {}
        alerts._apply_overrides(alert, {"finding_info.title": "X"})
        assert alert == {"finding_info": {"title": "X"}}

    def test_empty_string_skipped(self):
        alert: dict[str, Any] = {"x": "keep"}
        alerts._apply_overrides(alert, {"x": ""})
        assert alert == {"x": "keep"}

    def test_none_skipped(self):
        alert: dict[str, Any] = {"x": "keep"}
        alerts._apply_overrides(alert, {"x": None})
        assert alert == {"x": "keep"}

    def test_false_and_zero_are_applied(self):
        alert: dict[str, Any] = {}
        alerts._apply_overrides(alert, {"a": False, "b": 0})
        assert alert == {"a": False, "b": 0}


# ── Override application: bracket paths (P4.6 fix) ───────────────────────────

class TestOverridesBracketPaths:
    def test_resources_index_into_existing_list(self):
        alert: dict[str, Any] = {"resources": [{"name": "old"}]}
        alerts._apply_overrides(alert, {"resources[0].name": "bridge"})
        assert alert == {"resources": [{"name": "bridge"}]}

    def test_resources_index_pads_missing_slots(self):
        alert: dict[str, Any] = {"resources": [{"name": "a"}]}
        alerts._apply_overrides(alert, {"resources[2].name": "c"})
        assert alert["resources"][0] == {"name": "a"}
        assert alert["resources"][1] == {}
        assert alert["resources"][2] == {"name": "c"}

    def test_resources_creates_list_when_missing(self):
        alert: dict[str, Any] = {}
        alerts._apply_overrides(alert, {"resources[0].name": "fresh"})
        assert alert == {"resources": [{"name": "fresh"}]}

    def test_bracket_path_does_not_create_phantom_key(self):
        """The pre-fix bug: the literal key ``"resources[0]"`` would appear
        at the top level. Lock that out."""
        alert: dict[str, Any] = {"resources": [{}]}
        alerts._apply_overrides(alert, {"resources[0].type": "Device"})
        assert "resources[0]" not in alert
        assert alert["resources"][0]["type"] == "Device"

    def test_multiple_resources_overrides(self):
        alert: dict[str, Any] = {"resources": [{}]}
        alerts._apply_overrides(alert, {
            "resources[0].name": "host-a",
            "resources[0].type": "Device",
            "resources[1].name": "user-b",
            "resources[1].type": "User",
        })
        assert alert["resources"][0] == {"name": "host-a", "type": "Device"}
        assert alert["resources"][1] == {"name": "user-b", "type": "User"}

    def test_index_into_non_list_silently_skipped(self):
        """If ``resources`` is somehow a dict, an indexed override doesn't
        mutate it — and definitely doesn't raise."""
        alert: dict[str, Any] = {"resources": {"already": "a dict"}}
        alerts._apply_overrides(alert, {"resources[0].name": "bridge"})
        assert alert == {"resources": {"already": "a dict"}}

    def test_index_on_terminal_token(self):
        """``resources[2] = literal-string`` is allowed — sets the slot to a
        plain string. Edge case but the parser should handle it."""
        alert: dict[str, Any] = {"resources": []}
        alerts._apply_overrides(alert, {"resources[0]": "raw-string"})
        assert alert == {"resources": ["raw-string"]}
