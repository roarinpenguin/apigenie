"""Tests for ``wef_bindings`` — per-operator WEF push binding storage (v5.2).

This module is the durable layer behind the admin WEF binding card. It
sits between two existing surfaces:

* ``sources.windows_event_forwarding.WEFEmitter`` (consumes a binding
  config dict) — TDD'd in commits 4ae6f39..d41def2.
* ``admin.py`` REST routes (Phase C) — call into this module to CRUD
  bindings from the UI.

The acceptance criterion: an admin can create, list, edit, enable /
disable, and delete WEF bindings. Sensitive fields (Basic password) are
encrypted at rest via the same Fernet key chain that protects the admin
S1 token; client certs are encrypted via
``windows_event_forwarding.save_cert_bundle`` and tied to the binding
id, so deleting a binding also deletes its PEM bundle.

Spec: docs/ROADMAP_2026-06-12.md §"WEF bindings storage" + §"Admin UI"
+ TDD plan entry ``test_wef_bindings.py``.
"""
from __future__ import annotations

import pytest

# ── Fixtures / helpers ────────────────────────────────────────────────

_BASIC_CFG = {
    "target_host": "wec1.lab.example.com",
    "target_port": 5986,
    "target_path": "/wsman/SubscriptionManager/WEC",
    "auth_method": "basic",
    "basic_username": "wef-svc",
    "tls_verify": True,
    "ca_bundle_path": None,
    "rate_per_min": 60,
    "batch_size": 10,
    "jitter_pct": 10,
    "channels_enabled": [
        "Security", "System", "Microsoft-Windows-Sysmon/Operational",
    ],
}


def _create_basic(name: str = "DC01 → WEC1",
                  password: str = "s3cret",
                  owner_id: str | None = None,
                  **cfg_overrides) -> dict:
    """Helper: create a Basic-auth binding with sensible defaults."""
    import wef_bindings
    cfg = {**_BASIC_CFG, **cfg_overrides}
    return wef_bindings.create_binding(
        {"name": name, "config": cfg, "password": password},
        owner_id=owner_id,
    )


# ── Create + persistence ──────────────────────────────────────────────

def test_create_binding_assigns_id_and_timestamps():
    import wef_bindings
    bnd = _create_basic()
    assert bnd["id"].startswith("wef-")
    assert len(bnd["id"]) > len("wef-")
    assert bnd["name"] == "DC01 → WEC1"
    assert bnd["enabled"] is False, "new bindings must default to disabled"
    assert "created_at" in bnd and "updated_at" in bnd
    # Defaulted status block
    assert bnd["status"]["sent_total"] == 0
    assert bnd["status"]["last_push_at"] is None
    assert bnd["status"]["last_error"] is None


def test_create_binding_encrypts_basic_password_at_rest():
    import wef_bindings
    bnd = _create_basic(password="hunter2-very-secret")
    raw = wef_bindings._path(bnd["id"]).read_text()
    # The plaintext password must NOT appear in the persisted JSON.
    assert "hunter2-very-secret" not in raw, (
        "Basic password leaked into wef_bindings storage as plaintext"
    )
    # And the encrypted form must be present in the binding's config.
    assert bnd["config"].get("basic_password_enc"), (
        "Expected basic_password_enc to be populated after create"
    )
    # Fernet tokens start with this prefix.
    assert bnd["config"]["basic_password_enc"].startswith("gAAAAA")


def test_create_binding_strips_plaintext_password_from_returned_dict():
    import wef_bindings
    bnd = _create_basic(password="hunter2")
    # The returned binding must NOT carry a plaintext password key —
    # otherwise admin GET responses would round-trip the secret back to
    # the browser, defeating the whole point of encrypted storage.
    assert "password" not in bnd
    assert "password" not in bnd.get("config", {})


def test_create_binding_rejects_invalid_config():
    import wef_bindings
    bad_cfg = {**_BASIC_CFG, "target_host": "", "auth_method": "basic"}
    with pytest.raises(ValueError) as exc:
        wef_bindings.create_binding(
            {"name": "broken", "config": bad_cfg, "password": "x"},
        )
    msg = str(exc.value).lower()
    # Reuses wef.validate_binding_config under the hood, which complains
    # about missing target_host.
    assert "target_host" in msg


def test_create_binding_rejects_blank_name():
    import wef_bindings
    with pytest.raises(ValueError):
        wef_bindings.create_binding(
            {"name": "   ", "config": _BASIC_CFG, "password": "x"},
        )


def test_create_binding_with_mtls_does_not_require_password():
    """mTLS bindings have no Basic password; the PEM upload is a
    separate step (POST /admin/api/wef/bindings/<id>/cert). Creating
    a fresh mTLS binding with no password and no cert must succeed —
    the binding stays disabled until the operator uploads the PEM."""
    import wef_bindings
    cfg = {**_BASIC_CFG, "auth_method": "client_cert",
           "basic_username": None}
    bnd = wef_bindings.create_binding(
        {"name": "mTLS one", "config": cfg},
    )
    assert bnd["config"]["auth_method"] == "client_cert"
    assert bnd["config"].get("basic_password_enc") in (None, "", )
    assert bnd["config"].get("cert_uploaded") is False


# ── Get / list ────────────────────────────────────────────────────────

def test_get_binding_returns_none_for_unknown_id():
    import wef_bindings
    assert wef_bindings.get_binding("wef-does-not-exist") is None


def test_list_bindings_returns_all_for_admin():
    import wef_bindings
    a = _create_basic("A", owner_id="u-alice")
    b = _create_basic("B", owner_id="u-bob")
    c = _create_basic("C", owner_id=None)  # global / admin-owned
    all_ids = set(wef_bindings.list_bindings(owner_id=None).keys())
    assert {a["id"], b["id"], c["id"]} <= all_ids


def test_list_bindings_owner_isolation():
    """A user only sees their own bindings + public ones; private
    bindings owned by other users are hidden."""
    import wef_bindings
    alice_priv = _create_basic("Alice private", owner_id="u-alice")
    bob_priv = _create_basic("Bob private", owner_id="u-bob")

    # As alice we should see ours but not bob's.
    alice_view = wef_bindings.list_bindings_for_user("u-alice")
    assert alice_priv["id"] in alice_view
    assert bob_priv["id"] not in alice_view


# ── Update ────────────────────────────────────────────────────────────

def test_update_binding_partial_fields_preserve_rest():
    import wef_bindings
    bnd = _create_basic()
    updated = wef_bindings.update_binding(
        bnd["id"], {"name": "Renamed DC"},
    )
    assert updated["name"] == "Renamed DC"
    # Other fields untouched.
    assert updated["config"]["target_host"] == _BASIC_CFG["target_host"]
    assert updated["config"]["auth_method"] == "basic"
    assert updated["updated_at"] >= bnd["updated_at"]


def test_update_binding_password_re_encrypts():
    import wef_bindings
    bnd = _create_basic(password="old-pw")
    old_enc = bnd["config"]["basic_password_enc"]
    updated = wef_bindings.update_binding(
        bnd["id"], {"password": "new-pw"},
    )
    new_enc = updated["config"]["basic_password_enc"]
    assert new_enc and new_enc != old_enc, (
        "Updating the password must produce a new ciphertext"
    )
    raw = wef_bindings._path(bnd["id"]).read_text()
    assert "new-pw" not in raw, (
        "New password leaked into storage as plaintext"
    )


def test_update_binding_switching_auth_method_normalises_config():
    """Switching basic→client_cert must clear the stored Basic
    credentials so the operator can audit the binding without finding
    stale username/password fields they can no longer see in the UI."""
    import wef_bindings
    bnd = _create_basic(password="x")
    assert bnd["config"]["basic_username"]
    assert bnd["config"]["basic_password_enc"]
    new_cfg = {**bnd["config"], "auth_method": "client_cert"}
    updated = wef_bindings.update_binding(
        bnd["id"], {"config": new_cfg},
    )
    assert updated["config"]["auth_method"] == "client_cert"
    assert updated["config"]["basic_username"] in (None, "")
    assert updated["config"]["basic_password_enc"] in (None, "")


def test_update_binding_returns_none_for_unknown_id():
    import wef_bindings
    assert wef_bindings.update_binding(
        "wef-does-not-exist", {"name": "x"},
    ) is None


# ── Lifecycle: enable / disable ───────────────────────────────────────

def test_set_enabled_toggles_flag():
    import wef_bindings
    bnd = _create_basic()
    assert bnd["enabled"] is False
    updated = wef_bindings.set_enabled(bnd["id"], True)
    assert updated["enabled"] is True
    # Idempotent: enabling an already-enabled binding is a no-op success.
    again = wef_bindings.set_enabled(bnd["id"], True)
    assert again["enabled"] is True


def test_set_enabled_persists_across_reload():
    import wef_bindings
    bnd = _create_basic()
    wef_bindings.set_enabled(bnd["id"], True)
    # Round-trip through fresh load (simulating a process restart).
    reloaded = wef_bindings.get_binding(bnd["id"])
    assert reloaded["enabled"] is True


# ── Status updates from the runner ────────────────────────────────────

def test_record_push_result_updates_status_block():
    import wef_bindings
    bnd = _create_basic()
    wef_bindings.record_push_result(
        bnd["id"], sent=7, status_code=200, error=None,
    )
    after = wef_bindings.get_binding(bnd["id"])
    assert after["status"]["sent_total"] == 7
    assert after["status"]["last_status_code"] == 200
    assert after["status"]["last_error"] is None
    assert after["status"]["last_push_at"] is not None


def test_record_push_result_accumulates_sent_total():
    import wef_bindings
    bnd = _create_basic()
    wef_bindings.record_push_result(bnd["id"], sent=5, status_code=200)
    wef_bindings.record_push_result(bnd["id"], sent=3, status_code=202)
    after = wef_bindings.get_binding(bnd["id"])
    assert after["status"]["sent_total"] == 8


def test_record_push_result_captures_error_message():
    import wef_bindings
    bnd = _create_basic()
    wef_bindings.record_push_result(
        bnd["id"], sent=0, status_code=503, error="WEC down",
    )
    after = wef_bindings.get_binding(bnd["id"])
    assert after["status"]["last_error"] == "WEC down"
    assert after["status"]["last_status_code"] == 503


# ── Delete ────────────────────────────────────────────────────────────

def test_delete_binding_removes_record():
    import wef_bindings
    bnd = _create_basic()
    assert wef_bindings.delete_binding(bnd["id"]) is True
    assert wef_bindings.get_binding(bnd["id"]) is None


def test_delete_binding_returns_false_for_unknown_id():
    import wef_bindings
    assert wef_bindings.delete_binding("wef-nope") is False


def test_delete_binding_also_removes_cert_bundle():
    """A mTLS binding may carry an encrypted PEM at
    ``<CERT_STORAGE_DIR>/<binding_id>.pem.enc``. Deleting the binding
    must also delete that file so a re-created binding with the same
    id (unlikely but possible) starts clean."""
    import wef_bindings
    from sources import windows_event_forwarding as wef
    bnd = _create_basic()
    pem = (
        b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
        b"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"
    )
    wef.save_cert_bundle(bnd["id"], pem)
    assert wef.load_cert_bundle(bnd["id"]) == pem
    wef_bindings.delete_binding(bnd["id"])
    assert wef.load_cert_bundle(bnd["id"]) is None


# ── Effective config for the runner ───────────────────────────────────

def test_effective_config_strips_internal_fields():
    """``effective_config(bid)`` returns the dict the WEFEmitter
    expects — no metadata, no status, no name. The runner consumes
    this directly so it stays decoupled from the storage shape."""
    import wef_bindings
    bnd = _create_basic()
    cfg = wef_bindings.effective_config(bnd["id"])
    assert "target_host" in cfg
    assert "auth_method" in cfg
    # Storage-only keys must not leak.
    assert "name" not in cfg
    assert "enabled" not in cfg
    assert "status" not in cfg
    assert "created_at" not in cfg
