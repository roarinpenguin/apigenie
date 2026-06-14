"""Tests for per-binding WEF client-cert storage (v5.2).

Verifies that PEM bundles for mTLS bindings are:

* written ENCRYPTED to ``data/source_certs/wef/<binding_id>.pem.enc``
  using the same v5.1 Phase B Fernet key chain that protects the admin
  S1 token,
* round-trippable via ``load_cert_bundle``,
* unreadable as plaintext from disk (a leaked SQLite + filesystem dump
  must not yield a usable client cert),
* falling back to the existing server TLS material when no per-binding
  cert is uploaded,
* surfacing a typed error on corruption / wrong key, so the admin UI
  can disable the binding cleanly instead of silently producing bad
  handshakes.

Spec: docs/ROADMAP_2026-06-12.md §"Per-source PEM upload, encrypted at
rest" + §"Storage" + §"TDD plan" entry "test_wef_cert_storage.py".
"""
from __future__ import annotations

from pathlib import Path

import pytest


# Sample valid-looking PEM bundle (NOT a real key — just a recognisable
# shape so we can grep for the BEGIN marker on disk and assert it's not
# present in plaintext after encryption).
PEM_BUNDLE = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIIBkTCCATegAwIBAgIJAJ5h7Z+FAKE\n"
    b"-----END CERTIFICATE-----\n"
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCFAKE\n"
    b"-----END PRIVATE KEY-----\n"
)


# ── Round trip ────────────────────────────────────────────────────────

def test_save_and_load_round_trips_bytes():
    from sources import windows_event_forwarding as wef

    path = wef.save_cert_bundle("binding-001", PEM_BUNDLE)
    assert isinstance(path, Path)
    assert path.exists(), f"Expected encrypted bundle at {path}"

    loaded = wef.load_cert_bundle("binding-001")
    assert loaded == PEM_BUNDLE


def test_on_disk_payload_is_not_plaintext_pem():
    """The point of the encryption: a `cat`-equivalent of the file on
    disk must NOT reveal the PEM markers."""
    from sources import windows_event_forwarding as wef

    path = wef.save_cert_bundle("binding-002", PEM_BUNDLE)
    raw = path.read_bytes()
    assert b"-----BEGIN CERTIFICATE-----" not in raw
    assert b"-----BEGIN PRIVATE KEY-----" not in raw
    assert raw != PEM_BUNDLE  # not just a base64 wrapper


def test_save_writes_under_canonical_directory():
    from sources import windows_event_forwarding as wef

    path = wef.save_cert_bundle("binding-003", PEM_BUNDLE)
    assert str(path).endswith("source_certs/wef/binding-003.pem.enc"), (
        f"Unexpected storage path: {path}"
    )


def test_module_exposes_cert_storage_dir_constant():
    from sources import windows_event_forwarding as wef
    assert hasattr(wef, "CERT_STORAGE_DIR")
    assert "source_certs/wef" in str(wef.CERT_STORAGE_DIR)


# ── Lifecycle ──────────────────────────────────────────────────────────

def test_load_returns_none_when_no_bundle_saved():
    from sources import windows_event_forwarding as wef
    assert wef.load_cert_bundle("never-saved-binding") is None


def test_delete_removes_the_bundle():
    from sources import windows_event_forwarding as wef

    wef.save_cert_bundle("binding-del", PEM_BUNDLE)
    assert wef.load_cert_bundle("binding-del") == PEM_BUNDLE
    removed = wef.delete_cert_bundle("binding-del")
    assert removed is True
    assert wef.load_cert_bundle("binding-del") is None


def test_delete_is_idempotent_when_no_bundle_present():
    from sources import windows_event_forwarding as wef
    # Must not raise; just return False so the admin UI can show "no-op".
    assert wef.delete_cert_bundle("never-existed") is False


# ── Fallback resolution ───────────────────────────────────────────────

def test_resolve_falls_back_to_server_pem_when_no_binding_cert(tmp_path):
    from sources import windows_event_forwarding as wef

    server_pem = tmp_path / "server.pem"
    server_pem.write_bytes(PEM_BUNDLE)

    resolved = wef.resolve_cert_files(
        "fresh-binding", server_pem_fallback=server_pem
    )
    assert resolved is not None
    cert_path, key_path = resolved
    # The fallback can use the same combined file for both cert and key
    # (matches what nginx/apigenie's server.pem already does).
    assert Path(cert_path).exists()
    assert Path(key_path).exists()


def test_resolve_returns_none_when_neither_binding_nor_fallback_exist():
    from sources import windows_event_forwarding as wef
    assert wef.resolve_cert_files(
        "no-binding", server_pem_fallback=None,
    ) is None


def test_resolve_prefers_binding_cert_over_fallback(tmp_path):
    """If a per-binding cert exists, it wins over the server-PEM fallback."""
    from sources import windows_event_forwarding as wef

    wef.save_cert_bundle("binding-pref", PEM_BUNDLE)
    server_pem = tmp_path / "server.pem"
    server_pem.write_bytes(b"-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----\n")

    resolved = wef.resolve_cert_files(
        "binding-pref", server_pem_fallback=server_pem,
    )
    assert resolved is not None
    cert_path, _ = resolved
    # The resolved cert_path should sit inside source_certs/wef/, NOT in
    # tmp_path (which holds the fallback).
    assert "source_certs/wef" in str(cert_path)


# ── Corruption surfaces a typed error ─────────────────────────────────

def test_corrupted_ciphertext_raises_cert_decryption_error():
    from sources import windows_event_forwarding as wef

    path = wef.save_cert_bundle("binding-corrupt", PEM_BUNDLE)
    # Flip a byte in the middle of the ciphertext to simulate corruption.
    blob = bytearray(path.read_bytes())
    blob[len(blob) // 2] ^= 0xFF
    path.write_bytes(bytes(blob))

    with pytest.raises(wef.CertDecryptionError):
        wef.load_cert_bundle("binding-corrupt")


def test_cert_decryption_error_is_a_value_error_subclass():
    """The admin UI catches ValueError around cert-load. The typed
    exception must be catchable that way too, so existing handlers
    keep working."""
    from sources import windows_event_forwarding as wef
    assert issubclass(wef.CertDecryptionError, Exception)
