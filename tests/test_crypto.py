"""crypto.py — Fernet wrapper unit tests.

Exercises the three execution paths of ``_load_or_create_key``
(env-var, key-file, auto-generate), the encrypt/decrypt round-trip,
``is_encrypted`` detection, and the ``try_decrypt`` graceful-failure
behaviour that the silent migration in :mod:`s1_detection_library`
depends on.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def isolated_crypto(tmp_path, monkeypatch):
    """Reload :mod:`crypto` with a fresh ``APIGENIE_DATA_ROOT`` so
    ``data/secret.key`` doesn't leak between tests.

    Returns the freshly-imported module."""
    monkeypatch.setenv("APIGENIE_DATA_ROOT", str(tmp_path))
    monkeypatch.delenv("APIGENIE_SECRET_KEY", raising=False)
    import crypto                                     # noqa: PLC0415
    importlib.reload(crypto)                          # re-evaluate _DATA_ROOT
    crypto._reset_for_tests()
    yield crypto
    crypto._reset_for_tests()


# ── Key sourcing ─────────────────────────────────────────────────────────────


class TestKeySourcing:
    def test_env_var_takes_priority(self, isolated_crypto, monkeypatch, tmp_path):
        key = Fernet.generate_key().decode("ascii")
        monkeypatch.setenv("APIGENIE_SECRET_KEY", key)
        # Even with a (different) key file present, the env var wins.
        (tmp_path / "secret.key").write_bytes(Fernet.generate_key())
        # Reload to re-read env / data root
        importlib.reload(isolated_crypto)
        isolated_crypto._reset_for_tests()
        loaded = isolated_crypto._load_or_create_key().decode("ascii")
        assert loaded == key

    def test_key_file_used_when_no_env(self, isolated_crypto, tmp_path):
        key = Fernet.generate_key()
        (tmp_path / "secret.key").write_bytes(key)
        importlib.reload(isolated_crypto)
        isolated_crypto._reset_for_tests()
        loaded = isolated_crypto._load_or_create_key()
        assert loaded.strip() == key

    def test_auto_generates_and_persists(self, isolated_crypto, tmp_path):
        key_file = tmp_path / "secret.key"
        assert not key_file.exists()
        key = isolated_crypto._load_or_create_key()
        assert key_file.is_file()
        # Permissions tightened to 0600 where the filesystem supports it.
        if os.name == "posix":
            assert (key_file.stat().st_mode & 0o777) == 0o600
        # Second call reads the same key — does not regenerate.
        again = isolated_crypto._load_or_create_key()
        assert key == again

    def test_invalid_env_key_fails_loud(self, isolated_crypto, monkeypatch):
        monkeypatch.setenv("APIGENIE_SECRET_KEY", "not-a-valid-fernet-key")
        importlib.reload(isolated_crypto)
        isolated_crypto._reset_for_tests()
        with pytest.raises(RuntimeError, match="not a valid Fernet key"):
            isolated_crypto._load_or_create_key()


# ── Round-trip ───────────────────────────────────────────────────────────────


class TestRoundTrip:
    def test_encrypt_decrypt_basic(self, isolated_crypto):
        ct = isolated_crypto.encrypt("hello world")
        assert ct != "hello world"
        assert isolated_crypto.is_encrypted(ct)
        assert isolated_crypto.decrypt(ct) == "hello world"

    def test_encrypt_empty_is_empty(self, isolated_crypto):
        assert isolated_crypto.encrypt("") == ""
        assert isolated_crypto.decrypt("") == ""

    def test_encrypt_is_nondeterministic(self, isolated_crypto):
        """Fernet uses random IVs — same plaintext → different ciphertexts."""
        a = isolated_crypto.encrypt("same input")
        b = isolated_crypto.encrypt("same input")
        assert a != b
        assert isolated_crypto.decrypt(a) == isolated_crypto.decrypt(b) == "same input"

    def test_realistic_s1_token(self, isolated_crypto):
        """450-char S1 Management API token — matches the size of the
        token we found on the user's local DB."""
        token = "A" * 450
        ct = isolated_crypto.encrypt(token)
        assert isolated_crypto.decrypt(ct) == token


# ── is_encrypted detection ───────────────────────────────────────────────────


class TestIsEncrypted:
    def test_fernet_token_detected(self, isolated_crypto):
        ct = isolated_crypto.encrypt("anything")
        assert isolated_crypto.is_encrypted(ct)

    def test_plaintext_not_detected(self, isolated_crypto):
        assert not isolated_crypto.is_encrypted("plain-s1-token-xyz")
        assert not isolated_crypto.is_encrypted("eyJhbGc")        # JWT prefix
        assert not isolated_crypto.is_encrypted("")
        assert not isolated_crypto.is_encrypted(None)

    def test_bytes_input(self, isolated_crypto):
        ct = isolated_crypto.encrypt("x").encode("ascii")
        assert isolated_crypto.is_encrypted(ct)
        assert not isolated_crypto.is_encrypted(b"\x80\x81\x82")  # non-ascii


# ── try_decrypt: graceful failure ────────────────────────────────────────────


class TestTryDecrypt:
    def test_plaintext_passthrough(self, isolated_crypto):
        """Legacy plaintext blobs round-trip unchanged so the caller can
        re-save them encrypted on the next write."""
        assert isolated_crypto.try_decrypt("legacy-plain-token") == "legacy-plain-token"
        assert isolated_crypto.try_decrypt("") == ""

    def test_ciphertext_decrypts(self, isolated_crypto):
        ct = isolated_crypto.encrypt("secret-x")
        assert isolated_crypto.try_decrypt(ct) == "secret-x"

    def test_wrong_key_returns_empty(self, isolated_crypto, tmp_path, monkeypatch):
        """If a token was encrypted with key A and we now load key B,
        try_decrypt must return '' (UI prompts re-entry) — never raise."""
        ct_with_key_a = isolated_crypto.encrypt("secret-y")
        # Force a key rotation by writing a new key file and resetting cache.
        (tmp_path / "secret.key").write_bytes(Fernet.generate_key())
        isolated_crypto._reset_for_tests()
        assert isolated_crypto.try_decrypt(ct_with_key_a) == ""
