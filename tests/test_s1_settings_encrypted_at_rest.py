"""s1_detection_library — at-rest encryption + silent migration tests.

Verifies that:
- ``save_settings`` writes the ``api_token`` as a Fernet token (never plaintext).
- ``get_settings`` transparently decrypts.
- A legacy plaintext ``s1_settings.json`` (from pre-v5.1) is silently
  migrated to ciphertext on the next ``save_settings`` call.
- A key-misconfig surfaces as ``api_token == ""`` (no 500) so the UI can
  prompt the operator to re-enter.
"""

from __future__ import annotations

import importlib
import json

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def isolated_s1(tmp_path, monkeypatch):
    """Reload :mod:`crypto` and :mod:`s1_detection_library` against a
    fresh ``APIGENIE_DATA_ROOT`` so each test starts from no settings."""
    monkeypatch.setenv("APIGENIE_DATA_ROOT", str(tmp_path))
    monkeypatch.delenv("APIGENIE_SECRET_KEY", raising=False)
    import crypto                                     # noqa: PLC0415
    import s1_detection_library as s1                 # noqa: PLC0415
    importlib.reload(crypto)
    importlib.reload(s1)
    crypto._reset_for_tests()
    yield s1, crypto, tmp_path
    crypto._reset_for_tests()


def _read_settings_file(tmp_path) -> dict:
    f = tmp_path / "s1_settings.json"
    assert f.is_file(), "s1_settings.json should exist after save_settings()"
    return json.loads(f.read_text())


class TestEncryptedAtRest:
    def test_token_is_ciphertext_on_disk(self, isolated_s1):
        s1, crypto, tmp_path = isolated_s1
        s1.save_settings({"console_url": "https://demo.sentinelone.net",
                          "api_token": "real-mgmt-api-token-xyz"})
        on_disk = _read_settings_file(tmp_path)
        assert on_disk["console_url"] == "https://demo.sentinelone.net"   # plain
        assert on_disk["api_token"] != "real-mgmt-api-token-xyz"          # encrypted
        assert crypto.is_encrypted(on_disk["api_token"])

    def test_get_settings_returns_plaintext(self, isolated_s1):
        s1, _, _ = isolated_s1
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "tok-abc"})
        loaded = s1.get_settings()
        assert loaded["api_token"] == "tok-abc"
        assert loaded["console_url"] == "https://x.sentinelone.net"

    def test_empty_token_round_trip(self, isolated_s1):
        s1, _, tmp_path = isolated_s1
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": ""})
        on_disk = _read_settings_file(tmp_path)
        assert on_disk["api_token"] == ""                              # no spurious blob
        assert s1.get_settings()["api_token"] == ""

    def test_save_without_overwriting_token(self, isolated_s1):
        """Updating only the URL must preserve the previously-saved token."""
        s1, _, _ = isolated_s1
        s1.save_settings({"console_url": "https://a.sentinelone.net",
                          "api_token": "tok-keepme"})
        s1.save_settings({"console_url": "https://b.sentinelone.net"})
        loaded = s1.get_settings()
        assert loaded["console_url"] == "https://b.sentinelone.net"
        assert loaded["api_token"] == "tok-keepme"


class TestSilentMigration:
    def test_legacy_plaintext_is_migrated_on_next_save(self, isolated_s1):
        """A pre-v5.1 settings file with a plaintext ``api_token`` must
        keep working: get_settings returns the plaintext as-is, and the
        next save_settings re-encrypts it."""
        s1, crypto, tmp_path = isolated_s1
        legacy = {"console_url": "https://legacy.sentinelone.net",
                  "api_token": "PLAINTEXT-LEGACY-TOKEN"}
        (tmp_path / "s1_settings.json").write_text(json.dumps(legacy))

        # Read works against legacy plaintext (try_decrypt passthrough)
        loaded = s1.get_settings()
        assert loaded["api_token"] == "PLAINTEXT-LEGACY-TOKEN"

        # Triggering a save (even with no field changes) re-encrypts.
        s1.save_settings({})
        on_disk = _read_settings_file(tmp_path)
        assert crypto.is_encrypted(on_disk["api_token"])
        assert s1.get_settings()["api_token"] == "PLAINTEXT-LEGACY-TOKEN"


class TestKeyMisconfig:
    def test_wrong_key_returns_empty_token(self, isolated_s1, tmp_path, monkeypatch):
        """If APIGENIE_SECRET_KEY was rotated incorrectly (the key file
        / env var doesn't match the key the existing ciphertext was
        encrypted with), get_settings must return an empty token so the
        UI can prompt re-entry, NOT raise a 500."""
        s1, crypto, _ = isolated_s1
        s1.save_settings({"console_url": "https://x.sentinelone.net",
                          "api_token": "doomed-by-rotation"})
        # Rotate: force a different key
        (tmp_path / "secret.key").write_bytes(Fernet.generate_key())
        crypto._reset_for_tests()

        loaded = s1.get_settings()
        assert loaded["api_token"] == ""                               # graceful
        assert loaded["console_url"] == "https://x.sentinelone.net"    # URL survives
