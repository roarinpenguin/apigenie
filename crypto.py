"""Server-key Fernet wrapper for at-rest encryption of admin-global secrets.

v5.1 Phase B (Tier 2). Centralises the key-sourcing and encrypt / decrypt
plumbing so the rest of the codebase can call ``crypto.encrypt("…")`` /
``crypto.decrypt(blob)`` without thinking about key management.

Threat model
============

- **Protects against**: a third party reading ``data/`` off the host disk
  (laptop sync to Google Drive, stolen EC2 EBS snapshot, leaked SQLite
  backup). The ciphertext is meaningless without ``APIGENIE_SECRET_KEY``.
- **Does NOT protect against**: a running ApiGenie process being asked
  to decrypt — by design, the server needs the cleartext to talk to S1.
  Anyone with full filesystem read on a live container can grab both the
  key and the ciphertext and decrypt offline.

Use this for fields the server itself must read autonomously (i.e. NOT
user-typed secrets like per-user S1 tokens — those live in the browser,
see v5.1 Phase A / Tier 4).

Key sourcing
============

Priority order:

1. ``APIGENIE_SECRET_KEY`` environment variable (a urlsafe-base64 Fernet
   key, i.e. 44 chars). This is the recommended path in production —
   inject via Docker secrets, AWS SSM, or whatever your platform offers.
2. Fallback: ``${APIGENIE_DATA_ROOT}/secret.key`` (chmod 0600). Generated
   on first call if absent. **Operators must back this file up** —
   losing it means every encrypted blob in ``data/`` becomes unreadable.

When the fallback path is used we log a single ``WARNING`` so operators
notice they should promote the key to an env var (and back it up).

Auto-migration
==============

``is_encrypted()`` recognises Fernet tokens (they always start with
``gAAAAA`` — the version byte + base64 padding). Callers can use this
to detect legacy plaintext blobs and re-encrypt them transparently on
the next write, with no downtime / explicit migration script.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)


# ── Key sourcing ─────────────────────────────────────────────────────────────

_KEY_ENV_VAR = "APIGENIE_SECRET_KEY"
_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
_KEY_FILE = _DATA_ROOT / "secret.key"

_LOCK = threading.Lock()
_FERNET: Fernet | None = None


def _load_or_create_key() -> bytes:
    """Resolve the Fernet key once, caching the resulting cipher.

    Order: env var → key file → generate new key file (last resort).
    """
    env = os.getenv(_KEY_ENV_VAR, "").strip()
    if env:
        # Light validation: Fernet keys are 44 chars of urlsafe-base64
        # ending in '='. Wrong format → fail loud immediately rather
        # than corrupt every blob we write.
        try:
            Fernet(env.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                f"{_KEY_ENV_VAR} is set but not a valid Fernet key "
                f"(expect 44 urlsafe-base64 chars from Fernet.generate_key()): {exc}"
            ) from exc
        return env.encode("ascii")

    if _KEY_FILE.is_file():
        return _KEY_FILE.read_bytes().strip()

    # Fallback: generate one. Loud warning because losing this file ==
    # losing every encrypted blob in data/.
    _DATA_ROOT.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    _KEY_FILE.write_bytes(key)
    try:
        os.chmod(_KEY_FILE, 0o600)
    except OSError:                     # pragma: no cover — Windows / mounted FS
        pass
    log.warning(
        "Generated new ApiGenie secret key at %s. BACK THIS UP — losing it "
        "renders every encrypted at-rest blob (admin S1 token, future "
        "encrypted columns) permanently unreadable. Recommended: promote "
        "to the %s environment variable.",
        _KEY_FILE, _KEY_ENV_VAR,
    )
    return key


def _cipher() -> Fernet:
    """Thread-safe lazy-load of the Fernet cipher."""
    global _FERNET
    if _FERNET is None:
        with _LOCK:
            if _FERNET is None:
                _FERNET = Fernet(_load_or_create_key())
    return _FERNET


def _reset_for_tests() -> None:
    """Test hook — clear the cached cipher so a fresh key-file path is
    picked up. Never called from production code."""
    global _FERNET
    with _LOCK:
        _FERNET = None


# ── Public API ───────────────────────────────────────────────────────────────

# Fernet tokens always start with this prefix (version byte 0x80 +
# base64 padding). Used to distinguish ciphertext from legacy plaintext
# during the silent migration.
_FERNET_PREFIX = "gAAAAA"


def is_encrypted(blob: str | bytes | None) -> bool:
    """True if *blob* looks like a Fernet token. Used by callers that
    need to migrate legacy plaintext blobs on read."""
    if not blob:
        return False
    if isinstance(blob, bytes):
        try:
            blob = blob.decode("ascii")
        except UnicodeDecodeError:
            return False
    return blob.startswith(_FERNET_PREFIX)


def encrypt(plain: str) -> str:
    """Encrypt *plain* (UTF-8 string) → urlsafe-base64 Fernet token (str).

    Empty / falsy inputs round-trip as empty strings — saves callers
    from special-casing "no secret set yet"."""
    if not plain:
        return ""
    return _cipher().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt(blob: str) -> str:
    """Decrypt *blob* → UTF-8 string. Empty/falsy → empty string.

    Raises ``InvalidToken`` if the blob is malformed or the key doesn't
    match (typically: wrong / rotated ``APIGENIE_SECRET_KEY``)."""
    if not blob:
        return ""
    return _cipher().decrypt(blob.encode("ascii")).decode("utf-8")


def try_decrypt(blob: str) -> str:
    """Best-effort decrypt — returns *blob* unchanged if it doesn't look
    encrypted (legacy plaintext) or if decryption fails. Use this in
    read paths during the silent migration so a transient key-misconfig
    doesn't render the UI inert."""
    if not blob:
        return ""
    if not is_encrypted(blob):
        return blob                     # legacy plaintext — caller should re-save
    try:
        return decrypt(blob)
    except InvalidToken:
        log.error(
            "Fernet token failed to decrypt with the current key. "
            "Has %s changed? Returning empty string so the UI can prompt "
            "the operator to re-enter.", _KEY_ENV_VAR,
        )
        return ""


__all__ = [
    "encrypt",
    "decrypt",
    "try_decrypt",
    "is_encrypted",
    "InvalidToken",
]
