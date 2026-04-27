#!/usr/bin/env python3
"""Generate a PBKDF2-hashed admin password for ADMIN_PASSWORD_HASH in .env.

Usage:
    python3 scripts/hash_password.py             # prompts interactively
    python3 scripts/hash_password.py --plain p   # one-shot (NOT for shell history)

Hash format:
    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>

Verification is in admin.py; both must agree on parameters.

Why PBKDF2 and not scrypt? Because hashlib.scrypt requires an OpenSSL build
with scrypt support, which LibreSSL (used by stock macOS Python) lacks.
PBKDF2 is in every stdlib build, no exceptions.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import secrets
import sys

# OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.
ALGO = "sha256"
ITERATIONS = 600_000
DKLEN = 32
SALT_BYTES = 16


def hash_password(plain: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(ALGO, plain.encode("utf-8"), salt, ITERATIONS, dklen=DKLEN)
    return f"pbkdf2_{ALGO}${ITERATIONS}${salt.hex()}${dk.hex()}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plain", help="plaintext password (non-interactive; avoid in shell history)")
    args = ap.parse_args()

    if args.plain:
        plain = args.plain
    else:
        plain = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm: ")
        if plain != confirm:
            print("Passwords do not match.", file=sys.stderr)
            return 1
    if not plain:
        print("Password cannot be empty.", file=sys.stderr)
        return 1

    print(hash_password(plain))
    return 0


if __name__ == "__main__":
    sys.exit(main())
