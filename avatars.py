"""User avatars — 250×250 circular RGBA PNG.

The pure helper `make_circle_avatar` decodes an uploaded image, centre-square
crops it, resizes to 250×250 using Lanczos, then applies a circular alpha mask.

The on-disk store (`save_for_user`, `load_for_user`, `delete_for_user`) keeps
each user's processed avatar under `APIGENIE_DATA_DIR/avatars/{uid}.png` and
keeps the accounts.users.avatar_path column in sync.
"""
from __future__ import annotations

import io
import logging
import os
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageOps

import accounts

log = logging.getLogger(__name__)

# Public sizing constant — 250 is per the RBAC Phase 3 spec.
AVATAR_SIZE = 250

# Reject obviously oversized uploads up-front; 5 MB is generous for a square
# 250 px portrait and prevents trivial DoS via huge multipart bodies.
_MAX_INPUT_BYTES = 5 * 1024 * 1024

_DATA_DIR = Path(os.environ.get("APIGENIE_DATA_DIR", "/var/lib/apigenie"))
_AVATARS_DIR = _DATA_DIR / "avatars"


# ── Pure image processing ─────────────────────────────────────────────────────

def make_circle_avatar(data: bytes) -> bytes:
    """Decode → centre-crop square → resize-to-250 → circular alpha → PNG bytes.

    Raises ValueError on empty / oversize / undecodable input. Honours EXIF
    orientation. Combines any pre-existing alpha channel with the circular
    mask so transparent inputs stay transparent.
    """
    if not data:
        raise ValueError("Empty avatar input")
    if len(data) > _MAX_INPUT_BYTES:
        raise ValueError(f"Avatar input too large: {len(data)} bytes > {_MAX_INPUT_BYTES}")
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:
        raise ValueError(f"Cannot decode image: {exc}") from exc

    # Respect phone EXIF orientation before any cropping.
    img = ImageOps.exif_transpose(img).convert("RGBA")
    # Centre-square crop + Lanczos resize in one shot.
    img = ImageOps.fit(img, (AVATAR_SIZE, AVATAR_SIZE), Image.Resampling.LANCZOS)

    # Circular alpha mask.
    mask = Image.new("L", (AVATAR_SIZE, AVATAR_SIZE), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, AVATAR_SIZE - 1, AVATAR_SIZE - 1), fill=255)
    # Combine with the source's alpha so input transparency is preserved.
    src_alpha = img.split()[3]
    combined = ImageChops.multiply(mask, src_alpha)
    img.putalpha(combined)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


# ── Disk store wired to accounts.avatar_path ─────────────────────────────────

def _path_for(uid: str) -> Path:
    return _AVATARS_DIR / f"{uid}.png"


def save_for_user(uid: str, data: bytes) -> Path:
    """Process and persist a user's avatar. Returns the on-disk path."""
    if accounts.get_user(uid) is None:
        raise ValueError("Unknown user")
    processed = make_circle_avatar(data)
    _AVATARS_DIR.mkdir(parents=True, exist_ok=True)
    path = _path_for(uid)
    tmp = path.with_suffix(".png.tmp")
    tmp.write_bytes(processed)
    tmp.replace(path)
    accounts.update_user(uid, avatar_path=str(path))
    return path


def load_for_user(uid: str) -> bytes | None:
    """Return processed avatar bytes, or None if the user has none."""
    user = accounts.get_user(uid)
    if not user:
        return None
    raw = user.get("avatar_path") or str(_path_for(uid))
    path = Path(raw)
    if not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError as exc:
        log.warning("avatar read failed for %s: %s", uid, exc)
        return None


def delete_for_user(uid: str) -> bool:
    """Remove the avatar file and clear accounts.avatar_path. False if absent."""
    user = accounts.get_user(uid)
    if not user:
        return False
    raw = user.get("avatar_path") or str(_path_for(uid))
    path = Path(raw)
    if not path.is_file():
        return False
    try:
        path.unlink()
    except OSError as exc:
        log.warning("avatar delete failed for %s: %s", uid, exc)
        return False
    accounts.update_user(uid, avatar_path="")
    return True
