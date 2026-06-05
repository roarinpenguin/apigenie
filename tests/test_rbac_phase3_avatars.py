"""RBAC Phase 3 — user avatars (TDD).

A small pure-image helper (`avatars.make_circle_avatar`) produces a 250×250
circular RGBA PNG from any common image input. It must raise `ValueError` on
unreadable input. The on-disk store (`avatars.save_for_user` / `load_for_user`)
keeps each user's avatar under the apigenie data dir and is wired to the
accounts row via `avatar_path`.
"""
from __future__ import annotations

import io

import pytest


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sample_png(size=(400, 300), color=(120, 60, 180)) -> bytes:
    """Build a small in-memory PNG to feed the helper."""
    from PIL import Image
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _sample_jpeg(size=(640, 480), color=(20, 200, 40)) -> bytes:
    from PIL import Image
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


# ── Pure helper ──────────────────────────────────────────────────────────────

class TestMakeCircleAvatar:
    def test_png_input_returns_250x250_rgba_png(self):
        import avatars
        from PIL import Image

        out = avatars.make_circle_avatar(_sample_png())
        assert isinstance(out, bytes) and len(out) > 200
        img = Image.open(io.BytesIO(out))
        assert img.format == "PNG"
        assert img.size == (250, 250)
        assert img.mode == "RGBA"

    def test_jpeg_input_returns_250x250_rgba_png(self):
        import avatars
        from PIL import Image

        out = avatars.make_circle_avatar(_sample_jpeg())
        img = Image.open(io.BytesIO(out))
        assert img.size == (250, 250)
        assert img.mode == "RGBA"

    def test_corner_pixel_is_transparent_center_is_opaque(self):
        """The circular mask must clip corners (alpha=0) and keep the centre opaque."""
        import avatars
        from PIL import Image

        img = Image.open(io.BytesIO(avatars.make_circle_avatar(_sample_png())))
        assert img.getpixel((0, 0))[3] == 0          # top-left clipped
        assert img.getpixel((249, 249))[3] == 0      # bottom-right clipped
        assert img.getpixel((125, 125))[3] == 255    # centre opaque

    def test_invalid_bytes_raise_value_error(self):
        import avatars
        with pytest.raises(ValueError):
            avatars.make_circle_avatar(b"not an image at all")

    def test_empty_input_raises_value_error(self):
        import avatars
        with pytest.raises(ValueError):
            avatars.make_circle_avatar(b"")


# ── Disk store + accounts wiring ─────────────────────────────────────────────

class TestSaveAndLoad:
    def test_save_for_user_writes_file_and_updates_avatar_path(self, make_user):
        import accounts
        import avatars

        u = make_user("alice")
        path = avatars.save_for_user(u["id"], _sample_png())
        assert path.exists()
        assert path.is_file()
        # accounts row points to it
        updated = accounts.get_user(u["id"])
        assert updated["avatar_path"] == str(path)

    def test_load_for_user_returns_bytes(self, make_user):
        import avatars

        u = make_user("alice")
        avatars.save_for_user(u["id"], _sample_png())
        data = avatars.load_for_user(u["id"])
        assert data is not None and len(data) > 200
        # Round-trips back to a PNG
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        assert img.format == "PNG" and img.size == (250, 250)

    def test_load_returns_none_when_no_avatar(self, make_user):
        import avatars
        u = make_user("alice")
        assert avatars.load_for_user(u["id"]) is None

    def test_save_replaces_previous_avatar(self, make_user):
        import avatars

        u = make_user("alice")
        avatars.save_for_user(u["id"], _sample_png(color=(255, 0, 0)))
        first = avatars.load_for_user(u["id"])
        avatars.save_for_user(u["id"], _sample_png(color=(0, 0, 255)))
        second = avatars.load_for_user(u["id"])
        assert first != second

    def test_delete_for_user_removes_file_and_clears_path(self, make_user):
        import accounts
        import avatars

        u = make_user("alice")
        path = avatars.save_for_user(u["id"], _sample_png())
        assert avatars.delete_for_user(u["id"]) is True
        assert not path.exists()
        assert accounts.get_user(u["id"])["avatar_path"] in (None, "")

    def test_delete_when_no_avatar_returns_false(self, make_user):
        import avatars
        u = make_user("alice")
        assert avatars.delete_for_user(u["id"]) is False

    def test_save_for_unknown_user_raises(self):
        import avatars
        with pytest.raises(ValueError, match="Unknown user"):
            avatars.save_for_user("usr_does_not_exist", _sample_png())

    def test_oversize_input_rejected(self):
        """A safety guard prevents DoS via huge uploads — > 5 MB rejected."""
        import avatars
        big = b"\x89PNG\r\n\x1a\n" + b"\x00" * (5 * 1024 * 1024 + 10)
        with pytest.raises(ValueError, match="too large"):
            avatars.make_circle_avatar(big)
