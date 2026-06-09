"""pytest configuration for apigenie.

Redirects ALL storage paths to an isolated tmp dir BEFORE any project module
is imported so tests never touch the production /var/lib/apigenie volume. Each
test gets a clean DB + JSON tree via the autouse fixture below.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# 1) Env redirection MUST happen before any project import. Project modules
#    read these into module-level constants at import time, so the order
#    matters.
_TMPROOT = Path(tempfile.mkdtemp(prefix="apigenie-test-"))
# Three different env var names are read by different modules in this codebase
# (legacy reasons). Set all of them.
os.environ["APIGENIE_DATA_DIR"] = str(_TMPROOT)     # accounts.py / telemetry.py / replay.py
os.environ["APIGENIE_DATA"] = str(_TMPROOT)         # bans.py / request_log.py / intrusions.py
os.environ["APIGENIE_DATA_ROOT"] = str(_TMPROOT)    # profiles.py / detection_rules.py / log_pusher.py / …
os.environ["APIGENIE_DB"] = str(_TMPROOT / "apigenie.db")
# Keep admin password files off the production volume too.
os.environ.setdefault("ADMIN_PASSWORD_FILE", str(_TMPROOT / "admin_pass"))
os.environ.setdefault("USER_PASSWORD_FILE", str(_TMPROOT / "user_pass"))
os.environ.setdefault("INVESTIGATE_PASSWORD_FILE", str(_TMPROOT / "investigate_pass"))

# 2) Make the project importable from anywhere pytest is invoked.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Give each test a fresh DB file + profile/detection storage tree."""
    import accounts
    import detection_rules
    import profiles

    # --- accounts: per-test SQLite file ---
    db = tmp_path / "apigenie.db"
    monkeypatch.setattr(accounts, "DB_PATH", db)
    if accounts._conn is not None:
        try:
            accounts._conn.close()
        except Exception:
            pass
        accounts._conn = None
    accounts.init_db()

    # --- profiles: per-test JSON tree ---
    pf_root = tmp_path / "profiles_root"
    pf_root.mkdir()
    (pf_root / "profiles").mkdir()
    monkeypatch.setattr(profiles, "_DATA_ROOT", pf_root)
    monkeypatch.setattr(profiles, "PROFILES_DIR", pf_root / "profiles")
    monkeypatch.setattr(profiles, "_BINDINGS_FILE", pf_root / "source_profiles.json")
    monkeypatch.setattr(profiles, "_INTENSITY_FILE", pf_root / "source_intensity.json")
    profiles.set_current_user(None)

    # --- detection_rules: per-test JSON file ---
    monkeypatch.setattr(detection_rules, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(detection_rules, "_RULES_FILE", tmp_path / "detection_rules.json")
    detection_rules._last_fired.clear()

    # --- log_pusher: per-test push profiles file + certs dir ---
    import log_pusher
    monkeypatch.setattr(log_pusher, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(log_pusher, "_PROFILES_FILE", tmp_path / "push_profiles.json")
    monkeypatch.setattr(log_pusher, "_CERTS_DIR", tmp_path / "push_certs")
    (tmp_path / "push_certs").mkdir(exist_ok=True)

    # --- alert_push: per-test alert push profiles file + history ring buffer ---
    try:
        import alert_push
        monkeypatch.setattr(alert_push, "_DATA_ROOT", tmp_path)
        monkeypatch.setattr(alert_push, "_PROFILES_FILE", tmp_path / "alert_push_profiles.json")
        # The history is in-memory; wipe it so tests start from a clean slate.
        alert_push.clear_history()
    except ImportError:
        # P4.1 only — module appears in P4.2.
        pass

    # --- avatars: per-test on-disk store ---
    try:
        import avatars
        monkeypatch.setattr(avatars, "_DATA_DIR", tmp_path)
        monkeypatch.setattr(avatars, "_AVATARS_DIR", tmp_path / "avatars")
    except ImportError:
        # Pillow may not be installed yet during early TDD; avatar tests will
        # simply skip themselves when they try to import avatars.
        pass

    yield

    if accounts._conn is not None:
        try:
            accounts._conn.close()
        except Exception:
            pass
        accounts._conn = None


@pytest.fixture
def make_user():
    """Factory: create a user and return its dict (with id).

    Extra kwargs (entitlement_id, confirmed, ...) are forwarded to
    accounts.create_user so tests can attach RBAC entitlements at
    creation time.
    """
    import accounts

    def _make(username: str = "alice", *, is_admin: bool = False, **kwargs) -> dict:
        return accounts.create_user(
            username=username,
            email=f"{username}@test.local",
            password="testpassw0rd",
            is_admin=is_admin,
            **kwargs,
        )

    return _make
