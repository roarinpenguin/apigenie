"""User accounts, entitlements, and RBAC — SQLite-backed.

Single source of truth for identity and authorization in ApiGenie.

Uses the stdlib ``sqlite3`` module (no extra dependency) with the database file
living inside the data volume (``/var/lib/apigenie/apigenie.db``) so it persists
across container recreation and keeps the stack superportable.

Design: docs/RBAC_USER_PROFILES.md

The app runs single-process (uvicorn ``--workers 1``) but is async and has
background publisher threads, so every connection is opened with
``check_same_thread=False`` and all access is guarded by a module-level
re-entrant lock.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Storage ──────────────────────────────────────────────────────────────────
_DATA_DIR = Path(os.environ.get("APIGENIE_DATA_DIR", "/var/lib/apigenie"))
DB_PATH = Path(os.environ.get("APIGENIE_DB", str(_DATA_DIR / "apigenie.db")))

_LOCK = threading.RLock()
_conn: sqlite3.Connection | None = None


# ── Permission / category model ──────────────────────────────────────────────
class Perm:
    VIEW = "view"
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    # Storage value stays "manage" for backward-compatibility with entitlements
    # already persisted in the DB; only the user-facing label is "Operate".
    OPERATE = "manage"
    MANAGE = OPERATE  # deprecated alias — kept so existing references keep working


ALL_PERMS: tuple[str, ...] = (Perm.VIEW, Perm.CREATE, Perm.MODIFY, Perm.DELETE, Perm.OPERATE)

PERM_LABELS: dict[str, str] = {
    Perm.VIEW: "View",
    Perm.CREATE: "Create",
    Perm.MODIFY: "Modify",
    Perm.DELETE: "Delete",
    Perm.OPERATE: "Operate",
}

# Short, admin-facing explanations of what each permission level grants. Surfaced
# as tooltips in the entitlement editor and in docs/RBAC_MODEL.md.
PERM_DESCRIPTIONS: dict[str, str] = {
    Perm.VIEW: "See objects in this category (own + public shared).",
    Perm.CREATE: "Create new objects, and clone existing ones into your own copies.",
    Perm.MODIFY: "Edit objects you own in this category.",
    Perm.DELETE: "Delete objects you own in this category.",
    Perm.OPERATE: "Run/operate objects — start & stop log-push generation (Log Push only).",
}


class Category:
    LOG_PROFILES = "log_profiles"
    DETECTION_RULES = "detection_rules"
    LOG_PUSH = "log_push"
    ALERT_PUSH = "alert_push"
    LISTENERS = "listeners"
    SOURCE_BINDINGS = "source_bindings"


ALL_CATEGORIES: tuple[str, ...] = (
    Category.LOG_PROFILES,
    Category.DETECTION_RULES,
    Category.LOG_PUSH,
    Category.ALERT_PUSH,
    Category.LISTENERS,
    Category.SOURCE_BINDINGS,
)

CATEGORY_LABELS: dict[str, str] = {
    Category.LOG_PROFILES: "Log Profiles",
    Category.DETECTION_RULES: "Detection Rules",
    Category.LOG_PUSH: "Log Push Profiles",
    Category.ALERT_PUSH: "Alert Push Profiles",
    Category.LISTENERS: "Custom Listeners",
    Category.SOURCE_BINDINGS: "Source Bindings",
}

# Identifier kinds a user may register per source for pull-response matching.
IDENTIFIER_KINDS: tuple[str, ...] = (
    "bearer_token",
    "tenant_id",
    "client_id",
    "api_key",
    "basic_user",
    "subscription",
    "consumer_group",
)

# Account-token kinds (no-SMTP confirm / recovery handoff links).
TOKEN_KINDS: tuple[str, ...] = ("confirm", "recovery")
_TOKEN_TTL = timedelta(days=7)

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{1,62}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ── Password hashing (PBKDF2-HMAC-SHA256 — identical scheme to admin.py) ──────
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_DKLEN = 32
_PBKDF2_SALT_BYTES = 16


def hash_password(plain: str) -> str:
    salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, _PBKDF2_ITERATIONS, dklen=_PBKDF2_DKLEN)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(plain: str, encoded: str) -> bool:
    if not encoded:
        return False
    try:
        scheme, iters_str, salt_hex, hash_hex = encoded.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    try:
        iters = int(iters_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iters, dklen=len(expected))
    return hmac.compare_digest(actual, expected)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(12)}"


# ── Connection / schema ──────────────────────────────────────────────────────
def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


def init_db() -> None:
    """Create tables if absent. Idempotent — safe to call on every startup."""
    with _LOCK:
        conn = _get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS entitlements (
                id            TEXT PRIMARY KEY,
                name          TEXT UNIQUE NOT NULL,
                description   TEXT NOT NULL DEFAULT '',
                permissions   TEXT NOT NULL DEFAULT '{}',  -- json {category: [perm,...]}
                created_iso   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id             TEXT PRIMARY KEY,
                username       TEXT UNIQUE NOT NULL,
                email          TEXT NOT NULL DEFAULT '',
                pw_hash        TEXT NOT NULL DEFAULT '',
                entitlement_id TEXT,
                is_admin       INTEGER NOT NULL DEFAULT 0,
                confirmed      INTEGER NOT NULL DEFAULT 0,
                disabled       INTEGER NOT NULL DEFAULT 0,
                avatar_path    TEXT,
                console_url    TEXT NOT NULL DEFAULT '',
                console_token  TEXT NOT NULL DEFAULT '',
                created_iso    TEXT NOT NULL,
                last_login_iso TEXT,
                FOREIGN KEY (entitlement_id) REFERENCES entitlements(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS user_identifiers (
                id        TEXT PRIMARY KEY,
                user_id   TEXT NOT NULL,
                source    TEXT NOT NULL,
                id_kind   TEXT NOT NULL,
                id_value  TEXT NOT NULL,
                created_iso TEXT NOT NULL,
                UNIQUE (source, id_value),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_ident_value ON user_identifiers(id_value);

            CREATE TABLE IF NOT EXISTS account_tokens (
                token       TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                kind        TEXT NOT NULL,
                expires_iso TEXT NOT NULL,
                created_iso TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()


# ── Entitlements ─────────────────────────────────────────────────────────────
def _normalize_permissions(perms: dict[str, Any] | None) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for cat, levels in (perms or {}).items():
        if cat not in ALL_CATEGORIES:
            continue
        clean = [p for p in (levels or []) if p in ALL_PERMS]
        if clean:
            # de-dup, preserve canonical order
            out[cat] = [p for p in ALL_PERMS if p in clean]
    return out


def _ent_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "permissions": json.loads(row["permissions"] or "{}"),
        "created_iso": row["created_iso"],
    }


def create_entitlement(name: str, description: str = "", permissions: dict[str, Any] | None = None) -> dict[str, Any]:
    name = (name or "").strip()
    if not name:
        raise ValueError("Entitlement name is required")
    eid = _new_id("ent")
    with _LOCK:
        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO entitlements (id, name, description, permissions, created_iso) VALUES (?,?,?,?,?)",
                (eid, name, description or "", json.dumps(_normalize_permissions(permissions)), _now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Entitlement name already exists: {name}") from exc
    return get_entitlement(eid)  # type: ignore[return-value]


def update_entitlement(eid: str, name: str | None = None, description: str | None = None,
                       permissions: dict[str, Any] | None = None) -> dict[str, Any] | None:
    with _LOCK:
        conn = _get_conn()
        cur = get_entitlement(eid)
        if cur is None:
            return None
        new_name = (name if name is not None else cur["name"]).strip() or cur["name"]
        new_desc = description if description is not None else cur["description"]
        new_perms = _normalize_permissions(permissions) if permissions is not None else cur["permissions"]
        try:
            conn.execute(
                "UPDATE entitlements SET name=?, description=?, permissions=? WHERE id=?",
                (new_name, new_desc, json.dumps(new_perms), eid),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Entitlement name already exists: {new_name}") from exc
    return get_entitlement(eid)


def delete_entitlement(eid: str) -> bool:
    with _LOCK:
        conn = _get_conn()
        cur = conn.execute("DELETE FROM entitlements WHERE id=?", (eid,))
        conn.commit()
        return cur.rowcount > 0


def get_entitlement(eid: str) -> dict[str, Any] | None:
    with _LOCK:
        row = _get_conn().execute("SELECT * FROM entitlements WHERE id=?", (eid,)).fetchone()
    return _ent_row(row) if row else None


def list_entitlements() -> list[dict[str, Any]]:
    with _LOCK:
        rows = _get_conn().execute("SELECT * FROM entitlements ORDER BY name").fetchall()
    return [_ent_row(r) for r in rows]


# ── Users ────────────────────────────────────────────────────────────────────
def _user_row(row: sqlite3.Row, *, with_secrets: bool = False) -> dict[str, Any]:
    out = {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "entitlement_id": row["entitlement_id"],
        "is_admin": bool(row["is_admin"]),
        "confirmed": bool(row["confirmed"]),
        "disabled": bool(row["disabled"]),
        "avatar_path": row["avatar_path"],
        "console_url": row["console_url"],
        "has_console_token": bool(row["console_token"]),
        "has_password": bool(row["pw_hash"]),
        "created_iso": row["created_iso"],
        "last_login_iso": row["last_login_iso"],
    }
    if with_secrets:
        out["pw_hash"] = row["pw_hash"]
        out["console_token"] = row["console_token"]
    return out


def create_user(username: str, email: str = "", password: str | None = None,
                entitlement_id: str | None = None, is_admin: bool = False,
                confirmed: bool = False) -> dict[str, Any]:
    username = (username or "").strip()
    if not _USERNAME_RE.match(username):
        raise ValueError("Invalid username (2-63 chars: letters, digits, . _ -)")
    email = (email or "").strip()
    if email and not _EMAIL_RE.match(email):
        raise ValueError("Invalid email address")
    if entitlement_id and get_entitlement(entitlement_id) is None:
        raise ValueError("Unknown entitlement")
    uid = _new_id("usr")
    pw_hash = hash_password(password) if password else ""
    with _LOCK:
        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO users (id, username, email, pw_hash, entitlement_id, is_admin, confirmed, created_iso) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (uid, username, email, pw_hash, entitlement_id, 1 if is_admin else 0,
                 1 if confirmed else 0, _now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Username already exists: {username}") from exc
    return get_user(uid)  # type: ignore[return-value]


def update_user(uid: str, *, email: str | None = None, entitlement_id: str | None = None,
                confirmed: bool | None = None, disabled: bool | None = None,
                avatar_path: str | None = None, console_url: str | None = None,
                console_token: str | None = None) -> dict[str, Any] | None:
    with _LOCK:
        conn = _get_conn()
        cur = get_user(uid)
        if cur is None:
            return None
        sets: list[str] = []
        vals: list[Any] = []
        if email is not None:
            email = email.strip()
            if email and not _EMAIL_RE.match(email):
                raise ValueError("Invalid email address")
            sets.append("email=?"); vals.append(email)
        if entitlement_id is not None:
            if entitlement_id and get_entitlement(entitlement_id) is None:
                raise ValueError("Unknown entitlement")
            sets.append("entitlement_id=?"); vals.append(entitlement_id or None)
        if confirmed is not None:
            sets.append("confirmed=?"); vals.append(1 if confirmed else 0)
        if disabled is not None:
            sets.append("disabled=?"); vals.append(1 if disabled else 0)
        if avatar_path is not None:
            sets.append("avatar_path=?"); vals.append(avatar_path or None)
        if console_url is not None:
            sets.append("console_url=?"); vals.append(console_url.strip())
        if console_token is not None:
            sets.append("console_token=?"); vals.append(console_token.strip())
        if not sets:
            return cur
        vals.append(uid)
        conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", vals)
        conn.commit()
    return get_user(uid)


def set_password(uid: str, password: str) -> bool:
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    with _LOCK:
        conn = _get_conn()
        cur = conn.execute(
            "UPDATE users SET pw_hash=?, confirmed=1 WHERE id=?", (hash_password(password), uid)
        )
        conn.commit()
        return cur.rowcount > 0


def change_password(uid: str, current: str, new: str) -> bool:
    """Self-service password change.

    Verifies *current* against the user's stored hash and replaces it with
    *new*. Returns True on success, False if the user doesn't exist. Raises
    ValueError for any input failure (bad current, too-short new, disabled
    account, no password set).

    This is the helper behind the portal "Change password" form. The built-in
    admin (which lives outside the users table) is not handled here — it
    still uses /admin/api/change-password.
    """
    row = get_user(uid, with_secrets=True)
    if row is None:
        return False
    if row.get("disabled"):
        raise ValueError("Account is disabled")
    if not row.get("pw_hash"):
        raise ValueError("Account has no password set — use the recovery link instead")
    if not verify_password(current or "", row["pw_hash"]):
        raise ValueError("Current password is incorrect")
    # set_password() enforces the length minimum and re-hashes atomically.
    return set_password(uid, new)


def delete_user(uid: str) -> bool:
    with _LOCK:
        conn = _get_conn()
        cur = conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        return cur.rowcount > 0


def get_user(uid: str, *, with_secrets: bool = False) -> dict[str, Any] | None:
    with _LOCK:
        row = _get_conn().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return _user_row(row, with_secrets=with_secrets) if row else None


def get_user_by_username(username: str, *, with_secrets: bool = False) -> dict[str, Any] | None:
    with _LOCK:
        row = _get_conn().execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", ((username or "").strip(),)
        ).fetchone()
    return _user_row(row, with_secrets=with_secrets) if row else None


def list_users() -> list[dict[str, Any]]:
    with _LOCK:
        rows = _get_conn().execute("SELECT * FROM users ORDER BY username").fetchall()
    return [_user_row(r) for r in rows]


def _touch_login(uid: str) -> None:
    with _LOCK:
        conn = _get_conn()
        conn.execute("UPDATE users SET last_login_iso=? WHERE id=?", (_now_iso(), uid))
        conn.commit()


def verify_login(username: str, password: str) -> dict[str, Any] | None:
    """Return the user dict on valid credentials, else None.

    Disabled or unconfirmed (no password set) accounts cannot log in.
    """
    row = get_user_by_username(username, with_secrets=True)
    if not row or row["disabled"] or not row.get("pw_hash"):
        return None
    if not verify_password(password, row["pw_hash"]):
        return None
    _touch_login(row["id"])
    pub = get_user(row["id"])
    return pub


# ── Authorization ────────────────────────────────────────────────────────────
def get_permissions(user: dict[str, Any] | None) -> dict[str, list[str]]:
    """Resolve a user's effective permission map. Admin → all perms everywhere."""
    if not user:
        return {}
    if user.get("is_admin"):
        return {cat: list(ALL_PERMS) for cat in ALL_CATEGORIES}
    ent = get_entitlement(user["entitlement_id"]) if user.get("entitlement_id") else None
    return ent["permissions"] if ent else {}


def has_permission(user: dict[str, Any] | None, category: str, perm: str) -> bool:
    if user and user.get("is_admin"):
        return True
    return perm in get_permissions(user).get(category, [])


# ── Per-source identifiers ───────────────────────────────────────────────────
def _ident_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "source": row["source"],
        "id_kind": row["id_kind"],
        "id_value": row["id_value"],
        "created_iso": row["created_iso"],
    }


def add_identifier(user_id: str, source: str, id_kind: str, id_value: str) -> dict[str, Any]:
    source = (source or "").strip()
    id_value = (id_value or "").strip()
    if id_kind not in IDENTIFIER_KINDS:
        raise ValueError(f"Invalid identifier kind: {id_kind}")
    if not source or not id_value:
        raise ValueError("source and id_value are required")
    if get_user(user_id) is None:
        raise ValueError("Unknown user")
    iid = _new_id("idf")
    with _LOCK:
        conn = _get_conn()
        # Enforce GLOBAL uniqueness of the credential value (across every user
        # and source). A value identifies exactly one principal, so this keeps
        # identifier matching unambiguous and prevents one user's request from
        # ever being resolved to another user's profile.
        clash = conn.execute(
            "SELECT 1 FROM user_identifiers WHERE id_value=? LIMIT 1", (id_value,)
        ).fetchone()
        if clash is not None:
            raise ValueError("That identifier value is already in use. Each credential "
                             "value must be unique across all users and sources.")
        try:
            conn.execute(
                "INSERT INTO user_identifiers (id, user_id, source, id_kind, id_value, created_iso) "
                "VALUES (?,?,?,?,?,?)",
                (iid, user_id, source, id_kind, id_value, _now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("That identifier value is already in use.") from exc
        row = conn.execute("SELECT * FROM user_identifiers WHERE id=?", (iid,)).fetchone()
    return _ident_row(row)


def delete_identifier(iid: str) -> bool:
    with _LOCK:
        conn = _get_conn()
        cur = conn.execute("DELETE FROM user_identifiers WHERE id=?", (iid,))
        conn.commit()
        return cur.rowcount > 0


def list_identifiers(user_id: str) -> list[dict[str, Any]]:
    with _LOCK:
        rows = _get_conn().execute(
            "SELECT * FROM user_identifiers WHERE user_id=? ORDER BY source, id_kind", (user_id,)
        ).fetchall()
    return [_ident_row(r) for r in rows]


def match_user_by_identifier(value: str, source: str | None = None) -> str | None:
    """Return the user_id whose registered identifier matches *value*.

    Matching is exact on id_value. If *source* is given a same-source match is
    preferred. To fail safe, a value-only match is only honoured when it maps to
    exactly ONE user; an ambiguous value (which add_identifier now prevents)
    returns None so the caller falls back to the global profile rather than
    risking resolution to the wrong user.
    """
    value = (value or "").strip()
    if not value:
        return None
    with _LOCK:
        conn = _get_conn()
        if source:
            row = conn.execute(
                "SELECT user_id FROM user_identifiers WHERE id_value=? AND source=? LIMIT 1",
                (value, source),
            ).fetchone()
            if row:
                return row["user_id"]
        rows = conn.execute(
            "SELECT DISTINCT user_id FROM user_identifiers WHERE id_value=?", (value,)
        ).fetchall()
    if len(rows) == 1:
        return rows[0]["user_id"]
    return None


# ── Account tokens (no-SMTP confirm / recovery handoff) ──────────────────────
def issue_token(user_id: str, kind: str = "confirm") -> str:
    if kind not in TOKEN_KINDS:
        raise ValueError(f"Invalid token kind: {kind}")
    if get_user(user_id) is None:
        raise ValueError("Unknown user")
    tok = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + _TOKEN_TTL).isoformat(timespec="seconds")
    with _LOCK:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO account_tokens (token, user_id, kind, expires_iso, created_iso) VALUES (?,?,?,?,?)",
            (tok, user_id, kind, expires, _now_iso()),
        )
        conn.commit()
    return tok


def consume_token(token: str, kind: str | None = None) -> str | None:
    """Validate and delete a token. Returns its user_id, or None if invalid/expired."""
    if not token:
        return None
    with _LOCK:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM account_tokens WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        try:
            expired = datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_iso"])
        except ValueError:
            expired = True
        if expired or (kind is not None and row["kind"] != kind):
            conn.execute("DELETE FROM account_tokens WHERE token=?", (token,))
            conn.commit()
            return None
        uid = row["user_id"]
        conn.execute("DELETE FROM account_tokens WHERE token=?", (token,))
        conn.commit()
    return uid


def peek_token(token: str) -> dict[str, Any] | None:
    """Non-destructive token lookup (for rendering the set-password form)."""
    if not token:
        return None
    with _LOCK:
        row = _get_conn().execute("SELECT * FROM account_tokens WHERE token=?", (token,)).fetchone()
    if not row:
        return None
    try:
        if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_iso"]):
            return None
    except ValueError:
        return None
    return {"user_id": row["user_id"], "kind": row["kind"], "expires_iso": row["expires_iso"]}


# ── Stats ────────────────────────────────────────────────────────────────────
def counts() -> dict[str, int]:
    with _LOCK:
        conn = _get_conn()
        u = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        e = conn.execute("SELECT COUNT(*) c FROM entitlements").fetchone()["c"]
    return {"users": u, "entitlements": e}
