"""Per-operator WEF push binding storage (v5.2).

This is the durable layer behind the admin "WEF" tab. Each row holds
everything the runner needs to instantiate a
:class:`sources.windows_event_forwarding.WEFEmitter` against a real
Windows Event Collector — target host/port/path, auth method, credentials,
channel filter, and rate parameters — plus metadata for the UI (name,
owner, visibility) and a small status block updated by the runner after
each push.

Storage shape
=============

A single JSON file at ``data/wef_bindings.json``, keyed by binding id::

    {
      "wef-3f9c1b2a4d70": {
        "id":         "wef-3f9c1b2a4d70",
        "name":       "DC01 → WEC1",
        "enabled":    false,
        "owner_id":   "u-alice"  | null,
        "visibility": "private" | "public",
        "config":     { …WEFEmitter binding config… },
        "status":     { "last_push_at": …, "last_status_code": …,
                        "last_error": …, "sent_total": 0 },
        "created_at": "…",
        "updated_at": "…"
      },
      …
    }

Sensitive fields
================

* **Basic password** — accepted from the caller as
  ``payload["password"]`` (plaintext, from a form POST), encrypted via
  :mod:`crypto`'s Fernet key chain, stored under
  ``config.basic_password_enc``. The plaintext is **never** persisted
  and **never** returned in any read path.
* **Client cert (PEM)** — handled out-of-band by
  :func:`sources.windows_event_forwarding.save_cert_bundle` keyed by
  binding id. :func:`delete_binding` calls
  :func:`sources.windows_event_forwarding.delete_cert_bundle` to keep
  the two stores in sync.

The module is intentionally thin: validation delegates to
``windows_event_forwarding.validate_binding_config``,
normalisation to ``windows_event_forwarding.normalize_binding_config``
— so a v5.x change to the binding schema is a one-edit affair.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crypto import encrypt as _enc_str
from sources import windows_event_forwarding as _wef

log = logging.getLogger(__name__)


# ── Storage layout ───────────────────────────────────────────────────

DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
BINDINGS_FILE = DATA_ROOT / "wef_bindings.json"

_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return f"wef-{uuid.uuid4().hex[:12]}"


def _path(_bid: str) -> Path:
    """Storage path. Returns the single-file store regardless of id —
    callers (and tests) use this to read the on-disk JSON when they
    need to assert at the raw-bytes level."""
    return BINDINGS_FILE


def _load() -> dict[str, Any]:
    if not BINDINGS_FILE.is_file():
        return {}
    try:
        return json.loads(BINDINGS_FILE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("wef_bindings: corrupt %s (%s); starting empty",
                    BINDINGS_FILE, exc)
        return {}


def _save(data: dict[str, Any]) -> None:
    BINDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = BINDINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str))
    tmp.replace(BINDINGS_FILE)


# ── Validation ────────────────────────────────────────────────────────

def _validate(name: str, config: dict[str, Any]) -> None:
    """Raise :class:`ValueError` if *name* / *config* are unfit for
    storage. Reuses the source-module validator so the rules stay in
    one place."""
    if not (name or "").strip():
        raise ValueError("name is required")
    errors = _wef.validate_binding_config(config)
    if errors:
        raise ValueError("; ".join(errors))


# ── Internal: scrub secrets before returning to the caller ───────────

def _public_view(bnd: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *bnd* safe to hand back to API callers.

    Today the only secret in the binding's outer shape is the Basic
    password (under ``config.basic_password_enc``). We keep the encrypted
    form (the UI uses its presence to decide whether to show a
    "password set" badge) but always strip a stray plaintext
    ``password`` key that a buggy caller may have round-tripped in.
    """
    out = json.loads(json.dumps(bnd, default=str))  # deep copy
    out.pop("password", None)
    out.get("config", {}).pop("password", None)
    return out


# ── CRUD ──────────────────────────────────────────────────────────────

def create_binding(payload: dict[str, Any],
                   owner_id: str | None = None) -> dict[str, Any]:
    """Create a new WEF binding. Raises :class:`ValueError` on bad input.

    ``payload`` shape::

        {
          "name":       str,          # required
          "config":     {…},          # required; passes validate_binding_config
          "password":   str | None,   # optional; only meaningful for Basic auth
          "visibility": "private" | "public",   # default "private"
        }

    The plaintext password is encrypted on the way in and dropped from
    the persisted record. The returned dict is the public view (no
    plaintext password).
    """
    name = (payload.get("name") or "").strip()
    cfg_in = dict(payload.get("config") or {})
    _validate(name, cfg_in)

    # Normalise auth-method-dependent fields, then encrypt the password
    # if one was supplied and the auth method is Basic. We tolerate a
    # password being supplied for a client_cert binding (the normaliser
    # below will strip the basic_* fields), so we encrypt-then-normalise
    # in that order to avoid persisting a dangling ciphertext.
    password = payload.get("password")
    if password and cfg_in.get("auth_method") == "basic":
        cfg_in["basic_password_enc"] = _enc_str(password)
    cfg_in = _wef.normalize_binding_config(cfg_in)
    cfg_in.setdefault("cert_uploaded", False)

    bid = _new_id()
    now = _now_iso()
    bnd = {
        "id":         bid,
        "name":       name,
        "enabled":    False,
        "owner_id":   owner_id,
        "visibility": payload.get("visibility") or "private",
        "config":     cfg_in,
        "status":     {
            "last_push_at":     None,
            "last_status_code": None,
            "last_error":       None,
            "sent_total":       0,
        },
        "created_at": now,
        "updated_at": now,
    }

    with _lock:
        data = _load()
        data[bid] = bnd
        _save(data)

    return _public_view(bnd)


def get_binding(bid: str) -> dict[str, Any] | None:
    """Return the public view of *bid*, or ``None`` if no such binding."""
    bnd = _load().get(bid)
    return _public_view(bnd) if bnd else None


def list_bindings(owner_id: str | None = None) -> dict[str, dict[str, Any]]:
    """Return all bindings, keyed by id.

    When *owner_id* is None (the built-in admin / acting-as-self) every
    binding is visible. When given, the caller is a regular user and
    the public view filters to that user's own bindings plus any with
    ``visibility="public"``.
    """
    data = _load()
    if owner_id is None:
        return {k: _public_view(v) for k, v in data.items()}
    out: dict[str, dict[str, Any]] = {}
    for k, v in data.items():
        if v.get("owner_id") == owner_id or v.get("visibility") == "public":
            out[k] = _public_view(v)
    return out


def list_bindings_for_user(user_id: str) -> dict[str, dict[str, Any]]:
    """Return only the bindings *user_id* owns (no public-shared rows).

    Distinct from :func:`list_bindings` with ``owner_id=user_id``, which
    additionally surfaces public bindings. This view powers the "My
    bindings" lens in the admin UI.
    """
    return {
        k: _public_view(v) for k, v in _load().items()
        if v.get("owner_id") == user_id
    }


def update_binding(bid: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """Partial update. Returns the updated public view or ``None`` if no
    such binding.

    Supported keys in *payload*:

    * ``name``       — string, validated non-empty.
    * ``config``     — full or partial config dict; merged into the
                       existing config before re-validation.
    * ``password``   — plaintext; re-encrypted and written into
                       ``config.basic_password_enc``. Pass an empty
                       string to clear an existing password.
    * ``visibility`` — ``"private"`` / ``"public"``.
    * ``enabled``    — bool. Same end result as
                       :func:`set_enabled` but lets the admin form
                       update everything in one round-trip.
    """
    with _lock:
        data = _load()
        existing = data.get(bid)
        if existing is None:
            return None
        merged = json.loads(json.dumps(existing, default=str))  # deep copy

        if "name" in payload:
            merged["name"] = (payload["name"] or "").strip()
        if "visibility" in payload:
            merged["visibility"] = payload["visibility"] or "private"
        if "enabled" in payload:
            merged["enabled"] = bool(payload["enabled"])
        if "config" in payload:
            # Merge so a partial config doesn't clobber unrelated keys.
            new_cfg = {**merged.get("config", {}), **(payload["config"] or {})}
            merged["config"] = new_cfg
        if "password" in payload:
            pw = payload["password"]
            if pw:
                merged["config"]["basic_password_enc"] = _enc_str(pw)
            else:
                merged["config"]["basic_password_enc"] = None

        # Re-validate + re-normalise the merged result so a config edit
        # can't sneak a broken state through, and so an auth-method
        # switch wipes the now-stale credentials.
        _validate(merged["name"], merged["config"])
        merged["config"] = _wef.normalize_binding_config(merged["config"])
        merged["updated_at"] = _now_iso()

        data[bid] = merged
        _save(data)
        return _public_view(merged)


def set_enabled(bid: str, enabled: bool) -> dict[str, Any] | None:
    """Toggle the binding's participation in the push runner.

    Idempotent — enabling an already-enabled binding (or disabling a
    disabled one) is a successful no-op. The status block is NOT
    cleared on disable so the operator keeps the last error visible for
    diagnostics.
    """
    with _lock:
        data = _load()
        bnd = data.get(bid)
        if bnd is None:
            return None
        if bnd.get("enabled") == bool(enabled):
            return _public_view(bnd)
        bnd["enabled"] = bool(enabled)
        bnd["updated_at"] = _now_iso()
        _save(data)
        return _public_view(bnd)


def record_push_result(bid: str,
                       sent: int,
                       status_code: int | None,
                       error: str | None = None) -> dict[str, Any] | None:
    """Update the status block after a push attempt. Called by the
    runner; ``sent_total`` accumulates across pushes so the UI can
    show lifetime throughput.

    Returns the updated public view, or ``None`` if no such binding
    (e.g. binding deleted between push start and result write).
    """
    with _lock:
        data = _load()
        bnd = data.get(bid)
        if bnd is None:
            return None
        status = bnd.setdefault("status", {})
        status["last_push_at"] = _now_iso()
        status["last_status_code"] = status_code
        status["last_error"] = error
        status["sent_total"] = int(status.get("sent_total") or 0) + int(sent or 0)
        bnd["updated_at"] = _now_iso()
        _save(data)
        return _public_view(bnd)


def delete_binding(bid: str) -> bool:
    """Remove the binding row AND its on-disk cert bundle (if any).

    The cert deletion is best-effort — if the bundle is missing or the
    filesystem rejects the unlink we still consider the binding gone,
    because the row removal is the authoritative state. Returns
    ``True`` iff a row was actually removed.
    """
    with _lock:
        data = _load()
        if bid not in data:
            return False
        del data[bid]
        _save(data)
    try:
        _wef.delete_cert_bundle(bid)
    except Exception as exc:                       # pragma: no cover
        log.warning("wef_bindings: cert cleanup for %s failed: %s",
                    bid, exc)
    return True


# ── Runner-facing accessors ───────────────────────────────────────────

def effective_config(bid: str) -> dict[str, Any] | None:
    """Return the raw ``config`` dict the WEFEmitter expects, or None.

    The runner consumes this directly so the storage shape can evolve
    (e.g. add ``status``, ``visibility``, …) without forcing every
    consumer to know about the wrapper. Sensitive fields stay
    in-place — the runner needs the encrypted ``basic_password_enc`` to
    feed the emitter, which decrypts on first send via ``crypto.try_decrypt``.
    """
    data = _load()
    bnd = data.get(bid)
    if bnd is None:
        return None
    return json.loads(json.dumps(bnd.get("config") or {}, default=str))


def list_enabled_bindings() -> list[dict[str, Any]]:
    """Convenience for the runner: every binding where ``enabled=True``,
    full record (not the public view — the runner needs the status
    block to detect stale errors)."""
    return [v for v in _load().values() if v.get("enabled")]


__all__ = [
    "DATA_ROOT",
    "BINDINGS_FILE",
    "create_binding",
    "get_binding",
    "list_bindings",
    "list_bindings_for_user",
    "update_binding",
    "set_enabled",
    "record_push_result",
    "delete_binding",
    "effective_config",
    "list_enabled_bindings",
]
