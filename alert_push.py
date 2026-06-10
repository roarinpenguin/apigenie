"""Alert Push profile lifecycle — CRUD, ownership, UAM credential storage.

Mirrors ``log_pusher.py`` for symmetry: a JSON-backed list of profiles with
visibility / owner_id semantics that the existing ``_can_see_obj`` /
``_can_write_obj`` helpers in ``admin.py`` already know how to enforce.

What this module owns
---------------------
* Storage of Alert Push profiles in ``$APIGENIE_DATA_ROOT/alert_push_profiles.json``
* CRUD helpers (create / read / update / delete / clone)
* Public serialiser ``to_public_dict()`` that **redacts** the UAM service
  token so it never leaves the server in plaintext (matches the Phase 3.5
  pattern used by ``accounts.update_user`` for ``console_token``).
* A ``get_uam_token()`` resolver for the egress path (P4.3) — the send
  endpoint uses it to fetch the plaintext token just before calling
  ``alerts.send_alert``.

What this module does NOT own
-----------------------------
* Stream-mode background threads — those land in P4.4 alongside the same
  pattern used by ``log_pusher._push_loop``.
* Visibility filtering — the admin.py API layer applies ``_can_see_obj``
  per request, matching the Log Push convention.
* The actual send logic — see ``alerts.send_alert``.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import threading
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
_PROFILES_FILE = _DATA_ROOT / "alert_push_profiles.json"
_lock = threading.Lock()

# In-memory ring buffer of recent sends, keyed per profile_id. The "_global"
# key holds the cross-profile history (most recent first). Bounded so the
# memory footprint stays small even if a user spams Send.
_HISTORY_MAX = 50
_history: dict[str, deque[dict[str, Any]]] = {}
_history_lock = threading.Lock()

# Keys that may be UPDATEd by callers. Everything else (id, owner_id,
# created, status, alerts_sent, started_at) is module-managed.
_UPDATABLE_KEYS: tuple[str, ...] = (
    "name",
    "template_id",
    "visibility",
    "profile_id",
    "uam_ingest_url",
    "uam_account_id",
    "uam_site_id",
    "uam_group_id",
    "overrides",
    "mode",
    "rate",
    "duration",
    "link_xdr_assets",
    "enrich_observables",
)


# ── Storage ──────────────────────────────────────────────────────────────────

def _load_profiles() -> list[dict[str, Any]]:
    try:
        if _PROFILES_FILE.is_file():
            return json.loads(_PROFILES_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("alert_push: corrupt profiles file: %s", exc)
    return []


def _save_profiles(profiles: list[dict[str, Any]]) -> None:
    _PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PROFILES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(profiles, indent=2, default=str))
    tmp.replace(_PROFILES_FILE)


def _find(profiles: list[dict[str, Any]], profile_id: str) -> dict[str, Any] | None:
    for p in profiles:
        if p.get("id") == profile_id:
            return p
    return None


# ── Defaults ─────────────────────────────────────────────────────────────────

def _default_profile(data: dict[str, Any]) -> dict[str, Any]:
    """Build a fully-populated profile dict from a partial create payload.

    The shape matches the storage contract documented in
    ``docs/ALERT_PUSH.md`` (to be added in P4.7).
    """
    duration = data.get("duration") or {}
    return {
        # Identity
        "id": str(uuid.uuid4()),
        "name": (data.get("name") or "Untitled").strip(),
        "template_id": data.get("template_id") or "",
        # Ownership (set by admin._owner_stamp before reaching here)
        "owner_id": data.get("owner_id"),
        "visibility": data.get("visibility", "private"),
        # Log Profile binding (entity substitution, wired in P4.5)
        "profile_id": data.get("profile_id"),
        # Egress destination (UAM ingest)
        "uam_ingest_url": (data.get("uam_ingest_url") or
                           "https://ingest.us1.sentinelone.net").rstrip("/"),
        "uam_account_id": data.get("uam_account_id") or "",
        "uam_site_id": data.get("uam_site_id") or "",
        "uam_group_id": data.get("uam_group_id") or "",
        "uam_service_token": data.get("uam_service_token") or "",
        # User overrides (dot-path -> value)
        "overrides": data.get("overrides") or {},
        # Mode
        "mode": data.get("mode", "oneshot"),
        "rate": max(1, min(100, int(data.get("rate", 1) or 1))),
        "duration": {
            "value": max(1, int(duration.get("value", 5) or 5)),
            "unit": duration.get("unit") or "minutes",
        },
        "link_xdr_assets": bool(data.get("link_xdr_assets", False)),
        # Phase 4.7: attach MITRE attacks[] + harvested observables[]
        # to the alert before egress. Default ON — every shipped
        # template benefits, and the enricher is idempotent + cheap.
        "enrich_observables": bool(data.get("enrich_observables", True)),
        # Runtime state (mutated by send + stream; P4.3 / P4.4)
        "status": "stopped",
        "error": "",
        "alerts_sent": 0,
        "started_at": "",
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
    }


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_profile(data: dict[str, Any]) -> dict[str, Any]:
    """Create and persist a new Alert Push profile.

    ``data["owner_id"]`` and ``data["visibility"]`` are expected to already
    have been set by ``admin._owner_stamp``; missing values fall back to
    ``None`` and ``"private"`` respectively.
    """
    profile = _default_profile(data)
    with _lock:
        profiles = _load_profiles()
        profiles.append(profile)
        _save_profiles(profiles)
    log.info("alert_push: profile created: %s (%s)", profile["name"], profile["id"])
    return profile


def get_profile(profile_id: str) -> dict[str, Any] | None:
    """Return the raw profile dict (UAM token included) or None."""
    return _find(_load_profiles(), profile_id)


def list_profiles() -> list[dict[str, Any]]:
    """Return every stored profile (raw — UAM tokens included).

    The admin.py layer wraps each entry with ``to_public_dict`` before
    returning to the client so tokens never travel back to the browser.
    Visibility filtering is also applied by the admin layer via
    ``_can_see_obj`` (same as Log Push).
    """
    return list(_load_profiles())


def update_profile(profile_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
    """Update mutable fields. Returns the post-update profile or None.

    Special handling: ``uam_service_token`` is only overwritten when the
    caller supplies a non-empty string. Sending ``""`` or omitting the key
    preserves the saved token — same UX as the Phase 3.5
    ``console_token`` self-service flow, so a user can update the URL or
    account ID without re-pasting the secret.
    """
    with _lock:
        profiles = _load_profiles()
        p = _find(profiles, profile_id)
        if not p:
            return None
        for key in _UPDATABLE_KEYS:
            if key not in data:
                continue
            value = data[key]
            if key == "uam_ingest_url" and isinstance(value, str):
                value = value.rstrip("/")
            if key == "rate":
                value = max(1, min(100, int(value or 1)))
            if key == "duration" and isinstance(value, dict):
                value = {
                    "value": max(1, int(value.get("value", 5) or 5)),
                    "unit": value.get("unit") or "minutes",
                }
            if key == "link_xdr_assets":
                value = bool(value)
            if key == "enrich_observables":
                value = bool(value)
            p[key] = value
        # Token: only overwrite when caller sent a non-empty value.
        # The "__clear__" sentinel comes first because it IS a non-empty string
        # itself — without this guard the next branch would store it literally.
        token_in = data.get("uam_service_token")
        if token_in == "__clear__":
            # Explicit clear sentinel — matches the Phase 3.5 delete flow
            # but folded into PUT so callers don't need a separate route.
            p["uam_service_token"] = ""
        elif isinstance(token_in, str) and token_in.strip():
            p["uam_service_token"] = token_in.strip()
        _save_profiles(profiles)
    return p


def delete_profile(profile_id: str) -> bool:
    """Delete a profile by id. Returns True if removed, False if missing."""
    with _lock:
        profiles = _load_profiles()
        before = len(profiles)
        profiles = [p for p in profiles if p.get("id") != profile_id]
        if len(profiles) == before:
            return False
        _save_profiles(profiles)
    return True


def clone_profile(src: dict[str, Any], *, owner_id: str | None,
                  new_name: str | None = None) -> dict[str, Any]:
    """Clone an existing profile (typically one with ``visibility=public``)
    under a new owner. Runtime state, ID and creation timestamp reset; the
    secret UAM service token does **not** travel with the clone — the new
    owner must paste their own (avoids accidental credential propagation
    between users).
    """
    data = {k: copy.deepcopy(v) for k, v in src.items()
            if k in _UPDATABLE_KEYS or k == "template_id"}
    data["name"] = new_name or f"Copy of {src.get('name', 'Untitled')}"
    data["owner_id"] = owner_id
    data["visibility"] = "private"
    data["uam_service_token"] = ""   # do NOT carry secrets across owners
    return create_profile(data)


# ── Public serialiser (used by admin.py before returning to browser) ─────────

def to_public_dict(profile: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a copy of *profile* with the UAM service token redacted.

    The original ``uam_service_token`` field is removed and replaced with
    ``has_uam_service_token`` (bool). This is what the API hands back to
    the User Portal / Admin UI so the secret never travels client-side.

    Pass ``None`` through unchanged so call-sites can chain naturally:
    ``to_public_dict(get_profile(pid))``.
    """
    if profile is None:
        return None
    out = copy.deepcopy(profile)
    token = out.pop("uam_service_token", "") or ""
    out["has_uam_service_token"] = bool(token)
    return out


def get_uam_token(profile_id: str) -> str | None:
    """Resolve the plaintext UAM service token for a profile.

    Used by the send/egress path (P4.3) to feed ``alerts.send_alert``.
    Returns ``None`` when the profile doesn't exist OR the token slot is
    empty (the caller should surface a friendly "no token configured"
    error in that case).
    """
    p = get_profile(profile_id)
    if not p:
        return None
    tok = p.get("uam_service_token") or ""
    return tok or None


# ── History ring buffer (in-memory) ──────────────────────────────────────────
#
# The send / stream paths call ``record_send`` once per batch. The UI calls
# ``get_history(profile_id)`` for the per-profile panel and
# ``get_history("_global")`` for the cross-profile "Recent activity" view.
#
# Storage is intentionally in-memory: this is "what just happened" telemetry,
# not durable audit. If the container restarts, the buffer resets. (Durable
# audit logging belongs in the existing trace.py / intrusions pipeline, which
# already captures every HTTP request anyway.)

def summarise_results(template_id: str,
                      results: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll up a list of per-alert egress results into one history entry.

    ``results`` is the list returned by ``alerts.send_alert`` — each entry
    is the shape produced by ``alerts.egress_alert`` (ok / status_code /
    error / uid / ...). We fold them into one summary the UI can display
    on a single row.
    """
    success = [r for r in results if r.get("success")]
    failures = [r for r in results if not r.get("success")]
    # First non-empty error wins as the headline; UI can drill into the raw
    # results array if it wants per-alert detail.
    headline_err = next((r.get("error") or "" for r in failures
                         if r.get("error")), "")
    headline_status = next((r.get("status") for r in failures
                            if r.get("status")), None)
    if headline_status is None and results:
        headline_status = results[0].get("status")
    return {
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
        "template_id": template_id,
        "count": len(results),
        "success_count": len(success),
        "failure_count": len(failures),
        "uids": [r.get("alert_uid") for r in results if r.get("alert_uid")],
        "status": headline_status,
        "error": headline_err,
    }


def record_send(profile_id: str, entry: dict[str, Any]) -> None:
    """Append *entry* to the history for *profile_id* and the global buffer.

    Also bumps the profile's persistent ``alerts_sent`` counter by
    ``entry["success_count"]`` so the profile row in the UI shows lifetime
    successes without needing a separate counter.
    """
    with _history_lock:
        buf = _history.setdefault(profile_id, deque(maxlen=_HISTORY_MAX))
        buf.appendleft(entry)
        glob = _history.setdefault("_global", deque(maxlen=_HISTORY_MAX))
        # Tag with profile_id so the global view can render which profile
        # produced each entry (per-profile buffer doesn't need this since
        # the key already carries it).
        glob.appendleft({**entry, "profile_id": profile_id})

    success_delta = int(entry.get("success_count") or 0)
    if success_delta <= 0:
        return
    # Persist the counter bump in the JSON store. Failures DON'T count
    # toward alerts_sent — the field tracks accepted-by-UAM only.
    with _lock:
        profiles = _load_profiles()
        p = _find(profiles, profile_id)
        if p is not None:
            p["alerts_sent"] = int(p.get("alerts_sent") or 0) + success_delta
            _save_profiles(profiles)


def get_history(profile_id: str, *, limit: int = _HISTORY_MAX) -> list[dict[str, Any]]:
    """Return up to *limit* most-recent history entries for *profile_id*.

    Pass ``profile_id="_global"`` for the cross-profile view. Returns
    an empty list if nothing has been recorded yet.
    """
    with _history_lock:
        buf = _history.get(profile_id)
        if not buf:
            return []
        return list(buf)[:max(0, int(limit))]


def clear_history(profile_id: str | None = None) -> None:
    """Drop the in-memory history.

    With ``profile_id=None`` (default), clear every buffer — used by the
    test fixture so per-test state doesn't leak between tests. With a
    specific profile_id, drop just that profile's buffer (the UI exposes
    this as the per-row "Clear history" action in P4.3).
    """
    with _history_lock:
        if profile_id is None:
            _history.clear()
        else:
            _history.pop(profile_id, None)
            # Also drop matching entries from the global buffer so the
            # "Recent activity" view stays consistent.
            glob = _history.get("_global")
            if glob is not None:
                kept = [e for e in glob if e.get("profile_id") != profile_id]
                _history["_global"] = deque(kept, maxlen=_HISTORY_MAX)
