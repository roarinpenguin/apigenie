"""Event-mix overrides — selectable event types per simulated source.

Each ``sources/<vendor>.py`` declares an ``EVENT_CATALOG`` listing every event
type the vendor's API can emit (with the default weight we use today). At
request time, ``apply(templates, source)`` consults the active user's mix —
or the global admin mix as fallback — and returns a re-weighted template
dict with disabled events stripped out.

Storage shape mirrors ``profiles.bind_source`` so the RBAC story is the same:

* ``DATA_ROOT/source_event_mix.json``
* keys: ``{source}`` for the global/admin mix,
  ``{source}::u::{user_id}`` for a user's own override
* value::

    {
        "source": "cisco_duo",
        "owner_id": "u-...",   # null for global
        "mix": [
            {"event_id": "auth.success",      "enabled": true,  "weight": 0.70},
            {"event_id": "auth.fraud_marked", "enabled": false, "weight": 0.0},
            ...
        ]
    }

A user's mix shadows the global one for that user only; everyone else falls
back to global; sources without any mix fall back to the catalog defaults
declared in the source module itself. Disabled events never reach the
``weighted_choice`` call site.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from profiles import get_current_user as _get_current_user

log = logging.getLogger(__name__)

# ── Storage ──────────────────────────────────────────────────────────────────
_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
_MIX_FILE = _DATA_ROOT / "source_event_mix.json"
_lock = threading.Lock()

_USER_SEP = "::u::"


def _user_key(source: str, user_id: str) -> str:
    return f"{source}{_USER_SEP}{user_id}"


def _is_global_key(key: str) -> bool:
    return _USER_SEP not in key


def _load() -> dict[str, Any]:
    try:
        if _MIX_FILE.is_file():
            return json.loads(_MIX_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        log.warning("Corrupt source_event_mix.json — returning empty")
    return {}


def _save(data: dict[str, Any]) -> None:
    _MIX_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _MIX_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str))
    tmp.replace(_MIX_FILE)


# ── Mix CRUD ─────────────────────────────────────────────────────────────────

def set_mix(source: str, mix: list[dict[str, Any]],
            owner_id: str | None = None) -> dict[str, Any]:
    """Persist *mix* for *source*.

    ``mix`` is a list of ``{"event_id": str, "enabled": bool, "weight": float}``
    entries. Unknown event ids are kept (the source may add them later);
    entries the source no longer declares are simply ignored at resolve time.

    ``owner_id`` ``None`` writes the global/admin mix; otherwise writes a
    private mix scoped to that user.
    """
    cleaned: list[dict[str, Any]] = []
    for entry in mix or []:
        eid = str(entry.get("event_id", "")).strip()
        if not eid:
            continue
        weight = entry.get("weight", 0.0)
        try:
            weight = max(0.0, float(weight))
        except (TypeError, ValueError):
            weight = 0.0
        cleaned.append({"event_id": eid,
                        "enabled": bool(entry.get("enabled", True)),
                        "weight": weight})

    key = _user_key(source, owner_id) if owner_id else source
    record = {"source": source, "owner_id": owner_id, "mix": cleaned}
    with _lock:
        data = _load()
        data[key] = record
        _save(data)
    return record


def get_mix(source: str, user_id: str | None = None) -> dict[str, Any] | None:
    """Return the effective mix record for *source*.

    If *user_id* is given and that user has their own mix it wins; otherwise
    the global/admin mix is returned (or ``None`` if neither exists).
    """
    data = _load()
    if user_id:
        own = data.get(_user_key(source, user_id))
        if own:
            return own
    return data.get(source)


def reset_mix(source: str, owner_id: str | None = None) -> bool:
    """Remove the mix for *source*. Returns True iff a record existed."""
    key = _user_key(source, owner_id) if owner_id else source
    with _lock:
        data = _load()
        if key not in data:
            return False
        del data[key]
        _save(data)
    return True


def list_mixes() -> dict[str, Any]:
    """Global/admin mixes only — keyed by source."""
    return {k: v for k, v in _load().items() if _is_global_key(k)}


def list_mixes_for_user(user_id: str) -> dict[str, Any]:
    """A single user's own mixes, keyed by bare source name."""
    out: dict[str, Any] = {}
    suffix = f"{_USER_SEP}{user_id}"
    for k, v in _load().items():
        if k.endswith(suffix):
            out[k[: -len(suffix)]] = v
    return out


# ── Resolver — used by source generators ─────────────────────────────────────

def apply(templates: dict[str, tuple[Any, float]],
          source: str,
          user_id: str | None = "__current__",
          ) -> dict[str, tuple[Any, float]]:
    """Return a new *templates* dict with the active mix applied.

    * Disabled event_ids are removed.
    * Weights are replaced with the override values.
    * The result is renormalised so weights sum to 1.0 (preserving
      ``weighted_choice``'s contract).
    * When no override exists the input dict is returned unchanged.

    ``user_id`` defaults to the sentinel ``"__current__"`` which resolves to
    the request-scoped caller (see ``profiles.set_current_user``). Pass
    ``None`` explicitly to use the global mix only; pass a literal user id
    to scope the call elsewhere (mainly useful in tests).
    """
    if user_id == "__current__":
        user_id = _get_current_user()

    record = get_mix(source, user_id)
    if not record:
        return templates

    override = {e["event_id"]: e for e in record.get("mix", [])
                if isinstance(e, dict) and e.get("event_id")}

    out: dict[str, tuple[Any, float]] = {}
    for key, (payload, default_weight) in templates.items():
        ov = override.get(key)
        if ov is None:
            # No opinion from the user — keep the default.
            out[key] = (payload, default_weight)
            continue
        if not ov.get("enabled", True):
            # User explicitly disabled this event id.
            continue
        try:
            new_weight = max(0.0, float(ov.get("weight", default_weight)))
        except (TypeError, ValueError):
            new_weight = default_weight
        out[key] = (payload, new_weight)

    if not out:
        # Every event was disabled. Fall back to defaults rather than emit
        # nothing — surfacing an empty response would look like a bug.
        return templates

    total = sum(w for _, w in out.values())
    if total <= 0:
        # All weights zeroed but events still enabled → spread evenly.
        n = len(out)
        return {k: (p, 1.0 / n) for k, (p, _) in out.items()}

    return {k: (p, w / total) for k, (p, w) in out.items()}


# ── Catalog discovery helpers (used by admin API) ────────────────────────────

def merge_catalog_with_mix(catalog: list[dict[str, Any]],
                            source: str,
                            user_id: str | None = "__current__",
                            ) -> list[dict[str, Any]]:
    """Return the source's catalog enriched with the active enabled/weight.

    Each catalog entry is returned with two extra keys:

    * ``enabled`` — ``True`` unless the active mix turned it off
    * ``weight``  — effective weight (override if present, else default)

    Convenience for the admin UI: one call yields everything needed to
    render the per-source card.
    """
    if user_id == "__current__":
        user_id = _get_current_user()
    record = get_mix(source, user_id)
    override = {e["event_id"]: e for e in (record or {}).get("mix", [])
                if isinstance(e, dict) and e.get("event_id")}
    out: list[dict[str, Any]] = []
    for entry in catalog:
        eid = entry.get("id")
        ov = override.get(eid)
        merged = dict(entry)
        merged["enabled"] = True if ov is None else bool(ov.get("enabled", True))
        if ov is not None:
            try:
                merged["weight"] = max(0.0, float(ov.get("weight",
                                                         entry.get("default_weight", 0.0))))
            except (TypeError, ValueError):
                merged["weight"] = entry.get("default_weight", 0.0)
        else:
            merged["weight"] = entry.get("default_weight", 0.0)
        out.append(merged)
    return out
