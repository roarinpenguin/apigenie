"""Lightweight registry of simulated source modules.

Each module under ``sources/`` may declare:

* ``EVENT_CATALOG`` — a list of event-type metadata dicts grounded in the
  vendor's official API documentation. When this attribute is present the
  source participates in the event-mix override system (``event_mix.py``)
  and admins can re-weight or disable individual event types from the UI.

The helpers below iterate the package so callers ask the question
"which sources are mix-aware?" without hard-coding a list — sources opt in
just by declaring ``EVENT_CATALOG`` at module scope.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Any

log = logging.getLogger(__name__)

# Names to skip during module discovery. Sub-packages (currently
# ``sources.synthetic``) carry their own bundle of modules and don't have a
# vendor catalog at the package root; they're explored separately if needed.
_SKIP_NAMES: set[str] = {"__init__"}

# Bindings UI source ids that differ from the Python module filename.
# Mapping: ``ui_id -> module_name``. The bindings page in ``admin.py``
# (``SOURCES`` dict) uses marketing / product names that don't always match
# the on-disk module filename. The event-mix override system stores entries
# under the **canonical** (module-name) key so the source-side resolver in
# ``sources/<name>.py`` finds them; the admin UI sends the ui_id. Every
# entry-point that bridges the two sides must canonicalize via
# ``canonical_source_id`` before touching storage.
SOURCE_ID_ALIASES: dict[str, str] = {
    # Microsoft renamed Azure AD to Entra ID in 2023; the source module
    # kept the older filename to avoid touching every test fixture.
    "entra_id": "azure_ad",
    # Microsoft Defender XDR (Defender for Endpoint + Identity + Cloud Apps).
    "defender": "microsoft_defender",
}


def canonical_source_id(source: str) -> str:
    """Return the canonical (module-name) source id for *source*.

    Pass ``source`` through ``SOURCE_ID_ALIASES`` if it's a known alias;
    otherwise return it unchanged. Safe to call on any string — non-alias
    ids round-trip unmodified, so this can be applied unconditionally at
    every storage / lookup boundary.
    """
    return SOURCE_ID_ALIASES.get(source, source)


def iter_source_modules():
    """Yield ``(name, module)`` for every importable leaf source module.

    Iteration is lazy and import errors on a single module never break the
    iteration — that bug would otherwise hide the rest of the catalog from
    the admin UI.
    """
    import sources as _self
    for info in pkgutil.iter_modules(_self.__path__):
        if info.name in _SKIP_NAMES:
            continue
        if info.ispkg:
            # Sub-packages (e.g. sources.synthetic) ship their own
            # generators and don't expose an EVENT_CATALOG at the package
            # root. Recurse manually if/when needed.
            continue
        try:
            yield info.name, importlib.import_module(f"sources.{info.name}")
        except ImportError as exc:
            log.warning("sources: cannot import %s (%s)", info.name, exc)


def get_event_catalog(source: str) -> list[dict[str, Any]] | None:
    """Return the ``EVENT_CATALOG`` for *source* (or ``None`` if unknown
    / not mix-aware).

    *source* may be either a module-name id (``azure_ad``) or a bindings
    UI id (``entra_id``); aliases are resolved transparently.
    """
    source = canonical_source_id(source)
    for name, mod in iter_source_modules():
        if name == source:
            catalog = getattr(mod, "EVENT_CATALOG", None)
            if isinstance(catalog, list) and catalog:
                return catalog
            return None
    return None


def get_event_catalogs() -> dict[str, list[dict[str, Any]]]:
    """Return ``{source_name: EVENT_CATALOG}`` for every mix-aware source.

    Used by the admin UI to render a card per source and by tests to assert
    that newly-wired vendors actually picked up the override surface.

    Each catalog is emitted under **both** its canonical module-name id and
    any UI-side alias in ``SOURCE_ID_ALIASES``. The bindings page iterates
    ``admin.SOURCES`` (which uses the alias for some vendors) and looks up
    by that id — without the dual-emit, ``entra_id`` and ``defender`` would
    silently miss the Event Mix disclosure even though the source modules
    are fully wired.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    for name, mod in iter_source_modules():
        catalog = getattr(mod, "EVENT_CATALOG", None)
        if isinstance(catalog, list) and catalog:
            out[name] = catalog
    # Mirror each aliased catalog under its UI-side id. Skip aliases that
    # point at a module without an EVENT_CATALOG — never invent an empty
    # disclosure card.
    for alias, canonical in SOURCE_ID_ALIASES.items():
        if canonical in out:
            out[alias] = out[canonical]
    return out
