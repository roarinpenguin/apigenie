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


def get_persona_projection(source: str) -> dict[str, str] | None:
    """Return the ``PERSONA_PROJECTION`` for *source* (or ``None``).

    The projection is a mapping of **source-native event field path**
    (dotted, e.g. ``actor.alternateId``) ⇒ **canonical persona slot
    path** (e.g. ``victim_user.email``) defined in
    :data:`personas.CANONICAL_SCHEMA`. When the scenario engine
    creates a temp detection rule for a phase on this source it uses
    this map to splice the scenario's persona values into the rule's
    ``field_overrides`` — so every source involved in the scenario
    emits events grounded in the same victim, host, attacker and
    payload.

    ``None`` means "this source does not yet participate in cross-
    source correlation"; the caller (rule engine) must treat that as
    a no-op and emit the phase's own overrides untouched. Returning
    ``None`` rather than ``{}`` is intentional: a future audit can
    grep callers for the gap and add a projection where needed.

    *source* accepts either the canonical module-name id (``azure_ad``)
    or a bindings UI alias (``entra_id``, ``defender``).
    """
    source = canonical_source_id(source)
    for name, mod in iter_source_modules():
        if name == source:
            proj = getattr(mod, "PERSONA_PROJECTION", None)
            if isinstance(proj, dict) and proj:
                return proj
            return None
    return None


# ── Asset binding registry (v5.3 Step 2) ──────────────────────────────
#
# For SentinelOne STAR / Custom Detection rules to bind an alert to a
# real Target Asset (and not "Unknown Device"), the matched event must
# carry both:
#
# * an identifier in ``device.uid`` (endpoint/cloud) or ``user.uid``
#   (identity) sourced from the XDR asset inventory, and
# * a ``class_uid`` that classifies the event as asset-bearing —
#   the OCSF class id is enough; S1 resolves the actual category
#   from inventory.
#
# This table is the fallback when a source module doesn't pin its
# own ``ASSET_BINDING`` constant. Each entry is::
#
#     {"kind": "endpoint" | "identity" | "cloud" | "network" | "none",
#      "class_uid": int}
#
# ``kind="none"`` means the source is governance / posture data (Snyk,
# Tenable, Wiz) — the push loop SHOULD NOT try to bind these to a
# device or user. The corresponding ``class_uid`` is 0.
#
# OCSF class ids reference:
#   1007 — Process Activity        (endpoint EDR-shape)
#   3002 — Authentication          (identity)
#   4001 — Network Activity        (network appliance / firewall)
#   4002 — HTTP Activity           (proxy / WAF / CASB)
#   6003 — Web Resources Activity  (cloud control-plane)
_ASSET_BINDING_DEFAULTS: dict[str, dict[str, Any]] = {
    # identity (3002 — Authentication)
    "okta":               {"kind": "identity", "class_uid": 3002},
    "azure_ad":           {"kind": "identity", "class_uid": 3002},
    "cisco_duo":          {"kind": "identity", "class_uid": 3002},
    "m365":               {"kind": "identity", "class_uid": 3002},
    # cloud (6003 — Web Resources Activity)
    "aws_cloudtrail":     {"kind": "cloud",    "class_uid": 6003},
    "aws_guardduty":      {"kind": "cloud",    "class_uid": 6003},
    "aws_waf":            {"kind": "cloud",    "class_uid": 6003},
    "azure_platform":     {"kind": "cloud",    "class_uid": 6003},
    "gcp_audit":          {"kind": "cloud",    "class_uid": 6003},
    # endpoint (1007 — Process Activity)
    "sentinelone":        {"kind": "endpoint", "class_uid": 1007},
    "microsoft_defender": {"kind": "endpoint", "class_uid": 1007},
    # network — 4001 for raw network activity, 4002 for HTTP-shaped feeds
    "cato":               {"kind": "network",  "class_uid": 4001},
    "darktrace":          {"kind": "network",  "class_uid": 4001},
    "cloudflare":         {"kind": "network",  "class_uid": 4002},
    "mimecast":           {"kind": "network",  "class_uid": 4002},
    "netskope":           {"kind": "network",  "class_uid": 4002},
    "proofpoint":         {"kind": "network",  "class_uid": 4002},
    "zscaler_zpa":        {"kind": "network",  "class_uid": 4002},
    # governance — explicit opt-out so the push loop SKIPS binding.
    "snyk":               {"kind": "none",     "class_uid": 0},
    "tenable":            {"kind": "none",     "class_uid": 0},
    "wiz":                {"kind": "none",     "class_uid": 0},
}


def get_asset_binding(source: str) -> dict[str, Any] | None:
    """Return the asset-binding config for *source*, or ``None``.

    Resolution order — module-level constant wins over registry fallback,
    so a vendor source module can pin its kind / class_uid in the same
    file as ``EVENT_CATALOG`` / ``PERSONA_PROJECTION``::

        # sources/some_vendor.py
        ASSET_BINDING = {"kind": "cloud", "class_uid": 6003}

    Returns ``None`` (rather than a stub dict) for unknown source ids
    so the push loop can treat "no binding configured" and "explicit
    opt-out" as separate cases — the latter still ships the event
    (just with no asset stamp), the former skips binding entirely.

    Accepts either canonical module-name ids (``azure_ad``) or
    bindings-UI aliases (``entra_id``, ``defender``); aliases resolve
    via :data:`SOURCE_ID_ALIASES`.
    """
    if not source:
        return None
    source = canonical_source_id(source)
    # Module-level override has priority.
    for name, mod in iter_source_modules():
        if name == source:
            override = getattr(mod, "ASSET_BINDING", None)
            if isinstance(override, dict) and override:
                return override
            break
    # Fallback to the registry table.
    return _ASSET_BINDING_DEFAULTS.get(source)


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
