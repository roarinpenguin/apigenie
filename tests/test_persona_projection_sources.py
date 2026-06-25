"""Tests for the per-source PERSONA_PROJECTION map (v5.3 Step 1, Layer 2).

Every source the scenario engine can drive must declare a
``PERSONA_PROJECTION`` dict at module scope. The dict maps **OCSF /
source-native dotted field paths** that exist on a real event from
that source to **canonical persona slot paths** (e.g.
``victim_user.email``, ``attacker.ip``) defined in
:mod:`personas.CANONICAL_SCHEMA`.

When the scenario engine creates a temp detection rule for a phase
on source X, it expands the rule's ``field_overrides`` with X's
projection: every target field whose persona slot is populated gets
the canonical value stamped on it. End result: an Okta event, a
Proofpoint message, a Defender alert, an M365 audit record and a
Netskope page-visit all reference the SAME `john.doe@acme.test`,
the SAME laptop hostname, the SAME attacker IP — for the full
lifetime of the scenario.

Contract enforced here:

* The 8 v5.3-priority sources each expose a non-empty
  ``PERSONA_PROJECTION`` dict.
* Every persona slot referenced is a valid path under
  ``personas.CANONICAL_SCHEMA`` (no typos like ``victim_user.emai``).
* The aliases known to ``sources.SOURCE_ID_ALIASES`` resolve
  transparently — ``get_persona_projection('entra_id')`` returns
  the Azure AD map and ``get_persona_projection('defender')`` the
  Microsoft Defender one.
* ``get_persona_projection`` returns ``None`` for unknown / not-yet-
  wired sources (caller must treat None as "skip projection"; the
  rule engine still emits the phase's own overrides).
"""
from __future__ import annotations


# v5.3 priority list: the 8 sources we wire personas through first.
# Extras can be added incrementally without touching this test (the
# coverage check below iterates them explicitly).
_PRIORITY_SOURCES = [
    "okta",
    "proofpoint",
    "microsoft_defender",
    "azure_ad",
    "m365",
    "netskope",
    "aws_cloudtrail",
    "cisco_duo",
]


# ── Each priority source declares a projection ──────────────────────


def test_each_priority_source_has_persona_projection():
    """A new source added to the priority list above must ship with a
    PERSONA_PROJECTION constant in its module. Forgetting it means
    the scenario engine silently leaves that source uncorrelated."""
    import importlib

    missing = []
    empty = []
    for src in _PRIORITY_SOURCES:
        mod = importlib.import_module(f"sources.{src}")
        proj = getattr(mod, "PERSONA_PROJECTION", None)
        if proj is None:
            missing.append(src)
            continue
        if not isinstance(proj, dict) or not proj:
            empty.append(src)
    assert not missing, f"sources missing PERSONA_PROJECTION: {missing}"
    assert not empty, f"sources with empty PERSONA_PROJECTION: {empty}"


# ── No typos in the referenced persona slots ────────────────────────


def test_every_persona_slot_referenced_exists_in_canonical_schema():
    """Catch typos at boot time. If a source maps a field to
    'victim_user.emai' (missing l), the rule engine would silently
    fall through to None and the wire would carry an empty field —
    the test asserts every right-hand-side path is real."""
    import importlib
    import personas

    valid_paths = {
        f"{slot}.{field}"
        for slot, fields in personas.CANONICAL_SCHEMA.items()
        for field in fields
    }

    offenders: list[tuple[str, str, str]] = []
    for src in _PRIORITY_SOURCES:
        mod = importlib.import_module(f"sources.{src}")
        proj = getattr(mod, "PERSONA_PROJECTION", {}) or {}
        for event_field, slot_path in proj.items():
            if slot_path not in valid_paths:
                offenders.append((src, event_field, slot_path))
    assert not offenders, (
        f"projections reference unknown persona slot paths: {offenders}")


# ── Registry helper resolves via the source __init__ ────────────────


def test_get_persona_projection_resolves_canonical_source_ids():
    """The sources package exposes a ``get_persona_projection(name)``
    helper that mirrors the existing ``get_event_catalog`` pattern.
    For a canonical source id it returns that source's projection."""
    import sources

    proj = sources.get_persona_projection("okta")
    assert isinstance(proj, dict) and proj, (
        "okta projection must be non-empty")


def test_get_persona_projection_resolves_aliases():
    """The bindings UI uses 'entra_id' and 'defender' as source ids
    even though the modules are 'azure_ad' and 'microsoft_defender'.
    Without alias resolution scenarios that use the UI-side ids would
    silently skip persona splicing."""
    import sources

    entra = sources.get_persona_projection("entra_id")
    aad   = sources.get_persona_projection("azure_ad")
    assert entra == aad and entra, (
        "entra_id alias must resolve to azure_ad projection")

    defender = sources.get_persona_projection("defender")
    msdef    = sources.get_persona_projection("microsoft_defender")
    assert defender == msdef and defender, (
        "defender alias must resolve to microsoft_defender projection")


def test_get_persona_projection_returns_none_for_unknown():
    """Sources not yet wired (e.g. wiz, tenable, snyk in v5.3 phase 1)
    must return None — the rule engine treats None as 'skip splicing',
    which keeps phases on those sources running with their existing
    random data and never crashes."""
    import sources

    assert sources.get_persona_projection("not-a-real-source") is None
    # An empty / missing PERSONA_PROJECTION on a real module also
    # comes back as None (None signals "no projection to splice").
    # darktrace doesn't have one in v5.3 phase 1.
    assert sources.get_persona_projection("darktrace") is None
