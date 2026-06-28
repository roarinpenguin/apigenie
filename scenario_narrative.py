"""Scenario narrative fill — persona-anchored background ("a corredo") logs.

Beyond the few alert-triggering events a scenario phase injects (capped by
``max_events``), an analyst needs *context*: benign telemetry that wears the
same persona, so a pivot off an alert lands on a coherent cohort, plus a
plausible *neighbourhood* of look-alike entities (other users in the same
domain, other hosts in the same subnet, other UPNs/SPNs). SentinelOne Purple
AI's agentic auto-investigation queries for events *similar* to the one that
fired an alert; this module makes sure those similar events exist and look
real.

Two strata, both tagged with ``attack.id`` / ``phase.id`` (plus the per-source
preservation tokens the alert path uses, e.g. Proofpoint ``policyRoutes``) so
an operator can isolate the whole campaign in the data lake over a time window:

  * context (~80%)       — the victim persona's own benign activity.
  * neighbourhood (~20%) — sibling entities derived from the persona.

Neither stratum carries the phase's alert-triggering ``field_overrides`` — only
the persona-identity subset projected by the source's ``PERSONA_PROJECTION`` —
so they NEVER satisfy the detection rule and therefore never raise an alert.
The injector (``detection_rules.inject_detection_events``) applies the override
dicts returned here onto random benign base logs.
"""
from __future__ import annotations

import random as _random
from typing import Any

import personas as _personas

# Defaults for the per-scenario ``narrative`` config block. ``factor`` is the
# fraction of the live background batch we mirror as persona-anchored events on
# every poll, clamped to [per_poll_min, per_poll_max] so a tiny or huge batch
# both stay sensible. ``context_ratio`` splits that volume between the persona's
# own activity and the look-alike neighbourhood.
DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "context_ratio": 0.8,
    "factor": 0.5,
    "per_poll_min": 3,
    "per_poll_max": 40,
}


def build_metadata(spliced_overrides: dict[str, Any] | None,
                   projection: dict[str, str] | None,
                   attack_id: str,
                   phase_id: str,
                   source: str,
                   tags: dict[str, Any] | None = None,
                   cfg: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Precompute (once, at temp-rule creation) the narrative metadata stored
    on the phase's temporary rule.

    Returns ``None`` when there's nothing to anchor — no projection for the
    source, no persona-identity fields present in the spliced overrides, or the
    operator disabled the narrative fill for this scenario. A ``None`` result
    means the injector simply skips the narrative pass for that rule (the alert
    path is unaffected).
    """
    if not projection:
        return None
    proj_fields = set(projection.keys())
    identity = {f: v for f, v in (spliced_overrides or {}).items()
                if f in proj_fields and v is not None and v != ""}
    if not identity:
        return None

    cfg = {**DEFAULTS, **(cfg or {})}
    if not cfg.get("enabled", True):
        return None

    slots = {f: projection[f] for f in identity}

    # Reconstruct the (partial) victim bundle from the projected identity so
    # the neighbourhood generator can roll a *consistent* sibling (matching
    # email/upn/username, matching hostname/ip) rather than mutating each field
    # independently into a different person.
    victim_partial: dict[str, dict[str, Any]] = {}
    for field, value in identity.items():
        top, _, leaf = slots[field].partition(".")
        if not leaf:
            continue
        victim_partial.setdefault(top, {})[leaf] = value

    base_tags = dict(tags or {})
    base_tags["attack.id"] = attack_id
    base_tags["phase.id"] = phase_id

    ctx_ratio = min(1.0, max(0.0, float(cfg.get("context_ratio", 0.8))))
    return {
        "identity": identity,
        "slots": slots,
        "victim_partial": victim_partial,
        "tags": base_tags,
        "context_ratio": ctx_ratio,
        "factor": max(0.0, float(cfg.get("factor", 0.5))),
        "per_poll_min": max(0, int(cfg.get("per_poll_min", 3))),
        "per_poll_max": max(0, int(cfg.get("per_poll_max", 40))),
    }


def plan_counts(n_background: int, meta: dict[str, Any]) -> tuple[int, int]:
    """Return ``(n_context, n_neighbourhood)`` for a poll carrying
    *n_background* benign logs."""
    total = round(n_background * meta.get("factor", 0.5))
    total = max(meta.get("per_poll_min", 3),
                min(meta.get("per_poll_max", 40), total))
    n_context = round(total * meta.get("context_ratio", 0.8))
    n_neighbour = max(0, total - n_context)
    return n_context, n_neighbour


def build_override_batch(meta: dict[str, Any], n_background: int,
                         rng: Any = _random) -> list[dict[str, Any]]:
    """Return a shuffled list of override dicts to splice onto random benign
    base logs. Each dict carries the persona (or a sibling's) identity plus the
    correlation tags — but never the alert-triggering fields."""
    n_ctx, n_nbr = plan_counts(n_background, meta)
    tags = meta["tags"]
    identity = meta["identity"]
    slots = meta["slots"]
    out: list[dict[str, Any]] = []

    for _ in range(n_ctx):
        ov = dict(identity)
        ov.update(tags)
        out.append(ov)

    for _ in range(n_nbr):
        sibling = _personas.derive_neighbor_bundle(meta.get("victim_partial"))
        ov: dict[str, Any] = {}
        for field, slot_path in slots.items():
            val = _personas.resolve_path(sibling, slot_path)
            if val is None or val == "":
                continue
            ov[field] = val
        ov.update(tags)
        out.append(ov)

    rng.shuffle(out)
    return out
