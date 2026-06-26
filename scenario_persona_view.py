"""Read-only introspection of how a scenario's persona bundle lands
on the wire.

The runtime path is:

    scenario.personas        (canonical schema dict, one per scenario)
        │
        ▼
    phase.field_overrides    (operator-authored extras, optional)
        │  +
        ▼
    sources.PERSONA_PROJECTION[phase.source]   (per-source map of
        │                                       event_field ⇒ slot_path)
        ▼
    _splice_persona_overrides()
        │
        ▼
    {event_field: resolved_value}  ─►  stamped on a fraction of events
                                       at generation time by
                                       ``detection_rules._apply_overrides``

Until now there was no way for the operator to ask "given this
scenario, what victim email is Okta actually going to emit on the
wire?" without starting the scenario, waiting for an event, and
grepping a collector log. This module gives a synchronous answer:
build the same per-phase resolved-overrides dict the runtime would
build, plus a coverage map showing which canonical persona slots
are exercised by the scenario as a whole.

The output is purely diagnostic — no scenario state is mutated, no
events are generated, no rule is created. Wire it to a GET endpoint
and the operator can see, before clicking Start, exactly what
identity each source will project.
"""
from __future__ import annotations

from typing import Any

import personas
import sources as _sources


def inspect_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    """Build a diagnostic view of ``scenario``'s persona projection.

    Returns a dict shaped like:

    ::

        {
          "scenario_id": "<uuid>",
          "scenario_name": "...",
          "persona": { ...full bundle... },
          "persona_problems": [ ... validate_bundle() output ... ],
          "phases": [
            {
              "phase_id": "...", "source": "okta",
              "mitre_tactic": "Initial Access",
              "projection": [
                {"event_field": "actor.alternateId",
                 "persona_path": "victim_user.email",
                 "resolved_value": "john.doe@acme-corp.test",
                 "source_of_truth": "persona"},
                ...
              ],
              "operator_overrides": {"key": "value", ...},
              "missing_projection": false,
            }, ...
          ],
          "coverage": {
            "victim_user": {"sources": ["okta","m365"], "slots": ["email","upn"]},
            ...
          }
        }

    The ``source_of_truth`` flag tells the operator whether a field
    came from the persona bundle (``"persona"``) or from a per-phase
    ``field_overrides`` entry that the operator authored manually
    (``"operator"``) — useful when debugging why a particular event
    has a value the persona bundle doesn't seem to explain.

    Legacy scenarios that pre-date the persona bundle (no
    ``personas`` key on the record) are handled gracefully:
    ``persona`` is ``{}``, every phase reports
    ``"missing_projection": True``, and the UI degrades to "no
    persona configured" without exceptions.
    """
    if not isinstance(scenario, dict):
        return {"error": "scenario must be a dict"}

    bundle = scenario.get("personas") or {}
    persona_problems = (
        personas.validate_bundle(bundle) if bundle else
        ["no persona bundle on this scenario — pre-v5.x record?"]
    )

    phases_out: list[dict[str, Any]] = []
    # Track which (slot_root, field) pairs were touched by any source —
    # this is the coverage map the UI uses to flag dormant slots
    # ("nothing references attacker.asn in this scenario").
    coverage: dict[str, dict[str, set[str]]] = {}

    for phase in scenario.get("phases") or []:
        if not isinstance(phase, dict):
            continue
        src = phase.get("source") or ""
        projection_map = _sources.get_persona_projection(src) or {}
        operator_overrides = dict(phase.get("field_overrides") or {})

        projection_rows: list[dict[str, Any]] = []
        for event_field, slot_path in projection_map.items():
            # Operator-authored overrides win in the runtime splicer
            # (see attack_scenarios._splice_persona_overrides), so
            # mirror that precedence here for an accurate view.
            if event_field in operator_overrides:
                projection_rows.append({
                    "event_field":    event_field,
                    "persona_path":   slot_path,
                    "resolved_value": operator_overrides[event_field],
                    "source_of_truth": "operator",
                })
                continue
            value = personas.resolve_path(bundle, slot_path) if bundle else None
            projection_rows.append({
                "event_field":     event_field,
                "persona_path":    slot_path,
                "resolved_value":  value,
                "source_of_truth": "persona" if value is not None else "unresolved",
            })
            if value is not None:
                # Update coverage: track which sources hit which
                # (slot_root, field). ``victim_user.email`` ⇒
                # coverage["victim_user"]["sources"].add(src) and
                # coverage["victim_user"]["slots"].add("email").
                root = slot_path.split(".", 1)[0]
                field = slot_path.split(".", 1)[1] if "." in slot_path else ""
                bucket = coverage.setdefault(
                    root, {"sources": set(), "slots": set()})
                bucket["sources"].add(src)
                if field:
                    bucket["slots"].add(field)

        phases_out.append({
            "phase_id":            phase.get("phase_id"),
            "source":              src,
            "mitre_tactic":        phase.get("mitre_tactic"),
            "mitre_technique":     phase.get("mitre_technique"),
            "projection":          projection_rows,
            "operator_overrides":  {
                k: v for k, v in operator_overrides.items()
                if k not in projection_map
            },
            "missing_projection":  not bool(projection_map),
        })

    # Sets aren't JSON-serialisable — convert to sorted lists so the
    # response shape is stable across calls.
    coverage_out = {
        slot: {"sources": sorted(v["sources"]),
               "slots":   sorted(v["slots"])}
        for slot, v in coverage.items()
    }

    return {
        "scenario_id":      scenario.get("id"),
        "scenario_name":    scenario.get("name"),
        "persona":          bundle,
        "persona_problems": persona_problems,
        "phases":           phases_out,
        "coverage":         coverage_out,
    }
