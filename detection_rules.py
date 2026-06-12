"""Detection Rules — per-source alert-triggering log templates.

Each rule defines field overrides that, when applied to a normal log entry,
produce events matching specific SIEM detection rules. Rules have a configurable
periodicity that controls how often they fire within the normal log flow.

Rules are stored in ``DATA_ROOT/detection_rules.json``.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
_RULES_FILE = _DATA_ROOT / "detection_rules.json"
_lock = threading.Lock()

# Track last fire time per rule to enforce periodicity
_last_fired: dict[str, float] = {}


# ── Storage ──────────────────────────────────────────────────────────────────

def _load_rules() -> list[dict[str, Any]]:
    try:
        if _RULES_FILE.is_file():
            return json.loads(_RULES_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("detection_rules: corrupt file: %s", exc)
    return []


def _save_rules(rules: list[dict[str, Any]]) -> None:
    _DATA_ROOT.mkdir(parents=True, exist_ok=True)
    tmp = _RULES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(rules, indent=2, default=str))
    tmp.replace(_RULES_FILE)


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_rule(data: dict[str, Any]) -> dict[str, Any]:
    """Create a new detection rule. Returns the saved rule."""
    rule = {
        "id": str(uuid.uuid4()),
        "name": data.get("name", "Untitled rule"),
        "source": data.get("source", ""),
        "description": data.get("description", ""),
        "owner_id": data.get("owner_id"),
        "visibility": data.get("visibility", "private"),
        "enabled": data.get("enabled", True),
        "field_overrides": data.get("field_overrides", {}),
        "periodicity": max(1, int(data.get("periodicity", 10))),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    # Preserve scenario metadata if present (attack scenario temporary rules)
    if "_scenario_id" in data:
        rule["_scenario_id"] = data["_scenario_id"]
    if "_attack_id" in data:
        rule["_attack_id"] = data["_attack_id"]
    with _lock:
        rules = _load_rules()
        rules.append(rule)
        _save_rules(rules)
    log.info("Detection rule created: %s for %s", rule["name"], rule["source"])
    return rule


def get_rule(rule_id: str) -> dict[str, Any] | None:
    for r in _load_rules():
        if r["id"] == rule_id:
            return r
    return None


def update_rule(rule_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
    with _lock:
        rules = _load_rules()
        for r in rules:
            if r["id"] == rule_id:
                for key in ("name", "description", "enabled", "field_overrides", "source", "visibility"):
                    if key in data:
                        r[key] = data[key]
                if "periodicity" in data:
                    r["periodicity"] = max(1, int(data["periodicity"]))
                _save_rules(rules)
                log.info("Detection rule updated: %s", rule_id)
                return r
    return None


def delete_rule(rule_id: str) -> bool:
    with _lock:
        rules = _load_rules()
        before = len(rules)
        rules = [r for r in rules if r["id"] != rule_id]
        if len(rules) == before:
            return False
        _save_rules(rules)
    log.info("Detection rule deleted: %s", rule_id)
    return True


def list_rules(source: str | None = None) -> list[dict[str, Any]]:
    """List all rules, optionally filtered by source."""
    rules = _load_rules()
    if source:
        rules = [r for r in rules if r["source"] == source]
    return rules


# ── Field override application ───────────────────────────────────────────────

def _set_nested(obj: dict, dotted_key: str, value: Any) -> None:
    """Set a value in a nested dict using dot notation (e.g. 'outcome.result')."""
    parts = dotted_key.split(".")
    for part in parts[:-1]:
        if part not in obj or not isinstance(obj[part], dict):
            obj[part] = {}
        obj = obj[part]
    obj[parts[-1]] = value


def _apply_overrides(log_entry: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Apply field overrides to a log entry (deep copy first)."""
    entry = copy.deepcopy(log_entry)
    for key, value in overrides.items():
        _set_nested(entry, key, value)
    return entry


# ── Injection into log batches ───────────────────────────────────────────────

def _rule_visible_to_caller(rule: dict[str, Any], caller_id: str | None) -> bool:
    """Mirror admin._can_see_obj for detection rules.

    Rules with no owner_id are admin/global and fire for everyone. Public rules
    fire for everyone. Private rules fire only when their owner is the resolved
    caller. Legacy rules saved before Phase 2 lack both keys and default to
    admin-owned/public (fire for everyone) — see test_legacy_rule_without_owner.
    """
    owner = rule.get("owner_id")
    if owner is None:
        return True
    visibility = rule.get("visibility") or "public"
    if visibility == "public":
        return True
    return caller_id is not None and owner == caller_id


def inject_detection_events(source: str, logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Inject detection-rule events into a batch of normal logs.

    For each active rule matching *source* AND visible to the resolved caller,
    inject one event every N logs (where N = rule periodicity). The injected
    event is a copy of a random normal log with the rule's field_overrides
    applied.

    Also supports time-based periodicity: if periodicity > 100, it's treated
    as seconds between fires (e.g. 300 = fire once every 5 minutes).

    Returns the modified log list (may be longer than the input).
    """
    # v5.1 Phase C — drain any historical-mode scenario backlog for this
    # source first. Drained events are prepended to the live batch with
    # their original (backdated) timestamps preserved; per-source and
    # per-caller cursors ensure each caller's collector consumes its
    # slice exactly once. The drain is per-call cheap (one stat per
    # scenario, JSONL scan only when there is something to consume).
    try:
        import attack_scenarios
        backlog = attack_scenarios.drain_historical_backlog(source)
    except Exception:
        backlog = []
    if backlog:
        logs = list(backlog) + list(logs)

    # Resolve the caller (set by auth.py when a request's credential matches a
    # registered identifier; None for unauthenticated / bus-based ingest).
    # Imported lazily to avoid a hard dependency for callers that don't set it.
    try:
        from profiles import get_current_user
        caller_id = get_current_user()
    except Exception:
        caller_id = None
    rules = [r for r in _load_rules()
             if r["source"] == source
             and r.get("enabled", True)
             and _rule_visible_to_caller(r, caller_id)]
    if not rules or not logs:
        return logs

    import random
    now = time.time()
    result = list(logs)
    injected_count = 0

    # Lazy-imported recorder; only used for rules created by the attack
    # scenario engine (those carry ``_scenario_id``). Plain user-defined rules
    # bypass this path completely.
    _scn_record = None

    for rule in rules:
        rule_id = rule["id"]
        periodicity = rule.get("periodicity", 10)
        overrides = rule.get("field_overrides", {})

        if not overrides:
            continue

        # Per-scenario log hook (v5.0 Phase 3): if this is a scenario temp
        # rule, every successful injection gets recorded into the scenario's
        # ring buffer. Resolve the recorder once per call to keep the cost
        # off the normal-rule path.
        rule_scenario_id = rule.get("_scenario_id")
        if rule_scenario_id and _scn_record is None:
            try:
                from attack_scenarios import _record_event_safe as _scn_record  # noqa: F401
            except Exception:
                _scn_record = lambda *a, **k: None  # noqa: E731

        if periodicity > 100:
            # Time-based: fire if enough seconds have passed since last fire
            last = _last_fired.get(rule_id, 0)
            if now - last < periodicity:
                continue
            # Fire once
            base = random.choice(logs)
            detection_event = _apply_overrides(base, overrides)
            detection_event["_detection_rule"] = rule["name"]
            pos = random.randint(0, len(result))
            result.insert(pos, detection_event)
            _last_fired[rule_id] = now
            injected_count += 1
            if rule_scenario_id:
                _scn_record(rule_scenario_id,
                            overrides.get("phase.id", ""),
                            rule.get("_attack_id", ""),
                            source, detection_event)
        else:
            # Count-based: inject 1 event per N logs
            count = max(1, len(logs) // periodicity)
            for _ in range(count):
                base = random.choice(logs)
                detection_event = _apply_overrides(base, overrides)
                detection_event["_detection_rule"] = rule["name"]
                pos = random.randint(0, len(result))
                result.insert(pos, detection_event)
                injected_count += 1
                if rule_scenario_id:
                    _scn_record(rule_scenario_id,
                                overrides.get("phase.id", ""),
                                rule.get("_attack_id", ""),
                                source, detection_event)

    if injected_count:
        log.debug("Injected %d detection events into %s batch (%d→%d)",
                  injected_count, source, len(logs), len(result))

    return result
