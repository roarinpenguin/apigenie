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
        "enabled": data.get("enabled", True),
        "field_overrides": data.get("field_overrides", {}),
        "periodicity": max(1, int(data.get("periodicity", 10))),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
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
                for key in ("name", "description", "enabled", "field_overrides", "source"):
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

def inject_detection_events(source: str, logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Inject detection-rule events into a batch of normal logs.

    For each active rule matching *source*, inject one event every N logs
    (where N = rule periodicity). The injected event is a copy of a random
    normal log with the rule's field_overrides applied.

    Also supports time-based periodicity: if periodicity > 100, it's treated
    as seconds between fires (e.g. 300 = fire once every 5 minutes).

    Returns the modified log list (may be longer than the input).
    """
    rules = [r for r in _load_rules() if r["source"] == source and r.get("enabled", True)]
    if not rules or not logs:
        return logs

    import random
    now = time.time()
    result = list(logs)
    injected_count = 0

    for rule in rules:
        rule_id = rule["id"]
        periodicity = rule.get("periodicity", 10)
        overrides = rule.get("field_overrides", {})

        if not overrides:
            continue

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

    if injected_count:
        log.debug("Injected %d detection events into %s batch (%d→%d)",
                  injected_count, source, len(logs), len(result))

    return result
