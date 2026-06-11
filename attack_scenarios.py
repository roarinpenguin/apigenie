"""Attack Scenario Builder — multi-source, multi-phase attack simulation.

Orchestrates timed phases across multiple log sources to simulate realistic
attack campaigns mapped to MITRE ATT&CK. Each phase creates temporary
detection rules that inject attack-specific events into normal log flows.

Every injected event carries:
  - attack.id  — unique attack identifier (att-YYYYMMDD-NNNN)
  - phase.id   — MITRE tactic identifier (e.g. initial-access)
"""

from __future__ import annotations

import copy
import json
import logging
import os
import random
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
_SCENARIOS_FILE = _DATA_ROOT / "attack_scenarios.json"
_lock = threading.Lock()

# Active scheduler threads
_active_threads: dict[str, threading.Thread] = {}
_stop_events: dict[str, threading.Event] = {}
_pause_events: dict[str, threading.Event] = {}  # set = paused


# ── Storage ──────────────────────────────────────────────────────────────────

def _load_scenarios() -> list[dict[str, Any]]:
    try:
        if _SCENARIOS_FILE.is_file():
            return json.loads(_SCENARIOS_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("attack scenarios: corrupt file: %s", exc)
    return []


def _save_scenarios(scenarios: list[dict[str, Any]]) -> None:
    _DATA_ROOT.mkdir(parents=True, exist_ok=True)
    tmp = _SCENARIOS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(scenarios, indent=2, default=str))
    tmp.replace(_SCENARIOS_FILE)


def _find(scenarios: list[dict], sid: str) -> dict | None:
    for s in scenarios:
        if s["id"] == sid:
            return s
    return None


# ── Attack ID generation ─────────────────────────────────────────────────────

def generate_attack_id() -> str:
    """Generate attack ID: att-YYYYMMDD-NNNN"""
    now = datetime.now(timezone.utc)
    return f"att-{now.strftime('%Y%m%d')}-{random.randint(1000, 9999)}"


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_scenario(data: dict[str, Any]) -> dict[str, Any]:
    scenario = {
        "id": str(uuid.uuid4()),
        "name": data.get("name", "Untitled Scenario"),
        "template": data.get("template"),
        "attack_id": generate_attack_id(),
        "status": "stopped",
        "profile_id": data.get("profile_id"),
        "duration": data.get("duration", {"value": 4, "unit": "hours"}),
        "phases": data.get("phases", []),
        "events_injected": 0,
        "started_at": "",
        "paused_at": "",
        "elapsed_seconds": 0,
        "error": "",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    # Ensure each phase has an id
    for i, phase in enumerate(scenario["phases"]):
        if "id" not in phase:
            phase["id"] = f"phase-{i}"
        phase["status"] = "pending"
        phase["events_count"] = 0
    with _lock:
        scenarios = _load_scenarios()
        scenarios.append(scenario)
        _save_scenarios(scenarios)
    log.info("Scenario created: %s (%s)", scenario["name"], scenario["id"])
    return scenario


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    for s in _load_scenarios():
        if s["id"] == scenario_id:
            # Sync runtime status
            if s["id"] in _active_threads and _active_threads[s["id"]].is_alive():
                s["status"] = "running"
            return s
    return None


def update_scenario(scenario_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
    with _lock:
        scenarios = _load_scenarios()
        s = _find(scenarios, scenario_id)
        if not s:
            return None
        for key in ("name", "duration", "phases", "profile_id"):
            if key in data:
                s[key] = data[key]
        _save_scenarios(scenarios)
    return s


def delete_scenario(scenario_id: str) -> bool:
    stop_scenario(scenario_id)
    with _lock:
        scenarios = _load_scenarios()
        before = len(scenarios)
        scenarios = [s for s in scenarios if s["id"] != scenario_id]
        if len(scenarios) == before:
            return False
        _save_scenarios(scenarios)
    return True


def list_scenarios() -> list[dict[str, Any]]:
    scenarios = _load_scenarios()
    for s in scenarios:
        sid = s["id"]
        if sid in _active_threads and _active_threads[sid].is_alive():
            if sid in _pause_events and _pause_events[sid].is_set():
                s["status"] = "paused"
            else:
                s["status"] = "running"
        elif s["status"] == "running":
            s["status"] = "completed"
    return scenarios


# ── Validation, export, import (Phase 2 — custom scenario builder) ───────────

# Fields that exist only at runtime — they're regenerated whenever a scenario
# is started and must NOT round-trip through export/import (would otherwise
# leak attack IDs from one operator's lab into another's).
_RUNTIME_FIELDS: tuple[str, ...] = (
    "id", "attack_id", "status", "events_injected", "started_at",
    "paused_at", "elapsed_seconds", "error", "created", "template",
)

# Per-phase keys to keep in the exported JSON. Runtime status fields
# (status, events_count) are excluded — they're populated by the scheduler
# and have no meaning in a portable template.
_EXPORT_PHASE_KEYS: tuple[str, ...] = (
    "phase_id", "name", "source", "mitre_tactic", "mitre_technique",
    "time_offset_pct", "duration_pct", "periodicity", "field_overrides",
)


def validate_scenario_payload(data: Any) -> list[str]:
    """Return a list of human-readable validation errors. Empty list means
    the payload is acceptable for create / import / update. Designed to be
    strict enough to keep a malformed phase from crashing the scheduler at
    runtime, but lenient about optional fields (description, sources can
    differ across deployments)."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["payload must be a JSON object"]
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("'name' is required and must be a non-empty string")
    duration = data.get("duration") or {}
    if not isinstance(duration, dict):
        errors.append("'duration' must be an object {value, unit}")
    else:
        if not isinstance(duration.get("value"), (int, float)) or duration.get("value", 0) <= 0:
            errors.append("'duration.value' must be a positive number")
        if duration.get("unit") not in ("seconds", "minutes", "hours", "days", "weeks"):
            errors.append("'duration.unit' must be one of seconds|minutes|hours|days|weeks")
    phases = data.get("phases")
    if not isinstance(phases, list) or not phases:
        errors.append("'phases' must be a non-empty array")
        return errors
    for i, p in enumerate(phases):
        if not isinstance(p, dict):
            errors.append(f"phase #{i}: must be an object")
            continue
        for k in ("name", "source", "mitre_tactic", "mitre_technique"):
            if not isinstance(p.get(k), str) or not p.get(k, "").strip():
                errors.append(f"phase #{i}: '{k}' is required and must be a non-empty string")
        for k in ("time_offset_pct", "duration_pct"):
            v = p.get(k)
            if not isinstance(v, (int, float)) or not 0 <= v <= 100:
                errors.append(f"phase #{i}: '{k}' must be a number in [0, 100]")
        if p.get("time_offset_pct", 0) + p.get("duration_pct", 0) > 100:
            errors.append(
                f"phase #{i}: time_offset_pct + duration_pct exceeds 100 "
                f"(phase would end after the scenario does)")
        per = p.get("periodicity", 5)
        if not isinstance(per, (int, float)) or per <= 0:
            errors.append(f"phase #{i}: 'periodicity' must be a positive number")
        fo = p.get("field_overrides", {})
        if fo is not None and not isinstance(fo, dict):
            errors.append(f"phase #{i}: 'field_overrides' must be an object")
    return errors


def export_scenario(scenario_id: str) -> dict[str, Any] | None:
    """Return a portable JSON-serialisable copy of the scenario, stripped
    of runtime / instance-specific fields. ``None`` if no such scenario.

    The export format is intentionally a strict subset of what
    ``create_scenario`` accepts, so a round-trip is lossless for the
    fields a user can edit in the builder UI.
    """
    s = get_scenario(scenario_id)
    if not s:
        return None
    out: dict[str, Any] = {
        "name": s.get("name", ""),
        "description": s.get("description", ""),
        "duration": s.get("duration", {"value": 4, "unit": "hours"}),
        "profile_id": s.get("profile_id"),
        "phases": [],
        "_apigenie_schema": "attack_scenario/v1",
    }
    for p in s.get("phases", []):
        out["phases"].append({k: p[k] for k in _EXPORT_PHASE_KEYS if k in p})
    return out


def import_scenario(data: Any) -> dict[str, Any]:
    """Validate ``data`` (as returned by ``export_scenario`` or hand-written)
    and persist it as a new scenario. Raises ``ValueError`` on failure with
    a multi-line message so the REST handler can return a 400 carrying the
    full list of problems."""
    errors = validate_scenario_payload(data)
    if errors:
        raise ValueError("\n".join(errors))
    # Strip the schema marker if present — it's metadata, not a scenario field.
    payload = {k: v for k, v in data.items() if k != "_apigenie_schema"}
    return create_scenario(payload)


# ── Phase timing ─────────────────────────────────────────────────────────────

def _duration_to_seconds(duration: dict) -> int:
    multipliers = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}
    return duration.get("value", 1) * multipliers.get(duration.get("unit", "hours"), 3600)


def _calculate_phase_windows(phases: list[dict], total_seconds: int, start_time: float) -> list[dict]:
    """Calculate absolute start/end times for each phase."""
    windows = []
    for phase in phases:
        offset_pct = phase.get("time_offset_pct", 0) / 100.0
        duration_pct = phase.get("duration_pct", 10) / 100.0
        phase_start = start_time + (total_seconds * offset_pct)
        phase_end = phase_start + (total_seconds * duration_pct)
        windows.append({
            **phase,
            "_abs_start": phase_start,
            "_abs_end": phase_end,
            "_rule_id": None,
            "_push_started": False,
        })
    return windows


# ── Temporary detection rule management ──────────────────────────────────────

def _create_temp_rule(phase: dict, attack_id: str, scenario_id: str,
                       total_seconds: int, phase_start: float) -> str | None:
    """Create a temporary detection rule for a phase. Returns the rule ID."""
    import detection_rules

    # Calculate backdated timestamp for this phase
    now = time.time()
    time_into_scenario = now - phase_start
    total_offset = phase.get("time_offset_pct", 0) / 100.0
    backdate_seconds = total_seconds * total_offset

    overrides = dict(phase.get("field_overrides", {}))
    overrides["attack.id"] = attack_id
    overrides["phase.id"] = phase.get("phase_id", "unknown")

    rule_data = {
        "name": f"[SCENARIO] {phase.get('name', 'phase')}",
        "source": phase.get("source", ""),
        "description": f"Attack scenario phase: {phase.get('mitre_tactic', '')} ({phase.get('mitre_technique', '')})",
        "periodicity": phase.get("periodicity", 5),
        "enabled": True,
        "field_overrides": overrides,
        "_scenario_id": scenario_id,
        "_attack_id": attack_id,
    }

    rule = detection_rules.create_rule(rule_data)
    return rule.get("id") if rule else None


def _delete_temp_rule(rule_id: str) -> None:
    """Delete a temporary detection rule."""
    import detection_rules
    try:
        detection_rules.delete_rule(rule_id)
    except Exception as exc:
        log.warning("Failed to delete temp rule %s: %s", rule_id, exc)


def _cleanup_scenario_rules(scenario_id: str) -> None:
    """Delete all temporary rules for a scenario."""
    import detection_rules
    rules = detection_rules.list_rules()
    for r in rules:
        if r.get("_scenario_id") == scenario_id:
            detection_rules.delete_rule(r["id"])


# ── Push profile auto-start/stop ─────────────────────────────────────────────

def _find_push_profile_for_source(source: str) -> str | None:
    """Find a push profile matching the given source type."""
    import log_pusher
    for p in log_pusher.list_profiles():
        if p.get("source_type") == source and p.get("status") != "running":
            return p["id"]
    return None


def _auto_start_push(source: str) -> str | None:
    """Auto-start a push profile for a source. Returns profile ID or None."""
    import log_pusher
    pid = _find_push_profile_for_source(source)
    if pid:
        result = log_pusher.start_push(pid)
        if not isinstance(result, str):
            log.info("Auto-started push profile %s for source %s", pid[:8], source)
            return pid
    return None


def _auto_stop_push(profile_id: str) -> None:
    """Auto-stop a push profile."""
    import log_pusher
    log_pusher.stop_push(profile_id)
    log.info("Auto-stopped push profile %s", profile_id[:8])


# ── Scheduler ────────────────────────────────────────────────────────────────

def _is_push_source(source: str) -> bool:
    """Check if a source is a push source (not an HTTP pull source)."""
    import log_pusher
    import push_sources  # triggers registration
    return source in log_pusher.PUSH_SOURCE_TYPES


def _update_scenario_status(scenario_id: str, **kwargs) -> None:
    with _lock:
        scenarios = _load_scenarios()
        s = _find(scenarios, scenario_id)
        if s:
            for k, v in kwargs.items():
                s[k] = v
            _save_scenarios(scenarios)


def _update_phase_status(scenario_id: str, phase_id: str, **kwargs) -> None:
    with _lock:
        scenarios = _load_scenarios()
        s = _find(scenarios, scenario_id)
        if s:
            for phase in s.get("phases", []):
                if phase.get("id") == phase_id or phase.get("phase_id") == phase_id:
                    for k, v in kwargs.items():
                        phase[k] = v
            _save_scenarios(scenarios)


def _scheduler_loop(scenario_id: str) -> None:
    """Main scheduler loop for a scenario."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        return

    attack_id = scenario["attack_id"]
    total_seconds = _duration_to_seconds(scenario.get("duration", {}))
    start_time = time.time()
    elapsed_prior = scenario.get("elapsed_seconds", 0)

    # If resuming, adjust start_time to account for prior elapsed time
    if elapsed_prior > 0:
        start_time -= elapsed_prior

    phases = _calculate_phase_windows(scenario["phases"], total_seconds, start_time)
    stop_event = _stop_events.get(scenario_id)
    pause_event = _pause_events.get(scenario_id)

    log.info("Scenario %s started: %s (%s, %ds, %d phases)",
             scenario_id[:8], scenario["name"], attack_id, total_seconds, len(phases))

    _update_scenario_status(scenario_id, status="running",
                            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    total_injected = 0
    active_push_profiles: dict[str, str] = {}  # phase_id → push_profile_id

    try:
        while True:
            if stop_event and stop_event.is_set():
                break

            # Handle pause
            if pause_event and pause_event.is_set():
                pause_start = time.time()
                _update_scenario_status(scenario_id, status="paused",
                                        paused_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
                log.info("Scenario %s paused", scenario_id[:8])

                # Disable all active rules during pause
                for pw in phases:
                    if pw.get("_rule_id"):
                        import detection_rules
                        detection_rules.update_rule(pw["_rule_id"], {"enabled": False})

                # Wait for unpause or stop
                while pause_event.is_set():
                    if stop_event and stop_event.is_set():
                        break
                    time.sleep(1)

                if stop_event and stop_event.is_set():
                    break

                # Resume: shift all windows by pause duration
                pause_duration = time.time() - pause_start
                for pw in phases:
                    pw["_abs_start"] += pause_duration
                    pw["_abs_end"] += pause_duration
                    if pw.get("_rule_id"):
                        import detection_rules
                        detection_rules.update_rule(pw["_rule_id"], {"enabled": True})

                _update_scenario_status(scenario_id, status="running", paused_at="")
                log.info("Scenario %s resumed (paused for %ds)", scenario_id[:8], int(pause_duration))

            now = time.time()
            all_done = True

            for pw in phases:
                phase_id = pw.get("phase_id", pw.get("id", "?"))

                # Phase should start
                if now >= pw["_abs_start"] and now < pw["_abs_end"]:
                    all_done = False
                    if pw.get("_rule_id") is None:
                        # Create detection rule for this phase
                        rule_id = _create_temp_rule(pw, attack_id, scenario_id,
                                                     total_seconds, start_time)
                        pw["_rule_id"] = rule_id
                        _update_phase_status(scenario_id, phase_id, status="active")
                        log.info("Phase '%s' activated on %s", pw.get("name", phase_id), pw.get("source"))

                        # Auto-start push profile if needed
                        if _is_push_source(pw.get("source", "")):
                            push_pid = _auto_start_push(pw.get("source", ""))
                            if push_pid:
                                active_push_profiles[phase_id] = push_pid
                                pw["_push_started"] = True

                # Phase should end
                elif now >= pw["_abs_end"] and pw.get("_rule_id"):
                    _delete_temp_rule(pw["_rule_id"])
                    pw["_rule_id"] = None
                    _update_phase_status(scenario_id, phase_id, status="completed")
                    log.info("Phase '%s' completed", pw.get("name", phase_id))

                    # Auto-stop push profile
                    if phase_id in active_push_profiles:
                        _auto_stop_push(active_push_profiles.pop(phase_id))

                # Phase not yet started
                elif now < pw["_abs_start"]:
                    all_done = False

            # Update elapsed
            elapsed = time.time() - start_time
            _update_scenario_status(scenario_id, elapsed_seconds=int(elapsed))

            if all_done:
                break

            time.sleep(5)

    finally:
        # Cleanup: delete all scenario rules and stop push profiles
        _cleanup_scenario_rules(scenario_id)
        for push_pid in active_push_profiles.values():
            _auto_stop_push(push_pid)

        status = "stopped" if (stop_event and stop_event.is_set()) else "completed"
        _update_scenario_status(scenario_id, status=status)
        log.info("Scenario %s %s (%s)", scenario_id[:8], status, attack_id)


# ── Start / Stop / Pause / Resume ────────────────────────────────────────────

def start_scenario(scenario_id: str) -> dict[str, Any] | str:
    scenario = get_scenario(scenario_id)
    if not scenario:
        return "Scenario not found"
    if scenario_id in _active_threads and _active_threads[scenario_id].is_alive():
        return "Already running"

    # Generate fresh attack_id on each start
    attack_id = generate_attack_id()
    _update_scenario_status(scenario_id, attack_id=attack_id, events_injected=0,
                            elapsed_seconds=0, error="")
    # Reset phase statuses
    for phase in scenario.get("phases", []):
        phase_id = phase.get("phase_id", phase.get("id", "?"))
        _update_phase_status(scenario_id, phase_id, status="pending", events_count=0)

    stop_event = threading.Event()
    pause_event = threading.Event()
    _stop_events[scenario_id] = stop_event
    _pause_events[scenario_id] = pause_event

    t = threading.Thread(target=_scheduler_loop, args=(scenario_id,), daemon=True,
                         name=f"scenario-{scenario_id[:8]}")
    _active_threads[scenario_id] = t
    t.start()
    return scenario


def stop_scenario(scenario_id: str) -> bool:
    ev = _stop_events.pop(scenario_id, None)
    pause_ev = _pause_events.pop(scenario_id, None)
    if pause_ev:
        pause_ev.clear()  # unpause so thread can exit
    if ev:
        ev.set()
    t = _active_threads.pop(scenario_id, None)
    if t and t.is_alive():
        t.join(timeout=10)
        _update_scenario_status(scenario_id, status="stopped")
        _cleanup_scenario_rules(scenario_id)
        return True
    return False


def pause_scenario(scenario_id: str) -> bool:
    ev = _pause_events.get(scenario_id)
    if ev and not ev.is_set():
        ev.set()
        return True
    return False


def resume_scenario(scenario_id: str) -> bool:
    ev = _pause_events.get(scenario_id)
    if ev and ev.is_set():
        ev.clear()
        return True
    return False


def get_scenario_status(scenario_id: str) -> dict[str, Any]:
    scenario = get_scenario(scenario_id)
    if not scenario:
        return {"error": "not found"}
    running = scenario_id in _active_threads and _active_threads[scenario_id].is_alive()
    paused = scenario_id in _pause_events and _pause_events[scenario_id].is_set()
    return {
        "id": scenario_id,
        "attack_id": scenario.get("attack_id", ""),
        "status": "paused" if paused else ("running" if running else scenario.get("status", "stopped")),
        "elapsed_seconds": scenario.get("elapsed_seconds", 0),
        "phases": [{
            "phase_id": p.get("phase_id", p.get("id")),
            "name": p.get("name", ""),
            "source": p.get("source", ""),
            "mitre_tactic": p.get("mitre_tactic", ""),
            "mitre_technique": p.get("mitre_technique", ""),
            "status": p.get("status", "pending"),
        } for p in scenario.get("phases", [])],
    }
