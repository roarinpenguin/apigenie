"""Attack Scenario Builder — multi-source, multi-phase attack simulation.

Orchestrates timed phases across multiple log sources to simulate realistic
attack campaigns mapped to MITRE ATT&CK. Each phase creates temporary
detection rules that inject attack-specific events into normal log flows.

Every injected event carries:
  - attack.id  — unique attack identifier (att-YYYYMMDD-NNNN)
  - phase.id   — MITRE tactic identifier (e.g. initial-access)
"""

from __future__ import annotations

import collections
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
_pause_events: dict[str, threading.Event] = {}


# ── v5.1 Phase C — historical mode + setup notes ────────────────────────────
#
# `historical` scenarios pre-compute every event they would have emitted, age
# the timestamps backwards across the full duration, and queue them in a
# per-scenario, per-source on-disk backlog. The first collector pull on each
# source drains its slice ahead of the live event mix — making the attack
# story immediately visible at realistic historical timestamps.

# Static per-source hint registry used by `_generate_setup_notes`. Adding a
# simulated source means adding one row — keep entries terse, accurate to the
# vendor's docs, and operator-focused (what to configure, where, with which
# token). `kind` ∈ {"pull", "push", "bus", "unknown"}.
_SOURCE_SETUP_HINTS: dict[str, dict[str, Any]] = {
    # ── HTTP pull sources (collector polls the apigenie endpoint) ─────────
    "okta": {
        "kind": "pull",
        "endpoint": "GET /api/v1/logs",
        "auth": "SSWS <user API token>",
        "options": ["since=<ISO8601>", "limit=100"],
        "notes": "Configure an Okta System Log collector pointed at this endpoint with your per-user API token. Historical-mode scenarios are served at their backdated timestamps on the first poll.",
    },
    "aws_cloudtrail": {
        "kind": "pull",
        "endpoint": "POST /cloudtrail/LookupEvents",
        "auth": "AWS SigV4 (any non-empty Authorization header is accepted in the lab)",
        "options": ["MaxResults=50", "NextToken=<paging>"],
        "notes": "Point a CloudTrail collector / Lambda fan-out at this endpoint. The `eventTime` field is overridden to the backdated timestamp in historical mode.",
    },
    "aws_guardduty": {
        "kind": "pull",
        "endpoint": "GET /guardduty/detector/<id>/findings",
        "auth": "AWS SigV4 (lab-accepted as above)",
        "options": ["MaxResults=50"],
        "notes": "Standard GuardDuty findings collector. Historical events are stamped on `UpdatedAt`.",
    },
    "aws_waf": {
        "kind": "pull",
        "endpoint": "GET /waf/logs",
        "auth": "AWS SigV4",
        "options": ["limit=100"],
        "notes": "WAFv2 logging collector — point your Kinesis Firehose or polling agent here.",
    },
    "azure_ad": {
        "kind": "pull",
        "endpoint": "GET /v1.0/auditLogs/directoryAudits",
        "auth": "Bearer <Microsoft Graph token>",
        "options": ["$top=100", "$filter=<OData>"],
        "notes": "Microsoft Entra ID (legacy Azure AD) audit-log collector. Aka source-id `entra_id`.",
    },
    "cato": {
        "kind": "pull",
        "endpoint": "POST /api/v1/graphql2 (Cato Events Feed)",
        "auth": "x-api-key: <Cato API key>",
        "options": ["marker=<paging>"],
        "notes": "GraphQL Events Feed. Historical timestamps go on the `event_time` field.",
    },
    "cisco_duo": {
        "kind": "pull",
        "endpoint": "GET /admin/v1/logs/authentication",
        "auth": "HMAC-SHA1 signature with Duo integration key",
        "options": ["mintime", "maxtime", "limit=100"],
        "notes": "Duo Admin API collector. Timestamps land on `timestamp`.",
    },
    "cloudflare": {
        "kind": "pull",
        "endpoint": "GET /api/v4/zones/<zone>/logs/received",
        "auth": "X-Auth-Email + X-Auth-Key, or Bearer token",
        "options": ["start=<ISO>", "end=<ISO>"],
        "notes": "Cloudflare Logpush / Audit Logs collector.",
    },
    "darktrace": {
        "kind": "pull",
        "endpoint": "GET /modelbreaches",
        "auth": "DT API token signature",
        "options": ["minscore", "starttime", "endtime"],
        "notes": "Darktrace REST collector — model breaches + AI Analyst incidents.",
    },
    "gcp_audit": {
        "kind": "pull",
        "endpoint": "GET /v1/projects/<id>/logs:list",
        "auth": "Bearer <Google OAuth token>",
        "options": ["pageSize=50"],
        "notes": "Cloud Audit Logs (activity/system/data-access). Also exposed via Pub/Sub for push delivery — see `kind=bus`.",
    },
    "m365": {
        "kind": "pull",
        "endpoint": "GET /api/v1.0/<tenant>/activity/feed/subscriptions/content",
        "auth": "Bearer <Microsoft Graph token>",
        "options": ["contentType=Audit.<workload>"],
        "notes": "Microsoft 365 Management Activity API collector.",
    },
    "microsoft_defender": {
        "kind": "pull",
        "endpoint": "GET /api/alertsAndIncidents",
        "auth": "Bearer <Defender XDR token>",
        "options": ["$top=100"],
        "notes": "Microsoft Defender XDR alerts + incidents. Aka source-id `defender`.",
    },
    "mimecast": {
        "kind": "pull",
        "endpoint": "POST /api/audit/get-siem-logs",
        "auth": "Mimecast HMAC headers",
        "options": ["type=<feed>", "fileFormat=json"],
        "notes": "Mimecast SIEM endpoints (v1).",
    },
    "netskope": {
        "kind": "pull",
        "endpoint": "GET /api/v2/events/data/alert",
        "auth": "Netskope-Api-Token header",
        "options": ["alert_type=<...>", "limit=100"],
        "notes": "Netskope v2 events (alert/application/audit/page).",
    },
    "proofpoint": {
        "kind": "pull",
        "endpoint": "GET /v2/siem/all",
        "auth": "HTTP Basic with Proofpoint service principal",
        "options": ["sinceSeconds=<n>"],
        "notes": "Proofpoint TAP SIEM API.",
    },
    "sentinelone": {
        "kind": "pull",
        "endpoint": "Various /web/api/v2.1/* endpoints",
        "auth": "ApiToken <S1 mgmt API token>",
        "options": ["accountIds=<id>", "siteIds=<id>"],
        "notes": "SentinelOne Mgmt API v2.1 — broad surface. Historical events take their timestamp from the resource's own time field.",
    },
    "snyk": {
        "kind": "pull",
        "endpoint": "GET /v1/org/<id>/issues",
        "auth": "Authorization: token <Snyk token>",
        "options": ["perPage=100"],
        "notes": "Snyk Audit Logs + Issues.",
    },
    "tenable": {
        "kind": "pull",
        "endpoint": "GET /audit-log/v1/events",
        "auth": "X-ApiKeys: accessKey=...;secretKey=...",
        "options": ["limit=100"],
        "notes": "Tenable.io audit + vuln events.",
    },
    "wiz": {
        "kind": "pull",
        "endpoint": "POST /graphql (issuesV2)",
        "auth": "Bearer <Wiz token>",
        "options": ["first=100"],
        "notes": "Wiz GraphQL — issuesV2 + auditLogEntries.",
    },
    "zscaler_zpa": {
        "kind": "pull",
        "endpoint": "GET /mgmtconfig/v2/admin/customers/<id>/logs",
        "auth": "Bearer <ZPA token>",
        "options": ["pageSize=100"],
        "notes": "ZPA Log Streaming Service.",
    },
    # ── Push / bus sources (collector subscribes to apigenie) ─────────────
    "azure_platform": {
        "kind": "push",
        "endpoint": "Kafka topic 'azure-platform-events'",
        "auth": "SASL_SSL with the credentials shown on the Push Profiles tab",
        "options": ["batch_size=100", "compression=lz4"],
        "notes": "Start a push profile for `azure_platform` from the Push Profiles tab — the scenario will inject backdated events into the outbound stream on its first batch.",
    },
}

# Aliases that the Bindings UI uses for some sources (kept in sync with
# sources.SOURCE_ID_ALIASES so both ids land in setup_notes if a phase
# happens to use the alias).
_SOURCE_SETUP_ALIASES: dict[str, str] = {
    "entra_id": "azure_ad",
    "defender": "microsoft_defender",
}

# Per-source timestamp field name. When pre-staging a historical event we
# force this field to the chosen backdated timestamp (ISO-8601 or epoch
# depending on the source's native format) so it lands in the collector
# at the right point on the timeline. Sources not in this map get the
# timestamp on a synthetic `_ts` field only.
_SOURCE_TS_FIELD: dict[str, tuple[str, str]] = {
    # source: (field_name, format)  -- format ∈ {"iso", "iso_z", "epoch_s", "epoch_ms"}
    "okta":               ("published", "iso_z"),
    "aws_cloudtrail":     ("eventTime", "iso_z"),
    "aws_guardduty":      ("UpdatedAt", "iso_z"),
    "aws_waf":            ("timestamp", "epoch_ms"),
    "azure_ad":           ("activityDateTime", "iso_z"),
    "azure_platform":     ("time", "iso_z"),
    "cato":               ("event_time", "iso_z"),
    "cisco_duo":          ("timestamp", "epoch_s"),
    "cloudflare":         ("EdgeStartTimestamp", "iso_z"),
    "darktrace":          ("time", "epoch_ms"),
    "gcp_audit":          ("timestamp", "iso_z"),
    "m365":               ("CreationTime", "iso_z"),
    "microsoft_defender": ("createdDateTime", "iso_z"),
    "mimecast":           ("eventTime", "iso_z"),
    "netskope":           ("timestamp", "epoch_s"),
    "proofpoint":         ("messageTime", "iso_z"),
    "sentinelone":        ("createdAt", "iso_z"),
    "snyk":               ("created", "iso_z"),
    "tenable":            ("received", "iso_z"),
    "wiz":                ("createdAt", "iso_z"),
    "zscaler_zpa":        ("timestamp", "epoch_ms"),
}


def _backlog_dir() -> Path:
    """Return the on-disk directory holding per-scenario historical
    backlog files. Created lazily on first write."""
    return _DATA_ROOT / "attack_scenarios"


def _backlog_paths(scenario_id: str) -> tuple[Path, Path]:
    """Return (jsonl, idx) backlog paths for *scenario_id*."""
    d = _backlog_dir()
    return (d / f"{scenario_id}_backlog.jsonl",
            d / f"{scenario_id}_backlog.idx.json")


def _format_ts(ts: float, fmt: str) -> Any:
    """Format an epoch-seconds float into the per-source representation."""
    if fmt == "epoch_s":
        return int(ts)
    if fmt == "epoch_ms":
        return int(ts * 1000)
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    if fmt == "iso_z":
        # "...Z" form, no microseconds — matches most SaaS APIs.
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return dt.replace(microsecond=0).isoformat()  # "iso"


# ── Storage ──────────────────────────────────────────────────────────────────

def _load_scenarios() -> list[dict[str, Any]]:
    try:
        if _SCENARIOS_FILE.is_file():
            scenarios = json.loads(_SCENARIOS_FILE.read_text())
            # v5.1 Phase C migration: scenarios written before the C release
            # don't have `mode`/`visibility`/`owner_id`. Fill safe defaults
            # so the rest of the module can assume the fields exist.
            #   - mode defaults to "realtime" (preserves their existing UX)
            #   - visibility defaults to "public" (they were globally visible
            #     before this field existed; flipping them to "private" on
            #     load would surprise operators)
            for s in scenarios:
                s.setdefault("mode", "realtime")
                s.setdefault("visibility", "public")
                s.setdefault("owner_id", None)
                s.setdefault("events_per_phase", None)
            return scenarios
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
    # v5.1 Phase C — accept and normalise the new mode / visibility /
    # owner_id / events_per_phase knobs. Sensible defaults so existing
    # callers keep working bit-for-bit (mode=realtime preserves today's UX;
    # visibility=private is the secure default for *new* scenarios — only
    # legacy scenarios already on disk get the public back-compat default
    # in `_load_scenarios`).
    mode = data.get("mode", "realtime")
    if mode not in ("realtime", "historical"):
        mode = "realtime"
    visibility = data.get("visibility", "private")
    if visibility not in ("private", "public"):
        visibility = "private"

    # v5.3 — every scenario carries a persona bundle that anchors every
    # event it injects across every source involved (Okta victim ≡
    # Defender host ≡ Proofpoint recipient ≡ Entra UPN ≡ CloudTrail IAM
    # user, all sharing the same identity for the scenario's lifetime).
    # The operator MAY pre-supply a bundle (custom persona editor in
    # the UI, or hand-crafted templates); otherwise we roll a fresh
    # one. ``import_scenario`` deliberately strips any incoming
    # ``personas`` so two operators importing the same template don't
    # collide on the same victim — see the import path below.
    import personas as _personas_mod
    incoming_bundle = data.get("personas")
    if isinstance(incoming_bundle, dict) and incoming_bundle:
        bundle = incoming_bundle
    else:
        bundle = _personas_mod.generate_bundle()

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
        # Phase C fields
        "mode": mode,
        "visibility": visibility,
        "owner_id": data.get("owner_id"),
        "events_per_phase": data.get("events_per_phase"),
        # v5.3 cross-source entity correlation (see persona splicer
        # in ``_create_temp_rule``).
        "personas": bundle,
    }
    # Ensure each phase has an id
    for i, phase in enumerate(scenario["phases"]):
        if "id" not in phase:
            phase["id"] = f"phase-{i}"
        phase["status"] = "pending"
        phase["events_count"] = 0
    # Auto-fill the setup_notes block — derived from phases, regenerated on
    # every create / update / import. Never round-tripped through export.
    scenario["setup_notes"] = _generate_setup_notes(
        scenario["phases"], scenario["duration"])
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
        for key in ("name", "duration", "phases", "profile_id",
                    "mode", "visibility", "owner_id", "events_per_phase",
                    # v5.3 — allow the operator to replace the persona
                    # bundle from the UI editor. When ``personas`` is
                    # NOT in *data* the existing bundle survives the
                    # update untouched.
                    "personas"):
            if key in data:
                s[key] = data[key]
        # Regenerate setup_notes if anything that affects them changed.
        if "phases" in data or "duration" in data:
            s["setup_notes"] = _generate_setup_notes(
                s.get("phases", []), s.get("duration", {}))
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
    # Drop any captured events so a re-created scenario doesn't inherit them.
    clear_events(scenario_id)
    # Wipe any historical-mode backlog artifacts so disk doesn't grow with
    # ghosts of deleted scenarios.
    jsonl, idx = _backlog_paths(scenario_id)
    for p in (jsonl, idx):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.warning("attack scenarios: failed to remove backlog file %s: %s", p, exc)
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
    # v5.1.10 — phase ↔ vendor STAR rule mapping. Optional, list of
    # ``{name, source, severity, mitre, s1ql}`` entries. Carried through
    # export / import so a scenario shared between operators keeps its
    # "this phase fires THIS rule" annotation in the scenario card.
    "target_rules",
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
        # v5.1.10 — ``target_rules`` is optional. When present it must be a
        # list of objects each carrying at least a ``name`` string. All
        # other keys (source, severity, mitre, s1ql) are advisory and used
        # only by the scenario card renderer, so we don't lock them in.
        tr = p.get("target_rules")
        if tr is not None:
            if not isinstance(tr, list):
                errors.append(f"phase #{i}: 'target_rules' must be an array")
            else:
                for j, r in enumerate(tr):
                    if not isinstance(r, dict):
                        errors.append(
                            f"phase #{i}.target_rules[{j}]: must be an object")
                        continue
                    if not isinstance(r.get("name"), str) or not r.get("name", "").strip():
                        errors.append(
                            f"phase #{i}.target_rules[{j}]: 'name' is required "
                            f"and must be a non-empty string")
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
    # Also strip ``personas`` if a template smuggles one in: the import path
    # MUST roll a fresh bundle so two operators importing the same template
    # end up with two different victims. Templates that bundled a persona
    # by accident shouldn't pin every demo to the same identity.
    payload = {k: v for k, v in data.items()
               if k not in ("_apigenie_schema", "personas")}
    return create_scenario(payload)


# ── Per-scenario event log (Phase 3 — reporting + correlation) ───────────────
# Every time ``detection_rules.inject_detection_events`` fires a rule that
# carries a ``_scenario_id`` (i.e. a temporary rule the scheduler created for
# a phase), it calls ``record_event`` here so the operator can audit exactly
# what landed in their lab during a campaign. The log is purely in-memory
# (same model as ``log_pusher._event_logs``): cheap, bounded, and wiped on
# restart — which matches the engine since temp rules don't survive restarts
# anyway. Each ring buffer is capped at _MAX_SCENARIO_EVENT_LOG entries so a
# multi-day scenario at high periodicity can't grow without bound.

_MAX_SCENARIO_EVENT_LOG = 500

# Keys we keep from the injected event for the preview. Anything else is
# dropped — the goal is "what attack signal landed where + when", not full
# event archival (the actual events are still sent to the configured sinks
# via the normal HTTP / push pipelines).
_EVENT_PREVIEW_KEYS: tuple[str, ...] = (
    "type", "subtype", "severity", "Operation", "Workload", "operationName",
    "threatInfo.threatName", "threatInfo.classification",
    "mitre.tactic.name", "mitre.technique.id",
    "eventType", "category", "action", "subject", "_detection_rule",
)

_scenario_event_logs: dict[str, collections.deque] = {}
_event_log_lock = threading.Lock()


def _build_event_preview(event: dict) -> dict:
    """Pull a small set of well-known signal fields out of a fired event so
    the UI can render a one-line summary without storing the entire payload.
    Unknown fields are dropped; nothing in ``event`` is mutated."""
    preview: dict[str, Any] = {}
    for k in _EVENT_PREVIEW_KEYS:
        if k in event:
            preview[k] = event[k]
    return preview


def record_event(scenario_id: str, phase_id: str, attack_id: str,
                 source: str, event: dict) -> None:
    """Append a fired-event record to the scenario's ring buffer.
    Also bumps the persisted ``events_injected`` counter on the scenario so
    the card UI shows progress even after a container restart wipes the
    in-memory log."""
    with _event_log_lock:
        buf = _scenario_event_logs.get(scenario_id)
        if buf is None:
            buf = collections.deque(maxlen=_MAX_SCENARIO_EVENT_LOG)
            _scenario_event_logs[scenario_id] = buf
        buf.appendleft({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scenario_id": scenario_id,
            "phase_id": phase_id or "",
            "attack_id": attack_id or "",
            "source": source or "",
            "preview": _build_event_preview(event or {}),
        })
    # Bump the persisted counter on a best-effort basis. We grab the same
    # _lock the CRUD helpers use, so this stays serialised with create /
    # update / delete and won't race the scheduler's status writes.
    try:
        with _lock:
            scenarios = _load_scenarios()
            s = _find(scenarios, scenario_id)
            if s is not None:
                s["events_injected"] = s.get("events_injected", 0) + 1
                _save_scenarios(scenarios)
    except Exception:
        # Persistence is a "nice to have" — never let it break injection.
        pass


def _record_event_safe(scenario_id: str, phase_id: str, attack_id: str,
                       source: str, event: dict) -> None:
    """Exception-swallowing wrapper called from detection_rules so a bug in
    the event-log path can never break the actual event injection pipeline.
    Detection-rule firing is the hot path; logging is supporting telemetry."""
    try:
        record_event(scenario_id, phase_id, attack_id, source, event)
    except Exception as exc:
        log.warning("attack scenario event log: drop event (%s)", exc)


def get_events(scenario_id: str, limit: int = 200,
               phase_id: str | None = None,
               source: str | None = None) -> list[dict]:
    """Return up to ``limit`` most-recent events, newest first. Optional
    filters narrow by phase or source — applied in Python (the ring buffer
    is small enough that scanning costs less than maintaining indexes)."""
    with _event_log_lock:
        items = list(_scenario_event_logs.get(scenario_id, ()))
    if phase_id:
        items = [e for e in items if e.get("phase_id") == phase_id]
    if source:
        items = [e for e in items if e.get("source") == source]
    return items[:max(0, int(limit))]


def clear_events(scenario_id: str) -> None:
    """Drop all recorded events for a scenario. Called from delete_scenario
    so a re-created scenario with the same name starts with a clean slate."""
    with _event_log_lock:
        _scenario_event_logs.pop(scenario_id, None)


def _reset_event_logs_for_tests() -> None:
    """Clear every per-scenario buffer. Used by the test fixture only."""
    with _event_log_lock:
        _scenario_event_logs.clear()


# ── Phase 3.3: exportable attack timeline ────────────────────────────────────

# Cap on events embedded in a timeline export. The per-scenario ring buffer
# is bounded to _MAX_SCENARIO_EVENT_LOG (500) so this is mostly defensive,
# but the REST endpoint also caps the response to keep JSON downloads sane
# on long-running scenarios that survive multiple buffer rotations.
_MAX_TIMELINE_EVENTS = _MAX_SCENARIO_EVENT_LOG


def build_timeline(scenario_id: str) -> dict[str, Any] | None:
    """Return a chronologically-sorted phase + event timeline for a scenario.

    The resulting dict is designed for two consumers:

      * The Admin UI **Timeline** download button — operators grab a JSON
        snapshot mid-run or after completion and drop it next to a demo
        recording.
      * Offline reviewers — every entry is self-describing (no IDs that
        require a live engine to resolve) so the file is useful in
        isolation, hours or days later.

    Each entry in ``timeline`` carries:

      * ``ts``        — ISO-8601 timestamp (newest-first sort applied last)
      * ``kind``      — ``scenario_start`` / ``phase_start`` / ``event``
                         / ``phase_end`` / ``scenario_end``
      * ``phase_id``  — present on phase + event entries
      * ``source``    — present on phase_start + event
      * ``preview``   — present on event (the slim payload from Phase 3.1)
      * ``mitre_tactic`` / ``mitre_technique`` — on phase_start

    Phase boundaries are **derived** from ``started_at`` + ``duration`` +
    each phase's ``time_offset_pct`` / ``duration_pct``. Persisting them
    on every phase row would mean writing JSON on every scheduler tick;
    derivation is exact for the deterministic windowing the scheduler
    uses anyway. For a scenario that never ran (``started_at`` empty)
    only the phase metadata and any orphan events are included — no
    fabricated timestamps.
    """
    scenario = get_scenario(scenario_id)
    if scenario is None:
        return None

    started_iso = scenario.get("started_at", "")
    total_seconds = _duration_to_seconds(scenario.get("duration", {}))
    started_dt: datetime | None = None
    if started_iso:
        try:
            started_dt = datetime.fromisoformat(started_iso)
        except ValueError:
            started_dt = None

    timeline: list[dict[str, Any]] = []

    if started_dt is not None:
        # scenario_start anchor
        timeline.append({
            "ts": started_dt.isoformat(timespec="seconds"),
            "kind": "scenario_start",
            "attack_id": scenario.get("attack_id", ""),
            "name": scenario.get("name", ""),
        })
        # phase_start + phase_end anchors derived from offset/duration pct
        for phase in scenario.get("phases", []):
            phase_id = phase.get("phase_id", phase.get("id", ""))
            offset_pct = phase.get("time_offset_pct", 0) / 100.0
            duration_pct = phase.get("duration_pct", 10) / 100.0
            phase_start = started_dt + timedelta(seconds=total_seconds * offset_pct)
            phase_end = started_dt + timedelta(
                seconds=total_seconds * (offset_pct + duration_pct)
            )
            timeline.append({
                "ts": phase_start.isoformat(timespec="seconds"),
                "kind": "phase_start",
                "phase_id": phase_id,
                "name": phase.get("name", ""),
                "source": phase.get("source", ""),
                "mitre_tactic": phase.get("mitre_tactic", ""),
                "mitre_technique": phase.get("mitre_technique", ""),
            })
            timeline.append({
                "ts": phase_end.isoformat(timespec="seconds"),
                "kind": "phase_end",
                "phase_id": phase_id,
            })
        # scenario_end anchor only when the run has actually finished —
        # for a still-running scenario the "end" is in the future and
        # would be misleading on a mid-run export.
        if scenario.get("status") == "completed":
            scenario_end = started_dt + timedelta(seconds=total_seconds)
            timeline.append({
                "ts": scenario_end.isoformat(timespec="seconds"),
                "kind": "scenario_end",
            })

    # Captured events from the Phase 3.1 ring buffer. get_events returns
    # newest-first; we'll re-sort below so the ordering is consistent
    # with the derived phase anchors.
    for ev in get_events(scenario_id, limit=_MAX_TIMELINE_EVENTS):
        timeline.append({
            "ts": ev.get("ts", ""),
            "kind": "event",
            "phase_id": ev.get("phase_id", ""),
            "source": ev.get("source", ""),
            "attack_id": ev.get("attack_id", ""),
            "preview": ev.get("preview", {}),
        })

    # Sort the merged list chronologically (oldest-first). ISO-8601 with
    # the same offset format sorts lexicographically — no parsing needed.
    timeline.sort(key=lambda e: e.get("ts", ""))

    return {
        "scenario_id": scenario_id,
        "name": scenario.get("name", ""),
        "description": scenario.get("description", ""),
        "attack_id": scenario.get("attack_id", ""),
        "status": scenario.get("status", "stopped"),
        "started_at": started_iso,
        "duration": scenario.get("duration", {}),
        "elapsed_seconds": scenario.get("elapsed_seconds", 0),
        "events_injected": scenario.get("events_injected", 0),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "phases": [{
            "phase_id": p.get("phase_id", p.get("id", "")),
            "name": p.get("name", ""),
            "source": p.get("source", ""),
            "mitre_tactic": p.get("mitre_tactic", ""),
            "mitre_technique": p.get("mitre_technique", ""),
            "status": p.get("status", "pending"),
            "events_count": p.get("events_count", 0),
            "time_offset_pct": p.get("time_offset_pct", 0),
            "duration_pct": p.get("duration_pct", 10),
        } for p in scenario.get("phases", [])],
        "timeline": timeline,
    }


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

def _splice_persona_overrides(phase: dict, scenario: dict) -> dict:
    """Merge the scenario's persona bundle into ``phase['field_overrides']``.

    For each ``event_field ⇒ slot_path`` entry in the source's
    :data:`PERSONA_PROJECTION`, resolve ``slot_path`` against the
    scenario's ``personas`` bundle and stamp the value onto a *new*
    overrides dict. Phase-authored overrides win — the operator is
    the authority of last resort, persona splicing only fills gaps.

    Returns a fresh dict regardless of code path so the caller can
    mutate it (e.g. stamp ``attack.id`` / ``phase.id``) without
    risking corruption of the persisted phase record. Legacy
    scenarios that lack a ``personas`` key or sources that don't
    yet ship a projection silently round-trip the phase's existing
    overrides — keeps backward compatibility for in-flight scenarios.
    """
    import personas as _personas
    import sources as _sources

    base = dict(phase.get("field_overrides", {}))
    bundle = (scenario or {}).get("personas") or {}
    if not bundle:
        return base

    projection = _sources.get_persona_projection(phase.get("source", ""))
    if not projection:
        return base

    for event_field, slot_path in projection.items():
        if event_field in base:
            # Operator-authored override wins.
            continue
        value = _personas.resolve_path(bundle, slot_path)
        if value is None or value == "":
            # Empty slot ⇒ skip; never put an empty value on the wire.
            continue
        base[event_field] = value
    return base


def _create_temp_rule(phase: dict, attack_id: str, scenario_id: str,
                       total_seconds: int, phase_start: float) -> str | None:
    """Create a temporary detection rule for a phase. Returns the rule ID."""
    import detection_rules

    # Calculate backdated timestamp for this phase
    now = time.time()
    time_into_scenario = now - phase_start
    total_offset = phase.get("time_offset_pct", 0) / 100.0
    backdate_seconds = total_seconds * total_offset

    # Splice in the scenario's persona bundle so this phase's events
    # share entities (victim / attacker / host / payload) with every
    # other source involved in the same scenario. The scenario record
    # is fetched fresh from disk — by the time _create_temp_rule fires,
    # the scenario has already been persisted with its persona bundle
    # by ``create_scenario`` / ``update_scenario``.
    scenario = _find(_load_scenarios(), scenario_id) or {}
    overrides = _splice_persona_overrides(phase, scenario)
    overrides["attack.id"] = attack_id
    overrides["phase.id"] = phase.get("phase_id", "unknown")

    # v5.1.8 — Per-source robust tagging.
    #
    # Background: SDL parsers vary in how they surface unknown
    # top-level wire fields. M365 and Okta both round-trip
    # ``attack.id`` to ``unmapped.attack.id`` in the data lake; the
    # Proofpoint TAP parser, by contrast, strictly enforces its
    # documented schema and silently discards anything else. Without
    # extra plumbing, a Proofpoint scenario phase produces correctly
    # stamped events in apigenie that arrive in S1 stripped of their
    # ``attack.id``, making PowerQuery correlation across the three
    # sources impossible (the operator-visible symptom is "Proofpoint
    # = 0" rows when filtering by attack_id).
    #
    # The fix is source-targeted, not global: for Proofpoint, append
    # ``apigenie-attack:<id>`` and ``apigenie-phase:<id>`` tokens to
    # ``policyRoutes`` (a Proofpoint-native ``[String!]`` field that
    # every parser preserves verbatim). Operators can then filter on
    # ``policyRoutes contains 'apigenie-attack:att-XXX'`` regardless
    # of whether the Proofpoint parser would also surface
    # ``attack.id`` for that tenant version. Other sources keep the
    # plain ``attack.id`` / ``phase.id`` dotted overrides — they
    # already work.
    source = phase.get("source", "")
    if source == "proofpoint":
        existing_routes = overrides.get("policyRoutes")
        if not isinstance(existing_routes, list):
            existing_routes = ["default_inbound"]
        overrides["policyRoutes"] = list(existing_routes) + [
            f"apigenie-attack:{attack_id}",
            f"apigenie-phase:{phase.get('phase_id', 'unknown')}",
        ]

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
    # Optional realistic total-event cap for discrete-action phases (e.g. a
    # BEC admin action performed once). When set, the injector emits at most
    # this many events for the whole phase instead of scaling with the
    # background log volume on every collector poll.
    if phase.get("max_events") is not None:
        rule_data["max_events"] = phase.get("max_events")

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

    # v5.1 Phase C — historical mode: pre-stage every event onto disk
    # with backdated timestamps, mark the scenario completed, return
    # immediately. No scheduler thread, no temp detection rules — the
    # whole attack story is already in the past and waiting in the
    # per-source backlog for the next collector pull to drain.
    if scenario.get("mode") == "historical":
        try:
            staged = pre_stage_historical_events(scenario_id)
        except Exception as exc:
            log.exception("attack scenarios: historical pre-stage failed")
            _update_scenario_status(scenario_id, status="stopped",
                                    error=f"pre-stage failed: {exc}")
            return f"pre-stage failed: {exc}"
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _update_scenario_status(
            scenario_id,
            status="completed",
            started_at=now_iso,
            elapsed_seconds=_duration_to_seconds(scenario.get("duration", {})),
            events_injected=staged,
        )
        return get_scenario(scenario_id) or scenario

    # Realtime mode (default — preserves the existing UX).
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


# ── v5.1 Phase C — setup notes generator ─────────────────────────────────────


def _generate_setup_notes(phases: list[dict[str, Any]],
                          duration: dict[str, Any]) -> dict[str, Any]:
    """Derive the operator-facing setup notes from the scenario's phases.

    Returns a structured block describing every distinct source the
    scenario touches (sorted by source name) and what the operator must
    configure to honour the scenario end-to-end. Unknown sources surface
    as ``kind="unknown"`` rows so a typo is loud, not silent.

    The block is purely derived — regenerated on every create / update /
    import. Never round-tripped through ``export_scenario`` (the import
    path regenerates from phases on the other side).
    """
    # Collect unique sources from the phases, preserving the alias →
    # canonical mapping so the same hint surfaces under both ids.
    sources_seen: set[str] = set()
    for p in phases or []:
        src = (p.get("source") or "").strip()
        if src:
            sources_seen.add(src)

    rows: list[dict[str, Any]] = []
    for src in sorted(sources_seen):
        canonical = _SOURCE_SETUP_ALIASES.get(src, src)
        hint = _SOURCE_SETUP_HINTS.get(canonical)
        if hint is None:
            rows.append({
                "source": src,
                "kind": "unknown",
                "endpoint": "",
                "auth": "",
                "options": [],
                "notes": (
                    f"No setup hint registered for source '{src}'. Either "
                    f"this is a typo in a phase or the source is new — add "
                    f"a row to attack_scenarios._SOURCE_SETUP_HINTS and the "
                    f"notes will be auto-populated next time."
                ),
            })
        else:
            rows.append({"source": src, **hint})

    n_sources = len(rows)
    duration_value = duration.get("value", 4) if isinstance(duration, dict) else 4
    duration_unit = duration.get("unit", "hours") if isinstance(duration, dict) else "hours"
    summary = (
        f"This scenario emits events across {n_sources} source"
        f"{'' if n_sources == 1 else 's'} over "
        f"{duration_value} {duration_unit}."
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "sources": rows,
    }


# ── v5.1 Phase C — historical pre-staging + drain ────────────────────────────


# Env-var knob for the "events per phase" fallback when a phase is
# count-based (periodicity ≤ 100) and the scenario carries no explicit
# events_per_phase override.
_ASSUMED_RATE_PER_MIN = max(1, int(os.getenv("APIGENIE_SCN_ASSUMED_RATE_PER_MIN", "2")))


def _phase_event_count(phase: dict[str, Any],
                       scenario: dict[str, Any],
                       phase_duration_s: float) -> int:
    """Decide how many events to pre-stage for one phase in historical mode.

    Priority (first one set wins):
      1. ``phase["events_per_phase"]`` — per-phase override.
      2. ``scenario["events_per_phase"]`` — scenario-wide override.
      3. Time-based rules (``periodicity > 100``):
            ``max(1, phase_duration_s // periodicity)``.
      4. Count-based rules (``periodicity ≤ 100``):
            ``max(1, phase_duration_s // 60 * _ASSUMED_RATE_PER_MIN)``.
    """
    pep = phase.get("events_per_phase")
    if isinstance(pep, int) and pep > 0:
        return pep
    sep = scenario.get("events_per_phase")
    if isinstance(sep, int) and sep > 0:
        return sep
    periodicity = phase.get("periodicity", 5)
    if isinstance(periodicity, (int, float)) and periodicity > 100:
        return max(1, int(phase_duration_s // periodicity))
    minutes = max(1.0, phase_duration_s / 60.0)
    return max(1, int(minutes * _ASSUMED_RATE_PER_MIN))


def pre_stage_historical_events(scenario_id: str) -> int:
    """Pre-compute every event a historical-mode scenario would emit and
    write them to a per-scenario, per-source on-disk backlog.

    Returns the total number of events staged. Idempotent in the sense
    that a second call clobbers the previous backlog (a re-launch of a
    historical scenario is supposed to reset the timeline anyway).

    No-op (returns 0, writes nothing) for realtime-mode scenarios so the
    caller can use this as a generic "ensure backlog is current" hook.
    """
    scenario = get_scenario(scenario_id)
    if scenario is None:
        return 0
    if scenario.get("mode") != "historical":
        return 0

    total_seconds = _duration_to_seconds(scenario.get("duration", {}))
    now = time.time()
    base = now - total_seconds  # absolute t=0 for the scenario in the past

    rng = random.Random(scenario_id)  # deterministic-ish per scenario for tests
    visibility = scenario.get("visibility") or "public"
    owner_id = scenario.get("owner_id")
    attack_id = scenario.get("attack_id", "")

    jsonl_path, idx_path = _backlog_paths(scenario_id)
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    # Reset the in-memory ring buffer for this scenario — historical
    # launches should always start the preview from scratch.
    with _event_log_lock:
        _scenario_event_logs.pop(scenario_id, None)

    sources_touched: set[str] = set()
    total = 0
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for phase in scenario.get("phases", []):
            phase_id = phase.get("phase_id", phase.get("id", ""))
            source = (phase.get("source") or "").strip()
            if not source:
                continue
            sources_touched.add(source)
            offset_pct = phase.get("time_offset_pct", 0) / 100.0
            duration_pct = phase.get("duration_pct", 10) / 100.0
            t0 = base + total_seconds * offset_pct
            t1 = t0 + total_seconds * duration_pct
            phase_duration_s = t1 - t0
            n_events = _phase_event_count(phase, scenario, phase_duration_s)
            ts_field, ts_fmt = _SOURCE_TS_FIELD.get(source, ("", "iso_z"))
            overrides = dict(phase.get("field_overrides") or {})
            overrides.setdefault("attack.id", attack_id)
            overrides.setdefault("phase.id", phase_id)

            for _ in range(n_events):
                ts = rng.uniform(t0, t1)
                event: dict[str, Any] = {
                    "_source": source,
                    "_ts": ts,
                    "_scenario_id": scenario_id,
                    "_phase_id": phase_id,
                    "_owner_id": owner_id,
                    "_visibility": visibility,
                    "_attack_id": attack_id,
                    "_detection_rule": f"[SCENARIO] {phase.get('name', 'phase')}",
                }
                # Stamp the source-native timestamp field, if known, so a
                # collector sorting on it sees the event at the right
                # historical moment.
                if ts_field:
                    event[ts_field] = _format_ts(ts, ts_fmt)
                # Layer in the phase's field_overrides as flat keys —
                # cheap and good enough for the demo / investigation use
                # case. (Source-specific structured events can be added
                # later by wiring a public `generate_one(ctx)` per source.)
                for k, v in overrides.items():
                    event[k] = v
                fh.write(json.dumps(event, default=str) + "\n")
                total += 1

                # Mirror into the in-memory preview ring buffer so the
                # scenario card shows the full event count + previews
                # right after the launch returns.
                _record_event_safe(scenario_id, phase_id, attack_id, source, event)

    # Sidecar offset index — per-source, per-caller cursors. The map
    # is ``{source: {caller_key: offset}}`` where ``caller_key`` is the
    # resolved caller id from ``profiles.get_current_user()`` ("" for
    # unauthenticated). Each caller has its own view of the backlog so
    # the same demo can be replayed independently for multiple users
    # without one user's drain consuming another user's events. A
    # caller not present in the map gets the full backlog on its first
    # pull (offset implicitly 0).
    idx_path.write_text(
        json.dumps({src: {} for src in sorted(sources_touched)}, indent=2)
    )

    return total


def _drain_visible(ev: dict[str, Any], caller_id: str | None) -> bool:
    """Visibility predicate mirroring detection_rules._rule_visible_to_caller.

    Public events are visible to everyone (including unauthenticated /
    bus-based ingest). Private events only drain to their owner.
    """
    if ev.get("_visibility", "public") == "public":
        return True
    owner = ev.get("_owner_id")
    if owner is None:
        return True
    return caller_id is not None and owner == caller_id


def drain_historical_backlog(source: str,
                             max_items: int | None = None) -> list[dict[str, Any]]:
    """Return pre-staged events for *source* visible to the resolved caller.

    Resolution mirrors ``detection_rules._rule_visible_to_caller``:
      - ``profiles.get_current_user()`` supplies the caller id (None ⇒
        public-only).
      - Each source has its own cursor in ``<sid>_backlog.idx.json``;
        a drain of source X only advances X's offset.
      - ``max_items=None`` drains everything currently available for
        this (source, caller) pair — that's the demo-immediacy use case.

    No-op if no historical-mode scenarios have staged a backlog for
    *source* (returns ``[]``).
    """
    try:
        from profiles import get_current_user
        caller_id = get_current_user()
    except Exception:
        caller_id = None

    caller_key = caller_id or ""
    out: list[dict[str, Any]] = []
    d = _backlog_dir()
    if not d.is_dir():
        return out

    for idx_path in sorted(d.glob("*_backlog.idx.json")):
        scenario_id = idx_path.name.removesuffix("_backlog.idx.json")
        jsonl_path = d / f"{scenario_id}_backlog.jsonl"
        if not jsonl_path.is_file():
            continue
        try:
            idx_data = json.loads(idx_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        per_source = idx_data.get(source)
        if per_source is None:
            # Scenario does not touch this source — skip without opening
            # the backlog file at all.
            continue
        # Back-compat shim: very early backlog files (or legacy ones from
        # the design's first iteration) may have stored a flat int per
        # source instead of the per-caller dict. Treat that int as the
        # cursor for every caller — they'll each consume the rest of the
        # file the first time they pull.
        if isinstance(per_source, int):
            per_source = {}
            idx_data[source] = per_source

        start_offset = int(per_source.get(caller_key, 0))
        new_offset = start_offset
        try:
            with jsonl_path.open("rb") as fh:
                fh.seek(start_offset)
                for raw in fh:
                    new_offset += len(raw)
                    try:
                        ev = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("_source") != source:
                        continue
                    if not _drain_visible(ev, caller_id):
                        # Skip the event but still advance THIS caller's
                        # cursor past it — they can't see it, so leaving
                        # the cursor parked on it would force them to
                        # re-scan it on every subsequent pull. Other
                        # callers each have their own offset, so this
                        # doesn't affect their view.
                        continue
                    out.append(ev)
                    if max_items is not None and len(out) >= max_items:
                        break
        except OSError as exc:
            log.warning("attack scenarios: cannot read backlog %s: %s",
                        jsonl_path, exc)
            continue

        if new_offset != start_offset:
            per_source[caller_key] = new_offset
            try:
                idx_path.write_text(json.dumps(idx_data, indent=2))
            except OSError as exc:
                log.warning("attack scenarios: cannot persist drain cursor "
                            "for %s: %s", scenario_id, exc)

        if max_items is not None and len(out) >= max_items:
            break

    return out
