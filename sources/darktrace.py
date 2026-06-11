"""Darktrace mock data generator.

Event catalog spans two endpoint families:

* ``/modelbreaches`` — 6 model-breach categories (Compromise, Unusual
  Activity, Anomalous Connection, Device, User, etc.).
* ``/aianalyst/incidentevents`` — 4 AI Analyst incident severities
  (Critical/Informational/High/Medium).

Like cisco_duo and azure_ad, each entry carries an ``endpoint`` key so the
catalog-coverage test sums weights per family.
"""

import random
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    generate_hostname,
    generate_ip,
    generate_uuid,
    now_epoch_ms,
    now_iso,
    weighted_choice,
)

# Tuples kept under the original name for backwards compatibility with the
# generator code; the catalogue + template dicts below add the mix layer.
_MODELS = [
    ("Anomalous Connection / New User Agent", "Device / New User Agent", 5),
    ("Anomalous Connection / Rare External SSL Self-Signed", "Network / Rare External SSL", 7),
    ("Compromise / Agent Beacon", "Compromise / Beaconing Activity", 9),
    ("Device / New Device on Network", "Device / New Device", 3),
    ("Unusual Activity / Unusual External Data Transfer", "Network / Data Exfiltration", 8),
    ("User / Early Work Hours", "User / Unusual Work Hours", 4),
]

_AI_INCIDENT_CATEGORIES = [
    "Critical/potential-compromise",
    "Informational/new-credentials",
    "High/data-exfiltration",
    "Medium/unusual-activity",
]

# ── Event catalog ──────────────────────────────────────────────────────
EVENT_CATALOG: list[dict[str, Any]] = [
    # /modelbreaches — 6 categories. Uniform 1/6 ≈ 0.167 default preserves
    # the existing random.choice(_MODELS) distribution.
    {"id": "model_new_user_agent", "label": "Anomalous Connection / New User Agent",
     "endpoint": "modelbreaches", "default_weight": 0.1667,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/model-breaches"},
    {"id": "model_rare_ssl", "label": "Anomalous Connection / Rare External SSL Self-Signed",
     "endpoint": "modelbreaches", "default_weight": 0.1667,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/model-breaches"},
    {"id": "model_agent_beacon", "label": "Compromise / Agent Beacon",
     "endpoint": "modelbreaches", "default_weight": 0.1667,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/model-breaches"},
    {"id": "model_new_device", "label": "Device / New Device on Network",
     "endpoint": "modelbreaches", "default_weight": 0.1667,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/model-breaches"},
    {"id": "model_data_transfer", "label": "Unusual Activity / Unusual External Data Transfer",
     "endpoint": "modelbreaches", "default_weight": 0.1667,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/model-breaches"},
    {"id": "model_early_hours", "label": "User / Early Work Hours",
     "endpoint": "modelbreaches", "default_weight": 0.1665,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/model-breaches"},
    # /aianalyst/incidentevents — 4 categories. Uniform 0.25 default.
    {"id": "ai_critical_compromise", "label": "AI: Critical / potential compromise",
     "endpoint": "aianalyst", "default_weight": 0.25,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/ai-analyst"},
    {"id": "ai_info_new_creds", "label": "AI: Informational / new credentials",
     "endpoint": "aianalyst", "default_weight": 0.25,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/ai-analyst"},
    {"id": "ai_high_exfil", "label": "AI: High / data exfiltration",
     "endpoint": "aianalyst", "default_weight": 0.25,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/ai-analyst"},
    {"id": "ai_medium_unusual", "label": "AI: Medium / unusual activity",
     "endpoint": "aianalyst", "default_weight": 0.25,
     "docs_anchor": "customerportal.darktrace.com/inflection-help/ai-analyst"},
]

# Model-breach templates: id → (model_tuple, default_weight). The tuple
# (name, category, severity) becomes the payload returned by weighted_choice
# and is unpacked at the call site.
_MODEL_TEMPLATES: dict[str, tuple[Any, float]] = {
    "model_new_user_agent":  (_MODELS[0], 0.1667),
    "model_rare_ssl":        (_MODELS[1], 0.1667),
    "model_agent_beacon":    (_MODELS[2], 0.1667),
    "model_new_device":      (_MODELS[3], 0.1667),
    "model_data_transfer":   (_MODELS[4], 0.1667),
    "model_early_hours":     (_MODELS[5], 0.1665),
}

# AI-incident templates: id → (category_string, default_weight).
_AI_INCIDENT_TEMPLATES: dict[str, tuple[Any, float]] = {
    "ai_critical_compromise": (_AI_INCIDENT_CATEGORIES[0], 0.25),
    "ai_info_new_creds":      (_AI_INCIDENT_CATEGORIES[1], 0.25),
    "ai_high_exfil":           (_AI_INCIDENT_CATEGORIES[2], 0.25),
    "ai_medium_unusual":      (_AI_INCIDENT_CATEGORIES[3], 0.25),
}

_DEVICE_LABELS = ["Desktop", "Laptop", "Server", "Mobile Phone", "Network Equipment", "IoT Device", "Virtual Machine"]
_SEVERITIES = [0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]


def _generate_model_breach(ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    model_name, category, severity = weighted_choice(
        event_mix.apply(_MODEL_TEMPLATES, "darktrace")
    )
    ts_ms = now_epoch_ms() - random.randint(0, 3600000)
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src_ip = pm.get("ip") if pm else generate_ip()
    hostname = pm.get("primary_workstation", generate_hostname()) if pm else generate_hostname()
    dst_ip = pc2.get("ip_c2") if pc2 else generate_ip()

    return {
        "pbid": random.randint(100000, 999999),
        "time": ts_ms,
        "creationTime": ts_ms,
        "model": {
            "then": {
                "name": model_name,
                "pid": random.randint(1, 1000),
                "phid": random.randint(1, 1000),
                "uuid": generate_uuid(),
                "tags": [random.choice(["AP: C2 Comms", "AP: Exfiltration", "CIS-Control", "Compliance: GDPR"])],
                "interval": 0,
                "sequenced": False,
                "active": True,
                "modified": now_iso(),
                "activeTimes": {"devices": {}, "tags": {}},
                "actions": {
                    "alert": True,
                    "antigena": {},
                    "breach": True,
                    "model": True,
                    "setPriority": False,
                    "setTag": False,
                    "setType": False,
                    "tagTTL": 0,
                },
                "defeats": [],
                "created": {"by": "Darktrace"},
                "message": f"Model breach: {model_name}",
                "priority": severity,
                "category": category,
                "compliance": [],
            }
        },
        "score": round(random.uniform(0.5, 1.0), 4),
        "device": {
            "did": random.randint(1, 10000),
            "macaddress": f"00:11:22:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}",
            "vendor": random.choice(["Dell Inc.", "Apple Inc.", "Cisco Systems", "HP Inc.", "VMware"]),
            "ip": src_ip,
            "ips": [{"ip": src_ip, "timems": ts_ms, "time": now_iso(), "sid": random.randint(1, 10)}],
            "sid": random.randint(1, 10),
            "firstSeen": ts_ms - 86400000,
            "lastSeen": ts_ms,
            "os": random.choice(["Windows 10", "macOS 12", "Ubuntu 20.04", ""]),
            "devicelabel": random.choice(_DEVICE_LABELS),
            "tags": [],
            "hostname": hostname,
            "typelabel": random.choice(_DEVICE_LABELS),
        },
        "triggeredComponents": [
            {
                "time": ts_ms,
                "cbid": random.randint(1, 100000),
                "cid": random.randint(1, 1000),
                "chid": random.randint(1, 1000),
                "size": 1,
                "threshold": 0,
                "interval": 3600,
                "logic": {"data": [{"cr": random.uniform(0, 1), "l": model_name, "m": 0}], "targetScore": 1.0},
                "metric": {"mlid": random.randint(1, 500), "name": "unusual_connection_volumes"},
                "triggeredFilters": [],
                "breach": {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": random.choice([80, 443, 8080, 53, 22, 3389]),
                    "proto": random.choice(["tcp", "udp"]),
                },
            }
        ],
    }


def _generate_analyst_incident() -> dict[str, Any]:
    ts_ms = now_epoch_ms() - random.randint(0, 7200000)
    category = weighted_choice(event_mix.apply(_AI_INCIDENT_TEMPLATES, "darktrace"))

    return {
        "uuid": generate_uuid(),
        "exid": generate_uuid()[:8].upper(),
        "time": ts_ms,
        "name": f"AI Analyst Incident: {category.split('/')[1].replace('-', ' ').title()}",
        "groupCategory": category.split("/")[0],
        "groupScore": random.randint(20, 100),
        "acknowledged": False,
        "pinned": False,
        "breachDevices": [
            {
                "did": random.randint(1, 10000),
                "hostname": generate_hostname(),
                "ip": generate_ip(),
                "pbid": random.randint(100000, 999999),
            }
        ],
        "currentGroup": True,
        "groupingIds": [random.randint(100000, 999999) for _ in range(random.randint(1, 5))],
        "periods": [{"start": ts_ms - 3600000, "end": ts_ms}],
        "summary": f"Darktrace AI Analyst identified suspicious activity consistent with {category}.",
        "userTriggered": False,
        "mitreTactics": [random.choice(["Defense Evasion", "Lateral Movement", "Command and Control", "Exfiltration"])],
        "relatedBreaches": [],
    }


def get_model_breaches(limit: int = 50, minscore: float = 0.0) -> list[dict[str, Any]]:
    ctx = profiles.get_context("darktrace")
    count = profiles.scale_count("darktrace", min(limit, 50))
    breaches = [_generate_model_breach(ctx) for _ in range(count)]
    breaches = detection_rules.inject_detection_events("darktrace", breaches)
    return [b for b in breaches if b["score"] >= minscore]


def get_analyst_incidents(limit: int = 20) -> list[dict[str, Any]]:
    count = min(limit, 20)
    return [_generate_analyst_incident() for _ in range(count)]


STATUS_DATA = {
    "time": lambda: now_epoch_ms(),
    "version": "6.1.23",
    "build": "2024.01.15",
    "hostname": "darktrace-master.internal",
    "uptime": 1234567,
    "status": "online",
    "connected": True,
}


def get_status() -> dict[str, Any]:
    data = dict(STATUS_DATA)
    data["time"] = now_epoch_ms()
    return data
