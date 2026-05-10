"""Alert generators — per-source adapters producing SentinelOne UAM-compatible alerts.

Each adapter module exposes:
    SOURCE_KEY   : str            — registry key (e.g. "aws_guardduty")
    VENDOR_NAME  : str            — metadata.product.vendor_name
    PRODUCT_NAME : str            — metadata.product.name
    VARIANTS     : list[dict]     — alert subtypes with weighted probabilities
    generate(n, ctx=None) -> list — produce N native-style dicts

The ``build_s1_alert`` helper wraps each native dict into the canonical
SentinelOne OCSF S1 Security Alert schema.
"""

from __future__ import annotations

import importlib
import random
import time
import uuid
from typing import Any

# ── Canonical S1 Security Alert envelope ──────────────────────────────────────

_SEVERITY_MAP = {
    "informational": (1, "Informational"),
    "info":          (1, "Informational"),
    "low":           (2, "Low"),
    "medium":        (3, "Medium"),
    "high":          (4, "High"),
    "critical":      (5, "Critical"),
}


def _severity(raw: str | int | float) -> tuple[int, str]:
    """Normalise a vendor severity to (severity_id, severity_label)."""
    if isinstance(raw, (int, float)):
        if raw <= 2:
            return 1, "Informational"
        if raw <= 4:
            return 2, "Low"
        if raw <= 6:
            return 3, "Medium"
        if raw <= 8:
            return 4, "High"
        return 5, "Critical"
    return _SEVERITY_MAP.get(str(raw).lower().strip(), (3, "Medium"))


def build_s1_alert(
    *,
    finding_uid: str,
    title: str,
    description: str,
    severity_raw: str | int | float,
    vendor_name: str,
    product_name: str,
    resources: list[dict] | None = None,
    observables: list[dict] | None = None,
    evidences: list[dict] | None = None,
    finding_types: list[str] | None = None,
    unmapped: dict | None = None,
    attack_surface_ids: list[int] | None = None,
) -> dict[str, Any]:
    """Build a complete SentinelOne S1 Security Alert (OCSF-aligned).

    ``modified_time`` = now (ingestion time).
    ``logged_time``   = 1–120 s before modified_time.
    """
    now_ms = int(time.time() * 1000)
    logged_ms = now_ms - random.randint(1000, 120_000)
    sev_id, sev_label = _severity(severity_raw)

    alert: dict[str, Any] = {
        "finding_info": {
            "uid": finding_uid,
            "title": title,
            "desc": description,
        },
        "resources": resources or [],
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 99602001,
        "class_name": "S1 Security Alert",
        "activity_id": 1,
        "type_uid": 9960200101,
        "type_name": "S1 Security Alert: Create",
        "time": now_ms,
        "severity": sev_label.lower(),
        "severity_id": sev_id,
        "state_id": 1,
        "attack_surface_ids": attack_surface_ids or [1],
        "metadata": {
            "version": "1.1.0",
            "extension": {
                "name": "s1",
                "uid": "998",
                "version": "0.1.0",
            },
            "product": {
                "name": product_name,
                "vendor_name": vendor_name,
            },
            "logged_time": logged_ms,
            "modified_time": now_ms,
        },
        "observables": observables or [],
        "evidences": evidences or [],
    }

    if finding_types:
        alert["finding_info"]["types"] = finding_types
    if unmapped:
        alert["unmapped"] = unmapped

    return alert


# ── Source adapter registry ───────────────────────────────────────────────────

# module_name → adapter module (lazy-loaded)
_ADAPTER_MODULES = [
    # AWS sources excluded — SQS-based, not REST-pollable by S1
    "checkpoint_ngfw",
    "cortex_xdr",
    "microsoft_defender",
    "microsoft_entra_id",
    "mimecast",
    "netskope",
    "okta",
    "palo_alto_ngfw",
    "proofpoint_tap",
    "extrahop_revealx",
    "vectra_ai",
]

# source_key → adapter module (populated by load_adapters)
ALERT_SOURCES: dict[str, Any] = {}


def load_adapters() -> dict[str, Any]:
    """Import all adapter modules and register them."""
    for name in _ADAPTER_MODULES:
        try:
            mod = importlib.import_module(f"sources.alerts.{name}")
            ALERT_SOURCES[mod.SOURCE_KEY] = mod
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "Failed to load alert adapter %s: %s", name, exc
            )
    return ALERT_SOURCES


def generate_alerts(
    source_key: str,
    n: int = 1,
    ctx: Any = None,
) -> list[dict[str, Any]]:
    """Generate *n* S1-schema alerts for the given source.

    If *ctx* is a ProfileContext, profile entities are blended in by the adapter.
    """
    if not ALERT_SOURCES:
        load_adapters()

    adapter = ALERT_SOURCES.get(source_key)
    if adapter is None:
        raise ValueError(f"Unknown alert source: {source_key}")

    raw_alerts = adapter.generate(n, ctx=ctx)
    s1_alerts = []
    for raw in raw_alerts:
        s1 = build_s1_alert(
            finding_uid=raw.get("finding_uid", str(uuid.uuid4())),
            title=raw.get("title", "Alert"),
            description=raw.get("description", ""),
            severity_raw=raw.get("severity", "medium"),
            vendor_name=adapter.VENDOR_NAME,
            product_name=adapter.PRODUCT_NAME,
            resources=raw.get("resources"),
            observables=raw.get("observables"),
            evidences=raw.get("evidences"),
            finding_types=raw.get("finding_types"),
            unmapped=raw.get("unmapped"),
            attack_surface_ids=raw.get("attack_surface_ids"),
        )
        s1_alerts.append(s1)
    return s1_alerts


def list_alert_sources() -> list[dict[str, str]]:
    """Return metadata about all registered alert sources."""
    if not ALERT_SOURCES:
        load_adapters()
    result = []
    for key, mod in sorted(ALERT_SOURCES.items()):
        variants = [v.get("name", v.get("type", "?")) for v in getattr(mod, "VARIANTS", [])]
        result.append({
            "key": key,
            "vendor": mod.VENDOR_NAME,
            "product": mod.PRODUCT_NAME,
            "variant_count": len(variants),
            "variants": variants,
        })
    return result
