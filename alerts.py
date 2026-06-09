"""Alert Push — pre-built OCSF Findings sent to SentinelOne UAM ingest API.

Ported from jarvis_coding (Backend/api/app/services/alert_service.py). Compared
to the source:

* Templates are read-only resources shipped with the package, loaded once
  into a module-level cache.
* HTTP egress uses ``httpx.Client`` (already a project dep via geoip.py) so
  tests can inject a ``MockTransport`` instead of patching ``requests``.
* Every public function that does I/O accepts an optional pre-built
  ``client`` so the caller can share a single connection pool when sending
  many alerts in a stream.
* No global mutable state apart from the template cache — the Alert Push
  profile lifecycle (CRUD, RBAC, history) lives in admin.py (Phase 4.2+).

The wire protocol matches the SentinelOne UAM ingest API contract:

    POST {uam_ingest_url}/v1/alerts
    Authorization: Bearer {service_account_token}
    S1-Scope: {accountId}              # or {accountId}:{siteId}
    Content-Encoding: gzip
    Content-Type: application/json
    <gzip-compressed OCSF alert JSON>
"""
from __future__ import annotations

import copy
import gzip
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Templates live next to the apigenie source so they're shipped with the package.
# Override via env var so tests / packagers can point elsewhere.
_TEMPLATES_DIR = Path(os.environ.get(
    "APIGENIE_ALERT_TEMPLATES_DIR",
    str(Path(__file__).parent / "alert_templates"),
))

_DEFAULT_INGEST_URL = "https://ingest.us1.sentinelone.net"
_TIMEOUT_SECONDS = 30


# ── Template loading ─────────────────────────────────────────────────────────

_TEMPLATE_CACHE: dict[str, dict[str, Any]] | None = None


def _load_all() -> dict[str, dict[str, Any]]:
    global _TEMPLATE_CACHE
    if _TEMPLATE_CACHE is not None:
        return _TEMPLATE_CACHE
    cache: dict[str, dict[str, Any]] = {}
    if _TEMPLATES_DIR.exists():
        for path in sorted(_TEMPLATES_DIR.glob("*.json")):
            try:
                cache[path.stem] = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("alerts: failed to load template %s: %s", path.name, exc)
    else:
        log.warning("alerts: templates dir not found: %s", _TEMPLATES_DIR)
    _TEMPLATE_CACHE = cache
    return cache


def reload_templates() -> int:
    """Force-rescan the templates directory. Returns the number loaded."""
    global _TEMPLATE_CACHE
    _TEMPLATE_CACHE = None
    return len(_load_all())


def list_templates() -> list[dict[str, Any]]:
    """Return lightweight metadata for every template, suitable for a UI dropdown.

    Each item carries the fields the modal needs to render a template card:
    title, finding title/desc, OCSF class name, severity_id, and the product
    that the template models (Microsoft 365, HELIOS, ...). The list is sorted
    by (product, title) so the dropdown groups naturally.
    """
    out: list[dict[str, Any]] = []
    for tid, tmpl in _load_all().items():
        finding = tmpl.get("finding_info", {}) or {}
        product = (tmpl.get("metadata", {}) or {}).get("product", {}) or {}
        out.append({
            "id": tid,
            "title": finding.get("title") or tmpl.get("class_name") or tid,
            "finding_title": finding.get("title", ""),
            "finding_desc": finding.get("desc", ""),
            "class_name": tmpl.get("class_name", ""),
            "severity_id": tmpl.get("severity_id", 0),
            "product_name": product.get("name", ""),
            "vendor_name": product.get("vendor_name", ""),
        })
    out.sort(key=lambda x: (x.get("product_name", ""), x.get("title", "")))
    return out


def get_template(template_id: str) -> dict[str, Any] | None:
    """Return a deep copy of the full template JSON, or None if not found."""
    tmpl = _load_all().get(template_id)
    return copy.deepcopy(tmpl) if tmpl is not None else None


# ── Alert preparation ────────────────────────────────────────────────────────

# Strings inside template JSON that the prep step rewrites to per-alert values.
_TIME_SENTINEL = "DYNAMIC"
_PLACEHOLDER_UIDS = {"DYNAMIC_RESOURCE_UID", "placeholder_uid", "", None}


def _replace_dynamic(obj: Any, time_ms: int) -> None:
    """Recursively replace the ``"DYNAMIC"`` time sentinel with ``time_ms``."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if v == _TIME_SENTINEL:
                obj[k] = time_ms
            elif isinstance(v, (dict, list)):
                _replace_dynamic(v, time_ms)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if v == _TIME_SENTINEL:
                obj[i] = time_ms
            elif isinstance(v, (dict, list)):
                _replace_dynamic(v, time_ms)


def _apply_overrides(alert: dict[str, Any], overrides: dict[str, Any]) -> None:
    """Apply dot-path overrides into the alert tree.

    Empty / None values are skipped so a half-filled override form doesn't
    accidentally null out template fields. Use the explicit value ``False``
    or ``0`` if you actually mean to override with a falsy literal.
    """
    for key, value in overrides.items():
        if value is None or value == "":
            continue
        if "." in key:
            parts = key.split(".")
            cur: Any = alert
            for p in parts[:-1]:
                if not isinstance(cur, dict):
                    break
                cur = cur.setdefault(p, {})
            if isinstance(cur, dict):
                cur[parts[-1]] = value
        else:
            alert[key] = value


def prepare_alert(
    template: dict[str, Any],
    *,
    overrides: dict[str, Any] | None = None,
    time_ms: int | None = None,
) -> dict[str, Any]:
    """Build a ready-to-send alert from a template.

    Steps, in order:

      1. Deep-copy the template (caller's template stays pristine).
      2. Replace every ``"DYNAMIC"`` sentinel with ``time_ms`` (epoch ms).
      3. Inject a fresh UUID into ``finding_info.uid``.
      4. Inject fresh UUIDs into ``resources[].uid`` for placeholder slots.
      5. Apply dot-path overrides (overrides win over template defaults).

    The override step runs last so a user can deliberately override a
    just-generated UID by passing ``overrides={"finding_info.uid": "..."}``,
    which is occasionally useful when reproducing a deterministic test case.
    """
    alert = copy.deepcopy(template)
    if time_ms is None:
        time_ms = int(time.time() * 1000)
    _replace_dynamic(alert, time_ms)

    finding = alert.setdefault("finding_info", {})
    finding["uid"] = str(uuid.uuid4())

    for resource in alert.get("resources", []) or []:
        if not isinstance(resource, dict):
            continue
        if resource.get("uid") in _PLACEHOLDER_UIDS:
            resource["uid"] = str(uuid.uuid4())

    if overrides:
        _apply_overrides(alert, overrides)
    return alert


def build_scope(account_id: str, site_id: str | None = None) -> str:
    """Build the ``S1-Scope`` header: ``{account}`` or ``{account}:{site}``."""
    if site_id:
        return f"{account_id}:{site_id}"
    return account_id


# ── Egress ───────────────────────────────────────────────────────────────────

def egress_alert(
    alert: dict[str, Any],
    *,
    uam_ingest_url: str,
    service_token: str,
    account_id: str,
    site_id: str | None = None,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """POST a single prepared alert to the SentinelOne UAM ingest API.

    On success returns ``{"success": True, "status": 2xx, "alert_uid": ..., "data": ...}``.
    On failure returns ``{"success": False, ...}`` with status (0 for transport
    errors), error string, and a truncated detail body when available.

    The function never raises — callers can iterate over results from
    :func:`send_alert` and surface per-alert success/failure in the UI.
    """
    scope = build_scope(account_id, site_id)
    headers = {
        "Authorization": f"Bearer {service_token}",
        "S1-Scope": scope,
        "Content-Encoding": "gzip",
        "Content-Type": "application/json",
        "S1-Trace-Id": "apigenie-alert-push",
    }
    raw = json.dumps(alert).encode("utf-8")
    body = gzip.compress(raw)
    url = (uam_ingest_url or _DEFAULT_INGEST_URL).rstrip("/") + "/v1/alerts"
    alert_uid = (alert.get("finding_info") or {}).get("uid", "")

    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=_TIMEOUT_SECONDS)
    try:
        try:
            resp = client.post(url, headers=headers, content=body)
            resp.raise_for_status()
            try:
                data = resp.json() if resp.content else {}
            except json.JSONDecodeError:
                data = {"raw": resp.text[:500]}
            return {
                "success": True,
                "status": resp.status_code,
                "alert_uid": alert_uid,
                "data": data,
            }
        except httpx.HTTPStatusError as exc:
            return {
                "success": False,
                "status": exc.response.status_code,
                "alert_uid": alert_uid,
                "error": str(exc),
                "detail": exc.response.text[:500],
            }
        except httpx.RequestError as exc:
            return {
                "success": False,
                "status": 0,
                "alert_uid": alert_uid,
                "error": str(exc),
            }
    finally:
        if own_client:
            client.close()


def send_alert(
    template_id: str,
    *,
    uam_ingest_url: str,
    service_token: str,
    account_id: str,
    site_id: str | None = None,
    overrides: dict[str, Any] | None = None,
    count: int = 1,
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    """High-level helper: prepare and send N alerts from a template.

    Returns one result dict per alert sent. Each carries ``alert_index`` so the
    caller can correlate the result back to its position in the batch.
    """
    template = get_template(template_id)
    if template is None:
        return [{
            "success": False,
            "status": 0,
            "alert_uid": "",
            "error": f"template '{template_id}' not found",
        }]

    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=_TIMEOUT_SECONDS)
    try:
        results: list[dict[str, Any]] = []
        for i in range(max(1, count)):
            prepared = prepare_alert(template, overrides=overrides)
            result = egress_alert(
                prepared,
                uam_ingest_url=uam_ingest_url,
                service_token=service_token,
                account_id=account_id,
                site_id=site_id,
                client=client,
            )
            result["alert_index"] = i
            results.append(result)
        return results
    finally:
        if own_client:
            client.close()


def send_custom_alert(
    alert_json: dict[str, Any],
    *,
    uam_ingest_url: str,
    service_token: str,
    account_id: str,
    site_id: str | None = None,
    auto_generate_uid: bool = True,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Send a user-supplied alert JSON (no template).

    If ``auto_generate_uid`` is True, the same prep step that runs on
    templates is applied (fresh UID, timestamps, resource UIDs). Otherwise the
    JSON is sent verbatim, which is occasionally needed when re-sending a
    deterministic alert captured from elsewhere.
    """
    if auto_generate_uid:
        alert = prepare_alert(alert_json)
    else:
        alert = copy.deepcopy(alert_json)
    return egress_alert(
        alert,
        uam_ingest_url=uam_ingest_url,
        service_token=service_token,
        account_id=account_id,
        site_id=site_id,
        client=client,
    )
