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

The wire protocol matches the SentinelOne UAM ingest API contract (the
same one that ``jarvis_coding`` / HELIOS uses to push alerts):

    POST {uam_ingest_url}/v1/alerts
    Authorization: Bearer {service_account_token}
    S1-Scope: {accountId}              # or {accountId}:{siteId}
    Content-Encoding: gzip
    Content-Type: application/json
    S1-Trace-Id: apigenie-alert-push
    <gzip-compressed OCSF alert JSON>

**S1-Scope is clamped to account or account:site.** Empirically (verified
on ``usea1-purple`` 2026-06-10) the gateway returns 202 for
``account:site:group`` scoped sends but the downstream ingest processor
silently drops them. HELIOS never sends a group-scoped header — and
neither do we. The profile may still carry a ``group_id`` (kept as a
display-only hint); it just isn't routed in the header.
"""
from __future__ import annotations

import copy
import gzip
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Protocol

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

# Feature flag for the resolver's injected payload shape.
#
# DEFAULT IS ON (2026-06-10, v2.2). The correct UAM binding key for an
# ingested alert is the **XDR Asset ID** returned by
# ``GET /web/api/v2.1/xdr/assets`` (a 26-char alphanumeric string like
# ``3d3dp5xbcauhh5hhqa3so46e6y``). When that id lands in
# ``resources[].uid`` and the ``S1-Scope`` header is account-or-account:site,
# UAM binds the alert to the matching asset tile and populates
# ``assets[].agentUuid``. Verified by replicating the HELIOS /
# ``jarvis_coding`` recipe (``apollo_ransomware_scenario.py``) on
# ``usea1-purple`` 2026-06-10 — the test alert went from
# ``agentUuid=None / category=Device`` to
# ``agentUuid=57c2f3d40cdc4484b216c319aa9eb3c2 / category=Server`` in 10s.
#
# Earlier hypotheses about ``s1_metadata`` / ``s1_detection_metadata`` /
# ``device.agent`` driving binding were wrong: those blocks are UAM
# post-ingest annotations on the bound alert reference payload, not
# inputs UAM evaluates on the way in.
#
# Set ``APIGENIE_UAM_BINDING_V2=0`` to revert to the pre-binding legacy
# shape (hex UUID in ``resources[].uid``, no agent block). Alerts will
# land as synthetic tiles (no ``agentUuid``) but routing still works —
# kept reachable as a diagnostic fallback.
def _binding_shape_enabled() -> bool:
    return os.getenv("APIGENIE_UAM_BINDING_V2", "1").strip().lower() not in ("0", "false", "off", "no")


# Default-on enrichment: attach MITRE attacks[] + observables[] derived
# from the alert tree before egress. The HELIOS templates ApiGenie ships
# carry only finding_info.title + desc; the enricher adds the rich OCSF
# surface UAM rendering / downstream SOAR consumers expect. Disable per
# call via ``prepare_alert(..., enrich=False)`` or globally via env var.
def _enrich_default_enabled() -> bool:
    return os.getenv("APIGENIE_ALERT_ENRICH", "1").strip().lower() not in ("0", "false", "off", "no")


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


# Match a `[N]` segment used to index into a list, e.g. ``resources[0]``.
_BRACKET_INDEX_RE = re.compile(r"\[(\d+)\]")


def _tokenize_path(path: str) -> list[str | int]:
    """Split a dot-path with optional list indices into a token stream.

    Examples::

        "device.name"             -> ["device", "name"]
        "resources[0].name"       -> ["resources", 0, "name"]
        "resources[1].uid"        -> ["resources", 1, "uid"]
        "actor.user.uid"          -> ["actor", "user", "uid"]
        "matrix[0][1].x"          -> ["matrix", 0, 1, "x"]

    Empty segments are dropped so doubled separators (``a..b``) don't blow
    up the walker.
    """
    tokens: list[str | int] = []
    for segment in path.split("."):
        if not segment:
            continue
        matches = list(_BRACKET_INDEX_RE.finditer(segment))
        if not matches:
            tokens.append(segment)
            continue
        # Everything before the first ``[`` is the dict key the brackets index into.
        head = segment[: matches[0].start()]
        if head:
            tokens.append(head)
        for m in matches:
            tokens.append(int(m.group(1)))
    return tokens


def _apply_overrides(alert: dict[str, Any], overrides: dict[str, Any]) -> None:
    """Apply dot-path overrides into the alert tree.

    Empty / None values are skipped so a half-filled override form doesn't
    accidentally null out template fields. Use the explicit value ``False``
    or ``0`` if you actually mean to override with a falsy literal.

    Path syntax supports two segment forms:

    * ``dict.subkey`` — descend / create a nested dict
    * ``parent[N]``  — index into a list, padding with empty dicts so a
      missing slot is auto-created rather than silently dropped.

    Path/value type mismatches (e.g. asking for ``resources[0]`` when
    ``resources`` is currently a dict) are skipped silently — the override
    is best-effort, never raises, never mutates the wrong slot.
    """
    for key, value in overrides.items():
        if value is None or value == "":
            continue
        tokens = _tokenize_path(key)
        if not tokens:
            continue
        cur: Any = alert
        bad = False
        for idx, tok in enumerate(tokens[:-1]):
            next_tok = tokens[idx + 1]
            if isinstance(tok, int):
                if not isinstance(cur, list):
                    bad = True
                    break
                while len(cur) <= tok:
                    cur.append({})
                cur = cur[tok]
            else:
                if not isinstance(cur, dict):
                    bad = True
                    break
                default: list | dict = [] if isinstance(next_tok, int) else {}
                existing = cur.get(tok)
                if existing is None:
                    cur[tok] = default
                    cur = cur[tok]
                else:
                    cur = existing
        if bad:
            continue
        last = tokens[-1]
        if isinstance(last, int):
            if not isinstance(cur, list):
                continue
            while len(cur) <= last:
                cur.append({})
            cur[last] = value
        else:
            if isinstance(cur, dict):
                cur[last] = value


class AssetResolverProto(Protocol):
    """Structural type for the XDR asset resolver (P4.6).

    Defined here so :func:`prepare_alert` doesn't import ``s1_assets`` at
    module load (keeps the dependency direction one-way: ``alert_push`` and
    the send path pull in ``s1_assets``, ``alerts`` stays self-contained).
    Tests can pass any object exposing the same ``resolve_endpoint``
    signature.
    """

    def resolve_endpoint(self, name_hint: str) -> dict[str, Any] | None: ...


def _is_real_uid(uid: Any) -> bool:
    """True iff ``uid`` looks like a user-supplied / resolver-supplied ID.

    Empty / None / known placeholder sentinels do NOT count as real, so the
    resolver can still claim those slots.
    """
    if not isinstance(uid, str):
        return False
    if uid in _PLACEHOLDER_UIDS:
        return False
    return bool(uid)


def _inject_device_node(node: dict[str, Any], hit: dict[str, Any]) -> None:
    """Merge a resolver hit into an OCSF ``alert.device`` dict.

    The OCSF ``device.*`` object is filled out from a resolver hit for
    visual / display purposes — the **binding key UAM honours is
    ``resources[].uid``**, not ``device.uid``. We still populate
    ``device.*`` so the alert detail card shows the right hostname / OS /
    IP when a template carries a top-level device block.

    Field policy:

    * ``uid`` — agent's hex UUID (v2) / hex UUID (legacy). Both shapes
      use the hex form here because that's what OCSF ``device.uid`` is
      documented as. Binding doesn't depend on this slot.
    * ``name`` / ``hostname`` — overwritten with the canonical asset name
      from S1 so the alert detail shows the right label even when the
      caller's hint was a lowercase fragment.
    * ``ip`` / ``domain`` / ``os.name`` — fill only when empty.
    * ``os.type`` + ``os.type_id`` — set as a pair, skipped when the
      template already carried a non-Unknown OCSF enum.
    * ``agent`` block (v2 only) — ``agent.uid`` (numeric S1 agent id),
      ``agent.uuid`` (hex), ``agent.version``. Cosmetic in our payload
      (UAM doesn't read these for binding) but matches what real S1 EDR
      alerts ship with; helpful for downstream consumers reading the
      OCSF feed.
    * ``type_id`` (v2 only) — set to ``99`` (Other) when not already set.
    """
    # The new resolver hit dict carries the XDR Asset ID in ``uid`` and
    # the hex agent UUID in ``agent_uuid``. ``device.uid`` is documented
    # as a hex UUID in OCSF, so we use ``agent_uuid`` here. If the
    # resolver was built before the v2.2 refactor and returns the old
    # shape (hex in ``uid``), fall back to that so we don't crash on a
    # stale resolver in flight.
    device_uid = hit.get("agent_uuid") or hit.get("uid") or ""
    if device_uid:
        node["uid"] = device_uid
    if hit.get("hostname"):
        # Authority swap: the asset's canonical name wins over the hint.
        node["name"] = hit["hostname"]
        node["hostname"] = hit["hostname"]
    if not node.get("ip") and hit.get("ip"):
        node["ip"] = hit["ip"]
    if hit.get("domain") and not node.get("domain"):
        node["domain"] = hit["domain"]
    os_node = node.setdefault("os", {})
    if isinstance(os_node, dict):
        if not os_node.get("name") and hit.get("os_name"):
            os_node["name"] = hit["os_name"]
        existing_type_id = os_node.get("type_id")
        if (not existing_type_id or existing_type_id in (0, 99)) and hit.get("os_type_id"):
            os_node["type_id"] = hit["os_type_id"]
            if hit.get("os_type"):
                os_node["type"] = hit["os_type"]
    if _binding_shape_enabled():
        # device.agent — cosmetic in our flow; UAM doesn't read it for
        # binding (the XDR Asset ID in resources[].uid does that). We
        # populate it for OCSF feed consistency with real S1 EDR alerts.
        if hit.get("agent_id"):
            agent_node = node.setdefault("agent", {})
            if isinstance(agent_node, dict):
                agent_node["uid"] = hit["agent_id"]          # numeric S1 id
                if device_uid:
                    agent_node["uuid"] = device_uid          # hex UUID
                if hit.get("agent_version"):
                    agent_node["version"] = hit["agent_version"]
        if not node.get("type_id"):
            # 99 = "Other" in the OCSF device.type_id enum. Real S1 EDR alerts
            # ship with this value, so mirror it for visual consistency.
            node["type_id"] = 99


def _inject_resource_device(node: dict[str, Any], hit: dict[str, Any]) -> None:
    """Merge a resolver hit into an OCSF ``resources[]`` Device entry.

    **Critical contract**: ``resources[].uid`` is the **XDR Asset ID**
    returned by ``/web/api/v2.1/xdr/assets`` (alphanumeric, e.g.
    ``3d3dp5xbcauhh5hhqa3so46e6y``). That id is what UAM correlates
    against to bind the ingested alert to the existing asset tile —
    populating ``assets[].agentUuid`` in the UAM view. Verified by
    replicating the HELIOS / ``jarvis_coding`` recipe on
    ``usea1-purple`` 2026-06-10 (see top-of-module docstring).

    Earlier attempts at putting the numeric ``agent.id`` or hex
    ``agent.uuid`` into this slot all produced unbound (synthetic)
    tiles, regardless of any ``s1_metadata`` / ``s1_detection_metadata``
    decoration we added.

    Resource shape:

    * ``uid``  — XDR Asset ID (binding key)
    * ``name`` — canonical asset name (authority swap on the hint)
    * ``type`` — concatenated OS + machine label (e.g. "Windows server")
      or just the OS label or just "Device" — UAM uses this for the
      category icon on the synthetic tile.

    Hostname / IP / OS attributes are not written here — UAM doesn't
    display them at the resource layer (those live on ``device.*``).
    """
    if _binding_shape_enabled():
        # NEW (v2.2) shape: XDR Asset ID + descriptive type.
        if hit.get("uid"):
            node["uid"] = hit["uid"]         # XDR Asset ID — UAM binding key
        if hit.get("hostname"):
            node["name"] = hit["hostname"]   # canonical name
        os_label = hit.get("os_type") or ""
        machine = hit.get("machine_type") or ""
        if os_label and machine:
            node["type"] = f"{os_label} {machine}"
        elif os_label:
            node["type"] = os_label
        else:
            node["type"] = "Device"
    else:
        # LEGACY shape (pre-binding): hex UUID in uid, generic "Device" type,
        # hostname/ip copied across — same as the old _inject_endpoint_fields
        # did on resources entries. Kept reachable behind the
        # APIGENIE_UAM_BINDING_V2=0 flag for diagnostics.
        legacy_uid = hit.get("agent_uuid") or hit.get("uid") or ""
        if legacy_uid:
            node["uid"] = legacy_uid          # hex UUID (the pre-fix shape)
        if hit.get("hostname"):
            node["name"] = hit["hostname"]
            node["hostname"] = hit["hostname"]
        if not node.get("ip") and hit.get("ip"):
            node["ip"] = hit["ip"]
        if hit.get("domain") and not node.get("domain"):
            node["domain"] = hit["domain"]
        # Old shape left os untouched on resources, and type was
        # materialised by the caller (see _resolve_assets).


# Backward-compat alias for any external caller that still imports the old
# name. Existing call sites inside _resolve_assets have been updated to use
# the more specific helpers above.
_inject_endpoint_fields = _inject_device_node


# Tokens that, when present in an OCSF ``resources[].type`` string, mark the
# entry as a host/endpoint asset eligible for S1 agent resolution. The check
# is substring-based and case-insensitive so user-friendly variants like
# ``"Windows Server"``, ``"Linux Workstation"``, ``"Endpoint"`` all trigger
# the lookup the same way a bare ``"Device"`` does. Without this, a profile
# that customises ``resources[0].type`` to e.g. ``"Windows Server"`` for UI
# clarity would silently bypass the resolver and ingest as Unknown Device.
_DEVICE_TYPE_TOKENS: tuple[str, ...] = (
    "device",
    "server",
    "workstation",
    "endpoint",
    "host",
    "laptop",
    "desktop",
    "computer",
    "machine",
)


def _is_device_type(type_str: str | None) -> bool:
    """True when an OCSF ``resources[].type`` names a host/endpoint asset.

    Matches the bare canonical ``"Device"`` plus the common descriptive
    variants users write in the Alert Push editor (``"Windows Server"``,
    ``"Linux Workstation"``, ``"Endpoint"``, ``"Host"``, ``"Laptop"``…).
    The check is substring-based so ``"MacOS Workstation"``,
    ``"VDI Desktop"`` etc. all qualify.
    """
    s = (type_str or "").lower()
    if not s:
        return False
    return any(tok in s for tok in _DEVICE_TYPE_TOKENS)


def _classify_resource_name(name: str) -> str:
    """Heuristic OCSF type for a resource that lacks an explicit ``type``.

    The Proofpoint / O365 / phishing-style templates ship with
    ``resources[0]`` set to e.g. ``"jeanluc@starfleet.com"`` and no
    ``type`` field. Without explicit typing UAM's ingest pipeline defaults
    to treating the resource as a Device, which is why those alerts land
    as "Unknown Device" tiles in the inbox.

    The rule is intentionally narrow:

    * ``@`` in the name  → ``"User"``  (email / UPN shape)
    * non-empty otherwise → ``"Device"``
    * empty                → ``""`` (caller should skip)

    Tightening this later (e.g. detect IP-shaped → ``"Network Activity"``,
    SHA256-shaped → ``"File"``) is fine but unnecessary for P4.6 because
    the only inboxes we care about are endpoint + user.
    """
    if not name:
        return ""
    if "@" in name:
        return "User"
    return "Device"


def _resolve_assets(alert: dict[str, Any], resolver: AssetResolverProto) -> None:
    """Best-effort injection of S1 asset UUIDs into ``alert``.

    Behaviour matrix:

    * **Top-level** ``device`` — if present and the ``uid`` slot is empty
      or placeholder, the device name is looked up against S1 agents and a
      hit fills ``uid`` + enrichment.
    * **resources[]** with explicit ``type == "Device"`` — same lookup
      against S1 agents; on hit the resource gets ``uid`` and the standard
      enrichment fields filled.
    * **resources[]** with explicit ``type == "User"`` — left alone;
      Singularity Identity integration is deferred (the POC tenant returned
      404 on ``/active-directory/accounts`` during the live probe).
    * **resources[]** with no ``type`` AND a name containing ``@`` — the
      type field is materialised to ``"User"`` so UAM ingest doesn't auto-
      create a phantom "Unknown Device" tile for what is plainly an email
      address or UPN. No agent lookup is attempted.
    * **resources[]** with no ``type`` AND a name NOT containing ``@`` —
      treated as a Device candidate. On a successful S1 lookup the type is
      materialised to ``"Device"`` alongside the ``uid`` + enrichment.
      On a miss the resource is left untouched.
    * **Top-level device promotion** (legacy / v2-off only) — if the
      template carries no ``device`` section at all and the resolver
      claims a resources entry as a Device, a top-level ``device`` is
      synthesised. In v2 (the default) the promotion is skipped because
      the XDR-Asset-ID binding on ``resources[].uid`` is sufficient.

    Binding (v2.2, 2026-06-10) — on a successful resources[] hit the
    XDR Asset ID from the resolver lands in ``resources[].uid``. That's
    the whole recipe: no ``s1_metadata`` / ``s1_detection_metadata`` /
    ``device.agent`` magic is needed. UAM correlates against the XDR
    Asset ID directly and binds the alert to the existing asset tile.
    Verified by replicating the HELIOS / ``jarvis_coding`` recipe on
    ``usea1-purple``; see ``s1_assets.py`` module docstring for details.

    Top-level device promotion in v2 is **disabled** because the bound
    HELIOS reference proves resources-only is sufficient, and adding a
    synthesised ``device.uid`` (which would have to be the hex UUID,
    different identifier space) creates a second binding hint UAM may
    or may not honour. The legacy / v2-off path keeps the old
    promotion behaviour for back-compat.
    """
    # ── Step 1: top-level device, if any ────────────────────────────────────
    # Only mutated when the template already carries one; we use the
    # resolver hit to fill display fields (hostname / OS / IP) — the
    # binding key still lives in ``resources[].uid``.
    dev = alert.get("device")
    top_level_device_present = isinstance(dev, dict)
    if top_level_device_present and not _is_real_uid(dev.get("uid")):
        hint = dev.get("name") or dev.get("hostname") or ""
        if hint:
            hit = resolver.resolve_endpoint(hint)
            if hit:
                _inject_device_node(dev, hit)

    # ── Step 2: each resources[] entry ──────────────────────────────────────
    promoted = False
    for resource in alert.get("resources", []) or []:
        if not isinstance(resource, dict):
            continue
        existing_type = str(resource.get("type") or "").strip()
        name = resource.get("name") or resource.get("hostname") or ""
        if not name:
            continue
        # Resolve the effective OCSF type via explicit value first, falling
        # back to the name-shape heuristic only when nothing is set.
        effective_type = existing_type or _classify_resource_name(name)
        kind = effective_type.lower()

        if kind == "user":
            # Materialise type so UAM doesn't default-classify as Device.
            # We do NOT do an agent lookup — that's the wrong inventory for
            # users, and Identity isn't deployed in the POC tenant.
            if not existing_type:
                resource["type"] = "User"
            continue

        if not _is_device_type(effective_type):
            # Some other explicit type (File, Process, Network Activity…)
            # is fine — leave it untouched.
            continue

        # ── It's a Device shape (Device / Server / Workstation / Endpoint /
        # Windows Server / Linux Workstation / …). Try to resolve. ─────────
        if _is_real_uid(resource.get("uid")):
            # User pinned the UID via override; just confirm the type is set
            # so UAM treats it consistently. We do NOT do a lookup here:
            # the pin is authoritative on the binding side, and overwriting
            # with a name-based lookup could pick the wrong agent.
            if not existing_type:
                resource["type"] = "Device"
            continue
        hit = resolver.resolve_endpoint(name)
        if not hit:
            # Miss — don't mutate. Materialising type="Device" here would
            # just guarantee UAM mints an Unknown Device tile, which is
            # exactly the failure mode we're trying to avoid. Better to
            # leave the resource shape ambiguous so UAM falls back to its
            # own ingest defaults.
            continue
        _inject_resource_device(resource, hit)
        # Legacy fallback: when v2 is OFF the resource injector doesn't
        # materialise type; restore the original "Device" stamping so the
        # off-flag path is byte-equivalent to the pre-fix behaviour.
        if not _binding_shape_enabled() and not existing_type:
            resource["type"] = "Device"
        # First device hit + no top-level device → promote, but only in
        # the legacy / v2-off path. v2 with XDR Asset ID binding does not
        # need the device promotion — the bound-alert reference proves
        # resources-only is sufficient, and a promoted ``device.uid``
        # (hex UUID, different identifier space) creates a second
        # binding hint of unclear precedence. Keep v2 minimal.
        if (not _binding_shape_enabled()
                and not top_level_device_present
                and not promoted):
            new_dev: dict[str, Any] = {"name": name}
            _inject_device_node(new_dev, hit)
            alert["device"] = new_dev
            top_level_device_present = True
            promoted = True


def prepare_alert(
    template: dict[str, Any],
    *,
    overrides: dict[str, Any] | None = None,
    time_ms: int | None = None,
    resolver: AssetResolverProto | None = None,
    enrich: bool | None = None,
    template_id: str | None = None,
) -> dict[str, Any]:
    """Build a ready-to-send alert from a template.

    Steps, in order:

      1. Deep-copy the template (caller's template stays pristine).
      2. Replace every ``"DYNAMIC"`` sentinel with ``time_ms`` (epoch ms).
      3. Inject a fresh UUID into ``finding_info.uid`` and into every
         existing ``finding_info.related_events[].uid`` (HELIOS parity).
      4. Apply dot-path overrides (user-supplied values land first so they
         participate in resolver name lookups and beat any placeholder UID).
      5. If ``resolver`` is supplied, perform XDR asset lookup and inject
         ``device.uid`` / ``resources[type=Device].uid`` plus light
         enrichment when those slots are still empty (P4.6).
      6. If ``enrich`` is True (default), attach a MITRE ATT&CK
         ``attacks[]`` mapping + harvested OCSF ``observables[]`` via
         :mod:`alert_enrichment`. Runs **after** the resolver so the
         resolved canonical hostname / IP make it into the observables.
      7. Generate fresh UUIDs for any ``resources[].uid`` still in
         placeholder form, so UAM ingest never sees an empty UID even when
         a resource wasn't claimed by the resolver.

    The ``template_id`` kwarg lets the caller (typically
    :func:`send_alert`) thread the template stem into the enricher so
    the MITRE registry lookup is exact, not heuristic. Custom alerts
    (no template) pass ``None`` and the keyword fallback kicks in.
    """
    alert = copy.deepcopy(template)
    if time_ms is None:
        time_ms = int(time.time() * 1000)
    _replace_dynamic(alert, time_ms)

    finding = alert.setdefault("finding_info", {})
    finding["uid"] = str(uuid.uuid4())

    # Each related_events[] entry also gets its own fresh UUID — matches the
    # HELIOS / jarvis_coding alert_service contract. Without this every batch
    # would ship sibling events sharing ``"placeholder_uid"`` (or whatever
    # the template carried), which UAM will silently de-dupe.
    rel_events = finding.get("related_events")
    if isinstance(rel_events, list):
        for entry in rel_events:
            if isinstance(entry, dict):
                entry["uid"] = str(uuid.uuid4())

    if overrides:
        _apply_overrides(alert, overrides)

    if resolver is not None:
        _resolve_assets(alert, resolver)

    if enrich is None:
        enrich = _enrich_default_enabled()
    if enrich:
        # Imported lazily so unit tests that don't exercise the enricher
        # don't pay the import cost, and the enricher is decoupled from
        # the rest of the egress path (matches the resolver pattern).
        try:
            from . import alert_enrichment  # type: ignore[import-not-found]
        except ImportError:
            import alert_enrichment  # type: ignore[no-redef]
        alert_enrichment.enrich_alert(alert, template_id=template_id,
                                      time_ms=time_ms)

    for resource in alert.get("resources", []) or []:
        if not isinstance(resource, dict):
            continue
        if resource.get("uid") in _PLACEHOLDER_UIDS:
            resource["uid"] = str(uuid.uuid4())

    # v5.3 — class_uid lint. STAR / Custom Detection rules require a
    # non-zero ``class_uid`` to bind the alert to a Target Asset; a
    # template that ships without it (or with 0) will land in UAM as
    # "Unknown Device" no matter how good the resolver is. We DO NOT
    # block the send (back-compat for any operator-pasted custom
    # JSON) but surface a single warning so the issue is visible in
    # the container logs instead of debugging UAM ingest for an hour.
    cu = alert.get("class_uid")
    if not isinstance(cu, int) or cu <= 0:
        log.warning(
            "prepare_alert: template %r is missing a positive class_uid "
            "(got %r) — STAR / Custom Detection rules will bind this "
            "alert to 'Unknown Device'. Set a non-zero OCSF class_uid "
            "on the template (e.g. 1007 for endpoint, 3002 for "
            "identity, 4001 for network, 6003 for cloud).",
            template_id or alert.get("class_name") or "<unknown>", cu,
        )
    return alert


def build_scope(account_id: str, site_id: str | None = None,
                group_id: str | None = None) -> str:
    """Build the ``S1-Scope`` header. **Clamped to at most account:site**.

    Returns one of:
      * ``{account}``                              — account scope
      * ``{account}:{site}``                       — site scope

    Group-scoped sends (``{account}:{site}:{group}``) are silently
    dropped by the ``/v1/alerts`` gateway on the tenants we tested
    (``usea1-purple`` 2026-06-10) — the gateway returns 202 but the
    downstream ingest processor never lands them. HELIOS / jarvis_coding
    never sends a group-scoped header, and neither do we.

    The ``group_id`` argument is accepted for API compatibility with the
    profile shape, but it is **deliberately ignored** for routing. We
    still log a single ``debug`` line so the caller can see, in a
    container log, that the field was dropped.
    """
    if group_id:
        log.debug("alerts.build_scope: ignoring group_id=%r for routing "
                  "(S1-Scope is clamped to account:site)", group_id)
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
    group_id: str | None = None,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """POST a single prepared alert to the SentinelOne UAM ingest API.

    On success returns ``{"success": True, "status": 2xx, "alert_uid": ..., "data": ...}``.
    On failure returns ``{"success": False, ...}`` with status (0 for transport
    errors), error string, and a truncated detail body when available.

    The function never raises — callers can iterate over results from
    :func:`send_alert` and surface per-alert success/failure in the UI.
    """
    scope = build_scope(account_id, site_id, group_id)
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
    group_id: str | None = None,
    overrides: dict[str, Any] | None = None,
    count: int = 1,
    client: httpx.Client | None = None,
    resolver: AssetResolverProto | None = None,
    enrich: bool | None = None,
) -> list[dict[str, Any]]:
    """High-level helper: prepare and send N alerts from a template.

    Returns one result dict per alert sent. Each carries ``alert_index`` so the
    caller can correlate the result back to its position in the batch.

    If ``resolver`` is supplied, every prepared alert in the batch goes
    through XDR asset resolution before egress (P4.6). The resolver's
    internal cache means N alerts in one batch make at most one mgmt API
    call per distinct name.
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
            prepared = prepare_alert(template, overrides=overrides,
                                      resolver=resolver, enrich=enrich,
                                      template_id=template_id)
            result = egress_alert(
                prepared,
                uam_ingest_url=uam_ingest_url,
                service_token=service_token,
                account_id=account_id,
                site_id=site_id,
                group_id=group_id,
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
    group_id: str | None = None,
    auto_generate_uid: bool = True,
    client: httpx.Client | None = None,
    resolver: AssetResolverProto | None = None,
    enrich: bool | None = None,
) -> dict[str, Any]:
    """Send a user-supplied alert JSON (no template).

    If ``auto_generate_uid`` is True, the same prep step that runs on
    templates is applied (fresh UID, timestamps, resource UIDs) and the
    optional ``resolver`` is consulted. Otherwise the JSON is sent verbatim
    (occasionally needed when re-sending a deterministic alert captured
    from elsewhere). When ``auto_generate_uid`` is False the resolver is
    deliberately bypassed so the caller's payload arrives byte-identical.
    """
    if auto_generate_uid:
        alert = prepare_alert(alert_json, resolver=resolver, enrich=enrich)
    else:
        alert = copy.deepcopy(alert_json)
    return egress_alert(
        alert,
        uam_ingest_url=uam_ingest_url,
        service_token=service_token,
        account_id=account_id,
        site_id=site_id,
        group_id=group_id,
        client=client,
    )
