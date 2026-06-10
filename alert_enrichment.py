"""Alert enrichment — derive MITRE attacks + observables from an OCSF alert.

Why this module exists
======================
The HELIOS / jarvis_coding templates ApiGenie inherited carry only the
bare ``finding_info.title`` + ``finding_info.desc`` for each per-source
alert. They do not declare:

* a MITRE ATT&CK tactic / technique mapping (``attacks[]``), and
* observables (``observables[]``) extracted from the alert tree —
  hostnames, IPs, users, emails, files, URLs, hashes, processes —
  even though those values DO appear in the alert (under ``device``,
  ``resources[]``, ``actor.*``, ``src_endpoint.*``, ``dst_endpoint.*``,
  ``evidences[]``, ``url.*``, etc.).

UAM and downstream consumers happily render whatever observables /
attack mappings the alert ships with, so this module fills that gap at
prepare-time. The enrichment is deterministic, idempotent, and additive:

* If the template already carries ``finding_info.related_events[]`` the
  attacks/observables are merged into the existing entries (no
  overwrites of caller-supplied values).
* Otherwise, a single summary ``related_events[0]`` is synthesised so
  the alert always carries the rich OCSF surface.

The MITRE registry (:data:`MITRE_BY_TEMPLATE`) covers all 71 shipped
templates by stem id. Templates not in the registry fall back to a
vendor-keyword heuristic (:data:`MITRE_BY_KEYWORD`) so even custom
alerts (no template) still get a reasonable mapping when their
``metadata.product.vendor_name`` / ``finding_info.title`` mentions a
known vendor or behavior.

This module has no dependency on the network, the resolver, or
templates on disk — it is pure data transformation and is therefore
trivially unit-testable.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

log = logging.getLogger(__name__)

# OCSF observable.type_id enum (subset we emit). Documented at
# https://schema.ocsf.io/1.1.0/objects/observable — these are the values
# real S1 EDR / HELIOS alerts ship with, so we follow the same convention
# for visual + downstream consumer consistency.
OBS_HOSTNAME = 1
OBS_IP_ADDRESS = 2
OBS_MAC_ADDRESS = 3
OBS_USER_NAME = 4
OBS_EMAIL_ADDRESS = 5
OBS_URL_STRING = 6
OBS_FILE_NAME = 7
OBS_HASH = 8
OBS_PROCESS_NAME = 9
OBS_RESOURCE_UID = 10
OBS_ENDPOINT = 20
OBS_OTHER = 29  # used by HELIOS for ports, pids — kept as the catch-all

# Default MITRE ATT&CK version label — matches HELIOS advanced_sample_alert.json.
_DEFAULT_ATTACK_VERSION = "13.1"


# ── MITRE ATT&CK tactics + techniques registry ──────────────────────────────
#
# Each entry in :data:`MITRE_BY_TEMPLATE` is keyed by template stem
# (matching the JSON filename in ``alert_templates/``). The value is a
# list of attack dicts, each carrying:
#
#   {
#     "tactic":    {"uid": "TA000X", "name": "..."},
#     "technique": {"uid": "T1234[.001]", "name": "..."},
#     "version":   "13.1",
#   }
#
# When multiple tactics apply we emit each as its own entry — UAM
# renders all of them. The values used here align with the public
# ATT&CK Enterprise matrix v13.1.

_TA = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _atk(tactic: str, tid: str, tname: str) -> dict[str, Any]:
    """Build one attacks[] entry. ``tactic`` is the TA000x key."""
    return {
        "tactic": {"uid": tactic, "name": _TA[tactic]},
        "technique": {"uid": tid, "name": tname},
        "version": _DEFAULT_ATTACK_VERSION,
    }


# ──────────────────────────────────────────────────────────────────────
# Windows Event Log family
_MITRE_WEL = {
    "wel_brute_force_success": [
        _atk("TA0006", "T1110", "Brute Force"),
        _atk("TA0001", "T1078", "Valid Accounts"),
    ],
    "wel_hidden_scheduled_task": [
        _atk("TA0003", "T1053.005", "Scheduled Task/Job: Scheduled Task"),
        _atk("TA0005", "T1564", "Hide Artifacts"),
    ],
    "wel_ad_global_admin_group": [
        _atk("TA0004", "T1098", "Account Manipulation"),
        _atk("TA0003", "T1136", "Create Account"),
    ],
}

# Proofpoint family
_MITRE_PROOFPOINT = {
    "proofpoint_phishing_link_clicked": [
        _atk("TA0001", "T1566.002", "Phishing: Spearphishing Link"),
        _atk("TA0002", "T1204.001", "User Execution: Malicious Link"),
    ],
    "proofpoint_attachment_delivered": [
        _atk("TA0001", "T1566.001", "Phishing: Spearphishing Attachment"),
    ],
    "proofpoint_email_alert": [
        _atk("TA0001", "T1566", "Phishing"),
    ],
    "proofpoint_impostor_unblocked": [
        _atk("TA0001", "T1566.003", "Phishing: Spearphishing via Service"),
    ],
    "proofpoint_large_attachments": [
        _atk("TA0010", "T1048.003", "Exfiltration Over Alternative Protocol"),
    ],
    "proofpoint_outbound_phishing": [
        _atk("TA0008", "T1534", "Internal Spearphishing"),
    ],
    "proofpoint_phishing_unblocked": [
        _atk("TA0001", "T1566.001", "Phishing: Spearphishing Attachment"),
    ],
    "proofpoint_source_code_attachments": [
        _atk("TA0010", "T1567", "Exfiltration Over Web Service"),
    ],
}

# SharePoint / data exfil
_MITRE_SHAREPOINT = {
    "sharepoint_data_exfil_alert": [
        _atk("TA0010", "T1530", "Data from Cloud Storage"),
    ],
}

# Palo Alto Networks Firewall (THREAT log family)
_MITRE_PALO_ALTO = {
    "palo_alto_ramnit_c2": [
        _atk("TA0011", "T1071.001", "Application Layer Protocol: Web Protocols"),
        _atk("TA0011", "T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
        _atk("TA0011", "T1105", "Ingress Tool Transfer"),
    ],
    "palo_alto_bladabindi_backdoor": [
        _atk("TA0011", "T1071.001", "Application Layer Protocol: Web Protocols"),
        _atk("TA0011", "T1105", "Ingress Tool Transfer"),
        _atk("TA0011", "T1219", "Remote Access Software"),
    ],
}

# Microsoft 365 (Office 365 / Entra / Exchange / Purview / Defender)
# Grouped by behavior. Several O365 SC alerts are policy-violation
# summaries with no specific technique — we map those to a generic
# Discovery / Defense Evasion combination so the UAM ATT&CK panel isn't
# empty. Vendors of this size are noisy by design.
_MITRE_O365 = {
    # Defense evasion — policy / control tampering
    "o365_admin_consent_all":         [_atk("TA0004", "T1098.003", "Account Manipulation: Additional Cloud Roles")],
    "o365_antiphish_rule_disabled":   [_atk("TA0005", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "o365_app_role_assigned":         [_atk("TA0004", "T1098.003", "Account Manipulation: Additional Cloud Roles")],
    "o365_attachment_removed":        [_atk("TA0005", "T1070", "Indicator Removal")],
    "o365_audit_bypass":              [_atk("TA0005", "T1562.008", "Impair Defenses: Disable or Modify Cloud Logs")],
    "o365_ca_policy_deleted":         [_atk("TA0005", "T1556", "Modify Authentication Process")],
    "o365_ca_policy_updated":         [_atk("TA0005", "T1556", "Modify Authentication Process")],
    "o365_connector_removed":         [_atk("TA0005", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "o365_dlp_policy_deleted":        [_atk("TA0005", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "o365_federation_domain":         [_atk("TA0005", "T1556", "Modify Authentication Process")],
    "o365_full_access_app":           [_atk("TA0004", "T1098.003", "Account Manipulation: Additional Cloud Roles")],
    "o365_inbound_connector":         [_atk("TA0011", "T1090", "Proxy")],
    "o365_intune_ca_bypass":          [_atk("TA0005", "T1556", "Modify Authentication Process")],
    "o365_mail_transport_rule":       [_atk("TA0005", "T1564.008", "Hide Artifacts: Email Hiding Rules")],
    "o365_malware_filter_disabled":   [_atk("TA0005", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "o365_malware_policy_deleted":    [_atk("TA0005", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "o365_management_group_role":     [_atk("TA0004", "T1098.003", "Account Manipulation: Additional Cloud Roles")],
    "o365_outbound_connector":        [_atk("TA0010", "T1567", "Exfiltration Over Web Service")],
    "o365_service_principal":         [_atk("TA0003", "T1136.003", "Create Account: Cloud Account")],
    "o365_threats_zap":               [_atk("TA0005", "T1070", "Indicator Removal")],
    "o365_transport_rule_disabled":   [_atk("TA0005", "T1562.001", "Impair Defenses: Disable or Modify Tools")],
    "o365_url_removed":               [_atk("TA0005", "T1070", "Indicator Removal")],
    "o365_zap_removed":               [_atk("TA0005", "T1070", "Indicator Removal")],
    # Initial / credential access
    "o365_brute_force_success":       [_atk("TA0006", "T1110.003", "Brute Force: Password Spraying"),
                                       _atk("TA0001", "T1078.004", "Valid Accounts: Cloud Accounts")],
    "o365_noncompliant_login":        [_atk("TA0001", "T1078.004", "Valid Accounts: Cloud Accounts")],
    "o365_oauth_email_name":          [_atk("TA0001", "T1078.004", "Valid Accounts: Cloud Accounts"),
                                       _atk("TA0003", "T1098.001", "Account Manipulation: Additional Cloud Credentials")],
    "o365_oauth_nonalpha":            [_atk("TA0001", "T1078.004", "Valid Accounts: Cloud Accounts")],
    "o365_sneaky_2fa":                [_atk("TA0006", "T1621", "Multi-Factor Authentication Request Generation")],
    # Email collection / BEC
    "o365_auto_delete_rule":          [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")],
    "o365_bec_inbox_rule":            [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")],
    "o365_bec_rss_redirect":          [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")],
    "o365_bec_short_param":           [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")],
    "o365_external_redirection":      [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")],
    "o365_forwarding_rule":           [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")],
    "o365_inbox_rule_redirect":       [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")],
    "o365_mailbox_delegation":        [_atk("TA0009", "T1114.002", "Email Collection: Remote Email Collection")],
    # Suspicious mail-client / mass-mail apps (Collection)
    "o365_cloudsponge_activity":      [_atk("TA0009", "T1114", "Email Collection")],
    "o365_emclient_activity":         [_atk("TA0009", "T1114", "Email Collection")],
    "o365_fasthttp_activity":         [_atk("TA0009", "T1114", "Email Collection")],
    "o365_fastmail_activity":         [_atk("TA0009", "T1114", "Email Collection")],
    "o365_perfectdata_activity":      [_atk("TA0009", "T1114", "Email Collection")],
    "o365_sigparser_activity":        [_atk("TA0009", "T1114", "Email Collection")],
    "o365_spike_activity":            [_atk("TA0009", "T1114", "Email Collection")],
    "o365_supermailer_activity":      [_atk("TA0009", "T1114", "Email Collection")],
    "o365_zoominfo_activity":         [_atk("TA0009", "T1114", "Email Collection")],
    # Exfiltration via cloud-storage tools / RDP-as-vector
    "o365_rclone_download":           [_atk("TA0010", "T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage")],
    "o365_rclone_modify":             [_atk("TA0010", "T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage")],
    "o365_rdp_sharepoint_access":     [_atk("TA0008", "T1021.001", "Remote Services: Remote Desktop Protocol"),
                                       _atk("TA0010", "T1530", "Data from Cloud Storage")],
    "o365_rdp_upload":                [_atk("TA0008", "T1021.001", "Remote Services: Remote Desktop Protocol")],
    # Suspicious AI / abuse
    "o365_copilot_jailbreak":         [_atk("TA0002", "T1059", "Command and Scripting Interpreter")],
    # Security & Compliance alerts (severity-sensitivity wrappers)
    "o365_sc_high_alert":             [_atk("TA0007", "T1538", "Cloud Service Dashboard")],
    "o365_sc_info_alert":             [_atk("TA0007", "T1538", "Cloud Service Dashboard")],
    "o365_sc_low_alert":              [_atk("TA0007", "T1538", "Cloud Service Dashboard")],
    "o365_sc_medium_alert":           [_atk("TA0007", "T1538", "Cloud Service Dashboard")],
    "o365_restricted_sending":        [_atk("TA0040", "T1499", "Endpoint Denial of Service")],
}

# Default / advanced sample alerts
_MITRE_DEFAULT = {
    "advanced_sample_alert": [
        _atk("TA0001", "T1566.001", "Phishing: Spearphishing Attachment"),
        _atk("TA0011", "T1071.001", "Application Layer Protocol: Web Protocols"),
    ],
    "default_alert": [
        _atk("TA0002", "T1204.002", "User Execution: Malicious File"),
    ],
    "sample_alert": [],
}

# Merged registry — flat lookup by template stem.
MITRE_BY_TEMPLATE: dict[str, list[dict[str, Any]]] = {
    **_MITRE_WEL,
    **_MITRE_PROOFPOINT,
    **_MITRE_SHAREPOINT,
    **_MITRE_PALO_ALTO,
    **_MITRE_O365,
    **_MITRE_DEFAULT,
}


# Vendor-keyword fallback used when the template id isn't in the registry
# (e.g. ad-hoc / custom alerts). Keyed by lowercase substring; first hit
# wins. Order matters — broader keywords go last.
MITRE_BY_KEYWORD: list[tuple[str, list[dict[str, Any]]]] = [
    ("proofpoint",        [_atk("TA0001", "T1566", "Phishing")]),
    ("palo alto",         [_atk("TA0011", "T1071.001", "Application Layer Protocol: Web Protocols")]),
    ("phishing",          [_atk("TA0001", "T1566", "Phishing")]),
    ("brute force",       [_atk("TA0006", "T1110", "Brute Force")]),
    ("ransomware",        [_atk("TA0040", "T1486", "Data Encrypted for Impact")]),
    ("c2",                [_atk("TA0011", "T1071", "Application Layer Protocol")]),
    ("exfiltration",      [_atk("TA0010", "T1567", "Exfiltration Over Web Service")]),
    ("sharepoint",        [_atk("TA0009", "T1213.002", "Data from Information Repositories: Sharepoint")]),
    ("onedrive",          [_atk("TA0010", "T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage")]),
    ("scheduled task",    [_atk("TA0003", "T1053.005", "Scheduled Task/Job: Scheduled Task")]),
    ("oauth",             [_atk("TA0001", "T1078.004", "Valid Accounts: Cloud Accounts")]),
    ("conditional access", [_atk("TA0005", "T1556", "Modify Authentication Process")]),
    ("admin consent",     [_atk("TA0004", "T1098.003", "Account Manipulation: Additional Cloud Roles")]),
    ("forwarding rule",   [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")]),
    ("inbox rule",        [_atk("TA0009", "T1114.003", "Email Collection: Email Forwarding Rule")]),
    ("mailbox",           [_atk("TA0009", "T1114", "Email Collection")]),
    ("windows event",     [_atk("TA0001", "T1078", "Valid Accounts")]),
    ("microsoft",         [_atk("TA0001", "T1078.004", "Valid Accounts: Cloud Accounts")]),
]


def lookup_attacks(template_id: str | None,
                   alert: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Resolve the MITRE attacks[] list for a template / alert.

    Resolution order:
      1. Exact ``template_id`` hit in :data:`MITRE_BY_TEMPLATE`.
      2. Keyword scan against ``finding_info.title``,
         ``finding_info.desc``, and ``metadata.product.vendor_name`` —
         first match in :data:`MITRE_BY_KEYWORD` wins.
      3. Empty list (no attacks emitted).

    Returns a fresh list of attack dicts (callers may mutate them
    without polluting the registry).
    """
    if template_id and template_id in MITRE_BY_TEMPLATE:
        return [dict(a) for a in MITRE_BY_TEMPLATE[template_id]]
    if alert:
        haystack_parts: list[str] = []
        finding = alert.get("finding_info") or {}
        haystack_parts.append(str(finding.get("title", "")))
        haystack_parts.append(str(finding.get("desc", "")))
        product = (alert.get("metadata") or {}).get("product") or {}
        haystack_parts.append(str(product.get("vendor_name", "")))
        haystack_parts.append(str(product.get("name", "")))
        hay = " ".join(haystack_parts).lower()
        for kw, attacks in MITRE_BY_KEYWORD:
            if kw in hay:
                return [dict(a) for a in attacks]
    return []


# ── Observable harvester ────────────────────────────────────────────────────

def _add_obs(sink: list[dict[str, Any]], seen: set[tuple[str, str]],
             name: str, type_id: int, value: Any) -> None:
    """Append (name, type_id, value) to ``sink`` if not already present.

    Dedup key is ``(name, str(value))`` so the same observable surfaced
    from two different OCSF paths (e.g. ``device.hostname`` and
    ``actor.endpoint.hostname``) doesn't appear twice. Empty / None
    values are dropped.
    """
    if value is None or value == "":
        return
    key = (name, str(value))
    if key in seen:
        return
    seen.add(key)
    sink.append({"name": name, "type_id": type_id, "value": str(value)})


def _harvest_device(node: dict[str, Any], sink: list[dict[str, Any]],
                    seen: set[tuple[str, str]]) -> None:
    """Pull observables out of an OCSF ``device`` / endpoint-shaped dict."""
    if not isinstance(node, dict):
        return
    _add_obs(sink, seen, "device.hostname", OBS_HOSTNAME,
             node.get("hostname") or node.get("name"))
    _add_obs(sink, seen, "device.ip", OBS_IP_ADDRESS, node.get("ip"))
    _add_obs(sink, seen, "device.mac", OBS_MAC_ADDRESS, node.get("mac"))
    _add_obs(sink, seen, "device.uid", OBS_RESOURCE_UID, node.get("uid"))


def _harvest_endpoint(node: dict[str, Any], prefix: str,
                      sink: list[dict[str, Any]],
                      seen: set[tuple[str, str]]) -> None:
    """``src_endpoint`` / ``dst_endpoint`` — host + ip + port."""
    if not isinstance(node, dict):
        return
    _add_obs(sink, seen, f"{prefix}.hostname", OBS_HOSTNAME, node.get("hostname"))
    _add_obs(sink, seen, f"{prefix}.ip", OBS_IP_ADDRESS, node.get("ip"))
    if node.get("port") not in (None, ""):
        _add_obs(sink, seen, f"{prefix}.port", OBS_OTHER, node.get("port"))


def _harvest_user(node: dict[str, Any], sink: list[dict[str, Any]],
                  seen: set[tuple[str, str]]) -> None:
    """``user`` block — name / email / uid."""
    if not isinstance(node, dict):
        return
    _add_obs(sink, seen, "user.name", OBS_USER_NAME, node.get("name"))
    email = node.get("email_addr") or node.get("email")
    _add_obs(sink, seen, "user.email", OBS_EMAIL_ADDRESS, email)
    _add_obs(sink, seen, "user.uid", OBS_RESOURCE_UID, node.get("uid"))


def _harvest_file(node: dict[str, Any], prefix: str,
                  sink: list[dict[str, Any]],
                  seen: set[tuple[str, str]]) -> None:
    """OCSF ``file`` block — name + path + hashes[]."""
    if not isinstance(node, dict):
        return
    _add_obs(sink, seen, f"{prefix}.name", OBS_FILE_NAME, node.get("name"))
    _add_obs(sink, seen, f"{prefix}.path", OBS_FILE_NAME, node.get("path"))
    hashes = node.get("hashes")
    if isinstance(hashes, list):
        for h in hashes:
            if isinstance(h, dict):
                _add_obs(sink, seen, f"{prefix}.hash", OBS_HASH, h.get("value"))


def _harvest_process(node: dict[str, Any], prefix: str,
                     sink: list[dict[str, Any]],
                     seen: set[tuple[str, str]]) -> None:
    """OCSF ``process`` block — name + pid + cmd_line + nested file."""
    if not isinstance(node, dict):
        return
    _add_obs(sink, seen, f"{prefix}.name", OBS_PROCESS_NAME, node.get("name"))
    if node.get("pid") not in (None, ""):
        _add_obs(sink, seen, f"{prefix}.pid", OBS_OTHER, node.get("pid"))
    _add_obs(sink, seen, f"{prefix}.cmd_line", OBS_PROCESS_NAME,
             node.get("cmd_line"))
    if isinstance(node.get("file"), dict):
        _harvest_file(node["file"], f"{prefix}.file", sink, seen)


def _harvest_url(node: dict[str, Any], sink: list[dict[str, Any]],
                 seen: set[tuple[str, str]]) -> None:
    if not isinstance(node, dict):
        return
    _add_obs(sink, seen, "url.url", OBS_URL_STRING, node.get("url"))
    _add_obs(sink, seen, "url.hostname", OBS_HOSTNAME, node.get("hostname"))
    _add_obs(sink, seen, "url.path", OBS_URL_STRING, node.get("path"))


def _harvest_email(node: dict[str, Any], sink: list[dict[str, Any]],
                   seen: set[tuple[str, str]]) -> None:
    if not isinstance(node, dict):
        return
    _add_obs(sink, seen, "email.from", OBS_EMAIL_ADDRESS,
             node.get("from") or node.get("smtp_from"))
    to_field = node.get("to")
    if isinstance(to_field, list):
        for addr in to_field:
            _add_obs(sink, seen, "email.to", OBS_EMAIL_ADDRESS, addr)
    elif isinstance(to_field, str):
        _add_obs(sink, seen, "email.to", OBS_EMAIL_ADDRESS, to_field)
    _add_obs(sink, seen, "email.subject", OBS_OTHER, node.get("subject"))


def _harvest_resource(node: dict[str, Any], sink: list[dict[str, Any]],
                      seen: set[tuple[str, str]]) -> None:
    """``resources[]`` entry — type-aware: User-shape → email/user, else endpoint."""
    if not isinstance(node, dict):
        return
    rtype = str(node.get("type") or "").lower()
    name = node.get("name") or node.get("hostname") or ""
    uid = node.get("uid")
    if "user" in rtype or (name and isinstance(name, str) and "@" in name):
        if name and "@" in str(name):
            _add_obs(sink, seen, "resource.email", OBS_EMAIL_ADDRESS, name)
        elif name:
            _add_obs(sink, seen, "resource.user", OBS_USER_NAME, name)
    else:
        # Endpoint-ish (Device / Server / Workstation / Endpoint / Host / …).
        _add_obs(sink, seen, "resource.hostname", OBS_HOSTNAME, name)
    _add_obs(sink, seen, "resource.uid", OBS_RESOURCE_UID, uid)


def harvest_observables(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk the alert tree and emit a deduped OCSF ``observables[]`` list.

    Covers the OCSF paths real-world templates populate:

    * ``device.*``                — hostname, ip, mac, uid
    * ``resources[]``             — name (host or email), uid, type
    * ``actor.user.*``            — name, email, uid
    * ``actor.process.*``         — name, pid, cmd_line, file.{name,hashes}
    * ``actor.endpoint.*``        — same shape as device
    * ``src_endpoint.*`` / ``dst_endpoint.*`` — hostname, ip, port
    * ``url.*``                   — url, hostname, path
    * ``email.*``                 — from, to (list or scalar), subject
    * ``file.*``                  — name, path, hashes[]
    * ``process.*``               — same shape as actor.process
    * ``evidences[].process.*``   — recursive process+file harvest
    * ``evidences[].file.*``      — file harvest

    Returns a fresh list — caller is free to mutate.
    """
    sink: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(alert, dict):
        return sink

    _harvest_device(alert.get("device") or {}, sink, seen)

    for res in alert.get("resources") or []:
        _harvest_resource(res, sink, seen)

    # Templates ship the actor block under ``finding_info.actor`` (canonical
    # OCSF placement for our Phase-2 enriched alerts). Older payloads may
    # still put it at the top level — fall back to that for back-compat so
    # external/non-templated alerts keep enriching cleanly.
    fi = alert.get("finding_info") or {}
    actor = (fi.get("actor") if isinstance(fi, dict) else None) or alert.get("actor") or {}
    if isinstance(actor, dict):
        _harvest_user(actor.get("user") or {}, sink, seen)
        _harvest_process(actor.get("process") or {}, "actor.process", sink, seen)
        ep = actor.get("endpoint")
        if isinstance(ep, dict):
            _add_obs(sink, seen, "actor.endpoint.hostname", OBS_HOSTNAME,
                     ep.get("hostname") or ep.get("name"))
            _add_obs(sink, seen, "actor.endpoint.ip", OBS_IP_ADDRESS, ep.get("ip"))

    _harvest_endpoint(alert.get("src_endpoint") or {}, "src_endpoint", sink, seen)
    _harvest_endpoint(alert.get("dst_endpoint") or {}, "dst_endpoint", sink, seen)

    _harvest_url(alert.get("url") or {}, sink, seen)
    _harvest_email(alert.get("email") or {}, sink, seen)
    _harvest_file(alert.get("file") or {}, "file", sink, seen)
    _harvest_process(alert.get("process") or {}, "process", sink, seen)

    for ev in alert.get("evidences") or []:
        if not isinstance(ev, dict):
            continue
        _harvest_process(ev.get("process") or {}, "evidences.process", sink, seen)
        _harvest_file(ev.get("file") or {}, "evidences.file", sink, seen)
        _harvest_user(ev.get("user") or {}, sink, seen)

    return sink


# ── Top-level enrichment ────────────────────────────────────────────────────

def enrich_alert(alert: dict[str, Any], *,
                 template_id: str | None = None,
                 time_ms: int | None = None) -> dict[str, Any]:
    """Mutate ``alert`` in-place to add MITRE attacks + observables.

    Behaviour:

    * Resolves the MITRE ATT&CK ``attacks[]`` list via
      :func:`lookup_attacks` (template registry → vendor-keyword fallback
      → empty).
    * Walks the alert tree and harvests OCSF observables via
      :func:`harvest_observables`.
    * Ensures ``finding_info.related_events[]`` exists. When the
      template ships none, a single summary entry is synthesised. When
      it ships some, each existing entry receives (additively) the
      attacks + observables that aren't already there.
    * Every ``related_events[]`` entry is given a fresh ``uid`` (matches
      HELIOS contract; also a no-op when prepare_alert already did it,
      since UUIDs are idempotent under set semantics).
    * Returns a small report dict describing what was added — useful
      for the admin UI / send-response panel.

    Idempotency: calling ``enrich_alert`` twice on the same alert
    produces the same observable list (dedup) and the same attack list
    (matched by ``technique.uid``), so retries and re-renders are safe.

    The function is a no-op (returns an empty report) when ``alert`` is
    not a dict — defensive against malformed callers.
    """
    report = {
        "applied": False,
        "template_id": template_id or "",
        "attacks_added": 0,
        "observables_added": 0,
        "related_events": 0,
        "mode": "skip",
    }
    if not isinstance(alert, dict):
        return report

    attacks = lookup_attacks(template_id, alert)
    observables = harvest_observables(alert)

    finding = alert.setdefault("finding_info", {})
    if not isinstance(finding, dict):
        return report
    rel_events = finding.get("related_events")
    if not isinstance(rel_events, list) or not rel_events:
        # Synthesise one summary event so every alert ships rich OCSF
        # surface even when the template only carried title + desc.
        title = str(finding.get("title") or "Security Alert")
        new_event = {
            "uid": str(uuid.uuid4()),
            "type": "Security Alert",
            "message": title,
            "severity_id": int(alert.get("severity_id") or 0),
            "attacks": attacks,
            "observables": observables,
        }
        if time_ms is not None:
            new_event["time"] = time_ms
        finding["related_events"] = [new_event]
        report["mode"] = "synthesised"
    else:
        # Template carries pre-built related_events — respect authored
        # per-event narratives:
        #
        #   * If an entry already declares ``attacks[]`` (template author
        #     was explicit about the MITRE mapping for THIS step of the
        #     story) we leave it untouched. Broadcasting template-level
        #     attacks to every event would contaminate each step with
        #     the others' techniques.
        #   * If an entry has NO ``attacks[]`` yet, we backfill from the
        #     template-level lookup so the OCSF surface is non-empty.
        #
        # Same rule for ``observables[]``: respect when populated,
        # backfill when empty.
        #
        # Either way, every entry gets a fresh UID.
        for entry in rel_events:
            if not isinstance(entry, dict):
                continue
            entry["uid"] = str(uuid.uuid4())
            if not entry.get("attacks"):
                entry["attacks"] = [dict(a) for a in attacks]
            if not entry.get("observables"):
                entry["observables"] = list(observables)
        report["mode"] = "merged"

    report["applied"] = True
    report["attacks_added"] = len(attacks)
    report["observables_added"] = len(observables)
    report["related_events"] = len(finding["related_events"])
    return report
