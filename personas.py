"""Scenario persona bundles — shared entities across simulated sources.

An attack scenario in apigenie used to be five disjoint random streams
of events that just happened to share an ``attack.id`` tag: each
source picked its own victim / IP / hostname / hash via
``random.choice(_USERS)`` and friends. The result was correlation-
free noise pretending to be an attack — a real SOC analyst would
discard it on first inspection because the five alerts touch five
different people.

This module is the single source of truth for the entities the
runtime should anchor an attack to. A ``bundle`` is generated once
per scenario, persisted on the scenario record, and consulted by the
rule engine when it stamps overrides on the events of every source
involved in that scenario. The result: one victim, one attacker, one
laptop, one malicious file — visible across Okta, Proofpoint, M365,
Defender, Netskope, Entra ID, CloudTrail and Cisco Duo events for
the entire duration of the simulation.

The schema below is the contract every source's ``PERSONA_PROJECTION``
mapping is expected to resolve against. Adding a new slot here is a
backwards-compatible feature; renaming or removing a slot is a
breaking change that must come with projection updates on every
source that referenced it.

The module exposes three primitives:

* :func:`generate_bundle` — fresh, fully populated bundle. No
  arguments; non-deterministic across calls so two scenarios created
  back-to-back don't land on the same victim.
* :func:`resolve_path` — dotted-path walker; returns ``None`` for any
  path that fails to resolve. ``None`` is the explicit "fall through
  to the source's random default" signal the rule engine relies on
  (raising here would block every other override and kill the event
  mix).
* :func:`validate_bundle` — returns a list of human-readable problems
  (empty list ⇒ OK). Used by the (future) UI editor and by
  scenario import to reject corrupt or hand-edited bundles before
  they reach disk.
"""
from __future__ import annotations

import hashlib
import random
import string
import uuid
from typing import Any


# ── Canonical schema ────────────────────────────────────────────────
#
# Every key listed here is a slot a source's PERSONA_PROJECTION map
# may reference. Test ``test_persona_projection_sources`` enforces
# that no source mentions a slot that isn't on this list — typos like
# ``victim_user.emai`` would otherwise silently fall through to None
# and the analyst would see an empty field on the wire.
CANONICAL_SCHEMA: dict[str, list[str]] = {
    "victim_user": ["name", "username", "email", "upn", "object_id"],
    "victim_host": ["hostname", "ip", "os", "agent_uuid"],
    "attacker":    ["ip", "country", "email", "domain", "asn"],
    "malicious":   ["file_name", "sha256", "md5", "process", "cmd_line"],
}


# Demo people pool. Kept narrow so a single demo session shows a
# coherent cast — Slack #soc-demo doesn't want fifty random names.
# Names are realistic but obviously synthetic (no celebrities, no
# actual employees) so screenshots in marketing decks are safe.
_VICTIM_POOL: list[tuple[str, str, str]] = [
    # (display_name, username, email_local_part)
    ("John Doe",         "jdoe",        "john.doe"),
    ("Maria Bianchi",    "mbianchi",    "maria.bianchi"),
    ("Lukas Schneider",  "lschneider",  "lukas.schneider"),
    ("Aiko Tanaka",      "atanaka",     "aiko.tanaka"),
    ("Priya Patel",      "ppatel",      "priya.patel"),
    ("Ahmed Hassan",     "ahassan",     "ahmed.hassan"),
    ("Sofia Costa",      "scosta",      "sofia.costa"),
    ("Connor O'Brien",   "cobrien",     "connor.obrien"),
    ("Yuki Sato",        "ysato",       "yuki.sato"),
    ("Olivia Brown",     "obrown",      "olivia.brown"),
]

# Corporate / target domains for the victim. Kept short and clearly
# synthetic so they read as "my company" in a demo.
_TARGET_DOMAINS: list[str] = [
    "acme-corp.test",
    "globex-bank.test",
    "umbrella-health.test",
    "initech.test",
    "stark-industries.test",
]

# Attacker infrastructure pool. IPs are well-known "research" ranges
# (TOR-exit-ish, bulletproof hosters) so a SOC analyst recognises the
# shape; the country codes pair with them. These are NEVER routable
# in customer environments — picking 198.51.100.0/24 (TEST-NET-2)
# and 203.0.113.0/24 (TEST-NET-3) keeps the demos safe.
_ATTACKER_IPS: list[tuple[str, str, str]] = [
    # (ip, country, asn)
    ("185.220.101.42", "RU", "AS9009"),
    ("198.51.100.7",   "CN", "AS4837"),
    ("203.0.113.66",   "IR", "AS31549"),
    ("45.155.205.18",  "KP", "AS204601"),
    ("194.26.135.99",  "BY", "AS6697"),
    ("23.94.137.218",  "RU", "AS36352"),
]

# Bad-looking sender / C2 infra. Domains intentionally read as a
# phishing or commodity-malware lure. ``.bad``/``.scam`` are not real
# TLDs so an enrichment lookup against a live threat-intel feed
# resolves to nothing — exactly what we want for a self-contained lab.
_ATTACKER_DOMAINS: list[str] = [
    "invoice-corp.bad",
    "evilcorp.bad",
    "payroll-update.scam",
    "secure-bank-login.bad",
    "shared-document-link.scam",
    "office365-renewal.bad",
]

_ATTACKER_LOCAL_PARTS: list[str] = [
    "billing", "noreply", "accounts", "hr", "security", "payroll",
]

# Plausible malicious-payload filenames. Mix of office docs, scripts,
# and PE binaries so the simulated stories can hit Proofpoint
# attachment + WEF process + Defender file events with consistent
# names.
_MALICIOUS_FILES: list[tuple[str, str]] = [
    # (filename, primary process used for execution)
    ("Invoice_Q4.docm",            "WINWORD.EXE"),
    ("Payroll_Update.xlsm",        "EXCEL.EXE"),
    ("Shared_Document.pdf.js",     "wscript.exe"),
    ("HR_Policy_Update.docm",      "WINWORD.EXE"),
    ("VPN_Setup.exe",              "VPN_Setup.exe"),
    ("Statement.lnk",              "powershell.exe"),
    ("Order_Confirmation.iso",     "rundll32.exe"),
]


def _internal_ip() -> str:
    """Pick a plausible RFC1918 internal address for the victim host."""
    octets = [
        random.choice(["10.42", "10.10", "192.168.1", "192.168.5", "172.16.4"]),
        random.randint(1, 254),
        random.randint(1, 254),
    ]
    # Already provides the first two; pad with two random tail octets.
    head, tail2, tail3 = octets
    if head.count(".") == 1:           # "10.42" etc.
        return f"{head}.{tail2}.{tail3}"
    return f"{head}.{tail3}"            # "192.168.1" etc.


def _hostname_from_username(username: str) -> str:
    """Generate a hostname that visibly belongs to the victim, e.g.
    ``JDOE-LAPTOP-7``. Same username ⇒ same hostname prefix, so when
    you spot the host in a Defender alert and the user in an Okta
    event you can tie them by eye, without running a query."""
    suffix = random.randint(1, 99)
    return f"{username.upper()}-LAPTOP-{suffix}"


def _generate_sha256() -> str:
    """64-hex-char fingerprint, indistinguishable from a real SHA-256
    on the wire. Hashing UUID bytes is fast and gives us full entropy."""
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def _generate_md5() -> str:
    """32-hex-char fingerprint matching real MD5 shape."""
    return hashlib.md5(uuid.uuid4().bytes).hexdigest()


def _generate_cmd_line(process: str) -> str:
    """Plausible PowerShell / cscript invocation for the given
    process. The payload is base64-padding-shaped but decodes to
    nothing — it's a decoy that looks like the encoded PowerShell
    blobs SOC analysts see every week."""
    payload = "".join(random.choices(string.ascii_letters + string.digits, k=64)) + "=="
    if "powershell" in process.lower():
        return f"powershell.exe -NoP -W Hidden -Enc {payload}"
    if "wscript" in process.lower() or "cscript" in process.lower():
        return f"{process} //E:jscript /B {payload[:32]}"
    if "rundll32" in process.lower():
        return f"rundll32.exe shell32.dll,Control_RunDLL {payload[:16]}"
    return f'"{process}" /quiet /norestart'


# ── Public API ──────────────────────────────────────────────────────


def generate_bundle() -> dict[str, dict[str, Any]]:
    """Roll a fresh, fully populated persona bundle.

    Every slot in :data:`CANONICAL_SCHEMA` is filled. The bundle is
    JSON-serialisable so it can live on the scenario record on disk
    next to ``phases`` / ``duration`` without special handling.
    """
    # ── Victim user ──
    display, username, local_part = random.choice(_VICTIM_POOL)
    target_domain = random.choice(_TARGET_DOMAINS)
    email = f"{local_part}@{target_domain}"
    victim_user = {
        "name":      display,
        "username":  username,
        "email":     email,
        # On Entra ID / M365 the upn IS the email for the vast majority
        # of tenants; keeping them in sync avoids confusing the analyst
        # when she sees both fields in different products.
        "upn":       email,
        "object_id": str(uuid.uuid4()),
    }

    # ── Victim host ──
    victim_host = {
        "hostname":   _hostname_from_username(username),
        "ip":         _internal_ip(),
        "os":         random.choice([
            "Windows 11", "Windows 10", "macOS 14", "macOS 13",
        ]),
        "agent_uuid": uuid.uuid4().hex,
    }

    # ── Attacker ──
    ip, country, asn = random.choice(_ATTACKER_IPS)
    domain = random.choice(_ATTACKER_DOMAINS)
    attacker = {
        "ip":      ip,
        "country": country,
        "email":   f"{random.choice(_ATTACKER_LOCAL_PARTS)}@{domain}",
        "domain":  domain,
        "asn":     asn,
    }

    # ── Malicious payload ──
    filename, process = random.choice(_MALICIOUS_FILES)
    malicious = {
        "file_name": filename,
        "sha256":    _generate_sha256(),
        "md5":       _generate_md5(),
        "process":   process,
        "cmd_line":  _generate_cmd_line(process),
    }

    return {
        "victim_user": victim_user,
        "victim_host": victim_host,
        "attacker":    attacker,
        "malicious":   malicious,
    }


def resolve_path(bundle: dict[str, Any] | None, path: str) -> Any | None:
    """Walk a dotted persona path. ``None`` on any miss.

    Returning ``None`` rather than raising is intentional: a missing
    slot just means the projection should fall through to the
    source's existing random default. The rule engine never crashes
    on a partial bundle.
    """
    if not bundle or not isinstance(bundle, dict) or not path:
        return None
    cur: Any = bundle
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        if part not in cur:
            return None
        cur = cur[part]
    return cur


def validate_bundle(bundle: Any) -> list[str]:
    """Return a list of human-readable problems with *bundle*.

    Empty list ⇒ the bundle is structurally sound and every canonical
    slot is populated with a non-empty value. Used by import/export
    and by the (future) persona editor so the operator gets a clean
    list of fields to fix instead of a stack trace at runtime.
    """
    problems: list[str] = []
    if not isinstance(bundle, dict):
        return [f"bundle must be a dict, got {type(bundle).__name__}"]

    for slot, fields in CANONICAL_SCHEMA.items():
        if slot not in bundle:
            problems.append(f"missing top-level slot: {slot!r}")
            continue
        node = bundle[slot]
        if not isinstance(node, dict):
            problems.append(
                f"{slot!r} must be a dict, got {type(node).__name__}")
            continue
        for field in fields:
            val = node.get(field)
            if val is None or val == "":
                problems.append(f"{slot}.{field} is empty")
    return problems
