"""Log Profiles — reusable entity pools for deterministic, correlatable log generation.

Each profile defines users, machines, C2 servers, malware samples, and mail
senders.  When a profile is bound to a source, the source generator blends
profile entities with random noise at a configurable ratio.

Profiles are stored as JSON under ``DATA_ROOT/profiles/<uuid>.json``.
Source-to-profile bindings live in ``DATA_ROOT/source_profiles.json``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import threading
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Storage paths ─────────────────────────────────────────────────────────────
_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
PROFILES_DIR = _DATA_ROOT / "profiles"
_BINDINGS_FILE = _DATA_ROOT / "source_profiles.json"

_lock = threading.Lock()

# ── Star Wars padding pools ──────────────────────────────────────────────────
# Characters from Star Wars TV Series (The Mandalorian, Ahsoka, Andor,
# The Book of Boba Fett, Rebels, Clone Wars, Obi-Wan Kenobi, etc.)

_SW_USERS = [
    {"name": "Ahsoka Tano",        "email": "ahsoka@jedi-order.net",     "domain": "JEDI",       "username": "ahsoka",    "department": "Intelligence",    "city": "Corvus",      "country": "Outer Rim", "role": "Commander",  "primary_workstation": "shuttle-01",  "server_of_reference": "Ghost",       "workstation_ip": "10.77.1.10",  "server_ip": "172.16.77.10"},
    {"name": "Din Djarin",          "email": "din@mandalore.net",         "domain": "MANDALORE",  "username": "din",       "department": "Security",        "city": "Nevarro",     "country": "Outer Rim", "role": "Bounty Hunter","primary_workstation": "razorcrest",  "server_of_reference": "Gauntlet",    "workstation_ip": "10.77.2.10",  "server_ip": "172.16.77.20"},
    {"name": "Bo-Katan Kryze",      "email": "bokatan@mandalore.net",     "domain": "MANDALORE",  "username": "bokatan",   "department": "Command",         "city": "Kalevala",    "country": "Mandalore", "role": "Regent",     "primary_workstation": "gauntlet-br", "server_of_reference": "Nite-Owl",    "workstation_ip": "10.77.3.10",  "server_ip": "172.16.77.30"},
    {"name": "Hera Syndulla",       "email": "hera@phoenix-sqd.net",      "domain": "PHOENIX",    "username": "hera",      "department": "Operations",      "city": "Ryloth",      "country": "Outer Rim", "role": "General",    "primary_workstation": "ghost-helm",  "server_of_reference": "Ghost",       "workstation_ip": "10.77.4.10",  "server_ip": "172.16.77.40"},
    {"name": "Cassian Andor",       "email": "cassian@rebel-int.net",     "domain": "REBELLION",  "username": "cassian",   "department": "Intelligence",    "city": "Ferrix",      "country": "Inner Rim", "role": "Agent",      "primary_workstation": "ferrix-ws",   "server_of_reference": "Bravo-One",   "workstation_ip": "10.77.5.10",  "server_ip": "172.16.77.50"},
    {"name": "Sabine Wren",         "email": "sabine@mandalore.net",      "domain": "PHOENIX",    "username": "sabine",    "department": "Engineering",     "city": "Krownest",    "country": "Mandalore", "role": "Specialist", "primary_workstation": "phantom-ii",  "server_of_reference": "Ghost",       "workstation_ip": "10.77.6.10",  "server_ip": "172.16.77.60"},
    {"name": "Kanan Jarrus",        "email": "kanan@jedi-order.net",      "domain": "JEDI",       "username": "kanan",     "department": "Training",        "city": "Lothal",      "country": "Outer Rim", "role": "Knight",     "primary_workstation": "ghost-qrt",   "server_of_reference": "Ghost",       "workstation_ip": "10.77.7.10",  "server_ip": "172.16.77.70"},
    {"name": "Ezra Bridger",        "email": "ezra@jedi-order.net",       "domain": "JEDI",       "username": "ezra",      "department": "Operations",      "city": "Lothal",      "country": "Outer Rim", "role": "Padawan",    "primary_workstation": "tower-ws",    "server_of_reference": "Ghost",       "workstation_ip": "10.77.8.10",  "server_ip": "172.16.77.80"},
    {"name": "Boba Fett",           "email": "boba@hutt-council.net",     "domain": "HUTT",       "username": "boba",      "department": "Security",        "city": "Mos Espa",    "country": "Tatooine",  "role": "Daimyo",     "primary_workstation": "palace-ws",   "server_of_reference": "Slave-I",     "workstation_ip": "10.77.9.10",  "server_ip": "172.16.77.90"},
    {"name": "Fennec Shand",        "email": "fennec@hutt-council.net",   "domain": "HUTT",       "username": "fennec",    "department": "Operations",      "city": "Mos Espa",    "country": "Tatooine",  "role": "Enforcer",   "primary_workstation": "palace-ops",  "server_of_reference": "Slave-I",     "workstation_ip": "10.77.10.10", "server_ip": "172.16.77.100"},
]

_SW_MACHINES = [
    {"primary_workstation": "razorcrest",    "os_type": "linux",   "role": "workstation", "ip": "10.77.20.1"},
    {"primary_workstation": "gauntlet",      "os_type": "linux",   "role": "server",      "ip": "10.77.20.2"},
    {"primary_workstation": "ghost-helm",    "os_type": "linux",   "role": "workstation", "ip": "10.77.20.3"},
    {"primary_workstation": "phantom-ii",    "os_type": "linux",   "role": "workstation", "ip": "10.77.20.4"},
    {"primary_workstation": "tower-ws",      "os_type": "windows", "role": "workstation", "ip": "10.77.20.5"},
    {"primary_workstation": "ferrix-ws",     "os_type": "windows", "role": "workstation", "ip": "10.77.20.6"},
    {"primary_workstation": "palace-ws",     "os_type": "windows", "role": "server",      "ip": "10.77.20.7"},
    {"primary_workstation": "nite-owl-srv",  "os_type": "linux",   "role": "server",      "ip": "10.77.20.8"},
    {"primary_workstation": "lothal-dc",     "os_type": "windows", "role": "server",      "ip": "10.77.20.9"},
    {"primary_workstation": "krownest-bkp",  "os_type": "linux",   "role": "server",      "ip": "10.77.20.10"},
]

_SW_C2 = [
    {"ip_c2": "185.220.101.42",  "port": "443",  "fqdn": "imperial-relay.darkside.net"},
    {"ip_c2": "91.215.85.17",    "port": "8443", "fqdn": "shadow-council.sith.io"},
    {"ip_c2": "45.154.98.222",   "port": "4444", "fqdn": "inquisitor-c2.empire.org"},
    {"ip_c2": "193.56.29.100",   "port": "9090", "fqdn": "deathwatch.mando-splinter.net"},
    {"ip_c2": "77.91.124.55",    "port": "5555", "fqdn": "crimson-dawn.syndicate.io"},
]

_SW_MALWARE = [
    {"filename": "order66.exe",        "hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "source_process": "c:\\windows\\system32\\cmd.exe",        "cmdline": "/c order66.exe -silent"},
    {"filename": "darktroopers.dll",   "hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3", "source_process": "c:\\windows\\system32\\rundll32.exe",    "cmdline": "darktroopers.dll,Entry"},
    {"filename": "holocron.ps1",       "hash": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "source_process": "c:\\windows\\system32\\powershell.exe",  "cmdline": "-ep bypass -f holocron.ps1"},
    {"filename": "probe_droid.sh",     "hash": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5", "source_process": "/bin/bash",                              "cmdline": "-c ./probe_droid.sh --stealth"},
    {"filename": "kyber_miner.bin",    "hash": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6", "source_process": "/usr/bin/python3",                       "cmdline": "kyber_miner.bin --pool stratum+tcp://mining.sith.io:3333"},
    {"filename": "deathstar.bat",      "hash": "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1", "source_process": "c:\\windows\\system32\\cmd.exe",        "cmdline": "/c deathstar.bat -wipe"},
    {"filename": "spice_runner.elf",   "hash": "a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8", "source_process": "/bin/sh",                                "cmdline": "-c ./spice_runner.elf -exfil"},
    {"filename": "beskar_crypt.exe",   "hash": "b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8b1b2b3b4b5b6b7b8", "source_process": "c:\\windows\\system32\\powershell.exe",  "cmdline": "-enc UwB0AGEAcgB0AC0A"},
    {"filename": "sarlacc_worm.py",    "hash": "c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8c1c2c3c4c5c6c7c8", "source_process": "/usr/bin/python3",                       "cmdline": "sarlacc_worm.py --spread"},
    {"filename": "maul_rootkit.sys",   "hash": "d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8d1d2d3d4d5d6d7d8", "source_process": "c:\\windows\\system32\\sc.exe",         "cmdline": "create MaulSvc binPath= maul_rootkit.sys"},
]

_SW_MAIL_SENDERS = [
    {"mail_address": "emperor@galactic-empire.gov",    "subject": "New Imperial Decree",          "link": "https://bit.ly/imperial-decree",     "attachment_filename": "decree.pdf"},
    {"mail_address": "tarkin@deathstar.mil",           "subject": "Project Stardust Update",      "link": "https://bit.ly/stardust-doc",        "attachment_filename": "stardust_plans.docx"},
    {"mail_address": "thrawn@chiss-ascendancy.net",    "subject": "Strategic Analysis Report",    "link": "https://bit.ly/thrawn-analysis",     "attachment_filename": "analysis.xlsx"},
    {"mail_address": "gar.saxon@mandalore.gov",        "subject": "Mandatory Compliance Review",  "link": "https://bit.ly/saxon-compliance",    "attachment_filename": "compliance.pdf"},
    {"mail_address": "moff.gideon@remnant.mil",        "subject": "Asset Recovery Notice",        "link": "https://bit.ly/gideon-asset",        "attachment_filename": "recovery_tool.exe"},
]


# ── Limits ────────────────────────────────────────────────────────────────────
LIMITS = {
    "users": 10,
    "machines": 10,
    "c2_servers": 5,
    "malware": 10,
    "mail_senders": 5,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ensure_dirs():
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)


def _profile_path(profile_id: str) -> Path:
    return PROFILES_DIR / f"{profile_id}.json"


def _load_bindings() -> dict[str, Any]:
    if _BINDINGS_FILE.exists():
        try:
            return json.loads(_BINDINGS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            log.warning("Corrupt source_profiles.json — returning empty")
    return {}


def _save_bindings(data: dict[str, Any]):
    _BINDINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _BINDINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str))
    tmp.replace(_BINDINGS_FILE)


def _pad_list(items: list[dict], pool: list[dict], limit: int, rng: random.Random) -> list[dict]:
    """Return *items* padded with entries from *pool* up to *limit*, seeded."""
    if len(items) >= limit:
        return items[:limit]
    need = limit - len(items)
    shuffled = list(pool)
    rng.shuffle(shuffled)
    # Avoid duplicates with existing items (match on first key value)
    existing_keys = set()
    if items:
        first_key = next(iter(items[0]))
        existing_keys = {it[first_key] for it in items if first_key in it}
        candidates = [p for p in shuffled if p.get(first_key) not in existing_keys]
    else:
        candidates = shuffled
    return items + candidates[:need]


def _source_hash(source: str) -> int:
    """Deterministic int from a source name, used to vary the seed per-source."""
    return int(hashlib.md5(source.encode()).hexdigest()[:8], 16)


# ── Profile CRUD ──────────────────────────────────────────────────────────────

def create_profile(data: dict[str, Any]) -> dict[str, Any]:
    """Create a new profile. Returns the saved profile dict (with id & seed)."""
    _ensure_dirs()
    profile_id = str(uuid.uuid4())
    profile = {
        "id": profile_id,
        "name": data.get("name", "Untitled"),
        "description": data.get("description", ""),
        "seed": data.get("seed", random.randint(1, 2**31)),
        "users": data.get("users", [])[:LIMITS["users"]],
        "machines": data.get("machines", [])[:LIMITS["machines"]],
        "c2_servers": data.get("c2_servers", [])[:LIMITS["c2_servers"]],
        "malware": data.get("malware", [])[:LIMITS["malware"]],
        "mail_senders": data.get("mail_senders", [])[:LIMITS["mail_senders"]],
    }
    with _lock:
        _profile_path(profile_id).write_text(json.dumps(profile, indent=2))
    log.info("Profile created: %s (%s)", profile["name"], profile_id)
    return profile


def get_profile(profile_id: str) -> dict[str, Any] | None:
    p = _profile_path(profile_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def update_profile(profile_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
    with _lock:
        existing = get_profile(profile_id)
        if existing is None:
            return None
        for key in ("name", "description", "seed"):
            if key in data:
                existing[key] = data[key]
        for key in LIMITS:
            if key in data:
                existing[key] = data[key][:LIMITS[key]]
        _profile_path(profile_id).write_text(json.dumps(existing, indent=2))
    log.info("Profile updated: %s", profile_id)
    return existing


def delete_profile(profile_id: str) -> bool:
    with _lock:
        p = _profile_path(profile_id)
        if not p.exists():
            return False
        p.unlink()
        # Also remove any bindings referencing this profile
        bindings = _load_bindings()
        changed = False
        for src, bnd in list(bindings.items()):
            if bnd.get("profile_id") == profile_id:
                del bindings[src]
                changed = True
        if changed:
            _save_bindings(bindings)
    log.info("Profile deleted: %s", profile_id)
    return True


def list_profiles() -> list[dict[str, Any]]:
    _ensure_dirs()
    result = []
    for p in sorted(PROFILES_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text())
            result.append({
                "id": data["id"],
                "name": data.get("name", "?"),
                "description": data.get("description", ""),
                "users": len(data.get("users", [])),
                "machines": len(data.get("machines", [])),
                "c2_servers": len(data.get("c2_servers", [])),
                "malware": len(data.get("malware", [])),
                "mail_senders": len(data.get("mail_senders", [])),
            })
        except (json.JSONDecodeError, OSError, KeyError):
            continue
    return result


# ── Source-profile bindings ───────────────────────────────────────────────────

def bind_source(source: str, profile_id: str, ratio: int = 70) -> dict[str, Any]:
    """Bind a source to a profile with a blend ratio (0-100)."""
    ratio = max(0, min(100, ratio))
    with _lock:
        bindings = _load_bindings()
        bindings[source] = {"profile_id": profile_id, "ratio": ratio}
        _save_bindings(bindings)
    return bindings[source]


def unbind_source(source: str) -> bool:
    with _lock:
        bindings = _load_bindings()
        if source not in bindings:
            return False
        del bindings[source]
        _save_bindings(bindings)
    return True


def get_binding(source: str) -> dict[str, Any] | None:
    bindings = _load_bindings()
    return bindings.get(source)


def list_bindings() -> dict[str, Any]:
    return _load_bindings()


# ── ProfileContext — the interface generators use ─────────────────────────────

class ProfileContext:
    """Provides padded entity pools and a seeded RNG for a source.

    Usage in a generator::

        ctx = profiles.get_context("okta")
        if ctx:
            user = ctx.pick_user()   # profile entity or None (noise event)
            rng  = ctx.rng           # seeded Random for other decisions
    """

    def __init__(self, profile: dict[str, Any], source: str, ratio: int):
        self.profile = profile
        self.source = source
        self.ratio = ratio  # 0-100

        seed = profile.get("seed", 42)
        src_offset = _source_hash(source)
        self.rng = random.Random(seed + src_offset)

        # Padded pools
        self.users = _pad_list(profile.get("users", []), _SW_USERS, LIMITS["users"], random.Random(seed + 1))
        self.machines = _pad_list(profile.get("machines", []), _SW_MACHINES, LIMITS["machines"], random.Random(seed + 2))
        self.c2_servers = _pad_list(profile.get("c2_servers", []), _SW_C2, LIMITS["c2_servers"], random.Random(seed + 3))
        self.malware = _pad_list(profile.get("malware", []), _SW_MALWARE, LIMITS["malware"], random.Random(seed + 4))
        self.mail_senders = _pad_list(profile.get("mail_senders", []), _SW_MAIL_SENDERS, LIMITS["mail_senders"], random.Random(seed + 5))

    # ── Pickers — return an entity if the ratio dice says "profile",
    #    or None if the caller should generate noise instead. ──────────────

    def _should_use_profile(self) -> bool:
        return self.rng.randint(1, 100) <= self.ratio

    def pick_user(self) -> dict[str, Any] | None:
        if self._should_use_profile():
            return self.rng.choice(self.users)
        return None

    def pick_machine(self) -> dict[str, Any] | None:
        if self._should_use_profile():
            return self.rng.choice(self.machines)
        return None

    def pick_c2(self) -> dict[str, Any] | None:
        if self._should_use_profile():
            return self.rng.choice(self.c2_servers)
        return None

    def pick_malware(self) -> dict[str, Any] | None:
        if self._should_use_profile():
            return self.rng.choice(self.malware)
        return None

    def pick_mail_sender(self) -> dict[str, Any] | None:
        if self._should_use_profile():
            return self.rng.choice(self.mail_senders)
        return None


def get_context(source: str) -> ProfileContext | None:
    """Return a ProfileContext for *source*, or None if unbound."""
    binding = get_binding(source)
    if not binding:
        return None
    profile = get_profile(binding["profile_id"])
    if not profile:
        return None
    return ProfileContext(profile, source, binding.get("ratio", 70))


# ── Alert bindings ────────────────────────────────────────────────────────────
# Stored separately from source-profile bindings in alert_bindings.json.
# Each binding: source_key → {profile_id, max_volume, interval_seconds, enabled}

_ALERT_BINDINGS_FILE = _DATA_ROOT / "alert_bindings.json"


def _load_alert_bindings() -> dict[str, Any]:
    try:
        if _ALERT_BINDINGS_FILE.is_file():
            return json.loads(_ALERT_BINDINGS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _save_alert_bindings(data: dict[str, Any]) -> None:
    _ensure_dirs()
    _ALERT_BINDINGS_FILE.write_text(json.dumps(data, indent=2))


def bind_alert_source(
    source_key: str,
    profile_id: str,
    max_volume: int = 10,
    interval_seconds: int = 3600,
    enabled: bool = True,
) -> dict[str, Any]:
    """Bind an alert source to a profile with volume/interval config."""
    entry = {
        "profile_id": profile_id,
        "max_volume": max(1, min(1000, max_volume)),
        "interval_seconds": max(60, interval_seconds),
        "enabled": enabled,
    }
    with _lock:
        bindings = _load_alert_bindings()
        bindings[source_key] = entry
        _save_alert_bindings(bindings)
    return entry


def unbind_alert_source(source_key: str) -> bool:
    with _lock:
        bindings = _load_alert_bindings()
        if source_key not in bindings:
            return False
        del bindings[source_key]
        _save_alert_bindings(bindings)
    return True


def get_alert_binding(source_key: str) -> dict[str, Any] | None:
    return _load_alert_bindings().get(source_key)


def list_alert_bindings() -> dict[str, Any]:
    return _load_alert_bindings()


def get_alert_context(source_key: str) -> ProfileContext | None:
    """Return a ProfileContext for an alert source, or None if unbound."""
    binding = get_alert_binding(source_key)
    if not binding or not binding.get("enabled"):
        return None
    profile = get_profile(binding["profile_id"])
    if not profile:
        return None
    return ProfileContext(profile, f"alert_{source_key}", binding.get("ratio", 70))
