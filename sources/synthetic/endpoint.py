"""Endpoint telemetry — EDR / process / file / network events on a host.

Shape is loosely modelled on ECS (Elastic Common Schema) + a few SentinelOne /
CrowdStrike-flavoured fields a Lua collector would realistically project.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

from sources.synthetic import seeded_uuid

_HOSTS = [
    "DESKTOP-A1B2C3", "LAPTOP-FIN-01", "WIN-SRV-DC01", "WIN-SRV-FS01",
    "ubuntu-build-01", "ubuntu-jenkins-02", "macbook-eng-14",
    "rhel-prod-app-7", "rhel-prod-db-3", "win10-hr-22",
]
_USERS = [
    "alice.smith", "bob.jones", "charlie.davis", "diana.evans", "evan.foster",
    "svc_backup", "svc_monitor", "SYSTEM", "root", "administrator",
]
_PROCESSES = [
    ("svchost.exe",   "C:\\Windows\\System32\\svchost.exe", "services.exe"),
    ("powershell.exe","C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "explorer.exe"),
    ("cmd.exe",       "C:\\Windows\\System32\\cmd.exe", "explorer.exe"),
    ("chrome.exe",    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "explorer.exe"),
    ("python3",       "/usr/bin/python3", "bash"),
    ("bash",          "/bin/bash", "sshd"),
    ("sshd",          "/usr/sbin/sshd", "systemd"),
    ("nginx",         "/usr/sbin/nginx", "systemd"),
    ("curl",          "/usr/bin/curl", "bash"),
    ("wget",          "/usr/bin/wget", "bash"),
]
_FILE_PATHS = [
    "C:\\Users\\Public\\Documents\\report.docx",
    "C:\\Windows\\Temp\\update.exe",
    "/etc/passwd", "/etc/shadow", "/var/log/auth.log",
    "/home/alice/.ssh/id_rsa", "/tmp/payload.sh",
    "C:\\ProgramData\\config.xml", "C:\\Users\\bob\\Downloads\\invoice.pdf",
]
# (action, weight, mitre_id_or_None)
_ACTIONS = [
    ("process_start",       0.45, "T1059"),
    ("file_write",          0.18, None),
    ("file_read",           0.10, None),
    ("network_connect",     0.12, None),
    ("dns_query",           0.06, None),
    ("registry_modify",     0.04, "T1112"),
    ("module_load",         0.02, None),
    ("credential_access",   0.01, "T1003"),
    ("process_injection",   0.01, "T1055"),
    ("scheduled_task_create",0.01, "T1053"),
]


def _weighted_action(rng: random.Random) -> tuple[str, str | None]:
    r = rng.random()
    cum = 0.0
    for action, w, mitre in _ACTIONS:
        cum += w
        if r < cum:
            return action, mitre
    return _ACTIONS[-1][0], _ACTIONS[-1][2]


def _hash(rng: random.Random) -> str:
    return seeded_uuid(rng).hex + seeded_uuid(rng).hex[:32]


def generate(n: int, seed: int | None = None) -> list[dict]:
    rng = random.Random(seed) if seed is not None else random.Random()
    now = datetime.now(timezone.utc)
    out: list[dict] = []
    for i in range(max(0, n)):
        ts = now - timedelta(seconds=rng.randint(0, 600))
        action, mitre = _weighted_action(rng)
        proc, proc_path, parent = rng.choice(_PROCESSES)
        host = rng.choice(_HOSTS)
        user = rng.choice(_USERS)
        risk = rng.choices([1, 2, 3, 4, 5], weights=[55, 25, 12, 5, 3])[0]

        rec: dict = {
            "ts":         ts.isoformat(timespec="milliseconds"),
            "host":       {"id": uuid.uuid5(uuid.NAMESPACE_DNS, host).hex[:16], "name": host},
            "user":       {"name": user, "domain": "CORP"},
            "event":      {"action": action, "category": "host", "id": seeded_uuid(rng).hex},
            "process":    {
                "name":     proc,
                "executable": proc_path,
                "pid":      rng.randint(100, 65535),
                "parent":   {"name": parent, "pid": rng.randint(100, 65535)},
                "command_line": f"{proc_path} -arg{rng.randint(0, 9)}",
            },
            "risk_score": risk,
        }
        if mitre:
            rec["mitre"] = {"technique_id": mitre}
        if action in ("file_write", "file_read"):
            rec["file"] = {"path": rng.choice(_FILE_PATHS), "hash": {"sha256": _hash(rng)}}
        if action == "network_connect":
            rec["destination"] = {
                "ip":   f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
                "port": rng.choice([22, 80, 443, 445, 3389, 5985, 8080, 9090]),
            }
        if action == "dns_query":
            rec["dns"] = {"question": {"name": rng.choice([
                "update.example.com", "cdn.contoso.net", "telemetry.evil.example",
                "github.com", "raw.githubusercontent.com",
            ])}}
        out.append(rec)
    return out
