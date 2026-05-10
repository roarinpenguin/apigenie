"""Microsoft Defender alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "microsoft_defender"
VENDOR_NAME = "Microsoft"
PRODUCT_NAME = "Microsoft Defender for Endpoint"

VARIANTS = [
    {"name": "Ransomware activity detected",        "category": "Ransomware",       "severity": "high",     "weight": 15},
    {"name": "Suspicious credential dumping",       "category": "CredentialAccess",  "severity": "high",     "weight": 20},
    {"name": "Phishing URL clicked",                "category": "InitialAccess",     "severity": "medium",   "weight": 20},
    {"name": "Malicious file execution blocked",    "category": "Execution",         "severity": "high",     "weight": 15},
    {"name": "Lateral movement via SMB",            "category": "LateralMovement",   "severity": "medium",   "weight": 15},
    {"name": "Suspicious PowerShell download",      "category": "Execution",         "severity": "high",     "weight": 15},
]

_MITRE = {
    "Ransomware": ["T1486", "T1489"],
    "CredentialAccess": ["T1003", "T1110"],
    "InitialAccess": ["T1566"],
    "Execution": ["T1059.001"],
    "LateralMovement": ["T1021.002"],
}


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        machine = ctx.pick_machine() if ctx else None
        user = ctx.pick_user() if ctx else None
        hostname = machine.get("primary_workstation", "WORKSTATION-01") if machine else f"HOST-{random.randint(1,50):02d}.corp.local"
        username = user.get("username", "admin_service") if user else "admin_service"
        src_ip = machine.get("ip", f"10.50.60.{random.randint(1,254)}") if machine else f"10.50.60.{random.randint(1,254)}"
        dst_ip = _pick_c2(ctx)
        malware = _pick_malware(ctx)

        alerts.append({
            "finding_uid": f"da{random.randint(10**17, 10**18)}_{random.randint(10**9, 10**10)}",
            "title": f"[Defender] {v['name']} on {hostname}",
            "description": f"Microsoft Defender detected: {v['name']}. Host: {hostname}, User: {username}.",
            "severity": v["severity"],
            "finding_types": [v["category"], "Security Alert"],
            "resources": [{"uid": hostname, "name": hostname, "type": "computer"}],
            "observables": [
                {"name": src_ip, "type": "ip"},
                {"name": dst_ip, "type": "ip"},
                {"name": username, "type": "user"},
            ],
            "evidences": [{
                "process": {
                    "name": malware.get("source_process", "csrss.exe") if malware else "csrss.exe",
                    "cmd_line": malware.get("cmdline", "csrss.exe") if malware else "csrss.exe",
                    "file": {
                        "name": malware.get("filename", "suspicious.exe") if malware else "suspicious.exe",
                        "path": f"C:\\Windows\\Temp\\{malware.get('filename', 'suspicious.exe') if malware else 'suspicious.exe'}",
                    },
                }
            }],
            "unmapped": {
                "mitreTechniques": _MITRE.get(v["category"], []),
                "classification": "Confirmed",
                "detectionSource": "MicrosoftDefenderForEndpoint",
                "incidentId": random.randint(100000, 999999),
            },
        })
    return alerts


def _pick_c2(ctx: Any) -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"185.220.101.{random.randint(1,254)}")
    return f"185.220.101.{random.randint(1,254)}"


def _pick_malware(ctx: Any) -> dict | None:
    if ctx:
        return ctx.pick_malware()
    return None
