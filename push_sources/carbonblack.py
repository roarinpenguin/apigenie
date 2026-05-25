"""VMware Carbon Black Cloud log generator — alerts, watchlist hits, process events.

Matches CB Cloud SIEM connector / webhook output format.
Covers: CB_ANALYTICS alerts, WATCHLIST alerts, DEVICE_CONTROL,
and enriched process/netconn events.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_ORG_KEYS = ["ABCD1234", "EFGH5678"]
_DEVICE_NAMES = ["DESKTOP-HQ01", "LAPTOP-SALES02", "SRV-DC-01", "SRV-WEB-02", "WORKSTATION-IT05"]
_OS = ["WINDOWS", "WINDOWS", "WINDOWS", "MAC", "LINUX"]
_OS_VERSIONS = ["Windows 10 x64", "Windows 11 x64", "Windows Server 2022", "macOS 14.4", "Ubuntu 22.04"]
_USERS = ["CORP\\jsmith", "CORP\\agarcia", "CORP\\admin", "CORP\\mwilson", "LOCAL\\svc-monitor"]
_SEVERITIES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
_REASONS = [
    "Known malware detected", "Suspicious process behavior", "Credential access attempt",
    "Lateral movement detected", "Ransomware behavior", "Living-off-the-land binary misuse",
    "Unauthorized USB device", "Watchlist IOC match", "Process injection detected",
    "Suspicious PowerShell execution", "Registry persistence mechanism",
]
_WATCHLISTS = ["Carbon Black Advanced Threats", "AMSI Threat Intelligence",
               "Carbon Black Early Access", "ATT&CK Framework", "Custom IOCs"]
_PROCESS_NAMES = ["cmd.exe", "powershell.exe", "rundll32.exe", "wmic.exe", "certutil.exe",
                  "mshta.exe", "cscript.exe", "regsvr32.exe", "svchost.exe", "explorer.exe",
                  "chrome.exe", "outlook.exe"]

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"

def _alert(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    pm = ctx.pick_machine() if ctx else None
    pmal = ctx.pick_malware() if ctx else None
    hostname = pm.get("primary_workstation", random.choice(_DEVICE_NAMES)) if pm else random.choice(_DEVICE_NAMES)
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    sev = random.choices(_SEVERITIES, weights=[5,5,10,10,15,15,15,10,10,5])[0]
    reason = random.choice(_REASONS)
    alert_type = random.choice(["CB_ANALYTICS", "CB_ANALYTICS", "WATCHLIST", "DEVICE_CONTROL"])
    proc = pmal.get("filename", random.choice(_PROCESS_NAMES)) if pmal else random.choice(_PROCESS_NAMES)
    return {
        "type": "ALERT", "org_key": random.choice(_ORG_KEYS),
        "alert_url": f"https://defense.conferdeploy.net/alerts?alertId={generate_uuid()}",
        "id": generate_uuid(), "legacy_alert_id": f"AL_{generate_uuid().replace('-','')}",
        "category": alert_type, "severity": sev,
        "device_id": random.randint(100000, 9999999),
        "device_name": hostname, "device_os": random.choice(_OS),
        "device_os_version": random.choice(_OS_VERSIONS),
        "device_username": user,
        "device_external_ip": generate_ip(), "device_internal_ip": generate_ip(),
        "reason": reason,
        "process_name": proc, "process_path": f"c:\\windows\\system32\\{proc}",
        "process_guid": generate_uuid(),
        "process_cmdline": pmal.get("cmdline", f"{proc} /c whoami") if pmal else f"{proc} /c dir",
        "process_sha256": pmal.get("hash", generate_uuid().replace("-","") * 2) if pmal else generate_uuid().replace("-","") * 2,
        "parent_name": random.choice(["explorer.exe", "cmd.exe", "svchost.exe", "services.exe"]),
        "threat_id": generate_uuid(), "ioc_id": generate_uuid() if alert_type == "WATCHLIST" else None,
        "watchlists": [{"id": generate_uuid(), "name": random.choice(_WATCHLISTS)}] if alert_type == "WATCHLIST" else [],
        "tags": [random.choice(["AttackVector", "Malware", "SuspiciousBehavior"])],
        "workflow": {"state": random.choice(["OPEN", "IN_PROGRESS", "CLOSED"]),
                     "changed_by": random.choice(["SYSTEM", "analyst@corp.com"])},
        "first_event_time": _now(), "last_event_time": _now(),
        "create_time": _now(), "last_update_time": _now(),
        "vendor": "VMware", "product": "Carbon Black Cloud",
    }

def _process_event(ctx=None) -> dict[str, Any]:
    pm = ctx.pick_machine() if ctx else None
    hostname = pm.get("primary_workstation", random.choice(_DEVICE_NAMES)) if pm else random.choice(_DEVICE_NAMES)
    proc = random.choice(_PROCESS_NAMES)
    return {
        "type": "PROCESS_EVENT", "org_key": random.choice(_ORG_KEYS),
        "device_name": hostname, "device_os": random.choice(_OS),
        "process_name": proc, "process_pid": random.randint(100, 65535),
        "process_guid": generate_uuid(),
        "process_cmdline": f"{proc} {random.choice(['/c dir', '-enc ABC', '--version', '-h', '/s /q'])}",
        "parent_name": random.choice(["explorer.exe", "cmd.exe", "svchost.exe"]),
        "parent_pid": random.randint(100, 65535),
        "process_start_time": _now(), "event_timestamp": _now(),
        "vendor": "VMware", "product": "Carbon Black Cloud",
        "severity": "informational",
    }

def _netconn_event(ctx=None) -> dict[str, Any]:
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    hostname = pm.get("primary_workstation", random.choice(_DEVICE_NAMES)) if pm else random.choice(_DEVICE_NAMES)
    return {
        "type": "NETCONN_EVENT", "org_key": random.choice(_ORG_KEYS),
        "device_name": hostname, "process_name": random.choice(_PROCESS_NAMES),
        "remote_ip": pc2.get("ip_c2") if pc2 else generate_ip(),
        "remote_port": random.choice([80, 443, 8080, 4444, 8443, 53]),
        "local_ip": pm.get("ip") if pm else generate_ip(),
        "local_port": random.randint(1024, 65535),
        "domain": pc2.get("fqdn", generate_hostname()) if pc2 else generate_hostname(),
        "direction": random.choice(["OUTBOUND", "INBOUND"]),
        "event_timestamp": _now(),
        "vendor": "VMware", "product": "Carbon Black Cloud",
        "severity": "informational",
    }

_GENERATORS = [(_alert, 40), (_process_event, 35), (_netconn_event, 25)]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
