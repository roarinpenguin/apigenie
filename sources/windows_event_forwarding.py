"""Windows Event Forwarding push source (v5.2).

This module implements ApiGenie's WEF emitter: an outbound push source
where ApiGenie acts as a Domain Controller emitter, pushing synthetic
Windows EventLog records to an external Windows Event Collector (WEC)
over the real WS-Management / WS-Eventing wire protocol.

This file (step 1 of the green phase) ships only the event catalog and
the channel constants. Subsequent steps add the envelope builder
(step 2), the WEFEmitter + auth (step 3), the per-binding cert storage
(step 4), and the event-mix-aware generator (step 5). Tests for each
step live under ``tests/test_wef_<step>.py`` and were written before
this code (TDD red phase in commits e38998a and e88a04d).

Spec: docs/ROADMAP_2026-06-12.md §"v5.2 — Windows Event Forwarding push
source".

Catalog organisation
====================

Each EVENT_CATALOG entry follows the convention shared by every other
catalog-aware source in ``sources/`` (so it natively plugs into
``event_mix.merge_catalog_with_mix``) plus four WEF-specific fields the
envelope builder will need in step 2:

* ``id``             — string key, format ``"<channel>:<event_id>"``.
                       Used by ``event_mix`` overrides.
* ``label``          — short human-readable name.
* ``default_weight`` — float, relative frequency in the default mix.
* ``docs``           — Microsoft Learn URL.
* ``channel``        — Windows EventLog channel (one of CHANNELS).
* ``event_id``       — numeric Windows EventID.
* ``provider``       — ``Provider Name`` written into the EventLog XML.
* ``level``          — Windows severity level (Information, Warning,
                       Error, Critical, Verbose).
* ``data_fields``    — list of ``Data Name`` children the envelope
                       builder substitutes from the user / machine /
                       C2 profile data; empty if the event carries no
                       interesting user-data fields (e.g. service
                       lifecycle events).

The default weights are intentionally non-uniform — they reflect the
real-world DC log distribution where Sysmon process-create + Security
logon events dominate, AD modifications are rare-but-interesting, and
audit-log-clear (1102) is vanishingly rare but always suspicious.
Operators reshape this distribution through the Event Mix admin UI.
"""
from __future__ import annotations

import base64
import uuid
import xml.etree.ElementTree as ET
from typing import Any

import httpx

from crypto import try_decrypt


# ── Channels ──────────────────────────────────────────────────────────

# The six Windows EventLog channels WEF v5.2 simulates. The set is
# closed; new channels are explicit v5.x additions (see ROADMAP
# §"Non-goals" — additional ETW channels are deferred).
CHANNEL_SECURITY = "Security"
CHANNEL_SYSTEM = "System"
CHANNEL_DIRECTORY_SERVICE = "Directory Service"
CHANNEL_DNS_SERVER = "DNS Server"
CHANNEL_POWERSHELL = "Windows-PowerShell-Operational"
CHANNEL_SYSMON = "Microsoft-Windows-Sysmon/Operational"

CHANNELS: list[str] = [
    CHANNEL_SECURITY,
    CHANNEL_SYSTEM,
    CHANNEL_DIRECTORY_SERVICE,
    CHANNEL_DNS_SERVER,
    CHANNEL_POWERSHELL,
    CHANNEL_SYSMON,
]


# ── Default providers per channel ─────────────────────────────────────

# A single channel typically has one dominant provider; for System and
# Directory Service the picture is multi-provider (Service Control
# Manager, Kernel-General, Kernel-Power, ActiveDirectory_DomainService,
# EventLog, …). Per-entry override below where needed.
_DEFAULT_PROVIDERS: dict[str, str] = {
    CHANNEL_SECURITY: "Microsoft-Windows-Security-Auditing",
    CHANNEL_SYSTEM: "Service Control Manager",
    CHANNEL_DIRECTORY_SERVICE:
        "Microsoft-Windows-ActiveDirectory_DomainService",
    CHANNEL_DNS_SERVER: "Microsoft-Windows-DNSServer",
    CHANNEL_POWERSHELL: "Microsoft-Windows-PowerShell",
    CHANNEL_SYSMON: "Microsoft-Windows-Sysmon",
}


def _e(channel: str,
       event_id: int,
       label: str,
       *,
       provider: str | None = None,
       level: str = "Information",
       weight: float = 1.0,
       data_fields: list[str] | None = None,
       docs: str = "") -> dict[str, Any]:
    """Build a single EVENT_CATALOG entry.

    Keeping the helper local (no public re-export) lets the catalog
    rows stay readable as one line each without bloating module API.
    """
    return {
        "id": f"{channel}:{event_id}",
        "label": label,
        "default_weight": weight,
        "docs": docs,
        "channel": channel,
        "event_id": event_id,
        "provider": provider or _DEFAULT_PROVIDERS[channel],
        "level": level,
        "data_fields": data_fields or [],
    }


# Microsoft Learn doc base URLs (kept terse so each row stays one line).
_DOC_SEC = "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-{eid}"
_DOC_SYSMON = "https://learn.microsoft.com/sysinternals/downloads/sysmon"
_DOC_PS = "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows"
_DOC_DNS = "https://learn.microsoft.com/windows-server/networking/dns/dns-top"
_DOC_DS = "https://learn.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview"
_DOC_SYS_SCM = "https://learn.microsoft.com/windows/win32/services/service-control-manager"


# ── EVENT_CATALOG ─────────────────────────────────────────────────────

# Built in a single list literal below. To keep this file scannable the
# entries are grouped by channel and, within Security, by sub-domain
# (logon, account mgmt, group mgmt, …). Total: 193 entries.

EVENT_CATALOG: list[dict[str, Any]] = [
    # ── Security ─ Logon / logoff (23) ───────────────────────────────
    _e(CHANNEL_SECURITY, 4624, "Account successfully logged on",
       weight=20.0, data_fields=["TargetUserName", "TargetDomainName",
       "LogonType", "IpAddress", "WorkstationName"],
       docs=_DOC_SEC.format(eid=4624)),
    _e(CHANNEL_SECURITY, 4625, "Account failed to log on",
       weight=5.0, data_fields=["TargetUserName", "TargetDomainName",
       "Status", "IpAddress", "WorkstationName"],
       docs=_DOC_SEC.format(eid=4625)),
    _e(CHANNEL_SECURITY, 4634, "Account was logged off",
       weight=15.0, data_fields=["TargetUserName", "LogonType"]),
    _e(CHANNEL_SECURITY, 4647, "User-initiated logoff",
       weight=5.0, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4648, "Logon attempted using explicit credentials",
       weight=3.0, data_fields=["TargetUserName", "TargetServerName",
       "IpAddress"]),
    _e(CHANNEL_SECURITY, 4672, "Special privileges assigned to new logon",
       weight=2.0, data_fields=["SubjectUserName", "PrivilegeList"]),
    _e(CHANNEL_SECURITY, 4673, "Privileged service called",
       weight=1.0, data_fields=["SubjectUserName", "Service", "PrivilegeList"]),
    _e(CHANNEL_SECURITY, 4675, "SIDs were filtered",
       weight=0.1, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4768, "Kerberos TGT was requested",
       weight=15.0, data_fields=["TargetUserName", "TargetDomainName",
       "IpAddress", "Status"]),
    _e(CHANNEL_SECURITY, 4769, "Kerberos service ticket was requested",
       weight=20.0, data_fields=["TargetUserName", "ServiceName",
       "IpAddress", "Status"]),
    _e(CHANNEL_SECURITY, 4770, "Kerberos service ticket was renewed",
       weight=5.0, data_fields=["TargetUserName", "ServiceName"]),
    _e(CHANNEL_SECURITY, 4771, "Kerberos pre-authentication failed",
       weight=2.0, data_fields=["TargetUserName", "IpAddress", "Status"]),
    _e(CHANNEL_SECURITY, 4772, "Kerberos TGT request failed",
       weight=1.0, data_fields=["TargetUserName", "Status"]),
    _e(CHANNEL_SECURITY, 4773, "Kerberos service ticket request failed",
       weight=1.0, data_fields=["TargetUserName", "ServiceName"]),
    _e(CHANNEL_SECURITY, 4774, "Account was mapped for logon",
       weight=0.5, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4776, "Credential validation attempted by DC (NTLM)",
       weight=10.0, data_fields=["TargetUserName", "Workstation", "Status"]),
    _e(CHANNEL_SECURITY, 4777, "DC failed to validate credentials",
       weight=1.0, data_fields=["TargetUserName", "Workstation"]),
    _e(CHANNEL_SECURITY, 4778, "Session was reconnected to a Window Station",
       weight=1.0, data_fields=["AccountName", "ClientName", "ClientAddress"]),
    _e(CHANNEL_SECURITY, 4779, "Session was disconnected from a Window Station",
       weight=1.0, data_fields=["AccountName", "ClientName", "ClientAddress"]),
    _e(CHANNEL_SECURITY, 4800, "Workstation was locked",
       weight=3.0, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4801, "Workstation was unlocked",
       weight=3.0, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4802, "Screensaver was invoked",
       weight=1.0, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4803, "Screensaver was dismissed",
       weight=1.0, data_fields=["TargetUserName"]),

    # ── Security ─ Account management (14) ───────────────────────────
    _e(CHANNEL_SECURITY, 4720, "A user account was created",
       weight=1.0, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4722, "A user account was enabled",
       weight=1.0, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4723, "Account password change attempted",
       weight=2.0, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4724, "Account password reset attempted",
       weight=1.0, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4725, "A user account was disabled",
       weight=0.5, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4726, "A user account was deleted",
       weight=0.2, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4738, "A user account was changed",
       weight=2.0, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4740, "A user account was locked out",
       weight=1.0, level="Warning",
       data_fields=["TargetUserName", "TargetDomainName"]),
    _e(CHANNEL_SECURITY, 4767, "A user account was unlocked",
       weight=1.0, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4781, "The name of an account was changed",
       weight=0.2, data_fields=["OldTargetUserName", "NewTargetUserName"]),
    _e(CHANNEL_SECURITY, 4782, "The password hash of an account was accessed",
       weight=0.05, level="Warning",
       data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4793, "The Password Policy Checking API was called",
       weight=0.3, data_fields=["SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4798, "User's local group membership was enumerated",
       weight=3.0, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4799, "A security-enabled local group membership was enumerated",
       weight=3.0, data_fields=["TargetUserName", "SubjectUserName"]),

    # ── Security ─ Group management (16) ─────────────────────────────
    _e(CHANNEL_SECURITY, 4727, "A security-enabled global group was created",
       weight=0.3, data_fields=["TargetUserName", "SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4728, "A member was added to a security-enabled global group",
       weight=1.0, data_fields=["MemberName", "TargetUserName"]),
    _e(CHANNEL_SECURITY, 4729, "A member was removed from a security-enabled global group",
       weight=1.0, data_fields=["MemberName", "TargetUserName"]),
    _e(CHANNEL_SECURITY, 4730, "A security-enabled global group was deleted",
       weight=0.1, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4731, "A security-enabled local group was created",
       weight=0.3, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4732, "A member was added to a security-enabled local group",
       weight=1.0, data_fields=["MemberName", "TargetUserName"]),
    _e(CHANNEL_SECURITY, 4733, "A member was removed from a security-enabled local group",
       weight=1.0, data_fields=["MemberName", "TargetUserName"]),
    _e(CHANNEL_SECURITY, 4734, "A security-enabled local group was deleted",
       weight=0.1, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4735, "A security-enabled local group was changed",
       weight=0.5, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4737, "A security-enabled global group was changed",
       weight=0.5, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4754, "A security-enabled universal group was created",
       weight=0.2, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4755, "A security-enabled universal group was changed",
       weight=0.3, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4756, "A member was added to a security-enabled universal group",
       weight=1.0, data_fields=["MemberName", "TargetUserName"]),
    _e(CHANNEL_SECURITY, 4757, "A member was removed from a security-enabled universal group",
       weight=1.0, data_fields=["MemberName", "TargetUserName"]),
    _e(CHANNEL_SECURITY, 4758, "A security-enabled universal group was deleted",
       weight=0.1, data_fields=["TargetUserName"]),
    _e(CHANNEL_SECURITY, 4764, "A group's type was changed",
       weight=0.1, data_fields=["TargetUserName"]),

    # ── Security ─ Privilege use (2) ─────────────────────────────────
    _e(CHANNEL_SECURITY, 4674, "Operation was attempted on a privileged object",
       weight=2.0, data_fields=["SubjectUserName", "ObjectServer", "ObjectName"]),
    _e(CHANNEL_SECURITY, 4985, "The state of a transaction has changed",
       weight=0.5, data_fields=["SubjectUserName"]),

    # ── Security ─ Policy change (10) ────────────────────────────────
    _e(CHANNEL_SECURITY, 4715, "Audit policy on object changed",
       weight=0.1, level="Warning",
       data_fields=["SubjectUserName", "ObjectName"]),
    _e(CHANNEL_SECURITY, 4719, "System audit policy was changed",
       weight=0.1, level="Warning",
       data_fields=["SubjectUserName", "CategoryId"]),
    _e(CHANNEL_SECURITY, 4739, "Domain Policy was changed",
       weight=0.1, level="Warning",
       data_fields=["SubjectUserName", "DomainName"]),
    _e(CHANNEL_SECURITY, 4817, "Auditing settings on object were changed",
       weight=0.1, data_fields=["SubjectUserName", "ObjectName"]),
    _e(CHANNEL_SECURITY, 4902, "Per-user audit policy table was created",
       weight=0.1, data_fields=["PuasId"]),
    _e(CHANNEL_SECURITY, 4904, "Security event source attempted to register",
       weight=0.5, data_fields=["SubjectUserName", "EventSourceName"]),
    _e(CHANNEL_SECURITY, 4905, "Security event source attempted to unregister",
       weight=0.5, data_fields=["SubjectUserName", "EventSourceName"]),
    _e(CHANNEL_SECURITY, 4906, "CrashOnAuditFail value has changed",
       weight=0.05, level="Warning",
       data_fields=["SubjectUserName", "CrashOnAuditFailValue"]),
    _e(CHANNEL_SECURITY, 4907, "Auditing settings on object were changed",
       weight=0.2, data_fields=["SubjectUserName", "ObjectName"]),
    _e(CHANNEL_SECURITY, 4912, "Per-user audit policy was changed",
       weight=0.1, data_fields=["SubjectUserName", "TargetUserName"]),

    # ── Security ─ Object access (8) ─────────────────────────────────
    _e(CHANNEL_SECURITY, 4656, "A handle to an object was requested",
       weight=10.0, data_fields=["SubjectUserName", "ObjectName", "AccessMask"]),
    _e(CHANNEL_SECURITY, 4657, "A registry value was modified",
       weight=2.0, data_fields=["SubjectUserName", "ObjectName", "ObjectValueName"]),
    _e(CHANNEL_SECURITY, 4658, "The handle to an object was closed",
       weight=10.0, data_fields=["SubjectUserName", "HandleId"]),
    _e(CHANNEL_SECURITY, 4660, "An object was deleted",
       weight=2.0, data_fields=["SubjectUserName", "ObjectName"]),
    _e(CHANNEL_SECURITY, 4662, "An operation was performed on an object",
       weight=8.0, data_fields=["SubjectUserName", "ObjectName", "Properties"]),
    _e(CHANNEL_SECURITY, 4663, "An attempt was made to access an object",
       weight=5.0, data_fields=["SubjectUserName", "ObjectName", "AccessMask"]),
    _e(CHANNEL_SECURITY, 4664, "An attempt was made to create a hard link",
       weight=0.5, data_fields=["SubjectUserName", "FileName"]),
    _e(CHANNEL_SECURITY, 4670, "Permissions on an object were changed",
       weight=0.3, data_fields=["SubjectUserName", "ObjectName"]),

    # ── Security ─ Audit clear (2) ───────────────────────────────────
    _e(CHANNEL_SECURITY, 1100, "The event logging service has shut down",
       weight=0.05, level="Information",
       provider="Microsoft-Windows-Eventlog"),
    _e(CHANNEL_SECURITY, 1102, "The audit log was cleared",
       weight=0.05, level="Warning",
       provider="Microsoft-Windows-Eventlog",
       data_fields=["SubjectUserName", "SubjectDomainName"]),

    # ── Security ─ Process / token (11) ──────────────────────────────
    _e(CHANNEL_SECURITY, 4688, "A new process has been created",
       weight=30.0, data_fields=["SubjectUserName", "NewProcessName",
       "CommandLine", "ParentProcessName"]),
    _e(CHANNEL_SECURITY, 4689, "A process has exited",
       weight=25.0, data_fields=["SubjectUserName", "ProcessName"]),
    _e(CHANNEL_SECURITY, 4696, "A primary token was assigned to process",
       weight=1.0, data_fields=["SubjectUserName", "TargetUserName", "ProcessName"]),
    _e(CHANNEL_SECURITY, 4697, "A service was installed in the system",
       weight=0.5, level="Information",
       data_fields=["SubjectUserName", "ServiceName", "ServiceFileName",
       "ServiceType", "ServiceStartType"]),
    _e(CHANNEL_SECURITY, 4698, "A scheduled task was created",
       weight=0.5, data_fields=["SubjectUserName", "TaskName"]),
    _e(CHANNEL_SECURITY, 4699, "A scheduled task was deleted",
       weight=0.2, data_fields=["SubjectUserName", "TaskName"]),
    _e(CHANNEL_SECURITY, 4700, "A scheduled task was enabled",
       weight=0.3, data_fields=["SubjectUserName", "TaskName"]),
    _e(CHANNEL_SECURITY, 4701, "A scheduled task was disabled",
       weight=0.2, data_fields=["SubjectUserName", "TaskName"]),
    _e(CHANNEL_SECURITY, 4702, "A scheduled task was updated",
       weight=0.5, data_fields=["SubjectUserName", "TaskName"]),
    _e(CHANNEL_SECURITY, 4717, "System security access granted to an account",
       weight=0.1, data_fields=["SubjectUserName", "TargetSid", "AccessGranted"]),
    _e(CHANNEL_SECURITY, 4718, "System security access removed from an account",
       weight=0.1, data_fields=["SubjectUserName", "TargetSid", "AccessRemoved"]),

    # ── Security ─ Network share (5) ─────────────────────────────────
    _e(CHANNEL_SECURITY, 5140, "A network share object was accessed",
       weight=8.0, data_fields=["SubjectUserName", "ShareName", "IpAddress"]),
    _e(CHANNEL_SECURITY, 5142, "A network share object was added",
       weight=0.2, data_fields=["SubjectUserName", "ShareName"]),
    _e(CHANNEL_SECURITY, 5143, "A network share object was modified",
       weight=0.3, data_fields=["SubjectUserName", "ShareName"]),
    _e(CHANNEL_SECURITY, 5144, "A network share object was deleted",
       weight=0.1, data_fields=["SubjectUserName", "ShareName"]),
    _e(CHANNEL_SECURITY, 5145, "A network share object was checked for access",
       weight=15.0, data_fields=["SubjectUserName", "ShareName", "IpAddress"]),

    # ── Security ─ Windows Filtering Platform (8) ────────────────────
    _e(CHANNEL_SECURITY, 5152, "WFP blocked a packet",
       weight=2.0, data_fields=["SourceAddress", "DestAddress", "Protocol"]),
    _e(CHANNEL_SECURITY, 5153, "WFP blocked a packet (more restrictive)",
       weight=1.0, data_fields=["SourceAddress", "DestAddress", "Protocol"]),
    _e(CHANNEL_SECURITY, 5154, "WFP permitted app or service to listen",
       weight=2.0, data_fields=["Application", "SourcePort", "Protocol"]),
    _e(CHANNEL_SECURITY, 5155, "WFP blocked app or service from listening",
       weight=0.5, data_fields=["Application", "SourcePort", "Protocol"]),
    _e(CHANNEL_SECURITY, 5156, "WFP permitted a connection",
       weight=15.0, data_fields=["Application", "SourceAddress",
       "DestAddress", "Protocol"]),
    _e(CHANNEL_SECURITY, 5157, "WFP blocked a connection",
       weight=3.0, data_fields=["Application", "SourceAddress",
       "DestAddress", "Protocol"]),
    _e(CHANNEL_SECURITY, 5158, "WFP permitted a bind to a local port",
       weight=5.0, data_fields=["Application", "SourcePort", "Protocol"]),
    _e(CHANNEL_SECURITY, 5159, "WFP blocked a bind to a local port",
       weight=0.2, data_fields=["Application", "SourcePort", "Protocol"]),

    # ── Security ─ Windows Firewall rules (5) ────────────────────────
    _e(CHANNEL_SECURITY, 4946, "Rule added to Windows Firewall exception list",
       weight=0.3, data_fields=["SubjectUserName", "RuleName"]),
    _e(CHANNEL_SECURITY, 4947, "Rule modified in Windows Firewall exception list",
       weight=0.3, data_fields=["SubjectUserName", "RuleName"]),
    _e(CHANNEL_SECURITY, 4950, "Windows Firewall setting was changed",
       weight=0.2, data_fields=["SubjectUserName", "SettingType"]),
    _e(CHANNEL_SECURITY, 4954, "Windows Firewall GPO settings changed",
       weight=0.1, data_fields=["SubjectUserName"]),
    _e(CHANNEL_SECURITY, 4956, "Windows Firewall changed active profile",
       weight=0.2, data_fields=["NewProfile", "OldProfile"]),

    # ── System ─ Service Control Manager (5) ─────────────────────────
    _e(CHANNEL_SYSTEM, 7034, "Service terminated unexpectedly",
       weight=1.0, level="Error",
       provider="Service Control Manager",
       data_fields=["ServiceName"]),
    _e(CHANNEL_SYSTEM, 7035, "Service control message received",
       weight=10.0,
       provider="Service Control Manager",
       data_fields=["ServiceName", "ControlMessage"]),
    _e(CHANNEL_SYSTEM, 7036, "Service entered the running/stopped state",
       weight=20.0,
       provider="Service Control Manager",
       data_fields=["ServiceName", "ServiceState"]),
    _e(CHANNEL_SYSTEM, 7040, "Service start type was changed",
       weight=0.5,
       provider="Service Control Manager",
       data_fields=["ServiceName", "OldStartType", "NewStartType"]),
    _e(CHANNEL_SYSTEM, 7045, "A service was installed in the system",
       weight=0.5,
       provider="Service Control Manager",
       data_fields=["ServiceName", "ImagePath", "ServiceType",
       "StartType", "AccountName"]),

    # ── System ─ EventLog service + shutdown (5) ─────────────────────
    _e(CHANNEL_SYSTEM, 6005, "Event log service was started",
       weight=0.5, provider="EventLog"),
    _e(CHANNEL_SYSTEM, 6006, "Event log service was stopped",
       weight=0.3, provider="EventLog"),
    _e(CHANNEL_SYSTEM, 6008, "Previous shutdown was unexpected",
       weight=0.2, level="Error", provider="EventLog"),
    _e(CHANNEL_SYSTEM, 6013, "System uptime",
       weight=1.0, provider="EventLog"),
    _e(CHANNEL_SYSTEM, 1074, "System shutdown initiated by user/process",
       weight=0.5, provider="User32",
       data_fields=["User", "Process", "Reason"]),

    # ── System ─ Kernel (4) ──────────────────────────────────────────
    _e(CHANNEL_SYSTEM, 12, "Kernel-General — operating system started",
       weight=0.3, provider="Microsoft-Windows-Kernel-General"),
    _e(CHANNEL_SYSTEM, 13, "Kernel-General — operating system stopped",
       weight=0.2, provider="Microsoft-Windows-Kernel-General"),
    _e(CHANNEL_SYSTEM, 41, "Kernel-Power — system rebooted without clean shutdown",
       weight=0.1, level="Critical",
       provider="Microsoft-Windows-Kernel-Power"),
    _e(CHANNEL_SYSTEM, 219, "Kernel-PnP — driver failed to load",
       weight=0.2, level="Warning",
       provider="Microsoft-Windows-Kernel-PnP",
       data_fields=["DriverName"]),

    # ── Directory Service (20) ───────────────────────────────────────
    _e(CHANNEL_DIRECTORY_SERVICE, 1644, "LDAP search took too long",
       weight=8.0, data_fields=["Client", "FilterTime", "Filter"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 1655, "LDAP operation timed out",
       weight=1.0, level="Warning", data_fields=["Client", "Operation"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 1083, "Replication source unreachable",
       weight=0.3, level="Warning", data_fields=["SourceDC"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 1311, "KCC could not generate replication topology",
       weight=0.2, level="Warning"),
    _e(CHANNEL_DIRECTORY_SERVICE, 2887, "LDAP signing — simple bind allowed",
       weight=0.5, level="Warning", data_fields=["NumberOfBinds"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 2888, "LDAP signing — SASL bind without signing",
       weight=0.5, level="Warning", data_fields=["NumberOfBinds"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 2889, "LDAP signing — client signing not requested",
       weight=1.0, data_fields=["Client", "BindType"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 2486, "AD database write error",
       weight=0.05, level="Error"),
    _e(CHANNEL_DIRECTORY_SERVICE, 2095, "Replication failure",
       weight=0.2, level="Warning", data_fields=["SourceDC"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 5136, "Directory service object was modified",
       weight=3.0,
       provider="Microsoft-Windows-Security-Auditing",
       data_fields=["SubjectUserName", "DSName", "ObjectDN",
       "AttributeLDAPDisplayName", "AttributeValue"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 5137, "Directory service object was created",
       weight=1.0,
       provider="Microsoft-Windows-Security-Auditing",
       data_fields=["SubjectUserName", "ObjectDN"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 5138, "Directory service object was undeleted",
       weight=0.1,
       provider="Microsoft-Windows-Security-Auditing",
       data_fields=["SubjectUserName", "ObjectDN"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 5139, "Directory service object was moved",
       weight=0.5,
       provider="Microsoft-Windows-Security-Auditing",
       data_fields=["SubjectUserName", "OldObjectDN", "NewObjectDN"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 5141, "Directory service object was deleted",
       weight=0.3,
       provider="Microsoft-Windows-Security-Auditing",
       data_fields=["SubjectUserName", "ObjectDN"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 1126, "AD operation error",
       weight=0.1, level="Error"),
    _e(CHANNEL_DIRECTORY_SERVICE, 1864, "Replication latency",
       weight=0.5),
    _e(CHANNEL_DIRECTORY_SERVICE, 1216, "Replication consistency check passed",
       weight=2.0),
    _e(CHANNEL_DIRECTORY_SERVICE, 8230, "Replication consistency check failed",
       weight=0.05, level="Error"),
    _e(CHANNEL_DIRECTORY_SERVICE, 2080, "NTLM auditing — server",
       weight=2.0, data_fields=["UserName", "Workstation"]),
    _e(CHANNEL_DIRECTORY_SERVICE, 1788, "Trust relationship couldn't be verified",
       weight=0.1, level="Warning", data_fields=["TrustName"]),

    # ── DNS Server (15) ──────────────────────────────────────────────
    _e(CHANNEL_DNS_SERVER, 150, "Zone load complete",
       weight=0.5, docs=_DOC_DNS),
    _e(CHANNEL_DNS_SERVER, 256, "Dynamic update received",
       weight=10.0,
       data_fields=["Source", "RecordName", "RecordType"]),
    _e(CHANNEL_DNS_SERVER, 257, "Secure dynamic update authorized",
       weight=8.0,
       data_fields=["Source", "RecordName", "RecordType"]),
    _e(CHANNEL_DNS_SERVER, 258, "Dynamic update denied",
       weight=1.0, level="Warning",
       data_fields=["Source", "RecordName"]),
    _e(CHANNEL_DNS_SERVER, 259, "Refresh request received",
       weight=2.0, data_fields=["Source"]),
    _e(CHANNEL_DNS_SERVER, 260, "Refresh request denied",
       weight=0.2, level="Warning", data_fields=["Source"]),
    _e(CHANNEL_DNS_SERVER, 770, "Zone signing operation",
       weight=0.1, data_fields=["ZoneName"]),
    _e(CHANNEL_DNS_SERVER, 771, "Zone signed",
       weight=0.1, data_fields=["ZoneName"]),
    _e(CHANNEL_DNS_SERVER, 772, "Zone unsigned",
       weight=0.1, data_fields=["ZoneName"]),
    _e(CHANNEL_DNS_SERVER, 4013, "DNS server now running on a domain controller",
       weight=0.05),
    _e(CHANNEL_DNS_SERVER, 4015, "DNS server received unsigned update for secure zone",
       weight=0.2, level="Warning",
       data_fields=["Source", "ZoneName", "RecordName"]),
    _e(CHANNEL_DNS_SERVER, 4521, "Zone reload",
       weight=0.3, data_fields=["ZoneName"]),
    _e(CHANNEL_DNS_SERVER, 6000, "DNS service started",
       weight=0.1),
    _e(CHANNEL_DNS_SERVER, 6001, "DNS service stopped",
       weight=0.05),
    _e(CHANNEL_DNS_SERVER, 7062, "DNS packet loop detected",
       weight=0.05, level="Warning",
       data_fields=["RemoteIP"]),

    # ── Windows-PowerShell-Operational (10) ──────────────────────────
    _e(CHANNEL_POWERSHELL, 4100, "PowerShell engine state changed",
       weight=5.0, data_fields=["UserName", "HostName"], docs=_DOC_PS),
    _e(CHANNEL_POWERSHELL, 4103, "Module logging — pipeline execution",
       weight=15.0,
       data_fields=["UserName", "HostName", "Payload"]),
    _e(CHANNEL_POWERSHELL, 4104, "Script block logging — compiled",
       weight=10.0,
       data_fields=["UserName", "ScriptBlockId", "ScriptBlockText"]),
    _e(CHANNEL_POWERSHELL, 4105, "Started invocation of command",
       weight=8.0, data_fields=["UserName", "CommandName"]),
    _e(CHANNEL_POWERSHELL, 4106, "Completed invocation of command",
       weight=8.0, data_fields=["UserName", "CommandName"]),
    _e(CHANNEL_POWERSHELL, 40961, "Engine state — startup",
       weight=2.0, data_fields=["UserName", "HostName"]),
    _e(CHANNEL_POWERSHELL, 40962, "Engine state — ready",
       weight=2.0, data_fields=["UserName", "HostName"]),
    _e(CHANNEL_POWERSHELL, 53504, "Named pipe IPC",
       weight=0.5, data_fields=["PipeName"]),
    _e(CHANNEL_POWERSHELL, 600, "Provider lifecycle",
       weight=1.0, data_fields=["ProviderName", "NewProviderState"]),
    _e(CHANNEL_POWERSHELL, 800, "Pipeline execution detail",
       weight=5.0, data_fields=["UserName", "CommandLine"]),

    # ── Microsoft-Windows-Sysmon/Operational (30) ────────────────────
    _e(CHANNEL_SYSMON, 1, "Process creation",
       weight=40.0,
       data_fields=["UtcTime", "ProcessGuid", "ProcessId", "Image",
       "CommandLine", "ParentImage", "ParentCommandLine", "User",
       "Hashes"],
       docs=_DOC_SYSMON),
    _e(CHANNEL_SYSMON, 2, "File creation time changed",
       weight=2.0, data_fields=["Image", "TargetFilename",
       "CreationUtcTime", "PreviousCreationUtcTime"]),
    _e(CHANNEL_SYSMON, 3, "Network connection",
       weight=25.0, data_fields=["Image", "User", "Protocol",
       "SourceIp", "SourcePort", "DestinationIp", "DestinationPort"]),
    _e(CHANNEL_SYSMON, 4, "Sysmon service state changed",
       weight=0.1, data_fields=["State"]),
    _e(CHANNEL_SYSMON, 5, "Process terminated",
       weight=30.0, data_fields=["ProcessGuid", "ProcessId", "Image", "User"]),
    _e(CHANNEL_SYSMON, 6, "Driver loaded",
       weight=1.0, data_fields=["ImageLoaded", "Hashes", "Signature",
       "SignatureStatus"]),
    _e(CHANNEL_SYSMON, 7, "Image loaded",
       weight=15.0, data_fields=["Image", "ImageLoaded", "Hashes",
       "Signature", "SignatureStatus"]),
    _e(CHANNEL_SYSMON, 8, "CreateRemoteThread",
       weight=0.5, level="Warning",
       data_fields=["SourceImage", "TargetImage", "NewThreadId",
       "StartAddress"]),
    _e(CHANNEL_SYSMON, 9, "RawAccessRead",
       weight=0.3, data_fields=["Image", "Device"]),
    _e(CHANNEL_SYSMON, 10, "ProcessAccess",
       weight=2.0, data_fields=["SourceImage", "TargetImage",
       "GrantedAccess", "CallTrace"]),
    _e(CHANNEL_SYSMON, 11, "FileCreate",
       weight=25.0, data_fields=["Image", "TargetFilename",
       "CreationUtcTime"]),
    _e(CHANNEL_SYSMON, 12, "RegistryEvent — object created/deleted",
       weight=10.0, data_fields=["EventType", "Image", "TargetObject"]),
    _e(CHANNEL_SYSMON, 13, "RegistryEvent — value set",
       weight=15.0, data_fields=["EventType", "Image", "TargetObject",
       "Details"]),
    _e(CHANNEL_SYSMON, 14, "RegistryEvent — key/value rename",
       weight=1.0, data_fields=["EventType", "Image", "TargetObject",
       "NewName"]),
    _e(CHANNEL_SYSMON, 15, "FileCreateStreamHash",
       weight=1.0, data_fields=["Image", "TargetFilename", "Hash"]),
    _e(CHANNEL_SYSMON, 16, "Sysmon config state changed",
       weight=0.1, data_fields=["Configuration"]),
    _e(CHANNEL_SYSMON, 17, "PipeEvent — created",
       weight=2.0, data_fields=["EventType", "PipeName", "Image"]),
    _e(CHANNEL_SYSMON, 18, "PipeEvent — connected",
       weight=2.0, data_fields=["EventType", "PipeName", "Image"]),
    _e(CHANNEL_SYSMON, 19, "WmiEvent — filter activity",
       weight=0.5, data_fields=["EventType", "Operation", "User",
       "EventNamespace", "Name"]),
    _e(CHANNEL_SYSMON, 20, "WmiEvent — consumer activity",
       weight=0.5, data_fields=["EventType", "Operation", "User",
       "Name", "Type", "Destination"]),
    _e(CHANNEL_SYSMON, 21, "WmiEvent — filter-to-consumer binding",
       weight=0.3, data_fields=["EventType", "Operation", "User",
       "Consumer", "Filter"]),
    _e(CHANNEL_SYSMON, 22, "DNSEvent — DNS query",
       weight=20.0, data_fields=["QueryName", "QueryType", "QueryResults",
       "Image"]),
    _e(CHANNEL_SYSMON, 23, "FileDelete — archived",
       weight=3.0, data_fields=["Image", "TargetFilename", "Archived"]),
    _e(CHANNEL_SYSMON, 24, "ClipboardChange",
       weight=1.0, data_fields=["Image", "User", "Hashes"]),
    _e(CHANNEL_SYSMON, 25, "ProcessTampering",
       weight=0.1, level="Warning",
       data_fields=["Image", "Type"]),
    _e(CHANNEL_SYSMON, 26, "FileDeleteDetected",
       weight=2.0, data_fields=["Image", "TargetFilename"]),
    _e(CHANNEL_SYSMON, 27, "FileBlockExecutable",
       weight=0.2, level="Warning",
       data_fields=["Image", "TargetFilename", "Hashes"]),
    _e(CHANNEL_SYSMON, 28, "FileBlockShredding",
       weight=0.1, level="Warning",
       data_fields=["Image", "TargetFilename"]),
    _e(CHANNEL_SYSMON, 29, "FileExecutableDetected",
       weight=0.5, data_fields=["Image", "TargetFilename", "Hashes"]),
    _e(CHANNEL_SYSMON, 255, "Sysmon internal error",
       weight=0.05, level="Error", data_fields=["ID", "Description"]),
]


# ── Wire-protocol constants (WS-Management / WS-Eventing / EventLog) ─

# Canonical namespace URIs — must NOT drift; real Windows Event Collector
# subscriptions validate these strictly against the official Microsoft
# WS-Management profile. Anchoring them as module constants keeps the
# envelope builder and the tests on the same single source of truth.
NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
NS_ADDRESSING = "http://www.w3.org/2005/08/addressing"
NS_WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_EVENTING = "http://schemas.xmlsoap.org/ws/2004/08/eventing"
NS_WIN_EVENT = "http://schemas.microsoft.com/win/2004/08/events/event"

# WS-Eventing action URI carried in the wsa:Action header. A real WEC
# subscription dispatches incoming SOAP envelopes by this exact string.
WS_EVENTING_ACTION = "http://schemas.xmlsoap.org/ws/2004/08/eventing/Events"

# Content-Type the SOAP 1.2 outbound POST advertises. Pinned here so the
# push loop (step 3) and the test suite share one definition.
SOAP_CONTENT_TYPE = "application/soap+xml;charset=UTF-8"

# Windows EventLog severity → numeric Level code, per the EventLog XML
# schema. The EventLog viewer renders these strings; the wire format uses
# the integer.
_LEVEL_CODES: dict[str, str] = {
    "Critical": "1",
    "Error": "2",
    "Warning": "3",
    "Information": "4",
    "Verbose": "5",
}


# ── Envelope builder ──────────────────────────────────────────────────

def build_envelope(events: list[dict[str, Any]],
                   message_id: str | None = None) -> str:
    """Wrap *events* in a SOAP 1.2 / WS-Eventing envelope.

    Each item in *events* is a dict produced by the WEF event generator
    (step 5) or supplied directly by Attack Scenarios when draining a
    historical backlog. Required keys on each event:

    * ``event_id``       — int, Windows EventID
    * ``channel``        — str, EventLog channel name
    * ``provider``       — str, Provider Name
    * ``computer``       — str, FQDN of the emitting DC
    * ``time_created``   — str, ISO-8601 UTC timestamp (with trailing Z)
    * ``event_record_id``— int, monotonically increasing within the
                           emitting host
    * ``data``           — dict[str, str], EventData ``Data Name`` fields
                           (substituted from the profile's user / machine
                           / C2 inventory)

    Optional:

    * ``level``          — str, one of Critical / Error / Warning /
                           Information / Verbose. Defaults to Information.

    The returned string is a UTF-8 XML document the push loop posts
    verbatim as the HTTP body with ``Content-Type: SOAP_CONTENT_TYPE``.

    ``message_id`` is auto-generated as ``uuid:<uuid4>`` when not
    supplied; pass an explicit value when the caller (e.g. tests, or
    Attack Scenarios replaying a historical envelope) needs a stable
    correlation id.
    """
    if message_id is None:
        message_id = f"uuid:{uuid.uuid4()}"

    envelope = ET.Element(f"{{{NS_SOAP12}}}Envelope")

    # Header — wsa:Action + wsa:MessageID. A real production envelope
    # would also include wsa:To and wsman:ResourceURI; we leave those for
    # a later spec-pinning pass once a real WEC reports any issue.
    header = ET.SubElement(envelope, f"{{{NS_SOAP12}}}Header")
    action = ET.SubElement(header, f"{{{NS_ADDRESSING}}}Action")
    action.text = WS_EVENTING_ACTION
    msgid = ET.SubElement(header, f"{{{NS_ADDRESSING}}}MessageID")
    msgid.text = message_id

    # Body — <Events> wrapper carrying one <Event> per input. The
    # wrapper namespace is the WS-Eventing one; the inner <Event>
    # elements switch to the Windows EventLog namespace so the records
    # are byte-identical to what Windows itself would emit.
    body = ET.SubElement(envelope, f"{{{NS_SOAP12}}}Body")
    events_wrap = ET.SubElement(body, f"{{{NS_EVENTING}}}Events")
    for ev in events:
        _build_event_xml(events_wrap, ev)

    return ET.tostring(
        envelope, encoding="utf-8", xml_declaration=True,
    ).decode("utf-8")


def _build_event_xml(parent: ET.Element, ev: dict[str, Any]) -> None:
    """Append a single Windows EventLog ``<Event>`` to *parent*.

    Field order inside ``<System>`` follows the canonical Windows
    EventLog XML schema so downstream consumers that parse positionally
    (rare but not unheard of) still see the expected structure.
    ``xml.etree`` handles XML-special character escaping on element
    text and attribute values, so caller-supplied data with literal
    ``<``, ``>`` or ``&`` round-trips safely.
    """
    e = ET.SubElement(parent, f"{{{NS_WIN_EVENT}}}Event")

    system = ET.SubElement(e, f"{{{NS_WIN_EVENT}}}System")

    provider = ET.SubElement(system, f"{{{NS_WIN_EVENT}}}Provider")
    provider.set("Name", str(ev.get("provider", "")))

    eid = ET.SubElement(system, f"{{{NS_WIN_EVENT}}}EventID")
    eid.text = str(ev.get("event_id", ""))

    level = ET.SubElement(system, f"{{{NS_WIN_EVENT}}}Level")
    level.text = _LEVEL_CODES.get(str(ev.get("level", "Information")), "4")

    time_created = ET.SubElement(system, f"{{{NS_WIN_EVENT}}}TimeCreated")
    time_created.set("SystemTime", str(ev.get("time_created", "")))

    record_id = ET.SubElement(system, f"{{{NS_WIN_EVENT}}}EventRecordID")
    record_id.text = str(ev.get("event_record_id", 0))

    channel = ET.SubElement(system, f"{{{NS_WIN_EVENT}}}Channel")
    channel.text = str(ev.get("channel", ""))

    computer = ET.SubElement(system, f"{{{NS_WIN_EVENT}}}Computer")
    computer.text = str(ev.get("computer", ""))

    data = ev.get("data") or {}
    if data:
        event_data = ET.SubElement(e, f"{{{NS_WIN_EVENT}}}EventData")
        for name, value in data.items():
            d = ET.SubElement(event_data, f"{{{NS_WIN_EVENT}}}Data")
            d.set("Name", str(name))
            d.text = str(value)


# ── Binding configuration ─────────────────────────────────────────────

class BindingConfigError(Exception):
    """Raised when a WEF binding cannot be brought online.

    Examples: ``auth_method`` outside the supported set, Basic auth
    declared with a username but no password, mTLS declared with no
    resolvable client cert bundle.

    The admin UI catches this exception around binding-card save and
    surfaces the message inline; the push loop catches it around emitter
    construction and marks the binding as ``error`` in the Activity
    panel without taking the whole loop down.
    """


# The closed set of supported auth methods. Kerberos / Negotiate are
# explicitly out per the v5.2 spec (§"Non-goals").
_VALID_AUTH_METHODS: set[str] = {"basic", "client_cert"}


def normalize_binding_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *cfg* with fields not relevant to the chosen
    ``auth_method`` cleared.

    Called from the admin save handler so a binding that was switched
    from mTLS to Basic (or vice-versa) doesn't carry stale secrets the
    operator can no longer audit through the UI. Idempotent.
    """
    out = dict(cfg)
    method = out.get("auth_method")
    if method == "client_cert":
        # Switched to mTLS — drop any leftover Basic credentials.
        out["basic_username"] = None
        out["basic_password_enc"] = None
    elif method == "basic":
        # Switched to Basic — clear the per-binding cert flag so the
        # UI no longer claims a cert is in play. The cert bundle on disk
        # is removed separately by ``delete_cert_bundle`` from the admin
        # handler (step 4).
        out["cert_uploaded"] = False
    return out


def validate_binding_config(cfg: dict[str, Any]) -> list[str]:
    """Return a list of human-readable error strings describing *cfg*.

    Soft check used by the admin UI to flag misconfigurations inline
    before the binding goes live. Distinct from the hard
    ``BindingConfigError`` raised by ``WEFEmitter.__init__`` — this
    function never raises.
    """
    errors: list[str] = []
    method = cfg.get("auth_method")
    if method not in _VALID_AUTH_METHODS:
        errors.append(
            f"auth_method must be one of {sorted(_VALID_AUTH_METHODS)}; "
            f"got {method!r}"
        )
        return errors  # further checks are method-specific

    if method == "basic":
        username = (cfg.get("basic_username") or "").strip()
        if not username:
            errors.append(
                "basic_username is required when auth_method='basic'"
            )

    if not (cfg.get("target_host") or "").strip():
        errors.append("target_host is required")

    try:
        port = int(cfg.get("target_port", 0))
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        errors.append("target_port must be an integer in 1..65535")

    return errors


# ── Per-binding cert resolution (full implementation in step 4) ──────

def resolve_cert_files(binding_id: str | None,
                       server_pem_fallback: Any = None,
                       ) -> tuple[Any, Any] | None:
    """Return ``(cert_path, key_path)`` for *binding_id*'s mTLS bundle.

    Step 3 ships a STUB that always returns ``None``: the full
    implementation (per-binding encrypted PEM under
    ``data/source_certs/wef/<binding_id>.pem.enc`` with fallback to
    ``data/tls/server.pem``) lands in step 4. WEFEmitter calls this
    function indirectly via the module attribute so test_wef_auth can
    monkeypatch it; the stub keeps the public symbol stable for that
    monkeypatch to work today.
    """
    return None


# ── Push emitter ──────────────────────────────────────────────────────

def _stub_events_for_push(n: int) -> list[dict[str, Any]]:
    """Return *n* minimal valid events suitable for ``build_envelope``.

    Used by ``WEFEmitter.push_batch(event_count=N)`` until step 5 wires
    in the catalog-aware ``generate_events()`` with mix overrides and
    seed determinism. The current implementation is *just* good enough
    for the wire-shape tests in tests/test_wef_push_loop.py to pass —
    each event picks the first Sysmon process-create catalog entry and
    fills in static profile-like fields.
    """
    base_entry = next(
        (e for e in EVENT_CATALOG
         if e["channel"] == CHANNEL_SYSMON and e["event_id"] == 1),
        EVENT_CATALOG[0],
    )
    return [
        {
            "event_id": base_entry["event_id"],
            "channel": base_entry["channel"],
            "provider": base_entry["provider"],
            "computer": "DC01.lab.local",
            "level": base_entry["level"],
            "time_created": "2026-06-13T10:00:00.000Z",
            "event_record_id": i + 1,
            "data": {"Image": "C:\\Windows\\System32\\cmd.exe"},
        }
        for i in range(int(n))
    ]


class WEFEmitter:
    """Outbound WEF push emitter for a single ``source_binding`` row.

    One instance per active WEF binding, owned by the scheduler. The
    emitter is push-only: it does NOT open a listener port. Each
    ``push_batch()`` call builds a SOAP / WS-Eventing envelope and POSTs
    it to the configured WEC endpoint with the binding-specific auth
    material attached.

    The constructor performs the *hard* configuration checks
    (raises :class:`BindingConfigError` on a clearly broken binding) so
    a misconfigured row can't sit silently in the scheduler. mTLS cert
    resolution is deferred to first send: the binding may legitimately
    be saved before the operator uploads the PEM bundle, and we don't
    want the UI save to fail in that intermediate state.

    Parameters
    ----------
    binding_config
        The JSON blob stored in ``source_bindings.config`` for this
        binding. See docs/ROADMAP_2026-06-12.md §"Storage" for the
        schema.
    http_client
        Optional pre-built :class:`httpx.Client`. Tests inject a
        ``MockTransport``-backed client here so they can capture the
        outbound request shape without standing up a TLS endpoint.
        When omitted, a fresh ``httpx.Client()`` is created lazily on
        first send.
    binding_id
        The DB id of the binding row. Required for mTLS so
        :func:`resolve_cert_files` can find the per-binding cert
        bundle.
    """

    def __init__(self,
                 binding_config: dict[str, Any],
                 http_client: httpx.Client | None = None,
                 binding_id: str | None = None) -> None:
        self._cfg: dict[str, Any] = dict(binding_config)
        self._binding_id = binding_id
        self._http = http_client
        self._owns_http = http_client is None  # we'd close it on stop
        self._stopped = False

        method = self._cfg.get("auth_method")
        if method not in _VALID_AUTH_METHODS:
            raise BindingConfigError(
                f"WEF binding: unsupported auth_method {method!r}; "
                f"must be one of {sorted(_VALID_AUTH_METHODS)}"
            )

        if method == "basic":
            username = (self._cfg.get("basic_username") or "").strip()
            password_enc = (self._cfg.get("basic_password_enc") or "")
            if username and not password_enc:
                raise BindingConfigError(
                    "WEF binding: auth_method='basic' with "
                    "basic_username set requires basic_password_enc to "
                    "be non-empty"
                )
        # client_cert: cert resolution deferred to push_batch so the UI
        # can save the binding before the operator uploads the PEM.

    # ── Public API ────────────────────────────────────────────────

    def push_batch(self,
                   events: list[dict[str, Any]] | None = None,
                   event_count: int | None = None,
                   ) -> dict[str, Any]:
        """POST one or more SOAP envelopes to the configured WEC.

        Either *events* (explicit list, e.g. a historical-scenario
        backlog drain) or *event_count* (synthetic generation) must be
        provided. The full list is split into envelopes sized by the
        binding's ``batch_size``; each envelope becomes one HTTP POST.

        Returns a dict ``{sent: int, status_code: int|None, ok: bool}``.
        ``ok`` is True iff every POST returned 2xx.
        """
        if self._stopped:
            raise RuntimeError(
                "WEFEmitter is stopped; create a new instance to resume"
            )

        if events is not None:
            ev_list = list(events)
        elif event_count is not None:
            ev_list = _stub_events_for_push(int(event_count))
        else:
            ev_list = []

        if not ev_list:
            return {"sent": 0, "status_code": None, "ok": True}

        url = self._build_url()
        headers, post_kwargs = self._build_request_kwargs()

        client = self._client()

        batch_size = int(self._cfg.get("batch_size") or 1)
        if batch_size <= 0:
            batch_size = 1

        sent = 0
        last_status: int | None = None
        all_ok = True

        for i in range(0, len(ev_list), batch_size):
            batch = ev_list[i:i + batch_size]
            body = build_envelope(batch)
            resp = client.post(
                url, content=body, headers=headers, **post_kwargs,
            )
            last_status = resp.status_code
            if not (200 <= resp.status_code < 300):
                all_ok = False
            sent += len(batch)

        return {"sent": sent, "status_code": last_status, "ok": all_ok}

    def stop(self) -> None:
        """Mark the emitter stopped. Idempotent.

        The scheduler calls this on binding delete / app shutdown.
        Subsequent ``push_batch`` calls raise ``RuntimeError`` so a
        scheduler bug that keeps the loop alive past delete surfaces
        loudly instead of silently re-emitting.
        """
        if self._stopped:
            return
        self._stopped = True
        if self._owns_http and self._http is not None:
            try:
                self._http.close()
            except Exception:
                # Close-during-shutdown errors are non-fatal — the
                # scheduler is about to drop this instance anyway.
                pass

    # ── Internals ─────────────────────────────────────────────────

    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client()
        return self._http

    def _build_url(self) -> str:
        host = (self._cfg.get("target_host") or "").strip()
        port = int(self._cfg.get("target_port") or 5986)
        path = self._cfg.get("target_path") or "/wsman/SubscriptionManager/WEC"
        # Per the v5.2 spec: port 5985 is the plain-HTTP WinRM default;
        # everything else (5986 + custom) is HTTPS.
        scheme = "http" if port == 5985 else "https"
        return f"{scheme}://{host}:{port}{path}"

    def _build_request_kwargs(self) -> tuple[dict[str, str],
                                              dict[str, Any]]:
        """Return ``(headers, post_kwargs)`` for the outbound POST.

        Headers always contain Content-Type. Authorization is added
        only for Basic auth with both username + password configured.
        ``post_kwargs`` carries the ``cert=(certfile, keyfile)`` tuple
        for mTLS so httpx attaches the client cert on the TLS handshake.
        """
        headers: dict[str, str] = {"Content-Type": SOAP_CONTENT_TYPE}
        post_kwargs: dict[str, Any] = {}

        method = self._cfg.get("auth_method")
        if method == "basic":
            username = (self._cfg.get("basic_username") or "").strip()
            password_enc = self._cfg.get("basic_password_enc") or ""
            if username and password_enc:
                password = try_decrypt(password_enc)
                token = base64.b64encode(
                    f"{username}:{password}".encode("utf-8"),
                ).decode("ascii")
                headers["Authorization"] = f"Basic {token}"
        elif method == "client_cert":
            # Late-binding: pick up whatever resolve_cert_files()
            # returns NOW (so a test monkeypatch on the module attribute
            # is honoured even if WEFEmitter was constructed earlier).
            resolved = resolve_cert_files(
                self._binding_id, server_pem_fallback=None,
            )
            if resolved is None:
                raise BindingConfigError(
                    f"WEF binding: auth_method='client_cert' but no "
                    f"cert bundle resolvable for binding_id="
                    f"{self._binding_id!r}"
                )
            cert_path, key_path = resolved
            post_kwargs["cert"] = (str(cert_path), str(key_path))

        return headers, post_kwargs


__all__ = [
    "CHANNELS",
    "CHANNEL_SECURITY",
    "CHANNEL_SYSTEM",
    "CHANNEL_DIRECTORY_SERVICE",
    "CHANNEL_DNS_SERVER",
    "CHANNEL_POWERSHELL",
    "CHANNEL_SYSMON",
    "EVENT_CATALOG",
    "NS_SOAP12",
    "NS_ADDRESSING",
    "NS_WSMAN",
    "NS_EVENTING",
    "NS_WIN_EVENT",
    "WS_EVENTING_ACTION",
    "SOAP_CONTENT_TYPE",
    "build_envelope",
    "BindingConfigError",
    "normalize_binding_config",
    "validate_binding_config",
    "resolve_cert_files",
    "WEFEmitter",
]
