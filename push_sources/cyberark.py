"""CyberArk EPM / PAM log generator — privileged access management events.

Matches CyberArk Vault syslog CEF output and EPM event format.
Covers: credential checkout/checkin, privileged session start/end,
policy violations, password changes, safe operations, PSM recording,
admin audit.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_VAULT_NAMES = ["PasswordVault-01", "PasswordVault-02", "DR-Vault-01"]
_SAFE_NAMES = ["IT-Admins", "DBA-Accounts", "Network-Devices", "Cloud-Keys",
               "Root-Accounts", "Service-Accounts", "Emergency-Access",
               "Windows-DomainAdmins", "Unix-Root", "AWS-IAM-Keys"]
_PLATFORMS = ["WinServerLocal", "WinDomain", "UnixSSH", "CiscoEnable",
              "AWSAccessKeys", "AzureServicePrincipal", "OracleDB",
              "MySQLServer", "VMwareESXi", "F5BigIP"]
_USERS = ["admin.jsmith", "admin.agarcia", "svc.backup", "admin.mwilson",
          "dba.lchen", "net.admin01", "emer.access", "svc.deploy",
          "admin.root", "cloud.admin"]
_TARGET_MACHINES = ["SRV-DC-01", "SRV-DB-01", "SRV-WEB-02", "FW-CORE-01",
                    "SW-DIST-01", "SRV-EXCHANGE", "SRV-FILE-01", "ESXi-01",
                    "AWS-PROD-01", "AZURE-MGMT-01"]
_TARGET_ACCOUNTS = ["Administrator", "root", "sa", "enable", "IUSR",
                    "svc_sqlserver", "vmadmin", "azureadmin", "oracle", "admin"]
_PSM_SERVERS = ["PSM-01", "PSM-02", "PSM-DR-01"]
_REASONS = ["Scheduled maintenance", "Incident response", "Routine check",
            "Change request CR-" + str(random.randint(1000, 9999)),
            "Emergency access", "Audit requirement", "No reason provided"]
_GATEWAYS = ["PVWA-01.corp.local", "PVWA-02.corp.local"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


def _credential_checkout(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    target = random.choice(_TARGET_ACCOUNTS)
    machine = random.choice(_TARGET_MACHINES)
    return {
        "type": "credential_checkout",
        "timestamp": _now_iso(),
        "vendor": "CyberArk", "product": "EPM",
        "severity": random.choice(["informational", "informational", "warning"]),
        "event_id": generate_uuid(),
        "vault": random.choice(_VAULT_NAMES),
        "user": user,
        "source_ip": generate_ip(),
        "safe": random.choice(_SAFE_NAMES),
        "platform": random.choice(_PLATFORMS),
        "target_account": target,
        "target_machine": machine,
        "target_address": generate_ip(),
        "reason": random.choice(_REASONS),
        "ticket_id": f"INC{random.randint(100000, 999999)}" if random.random() < 0.4 else "",
        "gateway": random.choice(_GATEWAYS),
        "action": "Retrieve",
        "result": "Success",
        "dual_control_approver": random.choice(_USERS) if random.random() < 0.2 else "",
        "message": f"User {user} retrieved password for {target}@{machine}",
    }


def _credential_checkin(ctx=None) -> dict[str, Any]:
    ev = _credential_checkout(ctx)
    ev["type"] = "credential_checkin"
    ev["action"] = "Checkin"
    ev["message"] = f"User {ev['user']} checked in password for {ev['target_account']}@{ev['target_machine']}"
    return ev


def _session_start(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    target = random.choice(_TARGET_ACCOUNTS)
    machine = random.choice(_TARGET_MACHINES)
    protocol = random.choice(["RDP", "SSH", "SSH", "SQL", "HTTPS"])
    return {
        "type": "privileged_session_start",
        "timestamp": _now_iso(),
        "vendor": "CyberArk", "product": "EPM",
        "severity": "informational",
        "event_id": generate_uuid(),
        "session_id": generate_uuid(),
        "vault": random.choice(_VAULT_NAMES),
        "user": user,
        "source_ip": generate_ip(),
        "safe": random.choice(_SAFE_NAMES),
        "platform": random.choice(_PLATFORMS),
        "target_account": target,
        "target_machine": machine,
        "target_address": generate_ip(),
        "protocol": protocol,
        "psm_server": random.choice(_PSM_SERVERS),
        "recording_enabled": True,
        "session_duration_limit": random.choice([0, 3600, 7200, 14400]),
        "action": "PSMConnect",
        "result": "Success",
        "message": f"PSM session started: {user} -> {target}@{machine} ({protocol})",
    }


def _session_end(ctx=None) -> dict[str, Any]:
    ev = _session_start(ctx)
    ev["type"] = "privileged_session_end"
    ev["action"] = "PSMDisconnect"
    ev["session_duration_seconds"] = random.randint(30, 14400)
    ev["commands_recorded"] = random.randint(0, 500)
    ev["keystrokes_recorded"] = random.randint(0, 5000)
    ev["recording_size_bytes"] = random.randint(10000, 50000000)
    ev["message"] = f"PSM session ended: {ev['user']} -> {ev['target_account']}@{ev['target_machine']}"
    return ev


def _policy_violation(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    violations = [
        ("Exclusive access violation", "Account already checked out by another user", "high"),
        ("Access outside allowed time", "Access attempted outside business hours", "high"),
        ("Exceeded session duration", "Session exceeded maximum allowed duration", "warning"),
        ("Unauthorized safe access", "User attempted access to unauthorized safe", "critical"),
        ("Failed dual control", "Dual control approval not obtained", "high"),
        ("Password age violation", "Password not changed within required interval", "warning"),
        ("Connection from untrusted IP", "Connection from non-whitelisted source IP", "critical"),
    ]
    vname, vdesc, sev = random.choice(violations)
    return {
        "type": "policy_violation",
        "timestamp": _now_iso(),
        "vendor": "CyberArk", "product": "EPM",
        "severity": sev,
        "event_id": generate_uuid(),
        "vault": random.choice(_VAULT_NAMES),
        "user": user,
        "source_ip": generate_ip(),
        "violation_type": vname,
        "violation_detail": vdesc,
        "safe": random.choice(_SAFE_NAMES),
        "target_account": random.choice(_TARGET_ACCOUNTS),
        "target_machine": random.choice(_TARGET_MACHINES),
        "action": "PolicyViolation",
        "result": "Blocked",
        "message": f"Policy violation: {vname} by {user}",
    }


def _password_change(ctx=None) -> dict[str, Any]:
    target = random.choice(_TARGET_ACCOUNTS)
    machine = random.choice(_TARGET_MACHINES)
    success = random.random() > 0.1
    return {
        "type": "password_change",
        "timestamp": _now_iso(),
        "vendor": "CyberArk", "product": "EPM",
        "severity": "informational" if success else "high",
        "event_id": generate_uuid(),
        "vault": random.choice(_VAULT_NAMES),
        "initiator": random.choice(["CPM", "CPM", "Manual"]),
        "safe": random.choice(_SAFE_NAMES),
        "platform": random.choice(_PLATFORMS),
        "target_account": target,
        "target_machine": machine,
        "target_address": generate_ip(),
        "action": "CPMChangePassword" if success else "CPMChangePasswordFailed",
        "result": "Success" if success else "Failure",
        "failure_reason": "" if success else random.choice([
            "Network unreachable", "Authentication failed", "Account locked",
            "Password policy violation", "Connection timeout"]),
        "message": f"Password {'changed' if success else 'change failed'} for {target}@{machine}",
    }


def _safe_operation(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    ops = [
        ("SafeAdd", "Safe created", "informational"),
        ("SafeUpdate", "Safe settings modified", "informational"),
        ("SafeMemberAdd", "Member added to safe", "warning"),
        ("SafeMemberUpdate", "Member permissions updated", "warning"),
        ("SafeMemberDelete", "Member removed from safe", "warning"),
    ]
    op, desc, sev = random.choice(ops)
    return {
        "type": "safe_operation",
        "timestamp": _now_iso(),
        "vendor": "CyberArk", "product": "EPM",
        "severity": sev,
        "event_id": generate_uuid(),
        "vault": random.choice(_VAULT_NAMES),
        "user": user,
        "source_ip": generate_ip(),
        "safe": random.choice(_SAFE_NAMES),
        "action": op,
        "result": "Success",
        "affected_user": random.choice(_USERS) if "Member" in op else "",
        "message": f"{desc}: {random.choice(_SAFE_NAMES)} by {user}",
    }


def _admin_audit(ctx=None) -> dict[str, Any]:
    user = random.choice(["admin", "vaultadmin", "auditor"])
    actions = [
        ("Login", "Vault login", "informational"),
        ("Logout", "Vault logout", "informational"),
        ("UserAdd", "User account created", "warning"),
        ("UserUpdate", "User account modified", "warning"),
        ("UserSuspend", "User account suspended", "high"),
        ("PlatformAdd", "Platform created", "informational"),
        ("LicenseUpdate", "License updated", "informational"),
        ("BackupStart", "Vault backup started", "informational"),
        ("FailedLogin", "Failed vault login", "high"),
        ("EmergencyStationUsed", "Emergency station accessed", "critical"),
    ]
    action, desc, sev = random.choice(actions)
    return {
        "type": "admin_audit",
        "timestamp": _now_iso(),
        "vendor": "CyberArk", "product": "EPM",
        "severity": sev,
        "event_id": generate_uuid(),
        "vault": random.choice(_VAULT_NAMES),
        "user": user,
        "source_ip": generate_ip(),
        "action": action,
        "result": random.choice(["Success", "Success", "Failure"]) if action == "FailedLogin" else "Success",
        "component": random.choice(["PVWA", "Vault", "CPM", "PSM", "PTA"]),
        "message": f"{desc} by {user}",
    }


_GENERATORS = [
    (_credential_checkout, 20), (_credential_checkin, 15), (_session_start, 15),
    (_session_end, 10), (_policy_violation, 8), (_password_change, 12),
    (_safe_operation, 10), (_admin_audit, 10),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]


def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
