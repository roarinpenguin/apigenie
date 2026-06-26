"""Built-in attack scenario templates — 5 ready-made MITRE ATT&CK campaigns.

Each template defines phases with source, MITRE mapping, timing, and
field overrides. When instantiated, the engine creates temporary detection
rules that inject attack events into normal log flows.
"""

from __future__ import annotations
from typing import Any

TEMPLATES: dict[str, dict[str, Any]] = {}


def _register(key: str, name: str, description: str, phases: list[dict]) -> None:
    TEMPLATES[key] = {"key": key, "name": name, "description": description, "phases": phases}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Business Email Compromise (BEC)
# ═══════════════════════════════════════════════════════════════════════════════

_register("bec_phishing", "Business Email Compromise (BEC)",
    "Impostor phish → impersonation session via stolen token → illicit OAuth admin consent → "
    "suspicious inbox rule → persistent SendAs delegation. v5.1.9: every phase's "
    "field_overrides matches at least one vendor-shipped S1 STAR rule's s1ql so the "
    "demo tenant generates 5 correlated alerts in addition to the cross-source events.",
    [
        # ── Phase 1 ─────────────────────────────────────────────────────────
        # Target rule: "Proofpoint Impostor Email Unblocked" (sev=High).
        # s1ql excerpt:
        #   dataSource.name='Proofpoint' AND
        #   unmapped.threatsInfoMap contains '"classification":"impostor"' AND
        #   (unmapped.messageParts contains '"sandboxStatus":"THREAT"'
        #    OR unmapped.impostorScore > 80) AND
        #   NOT (unmapped.quarantineFolder = *)
        {
            "phase_id": "initial-access",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1566.001",
            "name": "Impostor phishing email delivered (BEC pretext)",
            "source": "proofpoint",
            "time_offset_pct": 0,
            "duration_pct": 10,
            "periodicity": 3,
            "field_overrides": {
                # v5.1.9: classification=impostor + impostorScore>80 + sandbox THREAT
                # + quarantineFolder empty → fires "Impostor Email Unblocked".
                "threatsInfoMap.0.threatType": "url",
                "threatsInfoMap.0.classification": "impostor",
                "threatsInfoMap.0.threat": "https://login-microsoftonline.evil.com/oauth2",
                "messageParts.0.sandboxStatus": "THREAT",
                "subject": "Urgent: CFO wire transfer approval needed",
                "quarantineFolder": "",
                "spamScore": 90,
                "phishScore": 95,
                "impostorScore": 90,
                "malwareScore": 0,
            },
        },
        # ── Phase 2 ─────────────────────────────────────────────────────────
        # Target rule: "Okta Impersonation Session Initiated" (sev=High).
        # s1ql:
        #   dataSource.name='Okta' AND
        #   (unmapped.eventType contains 'user.session.impersonation.initiate'
        #    OR unmapped.legacyEventType contains 'user.session.impersonation.initiate')
        {
            "phase_id": "credential-access",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1528",
            "name": "Impersonation session via stolen OAuth token",
            "source": "okta",
            "time_offset_pct": 10,
            "duration_pct": 15,
            "periodicity": 5,
            "field_overrides": {
                # v5.1.9: eventType + legacyEventType → fires "Impersonation Session".
                "eventType": "user.session.impersonation.initiate",
                "legacyEventType": "core.user_auth.impersonation_session_initiated",
                "outcome.result": "SUCCESS",
                "client.geographicalContext.country": "Russia",
                "client.geographicalContext.city": "Moscow",
                "client.userAgent.rawUserAgent": "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0",
                "securityContext.isProxy": True,
                "debugContext.debugData.risk": "HIGH",
            },
        },
        # ── Phase 3 ─────────────────────────────────────────────────────────
        # Target rule: "Office 365 Admin Consent Granted for All Principals" (sev=Low).
        # s1ql:
        #   dataSource.name='Microsoft O365' AND
        #   unmapped.Operation='Consent to application.' AND
        #   unmapped.ModifiedProperties contains 'ConsentType: AllPrincipals'
        {
            "phase_id": "privilege-escalation",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1098.003",
            "name": "Illicit OAuth app — admin consent granted for all principals",
            "source": "m365",
            "time_offset_pct": 25,
            "duration_pct": 20,
            "periodicity": 4,
            "field_overrides": {
                # v5.1.9: exact Operation literal + ModifiedProperties string with
                # the AllPrincipals marker → fires "Admin Consent Granted...".
                "Operation": "Consent to application.",
                "Workload": "AzureActiveDirectory",
                "ResultStatus": "Success",
                "ExternalAccess": True,
                "ModifiedProperties": (
                    "ConsentAction.Permissions: "
                    "[Scope: Mail.Read,Mail.Send,offline_access ConsentType: AllPrincipals]"
                ),
                "ObjectId": "OAuth-App-Phishing-Toolkit",
            },
        },
        # ── Phase 4 ─────────────────────────────────────────────────────────
        # Target rule: "Office 365 Inbox Rule Created or Modified with Suspicious
        # Parameters" (sev=Medium). s1ql third branch:
        #   activity_name in ('New-InboxRule','Set-InboxRule') AND
        #   Parameters matches '"Name":"MoveToFolder"' AND
        #   Parameters matches '"Value":"(Conversation History|RSS Feeds|Deleted Items|Junk Email)"' AND
        #   Parameters matches '"Name":"MarkAsRead"' AND
        #   Parameters matches '"Value":"True"'
        {
            "phase_id": "defense-evasion",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "T1564.008",
            "name": "Inbox rule hides forwarded mail in Deleted Items",
            "source": "m365",
            "time_offset_pct": 45,
            "duration_pct": 15,
            "periodicity": 8,
            "field_overrides": {
                # v5.1.9: New-InboxRule + Parameters[] with the MoveToFolder + MarkAsRead
                # combo that matches the rule's third branch → fires "Suspicious Parameters".
                "Operation": "New-InboxRule",
                "Workload": "Exchange",
                "ResultStatus": "Succeeded",
                "Parameters": [
                    {"Name": "Identity",            "Value": "compromised.user@apigenie.com"},
                    {"Name": "Name",                "Value": "Sync Issues Filter"},
                    {"Name": "MoveToFolder",        "Value": "Deleted Items"},
                    {"Name": "MarkAsRead",          "Value": "True"},
                    {"Name": "StopProcessingRules", "Value": "True"},
                ],
            },
        },
        # ── Phase 5 ─────────────────────────────────────────────────────────
        # Target rule: "Office 365 Mailbox Permissions Delegation" (sev=Info).
        # s1ql:
        #   metadata.product.name='Exchange' AND
        #   activity_name='Add-MailboxPermission' AND
        #   unmapped.Parameters contains:matchcase ('FullAccess','SendAs','SendOnBehalf') AND
        #   unmapped.UserId != 'NT AUTHORITY\SYSTEM (Microsoft.Exchange.ServiceHost)'
        {
            "phase_id": "persistence",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1098.002",
            "name": "Persistent SendAs delegation to attacker mailbox",
            "source": "m365",
            "time_offset_pct": 60,
            "duration_pct": 40,
            "periodicity": 3,
            "field_overrides": {
                # v5.1.9: Add-MailboxPermission + Parameters[] case-sensitive SendAs
                # → fires "Mailbox Permissions Delegation".
                "Operation": "Add-MailboxPermission",
                "Workload": "Exchange",
                "ResultStatus": "Succeeded",
                "ObjectId": "/o=ExchangeLabs/ou=...\\compromised.user",
                "Parameters": [
                    {"Name": "Identity",     "Value": "compromised.user@apigenie.com"},
                    {"Name": "User",         "Value": "exfil-drop@protonmail.com"},
                    {"Name": "AccessRights", "Value": "SendAs"},
                ],
            },
        },
    ]
)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Ransomware via Lateral Movement
# ═══════════════════════════════════════════════════════════════════════════════

_register("ransomware_lateral", "Ransomware via Lateral Movement",
    "Exploitation → C2 callback → credential dumping → lateral movement → discovery → ransomware deployment (SentinelOne XDR)",
    [
        {
            "phase_id": "initial-access",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190",
            "name": "Exploitation of public-facing application",
            "source": "paloalto",
            "time_offset_pct": 0,
            "duration_pct": 8,
            "periodicity": 5,
            "field_overrides": {
                "type": "THREAT",
                "subtype": "vulnerability",
                "severity": "critical",
                "action": "alert",
                "threat_name": "Apache Log4j Remote Code Execution Vulnerability",
                "threat_id": 92001,
                "direction": "client-to-server",
            },
        },
        {
            "phase_id": "command-and-control",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1071.001",
            "name": "C2 callback established",
            "source": "paloalto",
            "time_offset_pct": 8,
            "duration_pct": 12,
            "periodicity": 4,
            "field_overrides": {
                "type": "TRAFFIC",
                "subtype": "end",
                "action": "allow",
                "application": "ssl",
                "dst_zone": "untrust",
                "category": "command-and-control",
                "session_end_reason": "tcp-fin",
            },
        },
        {
            "phase_id": "credential-access",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1003.001",
            "name": "Credential dumping (LSASS)",
            "source": "sentinelone",
            "time_offset_pct": 20,
            "duration_pct": 15,
            "periodicity": 6,
            "field_overrides": {
                "type": "threat",
                "threatInfo.threatName": "LSASS Access Detected",
                "threatInfo.classification": "Infostealer",
                "threatInfo.confidenceLevel": "malicious",
                "threatInfo.classificationSource": "Behavioral AI",
                "severity": "Critical",
                "mitre.tactic.id": "TA0006",
                "mitre.tactic.name": "Credential Access",
                "mitre.technique.id": "T1003.001",
                "mitre.technique.name": "LSASS Memory",
                "threatInfo.commandLineArguments": "rundll32.exe C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\\\temp\\\\lsass.dmp full",
            },
        },
        {
            "phase_id": "lateral-movement",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021.002",
            "name": "Lateral movement via PsExec",
            "source": "sentinelone",
            "time_offset_pct": 35,
            "duration_pct": 20,
            "periodicity": 5,
            "field_overrides": {
                "type": "threat",
                "threatInfo.threatName": "Lateral Movement via PsExec",
                "threatInfo.classification": "Exploit",
                "threatInfo.confidenceLevel": "malicious",
                "threatInfo.classificationSource": "Behavioral AI",
                "severity": "High",
                "mitre.tactic.id": "TA0008",
                "mitre.tactic.name": "Lateral Movement",
                "mitre.technique.id": "T1021.002",
                "mitre.technique.name": "SMB/Windows Admin Shares",
                "threatInfo.originatorProcess": "psexesvc.exe",
                "threatInfo.commandLineArguments": "psexec.exe \\\\\\\\SRV-DC-01 -s cmd.exe /c whoami",
            },
        },
        {
            "phase_id": "discovery",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1018",
            "name": "Active Directory enumeration",
            "source": "entra_id",
            "time_offset_pct": 55,
            "duration_pct": 15,
            "periodicity": 4,
            "field_overrides": {
                "operationName": "List groups",
                "category": "GroupManagement",
                "resultType": "Success",
                "initiatedBy.user.displayName": "svc-compromised",
            },
        },
        {
            "phase_id": "impact",
            "mitre_tactic": "Impact",
            "mitre_technique": "T1486",
            "name": "Ransomware deployment",
            "source": "sentinelone",
            "time_offset_pct": 70,
            "duration_pct": 30,
            "periodicity": 3,
            "field_overrides": {
                "type": "threat",
                "threatInfo.threatName": "Ransomware Behavior - File Encryption",
                "threatInfo.classification": "Ransomware",
                "threatInfo.confidenceLevel": "malicious",
                "threatInfo.classificationSource": "Behavioral AI",
                "threatInfo.incidentStatus": "in_progress",
                "threatInfo.mitigationStatus": "mitigated",
                "threatInfo.mitigationActions": ["kill", "quarantine", "rollback"],
                "severity": "Critical",
                "mitre.tactic.id": "TA0040",
                "mitre.tactic.name": "Impact",
                "mitre.technique.id": "T1486",
                "mitre.technique.name": "Data Encrypted for Impact",
                "threatInfo.originatorProcess": "locker.exe",
            },
        },
    ]
)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Cloud Account Takeover
# ═══════════════════════════════════════════════════════════════════════════════

_register("cloud_account_takeover", "Cloud Account Takeover",
    "Token theft → illicit app consent → cloud discovery → privilege escalation → data theft → persistence",
    [
        {
            "phase_id": "credential-access",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1528",
            "name": "Stolen OAuth token login",
            "source": "okta",
            "time_offset_pct": 0,
            "duration_pct": 12,
            "periodicity": 5,
            "field_overrides": {
                "eventType": "user.session.start",
                "outcome.result": "SUCCESS",
                "client.geographicalContext.country": "Nigeria",
                "debugContext.debugData.risk": "HIGH",
                "debugContext.debugData.behaviors": "ANOMALOUS_DEVICE,ANOMALOUS_LOCATION",
            },
        },
        {
            "phase_id": "persistence",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1098.003",
            "name": "Illicit OAuth app consent",
            "source": "m365",
            "time_offset_pct": 12,
            "duration_pct": 13,
            "periodicity": 8,
            "field_overrides": {
                "Operation": "Consent to application.",
                "Workload": "AzureActiveDirectory",
                "ApplicationName": "MailReader Pro",
                "Permissions": "Mail.Read Mail.Send Mail.ReadWrite User.Read Files.ReadWrite.All",
                "ConsentType": "UserConsent",
            },
        },
        {
            "phase_id": "discovery",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1538",
            "name": "Cloud infrastructure enumeration",
            "source": "m365",
            "time_offset_pct": 25,
            "duration_pct": 15,
            "periodicity": 4,
            "field_overrides": {
                "Operation": "FileDownloaded",
                "Workload": "SharePoint",
                "SourceFileName": "Employee-Directory.xlsx",
                "SiteUrl": "https://contoso.sharepoint.com/sites/HR",
            },
        },
        {
            "phase_id": "privilege-escalation",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "T1078.004",
            "name": "PIM role escalation to Global Admin",
            "source": "m365",
            "time_offset_pct": 40,
            "duration_pct": 15,
            "periodicity": 10,
            "field_overrides": {
                "Operation": "Activate eligible role.",
                "Workload": "AzureActiveDirectory",
                "RoleName": "Global Administrator",
                "Justification": "Emergency access needed",
                "ActivationDuration": "PT8H",
            },
        },
        {
            "phase_id": "collection",
            "mitre_tactic": "Collection",
            "mitre_technique": "T1530",
            "name": "Mass file download from SharePoint",
            "source": "m365",
            "time_offset_pct": 55,
            "duration_pct": 25,
            "periodicity": 3,
            "field_overrides": {
                "Operation": "FileDownloaded",
                "Workload": "SharePoint",
                "SiteUrl": "https://contoso.sharepoint.com/sites/Finance",
                "SourceFileName": "Merger-Plans-Confidential.docx",
            },
        },
        {
            "phase_id": "persistence-2",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1136.003",
            "name": "Backdoor service principal created",
            "source": "entra_id",
            "time_offset_pct": 80,
            "duration_pct": 20,
            "periodicity": 10,
            "field_overrides": {
                "operationName": "Add service principal",
                "category": "ApplicationManagement",
                "resultType": "Success",
            },
        },
    ]
)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. DNS Poisoning + Data Exfiltration
# ═══════════════════════════════════════════════════════════════════════════════

_register("dns_exfiltration", "DNS Poisoning + Data Exfiltration",
    "DNS manipulation → C2 over DNS → internal recon → firewall evasion → data exfiltration → cleanup",
    [
        {
            "phase_id": "initial-access",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1584.002",
            "name": "Malicious DNS resolution",
            "source": "infoblox",
            "time_offset_pct": 0,
            "duration_pct": 12,
            "periodicity": 4,
            "field_overrides": {
                "type": "rpz",
                "subtype": "rpz_hit",
                "threat_type": "C2",
                "threat_level": "Critical",
                "rpz_action": "PASSTHRU",
                "query_name": "c2-beacon.evil-domain.xyz",
            },
        },
        {
            "phase_id": "command-and-control",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1071.004",
            "name": "C2 communication via DNS tunneling",
            "source": "infoblox",
            "time_offset_pct": 12,
            "duration_pct": 18,
            "periodicity": 3,
            "field_overrides": {
                "type": "threat",
                "subtype": "dns_tunneling",
                "threat_type": "DNS Tunneling",
                "threat_level": "Critical",
                "confidence": 95,
                "query_name": "aGVsbG8gd29ybGQ.tunnel.evil-domain.xyz",
            },
        },
        {
            "phase_id": "discovery",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046",
            "name": "Internal network scanning",
            "source": "fortigate",
            "time_offset_pct": 30,
            "duration_pct": 15,
            "periodicity": 4,
            "field_overrides": {
                "type": "anomaly",
                "subtype": "anomaly",
                "severity": "critical",
                "action": "detected",
                "attack": "scan_port",
                "count": 5000,
            },
        },
        {
            "phase_id": "defense-evasion",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "T1572",
            "name": "Encrypted tunnel to unknown destination",
            "source": "fortigate",
            "time_offset_pct": 45,
            "duration_pct": 15,
            "periodicity": 5,
            "field_overrides": {
                "type": "traffic",
                "subtype": "forward",
                "action": "accept",
                "service": "HTTPS",
                "hostname": "unknown-proxy.darkweb.onion.ws",
                "app": "Tor",
                "appcat": "Proxy",
            },
        },
        {
            "phase_id": "exfiltration",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1048.001",
            "name": "Data exfiltration via cloud upload",
            "source": "zscaler",
            "time_offset_pct": 60,
            "duration_pct": 25,
            "periodicity": 3,
            "field_overrides": {
                "type": "web",
                "event.action": "Blocked",
                "event.dlpdictnames": "PCI-DSS Credit Card Detection",
                "event.threatname": "Data Exfiltration",
                "event.urlcategory": "Advanced Security Risk",
                "event.requestsize": 52428800,
            },
        },
        {
            "phase_id": "defense-evasion-2",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "T1070.004",
            "name": "Audit log purge attempt",
            "source": "m365",
            "time_offset_pct": 85,
            "duration_pct": 15,
            "periodicity": 10,
            "field_overrides": {
                "Operation": "SearchPurged",
                "Workload": "SecurityComplianceCenter",
                "SearchName": "All activity last 30 days",
                "ResultCount": 0,
            },
        },
    ]
)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Insider Threat — Disgruntled Employee
# ═══════════════════════════════════════════════════════════════════════════════

_register("insider_threat", "Insider Threat — Disgruntled Employee",
    "Excessive data access → email exfiltration → cloud upload → off-hours VPN → evidence tampering → anomalous login",
    [
        {
            "phase_id": "collection",
            "mitre_tactic": "Collection",
            "mitre_technique": "T1530",
            "name": "Mass file downloads from SharePoint",
            "source": "m365",
            "time_offset_pct": 0,
            "duration_pct": 18,
            "periodicity": 3,
            "field_overrides": {
                "Operation": "FileDownloaded",
                "Workload": "SharePoint",
                "SiteUrl": "https://contoso.sharepoint.com/sites/Finance",
                "SourceFileName": "Customer-Data-Export.xlsx",
                "SourceRelativeUrl": "Shared Documents/Confidential/",
            },
        },
        {
            "phase_id": "exfiltration",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1048.003",
            "name": "Email forwarding to personal account",
            "source": "m365",
            "time_offset_pct": 18,
            "duration_pct": 17,
            "periodicity": 4,
            "field_overrides": {
                "Operation": "Set-Mailbox",
                "Workload": "Exchange",
                "Parameters": [{"Name": "ForwardingSmtpAddress", "Value": "smtp:personal@gmail.com"},
                               {"Name": "DeliverToMailboxAndForward", "Value": "True"}],
            },
        },
        {
            "phase_id": "exfiltration-2",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1567",
            "name": "Cloud upload with sensitive data",
            "source": "netskope",
            "time_offset_pct": 35,
            "duration_pct": 15,
            "periodicity": 4,
            "field_overrides": {
                "alert_type": "DLP",
                "alert_name": "Sensitive data uploaded to personal cloud",
                "app": "Dropbox",
                "object_type": "File",
                "severity": "critical",
                "dlp_rule": "PCI-DSS Credit Card Numbers",
                "activity": "Upload",
            },
        },
        {
            "phase_id": "persistence",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1133",
            "name": "Off-hours VPN access from foreign IP",
            "source": "cisco_duo",
            "time_offset_pct": 50,
            "duration_pct": 15,
            "periodicity": 5,
            "field_overrides": {
                "eventtype": "authentication",
                "result": "SUCCESS",
                "reason": "Valid passcode",
                "access_device.ip": "185.220.100.252",
                "access_device.location.country": "Romania",
                "timestamp": "2026-05-26T03:15:00Z",
            },
        },
        {
            "phase_id": "defense-evasion",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "T1070",
            "name": "Evidence tampering — audit search and inbox rule deletion",
            "source": "m365",
            "time_offset_pct": 65,
            "duration_pct": 20,
            "periodicity": 6,
            "field_overrides": {
                "Operation": "Remove-InboxRule",
                "Workload": "Exchange",
                "RuleName": "Auto-Forward",
            },
        },
        {
            "phase_id": "credential-access",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1078",
            "name": "Anomalous login from new device",
            "source": "okta",
            "time_offset_pct": 85,
            "duration_pct": 15,
            "periodicity": 5,
            "field_overrides": {
                "eventType": "user.session.start",
                "outcome.result": "SUCCESS",
                "client.geographicalContext.country": "Thailand",
                "debugContext.debugData.risk": "HIGH",
                "debugContext.debugData.behaviors": "NEW_DEVICE,ANOMALOUS_LOCATION",
            },
        },
    ]
)


def get_templates() -> list[dict[str, Any]]:
    """Return all templates as a list with summary info."""
    result = []
    for key, t in TEMPLATES.items():
        result.append({
            "key": key,
            "name": t["name"],
            "description": t["description"],
            "phase_count": len(t["phases"]),
            "sources": list(set(p["source"] for p in t["phases"])),
            "mitre_tactics": list(dict.fromkeys(p["mitre_tactic"] for p in t["phases"])),
        })
    return result


def get_template(key: str) -> dict[str, Any] | None:
    return TEMPLATES.get(key)
