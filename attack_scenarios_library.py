"""Built-in attack scenario templates — 5 ready-made MITRE ATT&CK campaigns.

Each template defines phases with source, MITRE mapping, timing, and
field overrides. When instantiated, the engine creates temporary detection
rules that inject attack events into normal log flows.
"""

from __future__ import annotations
from typing import Any

TEMPLATES: dict[str, dict[str, Any]] = {}


def _register(key: str, name: str, description: str, phases: list[dict],
              recommended_duration: dict | None = None) -> None:
    # ``recommended_duration`` ({"value": int, "unit": str}) lets a template
    # advertise the wall-clock run length it needs. It is pre-filled into the
    # Create-Scenario modal when the template is selected. apigenie imposes no
    # cadence of its own — events are generated on demand when the operator's
    # collector polls. What matters is that each phase window is wider than the
    # collector's poll interval (commonly ~120s) so at least one poll lands in
    # it; the recommended duration sizes the M365-heavy phases comfortably
    # above that with a couple of poll opportunities to spare.
    TEMPLATES[key] = {"key": key, "name": name, "description": description,
                      "phases": phases, "recommended_duration": recommended_duration}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Business Email Compromise (BEC)
# ═══════════════════════════════════════════════════════════════════════════════

_register("bec_phishing", "Business Email Compromise (BEC)",
    "Impostor phish → impersonation session via stolen token → illicit OAuth admin consent → "
    "anti-phishing policy removed → persistent mail exfiltration via transport rule. v5.1.16: "
    "all five phases fire VENDOR-SHIPPED rules that resolve the persona as the alert's Target "
    "Asset — Phase 1 (Proofpoint Impostor), Phase 2 (Okta Impersonation), Phase 3 (M365 Admin "
    "Consent), Phase 4 (M365 Anti-Phish Rule removal) and Phase 5 (M365 Transport Rule creation). "
    "Each M365 phase keys off SCALAR OCSF fields (activity_name / Operation), which the STAR "
    "engine evaluates correctly; the Parameters-array based platform rules are avoided because "
    "the collector flattens arrays into indexed keys the array-container path can't see. NOTE: "
    "the back-half phases are M365; run this scenario long enough that each M365 phase window is "
    "wider than your collector's poll interval (commonly ~120s) so every phase overlaps at least "
    "one poll. ~30 minutes gives each M365 phase 2-3 poll opportunities; much shorter runs can "
    "cause the narrow Phase 3/4 windows to fall between polls and emit no events.",
    [
        # ── Phase 1 ─────────────────────────────────────────────────────────
        # Target rule (v5.1.15): "Proofpoint Impostor Email Unblocked" — the
        # VENDOR-SHIPPED STAR rule. Empirically it fires correctly on this
        # tenant against the high-fidelity impostor email this phase emits
        # (impostorScore=90 / phishScore=95, clean recipient string) and it
        # resolves the recipient persona as the alert's Target Asset. The
        # earlier API-Genie custom rule keyed off `unmapped.impostorScore` /
        # `unmapped.phishScore` alone, which also matched apigenie's generic
        # Proofpoint background noise (recipients emitted as array literals
        # like `[bob@company.com]` that the OCSF normaliser cannot map to an
        # entity), so those alerts surfaced as "Unknown Device". Per the
        # shipped-rule-first principle the custom rule was retired and Phase 1
        # now targets the shipped rule directly.
        {
            "phase_id": "initial-access",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1566.001",
            "name": "Impostor phishing email delivered (BEC pretext)",
            "source": "proofpoint",
            "time_offset_pct": 0,
            "duration_pct": 10,
            "periodicity": 3,
            # v5.1.19 — realistic volume: a BEC pretext is one (maybe two)
            # impostor email(s), not a flood. Cap total events for the phase.
            "max_events": 2,
            "field_overrides": {
                # v5.1.12 — dot-notation rewrite. v5.1.9 stamped
                # ``threatsInfoMap.0.X`` / ``messageParts.0.X`` which
                # detection_rules._apply_overrides walks via _set_nested. That
                # helper does NOT understand list indices: it sees an integer
                # path segment as just another dict key, so the resulting
                # event ends up with ``threatsInfoMap = {"0": {...}}`` (a
                # dict) and — worse — the Proofpoint template's own
                # ``messageParts`` *array* gets clobbered into the same
                # ``{"0": {...}}`` shape because _set_nested overwrites
                # any non-dict node it encounters mid-path. The Proofpoint
                # parser on the S1 side strictly enforces the documented
                # array shape and silently drops the malformed event, so the
                # "Proofpoint Impostor Email Unblocked" rule never sees a
                # candidate. (This is the exact pitfall called out in
                # sources/proofpoint.py:82-88.)
                #
                # Fix: replace the *whole* list at top level. Same effect
                # for the s1ql ``contains '"classification":"impostor"'``
                # substring match, but the parser keeps the event intact.
                "threatsInfoMap": [
                    {
                        "threatType": "url",
                        "classification": "impostor",
                        "threat": "https://login-microsoftonline.evil.com/oauth2",
                    },
                ],
                # Override the whole messageParts list rather than poking
                # into index 0; preserve the template-realistic shape so
                # the parser accepts it.
                "messageParts": [
                    {
                        "contentType": "text/html",
                        "disposition": "inline",
                        "filename": "message.html",
                        "sandboxStatus": "THREAT",
                    },
                ],
                "subject": "Urgent: CFO wire transfer approval needed",
                # v5.1.12 — was ``quarantineFolder: ""``. The s1ql clause
                # ``NOT (unmapped.quarantineFolder = *)`` uses the SDL
                # wildcard, which matches any non-null value including
                # the empty string. Setting the field to ``None`` (which
                # JSON-serialises to ``null``) is the correct way to
                # leave the field absent in the data lake, so the NOT
                # clause does NOT exclude our impostor event.
                "quarantineFolder": None,
                "spamScore": 90,
                "phishScore": 95,
                "impostorScore": 90,
                "malwareScore": 0,
            },
            # v5.1.10 — phase ↔ vendor STAR rule mapping surfaced in the UI.
            # The scenario card's existing "S1 Rules" panel highlights every
            # rule whose ``name`` matches one of these entries with a 🎯
            # marker, and the s1ql field becomes the body of the clickable
            # rule-preview modal. Operators who edit the field_overrides
            # should keep this list in sync — or empty it if the phase is
            # no longer engineered to fire a specific rule.
            "target_rules": [
                {
                    "name": "Proofpoint Impostor Email Unblocked",
                    "source": "proofpoint",
                    "severity": "High",
                    "mitre": "T1566.001",
                    "s1ql": (
                        "dataSource.name = 'Proofpoint' AND "
                        "unmapped.impostorScore > 80 AND "
                        "unmapped.phishScore > 80"
                    ),
                },
            ],
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
            # v5.1.19 — one stolen-token impersonation session (small margin).
            "max_events": 2,
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
            "target_rules": [
                {
                    "name": "Okta Impersonation Session Initiated",
                    "source": "okta",
                    "severity": "High",
                    "mitre": "T1528",
                    "s1ql": (
                        "dataSource.name = 'Okta' AND "
                        "(unmapped.eventType contains 'user.session.impersonation.initiate' "
                        " OR unmapped.legacyEventType contains 'user.session.impersonation.initiate')"
                    ),
                },
            ],
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
            # v5.1.19 — admin consent is a single discrete action.
            "max_events": 1,
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
            "target_rules": [
                {
                    "name": "Office 365 Admin Consent Granted for All Principals",
                    "source": "m365",
                    "severity": "Low",
                    "mitre": "T1098.003",
                    "s1ql": (
                        "dataSource.name = 'Microsoft O365' AND "
                        "unmapped.Operation = 'Consent to application.' AND "
                        "unmapped.ModifiedProperties contains 'ConsentType: AllPrincipals'"
                    ),
                },
            ],
        },
        # ── Phase 4 ─────────────────────────────────────────────────────────
        # Target rule (v5.1.16): "Office 365 Deactivation or Removal of
        # Anti-Phish Rule" — a VENDOR-SHIPPED platform rule (High severity).
        # It keys off SCALAR fields only (metadata.product.name='Exchange' and
        # activity_name in ('Remove-AntiPhishRule','Disable-AntiPhishRule')),
        # which the STAR engine evaluates against the flattened lake event, so
        # it fires on this tenant AND — being a platform rule — resolves the
        # acting user as the alert's Target Asset (custom cloud-detection rules
        # cannot resolve the asset for agentless cloud events; platform rules
        # have the OCSF entity→asset mapping built in). Disabling anti-phishing
        # protection is a classic BEC defense-evasion step (MITRE T1562.001).
        {
            "phase_id": "defense-evasion",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "T1562.001",
            "name": "Anti-phishing policy removed to evade detection",
            "source": "m365",
            "time_offset_pct": 45,
            "duration_pct": 15,
            "periodicity": 8,
            # v5.1.19 — removing the anti-phish policy is a single action.
            "max_events": 1,
            "field_overrides": {
                # v5.1.16: Remove-AntiPhishRule on Exchange Online. The shipped
                # platform rule matches activity_name only (scalar), so no
                # Parameters-array dependency — the collector flattens arrays
                # into indexed keys that the STAR engine does not see under the
                # array-container path, which is why the Parameters-based
                # mailbox/inbox platform rules cannot fire here.
                "Operation": "Remove-AntiPhishRule",
                "Workload": "Exchange",
                "ResultStatus": "Succeeded",
                "Parameters": [
                    {"Name": "Identity", "Value": "Office365 AntiPhish Default"},
                ],
            },
            "target_rules": [
                {
                    "name": "Office 365 Deactivation or Removal of Anti-Phish Rule",
                    "source": "m365",
                    "severity": "High",
                    "mitre": "T1562.001",
                    "s1ql": (
                        "dataSource.name = 'Microsoft O365' AND "
                        "metadata.product.name = 'Exchange' AND "
                        "activity_name in ('Remove-AntiPhishRule','Disable-AntiPhishRule')"
                    ),
                },
            ],
        },
        # ── Phase 5 ─────────────────────────────────────────────────────────
        # Target rule (v5.1.16): "Office 365 Creation of Mail Transport Rule"
        # — a VENDOR-SHIPPED platform rule. Like Phase 4 it keys off SCALAR
        # fields only (metadata.product.name='Exchange' and
        # activity_name='New-TransportRule'), so it fires on this tenant AND
        # resolves the acting user as the Target Asset. An org-wide Exchange
        # transport rule that redirects mail to an external attacker mailbox is
        # a persistent BEC exfiltration channel (MITRE T1114.003 — Email
        # Collection: Email Forwarding Rule).
        {
            "phase_id": "persistence",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1114.003",
            "name": "Persistent mail exfiltration via Exchange transport rule",
            "source": "m365",
            "time_offset_pct": 60,
            "duration_pct": 40,
            "periodicity": 3,
            # v5.1.19 — one transport rule is created; cap to a single event.
            "max_events": 1,
            "field_overrides": {
                # v5.1.16: New-TransportRule that redirects all inbound mail to
                # an external mailbox. The shipped platform rule matches
                # activity_name only (scalar), so it fires regardless of the
                # Parameters-array flattening behaviour of the collector.
                "Operation": "New-TransportRule",
                "Workload": "Exchange",
                "ResultStatus": "Succeeded",
                "Parameters": [
                    {"Name": "Name",              "Value": "External Mail Sync"},
                    {"Name": "RedirectMessageTo", "Value": "exfil-drop@protonmail.com"},
                    {"Name": "Enabled",           "Value": "True"},
                ],
            },
            "target_rules": [
                {
                    "name": "Office 365 Creation of Mail Transport Rule",
                    "source": "m365",
                    "severity": "Medium",
                    "mitre": "T1114.003",
                    "s1ql": (
                        "dataSource.name = 'Microsoft O365' AND "
                        "metadata.product.name = 'Exchange' AND "
                        "activity_name = 'New-TransportRule'"
                    ),
                },
            ],
        },
    ],
    # The back-half phases are all M365 (privilege-escalation / defense-evasion
    # / persistence). apigenie emits on demand, so the only timing constraint is
    # that each phase window be wider than the collector's poll interval
    # (commonly ~120s). At 30 min the narrowest M365 window (defense-evasion,
    # 15%) is ~4.5 min — ~2 poll opportunities at 120s. Much shorter runs can
    # let Phase 3/4 fall between polls and emit nothing.
    recommended_duration={"value": 30, "unit": "minutes"},
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
            # v5.1.20 — realistic volume: a successful exploit is one (maybe
            # two) IPS hits, not a flood. Cap total events for the phase.
            "max_events": 2,
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
            # v5.1.20 — a few beacon sessions, not continuous background noise.
            "max_events": 3,
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
            # v5.1.20 — a single LSASS-access detection.
            "max_events": 1,
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
            # v5.1.20 — a couple of PsExec hops across hosts.
            "max_events": 2,
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
            # v5.1.20 — a handful of directory list operations.
            "max_events": 3,
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
            # v5.1.20 — one ransomware-behaviour detection (mitigated).
            "max_events": 1,
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
            # v5.1.20 — a stolen-token sign-in is one (maybe two) sessions.
            "max_events": 2,
            "field_overrides": {
                # v5.1.25 — fire the shipped "Okta High Severity Threat Detected"
                # rule (Okta ThreatInsight). Verified against the lake: the Okta
                # collector maps these to unmapped.eventType / unmapped.severity /
                # status. The background noise NEVER emits security.threat.detected,
                # so this is a clean, scenario-only discriminator. The earlier
                # debugContext.debugData.risk/behaviors overrides are DROPPED by the
                # collector (they land as null), so they cannot anchor a rule.
                "eventType": "security.threat.detected",
                "severity": "HIGH",
                "outcome.result": "SUCCESS",
                "displayMessage": "Okta ThreatInsight: malicious sign-in with stolen session token",
                "client.geographicalContext.country": "NG",
            },
            "target_rules": [
                {
                    "name": "Okta High Severity Threat Detected",
                    "source": "okta",
                    "severity": "High",
                    "mitre": "T1528",
                    "shipped_status": "Disabled",  # must be ENABLED on the tenant
                    "s1ql": (
                        "dataSource.name = 'Okta' and "
                        "(unmapped.eventType contains ('security.threat.detected','security.attack.start')) "
                        "and not (status = 'DENY') and not (unmapped.severity in ('INFO','WARN'))"
                    ),
                },
            ],
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
            # v5.1.20 — granting consent is a single discrete action.
            "max_events": 1,
            "field_overrides": {
                # v5.1.25 — fire the ACTIVE shipped "Office 365 Admin Consent
                # Granted for All Principals" rule (same rule BEC phase 3 proved).
                # It keys on unmapped.Operation + unmapped.ModifiedProperties
                # contains 'ConsentType: AllPrincipals', so the illicit app must be
                # granted tenant-wide (AllPrincipals) consent — a single-user
                # UserConsent does NOT fire it.
                "Operation": "Consent to application.",
                "Workload": "AzureActiveDirectory",
                "ApplicationName": "MailReader Pro",
                "ResultStatus": "Success",
                "ModifiedProperties": (
                    "ConsentAction.Permissions: "
                    "[Scope: Mail.Read,Mail.Send,Mail.ReadWrite,Files.ReadWrite.All "
                    "ConsentType: AllPrincipals]"
                ),
                "ObjectId": "OAuth-App-MailReader-Pro",
            },
            "target_rules": [
                {
                    "name": "Office 365 Admin Consent Granted for All Principals",
                    "source": "m365",
                    "severity": "Low",
                    "mitre": "T1098.003",
                    "shipped_status": "Active",
                    "s1ql": (
                        "dataSource.name = 'Microsoft O365' and "
                        "unmapped.Operation = 'Consent to application.' and "
                        "unmapped.ModifiedProperties contains 'ConsentType: AllPrincipals'"
                    ),
                },
            ],
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
            # v5.1.20 — a few recon downloads while the attacker maps the tenant.
            "max_events": 3,
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
            # v5.1.26 — retarget m365→entra_id. With Entra ID now streaming
            # (dataSource.name='Azure Active Directory'), the SHIPPED platform rule
            # "Azure User Added to a Highly Privileged Built-in Role" fires on the
            # directory-audit role assignment and — being a platform rule —
            # resolves the Target Asset (a custom O365 rule could not). Verified
            # field landing in the lake: the rule keys on
            # unmapped.activityDisplayName='Add member to role',
            # unmapped.operationType='Assign' (background uses 'Add' → NO noise),
            # and unmapped.targetResources contains 'Global Administrator'.
            "source": "entra_id",
            "time_offset_pct": 40,
            "duration_pct": 15,
            "periodicity": 10,
            # v5.1.20 — escalating to Global Admin is a single action.
            "max_events": 1,
            "field_overrides": {
                "activityDisplayName": "Add member to role",
                "operationType": "Assign",
                "result": "success",
                "category": "RoleManagement",
                "loggedByService": "Core Directory",
                # targetResources must carry the privileged role name the rule's
                # full-text `contains` keys on; a Role-typed target both satisfies
                # the rule and reads correctly in the alert detail.
                "targetResources": [
                    {"displayName": "Global Administrator", "type": "Role"},
                ],
            },
            "target_rules": [
                {
                    "name": "Azure User Added to a Highly Privileged Built-in Role",
                    "source": "entra_id",
                    "severity": "Medium",
                    "mitre": "T1078.004",
                    "shipped_status": "Disabled",  # must be ENABLED on the tenant
                    "s1ql": (
                        "dataSource.name = 'Azure Active Directory' and "
                        "unmapped.activityDisplayName = 'Add member to role' and "
                        "unmapped.operationType = 'Assign' and "
                        "unmapped.targetResources contains 'Global Administrator' and "
                        "unmapped.initiatedBy.app.displayName != 'MS-PIM'"
                    ),
                },
            ],
        },
        {
            "phase_id": "collection",
            "mitre_tactic": "Collection",
            "mitre_technique": "T1530",
            "name": "Mass file download from SharePoint",
            "source": "m365",
            "time_offset_pct": 55,
            "duration_pct": 25,
            "periodicity": 1,
            # v5.1.27 — the shipped "Office 365 Bulk File Download" rule is a
            # HIGH-VOLUME threshold rule: a 5-file burst (v5.1.20) was below
            # threshold and fired 0 alerts (validated on att-20260628-3123).
            # Emit a dense ~60-file burst by the persona within the window so
            # the per-user volume trips the rule.
            "max_events": 60,
            "field_overrides": {
                "Operation": "FileDownloaded",
                "Workload": "SharePoint",
                "SiteUrl": "https://contoso.sharepoint.com/sites/Finance",
                "SourceFileName": "Merger-Plans-Confidential.docx",
            },
            "target_rules": [
                {
                    "name": "Office 365 Bulk File Download",
                    "source": "m365",
                    "severity": "Medium",
                    "mitre": "T1530",
                    "shipped_status": "Active",
                    "note": "High-volume threshold rule; needs a dense per-user burst (~60 files) to trip — validated insufficient at 5.",
                },
            ],
        },
        {
            "phase_id": "persistence-2",
            "mitre_tactic": "Persistence",
            "mitre_technique": "T1136.003",
            "name": "Backdoor service principal created",
            # v5.1.25 — retarget entra_id→m365. The Entra ID / Azure AD collector
            # is NOT ingested on this tenant, but the identical directory op
            # arrives via the M365 Management Activity feed (verified in the lake:
            # dataSource.name='Microsoft O365', metadata.product.name=
            # 'AzureActiveDirectory', activity_name='Add service principal.'). The
            # shipped "Office 365 Service Principal Addition" rule matches it and,
            # being a platform rule, resolves the Target Asset.
            "source": "m365",
            "time_offset_pct": 80,
            "duration_pct": 20,
            "periodicity": 10,
            # v5.1.20 — one backdoor service principal is created.
            "max_events": 1,
            "field_overrides": {
                "Operation": "Add service principal.",
                "Workload": "AzureActiveDirectory",
                "ResultStatus": "Success",
            },
            "target_rules": [
                {
                    "name": "Office 365 Service Principal Addition",
                    "source": "m365",
                    "severity": "Info",
                    "mitre": "T1136.003",
                    "shipped_status": "Disabled",  # must be ENABLED on the tenant
                    "s1ql": (
                        "dataSource.name = 'Microsoft O365' and "
                        "metadata.product.name = 'AzureActiveDirectory' and "
                        "activity_name = 'Add service principal.'"
                    ),
                },
            ],
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
            "recommended_duration": t.get("recommended_duration"),
        })
    return result


def get_template(key: str) -> dict[str, Any] | None:
    return TEMPLATES.get(key)
