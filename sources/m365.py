"""Microsoft 365 Management Activity API mock data generator.

13 event categories covering the full M365 security audit surface:
1. Mailbox audit (BEC, data access)
2. Email threat protection (Defender for O365)
3. DLP violations
4. eDiscovery / Compliance
5. Admin operations (Exchange Online)
6. SharePoint / OneDrive file activity
7. Teams activity
8. OAuth / app consent grants
9. Inbox rules / mail forwarding
10. Power Platform
11. Privileged Identity Management
12. Unified Audit Log search
13. Quarantine actions

Endpoints mirror the O365 Management Activity API:
  POST /api/v1.0/{tenant}/activity/feed/subscriptions/start
  GET  /api/v1.0/{tenant}/activity/feed/subscriptions/content
"""

from __future__ import annotations

import random
from datetime import datetime, timezone, timedelta
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    generate_email,
    generate_ip,
    generate_hostname,
    generate_uuid,
    now_iso,
    weighted_choice,
)


# ── Persona projection ────────────────────────────────────────────────
# Every M365 audit record built by ``_base`` carries ``UserId`` (UPN
# of the actor), ``ClientIP`` (where the actor connected from), and
# ``ActorIpAddress`` (alias for ClientIP). Mailbox / threat / DLP
# variants add their own fields; we project the cross-record set so
# every workload looks consistent without having to override one
# projection per Operation type.
PERSONA_PROJECTION: dict[str, str] = {
    # The actor on an audit record is the victim — the compromised
    # mailbox / SharePoint user whose credentials are abused.
    "UserId":          "victim_user.upn",
    "MailboxOwnerUPN": "victim_user.upn",
    # The IP carried on the audit record is the attacker's exit node
    # (the credential is being used from external infrastructure).
    "ClientIP":        "attacker.ip",
    "ActorIpAddress":  "attacker.ip",
    # Phish/threat variants — sender is the attacker, recipient the victim.
    "SenderAddress":    "attacker.email",
    "RecipientAddress": "victim_user.email",
}


def _wchoice(items: list[tuple[str, int]]) -> str:
    """Weighted choice from a list of (value, weight) tuples."""
    vals = [v for v, _ in items]
    weights = [w for _, w in items]
    return random.choices(vals, weights=weights, k=1)[0]

_TENANT_IDS = ["contoso.onmicrosoft.com", "72f988bf-86f1-41af-91ab-2d7cd011db47"]
_USERS = ["jsmith@contoso.com", "agarcia@contoso.com", "mwilson@contoso.com",
           "lchen@contoso.com", "admin@contoso.com", "ceo@contoso.com",
           "hr-manager@contoso.com", "finance@contoso.com",
           "riker@starfleet.com", "data@starfleet.com",
           "ops@acme-corp.com", "analyst@roarinpenguin.com"]
_EXTERNAL_USERS = ["partner@vendor.com", "guest@external.org", "contractor@thirdparty.net"]

def _domain_from_user(email: str) -> str:
    """Extract domain from email, e.g. 'jsmith@contoso.com' -> 'contoso.com'."""
    return email.split("@", 1)[1] if "@" in email else "contoso.com"

def _org_id_for_domain(domain: str) -> str:
    """Return a tenant/org ID derived from domain (deterministic per domain)."""
    import hashlib
    h = hashlib.md5(domain.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def _sharepoint_url(domain: str, site: str = "General") -> str:
    """Generate a SharePoint URL for the given domain."""
    org = domain.split(".")[0]
    return f"https://{org}.sharepoint.com/sites/{site}"
_APPS = ["Microsoft Teams", "SharePoint Online", "Exchange Online", "OneDrive for Business",
         "Power Automate", "Power Apps", "Microsoft Forms", "Planner",
         "Dynamics 365", "Azure Portal"]
_IP_LOCATIONS = [
    {"city": "New York", "country": "US"}, {"city": "London", "country": "GB"},
    {"city": "Tokyo", "country": "JP"}, {"city": "Berlin", "country": "DE"},
    {"city": "Sydney", "country": "AU"}, {"city": "Unknown", "country": ""},
]
_SITES = ["https://contoso.sharepoint.com/sites/Engineering",
          "https://contoso.sharepoint.com/sites/Finance",
          "https://contoso.sharepoint.com/sites/HR",
          "https://contoso.sharepoint.com/sites/Legal",
          "https://contoso-my.sharepoint.com/personal/jsmith_contoso_com"]
_FILE_NAMES = ["Q3-Budget-2026.xlsx", "Employee-List.csv", "Merger-Plans.docx",
               "Credentials.txt", "passwords.xlsx", "Customer-Data.xlsx",
               "Contract-Draft.pdf", "Architecture-Diagram.vsdx", "Payroll.xlsx",
               "Board-Presentation.pptx", "API-Keys.json", "SSH-Keys.zip"]
_DLP_POLICIES = ["PCI-DSS Credit Card Detection", "SSN Detection", "HIPAA PHI Detection",
                 "Financial Data Protection", "Custom Sensitive Keywords"]
_SENSITIVE_TYPES = ["Credit Card Number", "U.S. Social Security Number (SSN)",
                    "International Banking Account Number (IBAN)",
                    "Azure Storage Account Key", "AWS Access Key"]
_TRANSPORT_RULES = ["Block External Forwarding", "Encrypt Confidential", "Disclaimer Footer",
                    "Block Executable Attachments", "Redirect to Compliance"]
_PHISH_VERDICTS = ["Phish", "High confidence phish", "Spam", "Malware", "Good"]
_QUARANTINE_REASONS = ["Phish", "High confidence phish", "Malware", "Spam", "Bulk"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"

def _recent() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 600))).isoformat(timespec="milliseconds") + "Z"

def _user(ctx=None) -> str:
    pu = ctx.pick_user() if ctx else None
    return pu.get("email", random.choice(_USERS)) if pu else random.choice(_USERS)

def _base(operation: str, workload: str, ctx=None) -> dict[str, Any]:
    user = _user(ctx)
    domain = _domain_from_user(user)
    loc = random.choice(_IP_LOCATIONS)
    return {
        "Id": generate_uuid(),
        "RecordType": random.randint(1, 100),
        "CreationTime": _now(),
        "Operation": operation,
        "OrganizationId": _org_id_for_domain(domain),
        "UserType": random.choice([0, 2, 3, 4, 5]),
        "UserKey": generate_uuid(),
        "Workload": workload,
        "ResultStatus": random.choice(["Succeeded", "Succeeded", "Succeeded", "PartiallySucceeded", "Failed"]),
        "ObjectId": "",
        "UserId": user,
        "ClientIP": generate_ip(),
        "Scope": "Online",
        "ActorIpAddress": generate_ip(),
        "City": loc["city"],
        "CountryCode": loc["country"],
        "_domain": domain,
    }


# ── 1. Mailbox audit ────────────────────────────────────────────────────────

def _mailbox_audit(ctx=None) -> dict[str, Any]:
    ops = [
        ("MailItemsAccessed", 35), ("Send", 20), ("MoveToDeletedItems", 10),
        ("HardDelete", 5), ("MailboxLogin", 15), ("SearchQueryInitiated", 8),
        ("UpdateInboxRules", 4), ("SendAs", 3),
    ]
    op = _wchoice(ops)
    e = _base(op, "Exchange", ctx)
    e["LogonType"] = random.choice([0, 1, 2])
    e["MailboxOwnerUPN"] = _user(ctx)
    e["Item"] = {"Id": generate_uuid(), "Subject": random.choice([
        "RE: Invoice #12345", "Project Update", "Confidential: Merger Plans",
        "Password Reset", "Wire Transfer Request", "Meeting Notes",
    ])} if op in ("MailItemsAccessed", "Send", "MoveToDeletedItems", "HardDelete") else {}
    e["ClientInfoString"] = random.choice(["Client=OWA", "Client=Outlook", "Client=ActiveSync",
                                            "Client=IMAP4", "Client=POP3", "Client=REST"])
    e["ExternalAccess"] = random.random() < 0.05
    e["severity"] = "medium" if op in ("HardDelete", "SendAs", "UpdateInboxRules") else "informational"
    return e


# ── 2. Email threat protection ──────────────────────────────────────────────

def _email_threat(ctx=None) -> dict[str, Any]:
    pms = ctx.pick_mail_sender() if ctx else None
    sender = pms.get("mail_address", random.choice(_EXTERNAL_USERS)) if pms else random.choice(_EXTERNAL_USERS)
    verdict = random.choices(_PHISH_VERDICTS, weights=[15, 10, 25, 10, 40])[0]
    e = _base("TIMailData", "ThreatIntelligence", ctx)
    e["SenderAddress"] = sender
    e["RecipientAddress"] = _user(ctx)
    e["Subject"] = pms.get("subject", random.choice(["Urgent Action Required", "Invoice Attached",
        "Your Account Has Been Locked", "Delivery Failed", "Shared Document"])) if pms else random.choice(["Urgent Action Required", "Invoice Attached", "Document Shared"])
    e["Verdict"] = verdict
    e["DeliveryAction"] = "Blocked" if verdict in ("Phish", "High confidence phish", "Malware") else "Delivered"
    e["AttachmentData"] = [{"FileName": pms.get("attachment_filename", "payload.exe") if pms else random.choice(["invoice.pdf", "document.xlsm", "update.exe"]),
                            "FileType": random.choice(["exe", "xlsm", "pdf", "docm", "html"]),
                            "SHA256": generate_uuid().replace("-", "") * 2,
                            "MalwareFamily": random.choice(["Emotet", "TrickBot", "QakBot", ""]) if verdict == "Malware" else ""}]
    e["PhishConfidenceLevel"] = random.randint(1, 5) if "phish" in verdict.lower() else 0
    e["ZapAction"] = random.choice(["None", "MoveToJunk", "MoveToDeletedItems", "Quarantine"]) if verdict != "Good" else "None"
    e["severity"] = "critical" if verdict in ("Malware", "High confidence phish") else "high" if verdict == "Phish" else "informational"
    return e


# ── 3. DLP violations ───────────────────────────────────────────────────────

def _dlp_violation(ctx=None) -> dict[str, Any]:
    e = _base("DlpRuleMatch", "Exchange", ctx)
    policy = random.choice(_DLP_POLICIES)
    e["PolicyName"] = policy
    e["PolicyId"] = generate_uuid()
    e["SensitiveInfoDetected"] = [{"SensitiveType": random.choice(_SENSITIVE_TYPES),
                                    "Count": random.randint(1, 50),
                                    "Confidence": random.randint(75, 100)}]
    e["Actions"] = random.choice([["NotifyUser"], ["BlockAccess"], ["NotifyUser", "GenerateIncidentReport"],
                                   ["Encrypt"], ["BlockAccess", "NotifyAdmin"]])
    e["IsOverride"] = random.random() < 0.1
    e["Justification"] = "Business justification provided" if e["IsOverride"] else ""
    e["severity"] = "high"
    return e


# ── 4. eDiscovery / Compliance ──────────────────────────────────────────────

def _ediscovery(ctx=None) -> dict[str, Any]:
    ops = [("SearchStarted", 30), ("SearchExported", 15), ("CaseCreated", 10),
           ("HoldApplied", 10), ("HoldRemoved", 5), ("CaseClosed", 5),
           ("MemberAdded", 15), ("SearchDeleted", 10)]
    op = _wchoice(ops)
    e = _base(op, "SecurityComplianceCenter", ctx)
    e["CaseName"] = random.choice(["Investigation-2026-001", "HR-Complaint-42", "Litigation-Hold-Finance",
                                     "Insider-Threat-Review", "GDPR-Subject-Request"])
    e["CaseId"] = generate_uuid()
    if "Search" in op:
        e["SearchName"] = random.choice(["All mailboxes - keyword search", "Custodian data collection",
                                          "Date range export", "Targeted user search"])
        e["SearchQuery"] = random.choice(["confidential AND merger", "password OR credential",
                                           "from:ceo@contoso.com", "has:attachment filetype:xlsx"])
    e["severity"] = "high" if op in ("SearchExported", "HoldRemoved") else "medium"
    return e


# ── 5. Admin operations (Exchange Online) ────────────────────────────────────

def _admin_exchange(ctx=None) -> dict[str, Any]:
    ops = [
        ("Set-Mailbox", 20), ("New-TransportRule", 10), ("Set-TransportRule", 10),
        ("Remove-TransportRule", 5), ("Set-OrganizationConfig", 8),
        ("Add-RoleGroupMember", 10), ("Remove-RoleGroupMember", 5),
        ("New-ManagementRoleAssignment", 8), ("Set-HostedContentFilterPolicy", 7),
        ("Set-MalwareFilterPolicy", 5), ("Set-SafeLinksPolicy", 5),
        ("Set-AntiPhishPolicy", 5), ("Disable-Mailbox", 2),
    ]
    op = _wchoice(ops)
    e = _base(op, "Exchange", ctx)
    e["Parameters"] = [{"Name": random.choice(["Identity", "ForwardingSmtpAddress", "DeliverToMailboxAndForward",
                                                 "AuditEnabled", "LitigationHoldEnabled"]),
                         "Value": random.choice(["True", "False", "external@evil.com", ""])}]
    e["ObjectId"] = random.choice(["jsmith@contoso.com", "CorpMailbox", "TransportRule-001"])
    e["severity"] = "high" if op in ("Set-Mailbox", "New-TransportRule", "Add-RoleGroupMember") else "medium"
    return e


# ── 6. SharePoint / OneDrive ────────────────────────────────────────────────

def _sharepoint(ctx=None) -> dict[str, Any]:
    ops = [
        ("FileDownloaded", 25), ("FileUploaded", 15), ("FileModified", 10),
        ("FileDeleted", 5), ("FileShared", 12), ("SharingSet", 8),
        ("AnonymousLinkCreated", 5), ("CompanyLinkCreated", 5),
        ("SiteCollectionAdminAdded", 3), ("FolderCreated", 5),
        ("ListItemUpdated", 4), ("PageViewed", 3),
    ]
    op = _wchoice(ops)
    e = _base(op, "SharePoint", ctx)
    domain = e.get("_domain", "contoso.com")
    site_name = random.choice(["Engineering", "Finance", "HR", "Legal", "General"])
    site = _sharepoint_url(domain, site_name)
    fname = random.choice(_FILE_NAMES)
    e["SiteUrl"] = site
    e["SourceRelativeUrl"] = f"Shared Documents/{random.choice(['', 'Confidential/', 'Public/', 'Archive/'])}"
    e["SourceFileName"] = fname
    e["ObjectId"] = f"{site}/{fname}"
    if "Shar" in op or "Link" in op:
        e["TargetUserOrGroupName"] = random.choice(_EXTERNAL_USERS + _USERS)
        e["SharingType"] = random.choice(["Company", "Anonymous", "Direct", "Guest"])
        e["EventData"] = f"<SharePointSharingOperation>{op}</SharePointSharingOperation>"
    e["UserAgent"] = random.choice(["OneDriveMpc/1.0", "Microsoft Office Word", "Mozilla/5.0 Chrome/124",
                                     "Microsoft SkyDriveSync", "SharePoint/16.0"])
    e["severity"] = "high" if op in ("AnonymousLinkCreated", "SiteCollectionAdminAdded", "FileShared") else "informational"
    return e


# ── 7. Teams ────────────────────────────────────────────────────────────────

def _teams(ctx=None) -> dict[str, Any]:
    ops = [
        ("MemberAdded", 15), ("MemberRemoved", 5), ("TeamCreated", 5),
        ("ChannelAdded", 8), ("ChannelDeleted", 3), ("MessageSent", 25),
        ("MessageUpdated", 5), ("MessageDeleted", 3), ("AppInstalled", 5),
        ("BotAddedToTeam", 3), ("TabAdded", 5), ("MeetingStarted", 10),
        ("GuestAccessEnabled", 3), ("FileUploaded", 5),
    ]
    op = _wchoice(ops)
    e = _base(op, "MicrosoftTeams", ctx)
    e["TeamName"] = random.choice(["Engineering", "Security Operations", "Finance", "All Company",
                                    "Project Alpha", "Incident Response"])
    e["TeamId"] = generate_uuid()
    if "Member" in op:
        e["Members"] = [{"UPN": random.choice(_USERS + _EXTERNAL_USERS), "Role": random.choice(["Member", "Owner", "Guest"])}]
    if "Channel" in op:
        e["ChannelName"] = random.choice(["General", "Random", "Alerts", "Confidential", "External"])
    if op == "AppInstalled":
        e["AppName"] = random.choice(["Trello", "Jira Cloud", "GitHub", "Polly", "Unknown App", "CustomBot"])
    e["severity"] = "high" if op in ("GuestAccessEnabled", "AppInstalled", "MemberAdded") else "informational"
    return e


# ── 8. OAuth / app consent ──────────────────────────────────────────────────

def _oauth_consent(ctx=None) -> dict[str, Any]:
    ops = [("Consent to application.", 40), ("Add OAuth2PermissionGrant.", 25),
           ("Add application.", 15), ("Add service principal.", 10),
           ("Update application.", 10)]
    op = _wchoice(ops)
    e = _base(op, "AzureActiveDirectory", ctx)
    app_names = ["MailReader Pro", "CloudBackup360", "SalesSync", "Unknown App",
                 "PhishingKit-C2", "LegitimateApp", "HR Portal", "Expense Tracker"]
    e["ApplicationName"] = random.choice(app_names)
    e["ApplicationId"] = generate_uuid()
    e["Permissions"] = random.choice([
        "Mail.Read Mail.ReadWrite",
        "Mail.Read Mail.Send User.Read Files.ReadWrite.All",
        "Directory.Read.All User.Read.All",
        "full_access_as_app",
        "User.Read offline_access",
    ])
    e["ConsentType"] = random.choice(["AdminConsent", "UserConsent", "AdminConsent"])
    e["IsAdminConsent"] = e["ConsentType"] == "AdminConsent"
    e["severity"] = "critical" if "full_access" in e["Permissions"] or "ReadWrite.All" in e["Permissions"] else "high"
    return e


# ── 9. Inbox rules / mail forwarding ────────────────────────────────────────

def _inbox_rules(ctx=None) -> dict[str, Any]:
    ops = [("New-InboxRule", 35), ("Set-InboxRule", 20), ("Remove-InboxRule", 10),
           ("Set-Mailbox", 20), ("UpdateInboxRules", 15)]
    op = _wchoice(ops)
    e = _base(op, "Exchange", ctx)
    if "InboxRule" in op:
        e["RuleName"] = random.choice(["", "Auto-Forward", "Move to RSS", "Delete Notifications",
                                        "Forward Externally", "Mark as Read"])
        e["RuleCondition"] = random.choice(["SubjectContainsWords:invoice", "From:security@",
                                             "SubjectOrBodyContainsWords:password", "HasAttachment:true", ""])
        e["RuleActions"] = random.choice(["ForwardTo:external@evil.com", "MoveToFolder:RSS Feeds",
                                           "Delete", "MarkAsRead", "ForwardAsAttachmentTo:personal@gmail.com"])
    if op == "Set-Mailbox":
        e["Parameters"] = [{"Name": "ForwardingSmtpAddress", "Value": f"smtp:{random.choice(_EXTERNAL_USERS)}"},
                           {"Name": "DeliverToMailboxAndForward", "Value": "True"}]
    e["severity"] = "critical" if "Forward" in str(e.get("RuleActions", "")) or "Forward" in str(e.get("Parameters", "")) else "medium"
    return e


# ── 10. Power Platform ─────────────────────────────────────────────────────

def _power_platform(ctx=None) -> dict[str, Any]:
    ops = [("CreateFlow", 25), ("EditFlow", 15), ("DeleteFlow", 5),
           ("ShareApp", 15), ("CreateApp", 10), ("CreateConnection", 15),
           ("DeleteConnection", 5), ("CreateEnvironment", 10)]
    op = _wchoice(ops)
    e = _base(op, "PowerPlatform", ctx)
    e["FlowName"] = random.choice(["Auto-forward emails", "Sync to Dropbox", "Alert on new file",
                                    "Export contacts daily", "Send to external API"])
    e["ConnectorNames"] = random.choice(["Office 365 Outlook", "SharePoint", "Dropbox", "HTTP",
                                          "SQL Server", "Salesforce", "Custom API"])
    e["EnvironmentName"] = random.choice(["Default", "Production", "Sandbox", "Developer"])
    e["severity"] = "high" if op in ("CreateConnection", "ShareApp") else "medium"
    return e


# ── 11. Privileged Identity Management ──────────────────────────────────────

def _pim(ctx=None) -> dict[str, Any]:
    ops = [("Activate eligible role.", 30), ("Add eligible member to role.", 15),
           ("Add member to role.", 15), ("Remove member from role.", 10),
           ("Role setting updated.", 10), ("Approve role activation.", 10),
           ("Deny role activation.", 5), ("Renew role assignment.", 5)]
    op = _wchoice(ops)
    e = _base(op, "AzureActiveDirectory", ctx)
    e["RoleName"] = random.choice(["Global Administrator", "Exchange Administrator",
                                     "Security Administrator", "User Administrator",
                                     "SharePoint Administrator", "Compliance Administrator",
                                     "Privileged Role Administrator", "Application Administrator"])
    e["TargetUser"] = _user(ctx)
    e["Justification"] = random.choice(["Emergency access needed", "Scheduled maintenance",
                                          "Incident response", "Ticket #" + str(random.randint(1000, 9999)), ""])
    e["ActivationDuration"] = random.choice(["PT1H", "PT4H", "PT8H", "P1D"])
    e["severity"] = "critical" if "Global" in e["RoleName"] or "Privileged" in e["RoleName"] else "high"
    return e


# ── 12. Unified Audit Log search ────────────────────────────────────────────

def _audit_log_search(ctx=None) -> dict[str, Any]:
    ops = [("SearchStarted", 40), ("SearchCompleted", 30), ("SearchExported", 20),
           ("SearchPurged", 10)]
    op = _wchoice(ops)
    e = _base(op, "SecurityComplianceCenter", ctx)
    e["SearchName"] = random.choice(["All activity last 30 days", "User investigation - jsmith",
                                      "Failed logins report", "Admin activity audit",
                                      "Data exfiltration check"])
    e["SearchCriteria"] = {"StartDate": _recent(), "EndDate": _now(),
                           "Operations": random.choice(["*", "FileDownloaded,FileShared", "MailboxLogin", "Set-Mailbox"])}
    e["ResultCount"] = random.randint(0, 50000)
    e["severity"] = "high" if op in ("SearchExported", "SearchPurged") else "medium"
    return e


# ── 13. Quarantine actions ──────────────────────────────────────────────────

def _quarantine(ctx=None) -> dict[str, Any]:
    ops = [("QuarantineRelease", 30), ("QuarantineDelete", 25),
           ("QuarantinePreview", 20), ("QuarantineRequestRelease", 15),
           ("QuarantineDeny", 10)]
    op = _wchoice(ops)
    e = _base(op, "Exchange", ctx)
    e["QuarantineReason"] = random.choice(_QUARANTINE_REASONS)
    e["MessageId"] = f"<{generate_uuid()}@{random.choice(['sender.com', 'phishing.org', 'marketing.biz'])}>"
    e["SenderAddress"] = random.choice(_EXTERNAL_USERS)
    e["RecipientAddress"] = _user(ctx)
    e["Subject"] = random.choice(["Urgent: Payment Required", "Account Verification",
                                    "Your parcel is waiting", "Invoice Attached", "Meeting Request"])
    e["ReleasedBy"] = _user(ctx) if "Release" in op else ""
    e["severity"] = "high" if op == "QuarantineRelease" else "medium"
    return e


# ── 14. User login / logout ──────────────────────────────────────────────────

def _user_login(ctx=None) -> dict[str, Any]:
    ops = [("UserLoggedIn", 35), ("UserLoginFailed", 15),
           ("MailboxLogin", 15), ("UserLoggedOut", 10),
           ("ForeignRealmIndexLogonInitialAuthUsingADFSFederatedToken", 5),
           ("UserAuthenticationMethod", 10), ("SessionStarted", 5),
           ("SessionEnded", 5)]
    op = _wchoice(ops)
    e = _base(op, "AzureActiveDirectory", ctx)
    success = op not in ("UserLoginFailed",)
    e["LogonType"] = random.choice([0, 1, 2])
    e["ClientApplication"] = random.choice(["Outlook", "OWA", "ActiveSync", "IMAP4", "POP3",
                                              "Microsoft Teams", "SharePoint Online", "OneDrive",
                                              "PowerShell", "Azure Portal", "Third-Party App"])
    e["Protocol"] = random.choice(["OAuth2:Authorize", "BasicAuth", "ADFS", "WS-Federation",
                                     "ROPC", "DeviceCode", "ActiveSync"])
    e["DeviceProperties"] = {
        "OS": random.choice(["Windows 11", "Windows 10", "macOS", "iOS", "Android", "Linux"]),
        "BrowserType": random.choice(["Chrome", "Edge", "Safari", "Firefox", "Outlook", ""]),
        "IsCompliant": random.choice([True, True, True, False]),
        "IsManagedDevice": random.choice([True, True, False]),
    }
    e["ErrorNumber"] = 0 if success else random.choice([
        50126, 50053, 50055, 50057, 50076, 53003, 500121, 700016,
    ])
    e["ErrorDescription"] = "" if success else random.choice([
        "Invalid username or password", "Account locked",
        "Password expired", "Account disabled",
        "MFA required but not completed", "Conditional Access policy blocked",
        "Session expired", "Application not found in tenant",
    ])
    e["IsInteractive"] = random.choice([True, True, False])
    e["TokenType"] = random.choice(["AccessToken", "RefreshToken", "IdToken"])
    loc = random.choice(_IP_LOCATIONS)
    e["GeoLocation"] = {"City": loc["city"], "Country": loc["country"],
                         "Latitude": round(random.uniform(-90, 90), 4),
                         "Longitude": round(random.uniform(-180, 180), 4)}
    e["UserAgent"] = random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1",
        "Microsoft Office/16.0", "BAV2ROPC", "CBAinPROD",
        "python-requests/2.31.0", "Outlook/16.0",
    ])
    e["ResultStatus"] = "Succeeded" if success else "Failed"
    e["severity"] = "high" if not success else "informational"
    return e


# ── Event type weights ──────────────────────────────────────────────────────

# Event-mix scope is the TOP-LEVEL category selector. An admin can disable
# or reweight whole categories (e.g. "only show me OAuth consent + PIM" for
# a privileged-access demo). The per-category inner ops dispatch (mailbox
# operations, SharePoint operations, etc.) stays hard-coded — wiring those
# too would explode the catalogue with hundreds of entries and dilute the
# demo value.
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "mailbox_audit", "label": "Mailbox audit (Exchange BEC / data access)",
     "default_weight": 0.16,
     "docs_anchor": "learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#exchange-mailbox-audit"},
    {"id": "email_threat", "label": "Email threat protection (Defender for O365)",
     "default_weight": 0.10,
     "docs_anchor": "learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#advanced-threat-protection-schema"},
    {"id": "dlp_violation", "label": "DLP rule match",
     "default_weight": 0.05,
     "docs_anchor": "learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#data-loss-prevention-dlp-schema"},
    {"id": "ediscovery", "label": "eDiscovery / Compliance search",
     "default_weight": 0.04,
     "docs_anchor": "learn.microsoft.com/en-us/microsoft-365/compliance/ediscovery"},
    {"id": "admin_exchange", "label": "Exchange Online admin operation",
     "default_weight": 0.07,
     "docs_anchor": "learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#exchange-admin-schema"},
    {"id": "sharepoint", "label": "SharePoint / OneDrive file activity",
     "default_weight": 0.16,
     "docs_anchor": "learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#sharepoint-schema"},
    {"id": "teams", "label": "Microsoft Teams activity",
     "default_weight": 0.09,
     "docs_anchor": "learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#microsoft-teams-schema"},
    {"id": "oauth_consent", "label": "OAuth / app consent grant",
     "default_weight": 0.05,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent"},
    {"id": "inbox_rules", "label": "Inbox rules / mail forwarding",
     "default_weight": 0.05,
     "docs_anchor": "learn.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/mailbox-audit-logging"},
    {"id": "power_platform", "label": "Power Platform (Flow / App / Connection)",
     "default_weight": 0.03,
     "docs_anchor": "learn.microsoft.com/en-us/power-platform/admin/logging-power-automate"},
    {"id": "pim", "label": "Privileged Identity Management (role activation)",
     "default_weight": 0.04,
     "docs_anchor": "learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure"},
    {"id": "audit_log_search", "label": "Unified Audit Log search",
     "default_weight": 0.03,
     "docs_anchor": "learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-search"},
    {"id": "quarantine", "label": "Quarantine release / delete / preview",
     "default_weight": 0.03,
     "docs_anchor": "learn.microsoft.com/en-us/microsoft-365/security/office-365-security/quarantine-about"},
    {"id": "user_login", "label": "User login / logout / session",
     "default_weight": 0.10,
     "docs_anchor": "learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#azure-active-directory-secure-token-service-sts-logon-schema"},
]

# Catalogue ids → (generator callable, default weight). The dict keys MUST
# match EVENT_CATALOG ids exactly so an admin's override binds 1:1.
_EVENT_TEMPLATES: dict[str, tuple[Any, float]] = {
    "mailbox_audit":     (_mailbox_audit,     0.16),
    "email_threat":      (_email_threat,      0.10),
    "dlp_violation":     (_dlp_violation,     0.05),
    "ediscovery":        (_ediscovery,        0.04),
    "admin_exchange":    (_admin_exchange,    0.07),
    "sharepoint":        (_sharepoint,        0.16),
    "teams":             (_teams,             0.09),
    "oauth_consent":     (_oauth_consent,     0.05),
    "inbox_rules":       (_inbox_rules,       0.05),
    "power_platform":    (_power_platform,    0.03),
    "pim":               (_pim,               0.04),
    "audit_log_search":  (_audit_log_search,  0.03),
    "quarantine":        (_quarantine,        0.03),
    "user_login":        (_user_login,        0.10),
}


# ── Public API ──────────────────────────────────────────────────────────────

def get_content_response(
    content_type: str = "Audit.General",
    limit: int = 50,
    *,
    base_url: str | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Return M365 Management Activity API content blobs.

    ``base_url`` + ``tenant_id`` (both optional) let the FastAPI route
    stamp the contentUri back at the same host + tenant the collector
    is talking to, so the follow-up
    ``GET <contentUri>`` lands on apigenie's
    ``/api/v1.0/<tenant>/activity/feed/audit/<id>`` route (which we
    serve) instead of leaking to the real ``manage.office.com``
    (which has never heard of our fake client_id / tenant and
    therefore returns HTTP 401 to the collector — the
    user-visible "m365 401" symptom).

    When either kwarg is omitted, the legacy
    ``https://manage.office.com/.../<rand>/...`` shape is preserved,
    so internal callers / unit-test snapshots that don't go through
    the HTTP layer keep their current wire form.
    """
    ctx = profiles.get_context("m365")
    count = profiles.scale_count("m365", min(limit, 100))

    templates = event_mix.apply(_EVENT_TEMPLATES, "m365")
    events = [weighted_choice(templates)(ctx=ctx) for _ in range(count)]
    events = detection_rules.inject_detection_events("m365", events)

    # Build the contentUri prefix once. The base_url is rstrip'd so a
    # caller that hands us ``"https://host/"`` doesn't produce a double
    # slash like ``https://host//api/v1.0/...``.
    if base_url and tenant_id:
        uri_prefix = (f"{base_url.rstrip('/')}/api/v1.0/{tenant_id}"
                      f"/activity/feed/audit/")
    else:
        # Legacy default — kept for backwards compat with internal
        # callers / snapshot tests. Real customer traffic always goes
        # through the FastAPI route, which now supplies both kwargs.
        uri_prefix = (f"https://manage.office.com/api/v1.0/"
                      f"{random.choice(_TENANT_IDS)}/activity/feed/audit/")

    # Wrap in content blob format (like the real API returns content URIs)
    blobs = []
    for ev in events:
        blobs.append({
            "contentUri": f"{uri_prefix}{generate_uuid()}",
            "contentId": generate_uuid(),
            "contentType": content_type,
            "contentCreated": ev.get("CreationTime", _now()),
            "contentExpiration": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(timespec="milliseconds") + "Z",
        })

    return {"blobs": blobs, "events": events}


def get_subscriptions_response() -> list[dict[str, Any]]:
    """Return active subscriptions (mimics /subscriptions/list)."""
    return [
        {"contentType": "Audit.AzureActiveDirectory", "status": "enabled", "webhook": None},
        {"contentType": "Audit.Exchange", "status": "enabled", "webhook": None},
        {"contentType": "Audit.SharePoint", "status": "enabled", "webhook": None},
        {"contentType": "Audit.General", "status": "enabled", "webhook": None},
    ]
