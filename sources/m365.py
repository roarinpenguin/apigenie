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
import profiles
from generators import (
    generate_email,
    generate_ip,
    generate_hostname,
    generate_uuid,
    now_iso,
)


def _wchoice(items: list[tuple[str, int]]) -> str:
    """Weighted choice from a list of (value, weight) tuples."""
    vals = [v for v, _ in items]
    weights = [w for _, w in items]
    return random.choices(vals, weights=weights, k=1)[0]

_TENANT_IDS = ["contoso.onmicrosoft.com", "72f988bf-86f1-41af-91ab-2d7cd011db47"]
_USERS = ["jsmith@contoso.com", "agarcia@contoso.com", "mwilson@contoso.com",
           "lchen@contoso.com", "admin@contoso.com", "ceo@contoso.com",
           "hr-manager@contoso.com", "finance@contoso.com"]
_EXTERNAL_USERS = ["partner@vendor.com", "guest@external.org", "contractor@thirdparty.net"]
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
    loc = random.choice(_IP_LOCATIONS)
    return {
        "Id": generate_uuid(),
        "RecordType": random.randint(1, 100),
        "CreationTime": _now(),
        "Operation": operation,
        "OrganizationId": random.choice(_TENANT_IDS),
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
    site = random.choice(_SITES)
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

_EVENT_GENERATORS = [
    (_mailbox_audit,      16),
    (_email_threat,       10),
    (_dlp_violation,       5),
    (_ediscovery,          4),
    (_admin_exchange,      7),
    (_sharepoint,         16),
    (_teams,               9),
    (_oauth_consent,       5),
    (_inbox_rules,         5),
    (_power_platform,      3),
    (_pim,                 4),
    (_audit_log_search,    3),
    (_quarantine,          3),
    (_user_login,         10),
]

_GENERATORS = [g for g, _ in _EVENT_GENERATORS]
_WEIGHTS = [w for _, w in _EVENT_GENERATORS]


# ── Public API ──────────────────────────────────────────────────────────────

def get_content_response(content_type: str = "Audit.General", limit: int = 50) -> dict[str, Any]:
    """Return M365 Management Activity API content blobs."""
    ctx = profiles.get_context("m365")
    count = profiles.scale_count("m365", min(limit, 100))

    events = [random.choices(_GENERATORS, weights=_WEIGHTS, k=1)[0](ctx=ctx) for _ in range(count)]
    events = detection_rules.inject_detection_events("m365", events)

    # Wrap in content blob format (like the real API returns content URIs)
    blobs = []
    for ev in events:
        blobs.append({
            "contentUri": f"https://manage.office.com/api/v1.0/{random.choice(_TENANT_IDS)}/activity/feed/audit/{generate_uuid()}",
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
