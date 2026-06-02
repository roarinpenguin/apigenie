"""Mimecast Email Security Cloud Gateway — SIEM API 2.0 pull source.

Matches the real Mimecast API 2.0 SIEM endpoints:
  POST /oauth/token          — OAuth2 client credentials grant
  GET  /siem/v1/events/cg    — SIEM event stream (Cloud Gateway)

Auth: OAuth2 client_credentials → Bearer token
Pagination: mc-siem-token header (opaque cursor)

Log types (8, matching real Mimecast MTA pipeline):
  1. receipt     — MTA receives inbound/outbound/internal email
  2. process     — policies applied (spam hold, DLP, attachment scanning)
  3. delivery    — email delivered or delivery failed
  4. av          — antivirus detection (malware in attachments)
  5. spam        — spam event thread detection
  6. ttp_url     — Targeted Threat Protection URL Protect (malicious link click)
  7. ttp_attach  — TTP Attachment Protect (sandbox malware detection)
  8. ttp_imperson — TTP Impersonation Protect (BEC/spoofing detection)
"""

from __future__ import annotations

import random
import base64
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_uuid
from detection_rules import inject_detection_events
import profiles

# ── Constants ────────────────────────────────────────────────────────────────

_ACCOUNT_CODES = ["C0A0", "C1A1", "C2B2", "C46A75"]

_INTERNAL_DOMAINS = ["contoso.com", "acme-corp.com", "roarinpenguin.com"]
_EXTERNAL_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "protonmail.com",
    "partner-corp.com", "vendor-inc.com", "supplier.io",
    "phishing-site.xyz", "malware-delivery.net", "spoofed-bank.com",
]
_INTERNAL_USERS = [
    "jsmith", "agarcia", "mwilson", "lchen", "admin", "ceo",
    "cfo", "hr-team", "it-support", "soc-analyst",
]
_EXTERNAL_USERS = [
    "john.doe", "jane.smith", "info", "support", "billing",
    "noreply", "security-alert", "helpdesk", "invoice",
    "accounts-payable", "hr-notification",
]
_SUBJECTS_NORMAL = [
    "Q3 Budget Review", "Meeting Tomorrow at 10am", "Project Update",
    "RE: Invoice #4521", "Weekly Status Report", "Team Lunch Friday",
    "New Policy Document", "VPN Access Request", "RE: Onboarding Checklist",
    "Conference Room Booking", "Out of Office: John Smith",
]
_SUBJECTS_MALICIOUS = [
    "URGENT: Wire Transfer Required", "Invoice Attached for Payment",
    "Your Account Has Been Suspended", "Action Required: Password Reset",
    "Shared Document from CEO", "Bonus Payment Confirmation",
    "Tax Return Document", "Delivery Notification - Package Held",
    "Security Alert: Unusual Sign-In", "RE: Contract Amendment",
]
_VIRUS_NAMES = [
    "Trojan.GenericKD.46534871", "W97M/Downloader.AKN", "Anomali:Phishing",
    "VBA/TrojanDownloader.Agent.OQN", "Exploit.CVE-2017-11882",
    "Heur:Trojan.Script.Generic", "PDF/Phishing.Agent.BT",
    "JS/Danger.ScriptAttachment", "Emotet.AV", "QakBot.Banker",
]
_FILE_NAMES = [
    "Invoice_2024.xlsm", "Payment_Details.docx", "Contract_Amendment.pdf",
    "Shipping_Label.zip", "Resume_JohnDoe.doc", "Q4_Report.xlsx",
    "PurchaseOrder_8832.pdf", "Scan_001.pdf", "IMG_20240315.pdf.exe",
    "RFQ_Response.docm",
]
_FILE_EXTENSIONS = ["xlsm", "docx", "pdf", "zip", "doc", "xlsx", "docm", "html"]
_FILE_MIMES = [
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/pdf", "application/zip",
    "application/vnd.ms-office", "application/octet-stream",
    "text/html",
]
_URL_CATEGORIES = [
    "Phishing & Fraud", "Malware", "Blocked", "Suspicious",
    "Newly Observed Domain", "Spam",
]
_MALICIOUS_URLS = [
    "https://login-microsoft365.phishing.xyz/auth",
    "http://bgmtechnology.com.au/payload",
    "https://secure-docusign.malware-delivery.net/view",
    "http://bit.ly/3xM4lw4r3",
    "https://docs-google.spoofed-bank.com/shared",
    "http://192.168.1.100:8080/update.exe",
]
_TLS_VERSIONS = ["TLSv1.2", "TLSv1.3", "TLSv1.2", "TLSv1.3"]
_CIPHERS = [
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
]
_DIRECTIONS = ["Inbound", "Inbound", "Inbound", "Outbound", "Internal"]
_ACTIONS_RECEIPT = ["Acc", "Acc", "Acc", "Acc", "Rej"]
_ACTIONS_PROCESS = ["Acc", "Acc", "Acc", "Hld"]
_HOLD_REASONS = ["Spm", "Admin", "Content", "Sandbox", "Impersonation"]
_IMPERSONATION_DEFS = [
    "Default Impersonation Definition", "Executive Protection Policy",
    "VIP Sender Protection", "Finance Team Protection",
]
_ROUTES = ["Inbound", "Outbound", "Internal"]
_DELIVERY_ROUTES = [
    "Mimecast Exchange Route", "Primary MX Route",
    "Google Workspace Route", "Office 365 Route",
]
_REJECTION_TYPES = [
    "Invalid Recipient Address", "SPF Hard Fail",
    "DMARC Quarantine", "Blocked Sender", "Rate Limited",
]
_REJECTION_CODES = [550, 551, 553, 554, 421]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")


def _past(max_hours: int = 24) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=random.randint(1, max_hours * 3600))
    return dt.strftime("%Y-%m-%dT%H:%M:%S+0000")


def _acode() -> str:
    """Generate a Mimecast-style aCode (Base64-like 22-char ID)."""
    return base64.urlsafe_b64encode(random.randbytes(16)).decode()[:22]


def _sha256() -> str:
    return hashlib.sha256(random.randbytes(32)).hexdigest()


def _sha1() -> str:
    return hashlib.sha1(random.randbytes(20)).hexdigest()


def _md5() -> str:
    return hashlib.md5(random.randbytes(16)).hexdigest()


def _internal_email() -> str:
    return f"{random.choice(_INTERNAL_USERS)}@{random.choice(_INTERNAL_DOMAINS)}"


def _external_email() -> str:
    return f"{random.choice(_EXTERNAL_USERS)}@{random.choice(_EXTERNAL_DOMAINS)}"


def _msg_id() -> str:
    rand = "".join(random.choices("0123456789ABCDEF", k=12))
    domain = random.choice(_INTERNAL_DOMAINS + _EXTERNAL_DOMAINS)
    return f"<{rand}@{domain}>"


def _make_token(offset: int) -> str:
    return base64.b64encode(json.dumps({"offset": offset, "ts": _now()}).encode()).decode()


# ── Event generators ─────────────────────────────────────────────────────────

def _receipt_event(ctx=None) -> dict[str, Any]:
    """MTA receipt log — email received by Mimecast."""
    direction = random.choice(_DIRECTIONS)
    is_inbound = direction == "Inbound"
    sender = _external_email() if is_inbound else _internal_email()
    rcpt = _internal_email() if is_inbound else _external_email()
    if direction == "Internal":
        sender = _internal_email()
        rcpt = _internal_email()
    action = random.choices(_ACTIONS_RECEIPT, weights=[40, 25, 20, 10, 5])[0]
    spam_score = random.randint(0, 100) if action == "Acc" else 0
    ev = {
        "type": "MTA", "subtype": "receipt",
        "datetime": _past(),
        "aCode": _acode(),
        "acc": random.choice(_ACCOUNT_CODES),
        "SpamLimit": random.choice([0, 25, 50]),
        "IP": generate_ip(),
        "Dir": direction,
        "MsgId": _msg_id(),
        "Subject": random.choice(_SUBJECTS_NORMAL),
        "headerFrom": sender,
        "Sender": sender,
        "Rcpt": rcpt,
        "SpamInfo": "[]",
        "Act": action,
        "TlsVer": random.choice(_TLS_VERSIONS),
        "Cphr": random.choice(_CIPHERS),
        "SpamScore": spam_score,
        "SpamProcessingDetail": json.dumps({
            "spf": {"info": random.choice(["SPF_PASS", "SPF_FAIL", "SPF_SOFTFAIL", "SPF_NONE"]), "allow": action == "Acc"},
            "dkim": {"info": random.choice(["DKIM_PASS", "DKIM_FAIL", "DKIM_UNKNOWN"]), "allow": True},
            "dmarc": {"info": random.choice(["DMARC_PASS", "DMARC_FAIL", "DMARC_NONE"]), "allow": action == "Acc"},
        }),
    }
    if action == "Rej":
        ev["RejType"] = random.choice(_REJECTION_TYPES)
        ev["Error"] = f"Failed {ev['RejType'].lower()} verification"
        ev["RejCode"] = random.choice(_REJECTION_CODES)
        ev["RejInfo"] = ev["RejType"]
        del ev["SpamScore"]
        del ev["SpamInfo"]
    return ev


def _process_event(ctx=None) -> dict[str, Any]:
    """MTA process log — policies applied to email."""
    action = random.choices(_ACTIONS_PROCESS, weights=[50, 25, 15, 10])[0]
    att_cnt = random.choices([0, 0, 1, 2, 3], weights=[40, 20, 20, 15, 5])[0]
    att_names = random.sample(_FILE_NAMES, k=min(att_cnt, len(_FILE_NAMES))) if att_cnt else []
    att_size = sum(random.randint(1000, 500000) for _ in range(att_cnt))
    ev = {
        "type": "MTA", "subtype": "process",
        "datetime": _past(),
        "aCode": _acode(),
        "acc": random.choice(_ACCOUNT_CODES),
        "AttSize": att_size,
        "Act": action,
        "AttCnt": att_cnt,
        "AttNames": att_names if att_names else None,
        "MsgSize": random.randint(2000, 500000),
        "MsgId": _msg_id(),
    }
    if action == "Hld":
        ev["Hld"] = random.choice(_HOLD_REASONS)
        ev["IPNewDomain"] = random.random() < 0.15
        ev["IPReplyMismatch"] = random.random() < 0.05
        ev["IPInternalName"] = random.random() < 0.1
        ev["IPThreadDict"] = random.random() < 0.05
        ev["IPSimilarDomain"] = random.random() < 0.1
    return ev


def _delivery_event(ctx=None) -> dict[str, Any]:
    """MTA delivery log — email delivered or failed."""
    delivered = random.random() < 0.9
    direction = random.choice(_DIRECTIONS)
    is_inbound = direction == "Inbound"
    sender = _external_email() if is_inbound else _internal_email()
    rcpt = _internal_email() if is_inbound else _external_email()
    ev = {
        "type": "MTA", "subtype": "delivery",
        "datetime": _past(),
        "aCode": _acode(),
        "acc": random.choice(_ACCOUNT_CODES),
        "Delivered": delivered,
        "IP": generate_ip(),
        "AttCnt": random.choices([0, 1, 2], weights=[60, 30, 10])[0],
        "Dir": direction,
        "MsgId": _msg_id(),
        "Subject": random.choice(_SUBJECTS_NORMAL),
        "Latency": random.randint(200, 120000),
        "Sender": sender,
        "Rcpt": rcpt,
        "AttSize": random.randint(0, 100000),
        "Attempt": 1 if delivered else random.randint(1, 14),
        "Snt": random.randint(5000, 500000) if delivered else 0,
        "UseTls": random.choice(["Yes", "Yes", "Yes", "No"]),
    }
    if delivered:
        ev["ReceiptAck"] = f"250 2.6.0 {_msg_id()} Queued mail for delivery"
        ev["TlsVer"] = random.choice(_TLS_VERSIONS)
        ev["Cphr"] = random.choice(_CIPHERS)
        ev["Route"] = random.choice(_DELIVERY_ROUTES)
    else:
        ev["Err"] = random.choice(["Connection timed out", "Connection refused",
                                    "No answer from host", "TLS handshake failed"])
        ev["RejType"] = "Recipient server unavailable or busy"
        ev["ReceiptAck"] = None
    return ev


def _av_event(ctx=None) -> dict[str, Any]:
    """Antivirus detection log."""
    fname = random.choice(_FILE_NAMES)
    ext = fname.rsplit(".", 1)[-1] if "." in fname else "bin"
    return {
        "type": "AV", "subtype": "av",
        "datetime": _past(),
        "acc": random.choice(_ACCOUNT_CODES),
        "MimecastIP": random.random() < 0.1,
        "fileName": fname,
        "sha256": _sha256(),
        "sha1": _sha1(),
        "md5": _md5(),
        "Size": random.randint(10000, 5000000),
        "IP": generate_ip(),
        "Recipient": _internal_email(),
        "SenderDomain": random.choice(_EXTERNAL_DOMAINS),
        "fileExt": ext,
        "Subject": random.choice(_SUBJECTS_MALICIOUS),
        "MsgId": _msg_id(),
        "Sender": _external_email(),
        "Virus": random.choice(_VIRUS_NAMES),
        "SenderDomainInternal": False,
        "fileMime": random.choice(_FILE_MIMES),
        "CustomerIP": random.random() < 0.3,
        "Route": "Inbound",
    }


def _spam_event(ctx=None) -> dict[str, Any]:
    """Spam event thread log."""
    return {
        "type": "SpamEventThread", "subtype": "spam",
        "datetime": _past(),
        "aCode": _acode(),
        "acc": random.choice(_ACCOUNT_CODES),
        "Sender": _external_email(),
        "SourceIP": generate_ip(),
        "Recipient": _internal_email(),
        "SenderDomain": random.choice(_EXTERNAL_DOMAINS),
        "Subject": random.choice(_SUBJECTS_MALICIOUS),
        "MsgId": _msg_id(),
        "Route": "Inbound",
        "headerFrom": _external_email(),
    }


def _ttp_url_event(ctx=None) -> dict[str, Any]:
    """TTP URL Protect log — malicious link clicked."""
    pc2 = ctx.pick_c2() if ctx else None
    url = pc2.get("fqdn", random.choice(_MALICIOUS_URLS)) if pc2 else random.choice(_MALICIOUS_URLS)
    if not url.startswith("http"):
        url = f"https://{url}/login"
    return {
        "type": "TTPUrl", "subtype": "ttp_url",
        "datetime": _past(),
        "acc": random.choice(_ACCOUNT_CODES),
        "reason": random.choice(["malicious", "suspicious", "phishing"]),
        "url": url,
        "route": random.choice(["inbound", "internal"]),
        "sourceIp": generate_ip(),
        "sender": _external_email(),
        "recipient": _internal_email(),
        "urlCategory": random.choice(_URL_CATEGORIES),
        "senderDomain": random.choice(_EXTERNAL_DOMAINS),
        "Subject": random.choice(_SUBJECTS_MALICIOUS),
        "MsgId": _msg_id(),
        "action": random.choice(["block", "warn", "allow"]),
        "userOverride": random.random() < 0.05,
    }


def _ttp_attach_event(ctx=None) -> dict[str, Any]:
    """TTP Attachment Protect log — sandbox malware detection."""
    fname = random.choice(_FILE_NAMES)
    ext = fname.rsplit(".", 1)[-1] if "." in fname else "bin"
    return {
        "type": "TTPAttachment", "subtype": "ttp_attach",
        "datetime": _past(),
        "acc": random.choice(_ACCOUNT_CODES),
        "fileName": fname,
        "sha256": _sha256(),
        "sha1": _sha1(),
        "md5": _md5(),
        "Size": random.randint(10000, 5000000),
        "IP": generate_ip(),
        "Recipient": _internal_email(),
        "SenderDomain": random.choice(_EXTERNAL_DOMAINS),
        "fileExt": ext,
        "Sender": _external_email(),
        "fileMime": random.choice(_FILE_MIMES),
        "Route": "Inbound",
        "Subject": random.choice(_SUBJECTS_MALICIOUS),
        "MsgId": _msg_id(),
        "actionTriggered": random.choice(["safe", "malicious", "suspicious"]),
        "IsCompleted": True,
    }


def _ttp_impersonation_event(ctx=None) -> dict[str, Any]:
    """TTP Impersonation Protect log — BEC/spoofing detection."""
    return {
        "type": "TTPImpersonation", "subtype": "ttp_imperson",
        "datetime": _past(),
        "aCode": _acode(),
        "acc": random.choice(_ACCOUNT_CODES),
        "Sender": _external_email(),
        "Recipient": _internal_email(),
        "IP": generate_ip(),
        "Subject": random.choice(_SUBJECTS_MALICIOUS),
        "Definition": random.choice(_IMPERSONATION_DEFS),
        "Hits": random.randint(1, 5),
        "Action": random.choice(["Hold", "Bounce", "Tag Subject"]),
        "TaggedExternal": random.random() < 0.3,
        "TaggedMalicious": random.random() < 0.6,
        "MsgId": _msg_id(),
        "InternalName": random.random() < 0.4,
        "CustomName": random.random() < 0.1,
        "NewDomain": random.random() < 0.2,
        "SimilarInternalDomain": random.random() < 0.15,
        "SimilarCustomExternalDomain": random.random() < 0.05,
        "SimilarMimecastExternalDomain": random.random() < 0.05,
        "ReplyMismatch": random.random() < 0.1,
        "ThreatDictionary": random.random() < 0.1,
        "CustomThreatDictionary": random.random() < 0.05,
        "Route": "Inbound",
    }


# ── Generator registry ───────────────────────────────────────────────────────

_GENERATORS = [
    (_receipt_event, 30),
    (_process_event, 20),
    (_delivery_event, 25),
    (_av_event, 5),
    (_spam_event, 5),
    (_ttp_url_event, 5),
    (_ttp_attach_event, 5),
    (_ttp_impersonation_event, 5),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]


# ── Public API ───────────────────────────────────────────────────────────────

def generate_events(count: int = 20, event_type: str = "") -> list[dict[str, Any]]:
    """Generate Mimecast SIEM events.

    Args:
        count: Number of events to generate.
        event_type: Optional filter — 'receipt', 'process', 'delivery', 'av',
                    'spam', 'ttp_url', 'ttp_attach', 'ttp_imperson', or '' for all.
    """
    ctx = profiles.get_context("mimecast")
    count = profiles.scale_count("mimecast", count)
    events = []
    for _ in range(count):
        if event_type:
            gen = next((g for g, _ in _GENERATORS if g.__name__ == f"_{event_type}_event"), None)
            if gen:
                events.append(gen(ctx=ctx))
                continue
        gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
        events.append(gen(ctx=ctx))
    events = inject_detection_events("mimecast", events)
    return events


def generate_siem_response(count: int = 20, event_type: str = "",
                           token: str = "") -> dict[str, Any]:
    """Generate a full SIEM API response with pagination token."""
    events = generate_events(count=count, event_type=event_type)
    next_token = _make_token(len(events))
    return {
        "data": events,
        "meta": {
            "pagination": {
                "next": next_token if len(events) >= count else None,
                "pageSize": len(events),
            },
            "status": 200,
        },
    }


# ── TTP Impersonation Protect dedicated endpoint ────────────────────────────
# Matches POST /api/ttp/impersonation/get-logs response format exactly.
# This is a separate API from the SIEM stream, used by collectors that pull
# impersonation events directly.

_SIMILAR_DOMAINS = [
    ("contoso.com", "c0ntoso.com"), ("contoso.com", "contoso-mail.com"),
    ("acme-corp.com", "acme-c0rp.com"), ("acme-corp.com", "acmecorp.net"),
    ("roarinpenguin.com", "roarinpenguin.org"), ("starfleet.com", "starfl33t.com"),
    ("company.com", "c0mpany.com"), ("company.com", "company-secure.com"),
]
_IDENTIFIER_TYPES = [
    "internal_user_name", "similar_internal_domain", "similar_custom_domain",
    "reply_address_mismatch", "targeted_threat_dictionary", "new_domain",
]
_IMPERSONATION_ACTIONS = ["none", "hold", "bounce", "tag_subject"]


def _ttp_impersonation_log(ctx=None) -> dict[str, Any]:
    """Generate a single TTP Impersonation Protect log in the exact format
    returned by POST /api/ttp/impersonation/get-logs."""
    pu = ctx.pick_user() if ctx else None
    pms = ctx.pick_mail_sender() if ctx else None

    recipient = pu.get("email", _internal_email()) if pu else _internal_email()
    sender = pms.get("mail_address", _external_email()) if pms else _external_email()
    sender_domain = sender.split("@", 1)[1] if "@" in sender else random.choice(_EXTERNAL_DOMAINS)
    recipient_domain = recipient.split("@", 1)[1] if "@" in recipient else random.choice(_INTERNAL_DOMAINS)

    tagged_malicious = random.random() < 0.6
    tagged_external = random.random() < 0.3
    hits = random.randint(1, 5)

    # Build impersonation results — why this was flagged
    num_results = random.randint(1, 3)
    impersonation_results = []
    similar_pair = random.choice(_SIMILAR_DOMAINS)
    for _ in range(num_results):
        source_type = random.choice([
            "internal_user_name", "similar_internal_domain",
            "similar_custom_external_domain", "new_domain",
            "reply_address_mismatch", "targeted_threat_dictionary",
        ])
        impersonation_results.append({
            "checkerResult": source_type,
            "impersonationDomainSource": similar_pair[0],
            "stringSimilarToDomain": similar_pair[1],
        })

    # Identifiers — which impersonation checks matched
    identifiers = random.sample(_IDENTIFIER_TYPES, k=min(hits, len(_IDENTIFIER_TYPES)))

    return {
        "id": generate_uuid(),
        "senderAddress": sender,
        "recipientAddress": recipient,
        "subject": pms.get("subject", random.choice(_SUBJECTS_MALICIOUS)) if pms else random.choice(_SUBJECTS_MALICIOUS),
        "eventTime": _past(),
        "definition": random.choice(_IMPERSONATION_DEFS),
        "action": random.choice(_IMPERSONATION_ACTIONS),
        "hits": hits,
        "taggedMalicious": tagged_malicious,
        "taggedExternal": tagged_external,
        "senderIpAddress": generate_ip(),
        "messageId": _msg_id(),
        "identifiers": identifiers,
        "impersonationResults": impersonation_results,
    }


def generate_ttp_impersonation_response(count: int = 25,
                                         page_token: str = "") -> dict[str, Any]:
    """Generate a full /api/ttp/impersonation/get-logs response.

    Matches the exact Mimecast API response schema with impersonationLogs array,
    pagination, and proper field names.
    """
    ctx = profiles.get_context("mimecast")
    count = profiles.scale_count("mimecast", count)
    logs = [_ttp_impersonation_log(ctx=ctx) for _ in range(count)]
    logs = inject_detection_events("mimecast", logs)
    total = max(count, random.randint(count, count * 5))
    next_token = _make_token(count) if count >= 10 else None
    return {
        "fail": [],
        "meta": {
            "status": 200,
            "pagination": {
                "pageSize": count,
                "next": next_token,
                "totalCount": total,
            },
        },
        "data": [
            {
                "impersonationLogs": logs,
            }
        ],
    }


# ── API 1.0 dedicated endpoints ─────────────────────────────────────────────
# Each matches the exact response format expected by Mimecast collectors.

def generate_siem_logs_response(count: int = 25, log_type: str = "") -> dict[str, Any]:
    """POST /api/audit/get-siem-logs — MTA receipt/process/delivery logs.

    Returns events as application/json with mc-siem-token pagination.
    The SIEM log types (receipt, process, delivery) are the MTA pipeline events.
    """
    ctx = profiles.get_context("mimecast")
    count = profiles.scale_count("mimecast", count)
    mta_generators = [_receipt_event, _process_event, _delivery_event]
    mta_weights = [35, 25, 40]
    events = []
    for _ in range(count):
        if log_type:
            gen = next((g for g in mta_generators if g.__name__ == f"_{log_type}_event"), None)
            if gen:
                events.append(gen(ctx=ctx))
                continue
        gen = random.choices(mta_generators, weights=mta_weights, k=1)[0]
        events.append(gen(ctx=ctx))
    events = inject_detection_events("mimecast", events)
    return events, _make_token(count)


def _ttp_url_log(ctx=None) -> dict[str, Any]:
    """Generate a single TTP URL Protect log in the exact format
    returned by POST /api/ttp/url/get-logs."""
    pc2 = ctx.pick_c2() if ctx else None
    pms = ctx.pick_mail_sender() if ctx else None
    url = pc2.get("fqdn", random.choice(_MALICIOUS_URLS)) if pc2 else random.choice(_MALICIOUS_URLS)
    if not url.startswith("http"):
        url = f"https://{url}/login"
    sender = pms.get("mail_address", _external_email()) if pms else _external_email()
    sender_domain = sender.split("@", 1)[1] if "@" in sender else random.choice(_EXTERNAL_DOMAINS)
    return {
        "id": generate_uuid(),
        "senderAddress": sender,
        "recipientAddress": _internal_email(),
        "url": url,
        "ttpDefinition": "Default URL Protect Definition",
        "subject": pms.get("subject", random.choice(_SUBJECTS_MALICIOUS)) if pms else random.choice(_SUBJECTS_MALICIOUS),
        "action": random.choice(["block", "warn", "allow"]),
        "adminOverride": random.choice(["N/A", "N/A", "N/A", "Allow"]),
        "userOverride": random.choice(["None", "None", "None", "Allow"]),
        "scanResult": random.choice(["malicious", "suspicious", "phishing", "clean"]),
        "category": random.choice(_URL_CATEGORIES),
        "route": random.choice(["inbound", "internal"]),
        "sendingIp": generate_ip(),
        "userAwarenessAction": random.choice(["N/A", "Continue", "Block"]),
        "date": _past(),
        "messageId": _msg_id(),
    }


def generate_ttp_url_response(count: int = 25, page_token: str = "") -> dict[str, Any]:
    """POST /api/ttp/url/get-logs — TTP URL Protect click logs."""
    ctx = profiles.get_context("mimecast")
    count = profiles.scale_count("mimecast", count)
    logs = [_ttp_url_log(ctx=ctx) for _ in range(count)]
    logs = inject_detection_events("mimecast", logs)
    total = max(count, random.randint(count, count * 5))
    next_token = _make_token(count) if count >= 10 else None
    return {
        "fail": [],
        "meta": {
            "status": 200,
            "pagination": {"pageSize": count, "next": next_token, "totalCount": total},
        },
        "data": [{"clickLogs": logs}],
    }


def _ttp_attachment_log(ctx=None) -> dict[str, Any]:
    """Generate a single TTP Attachment Protect log in the exact format
    returned by POST /api/ttp/attachment/get-logs."""
    pms = ctx.pick_mail_sender() if ctx else None
    fname = random.choice(_FILE_NAMES)
    ext = fname.rsplit(".", 1)[-1] if "." in fname else "bin"
    sender = pms.get("mail_address", _external_email()) if pms else _external_email()
    return {
        "id": generate_uuid(),
        "senderAddress": sender,
        "recipientAddress": _internal_email(),
        "fileName": fname,
        "fileType": ext,
        "result": random.choice(["safe", "malicious", "timeout", "error"]),
        "actionTriggered": random.choice(["none", "hold", "bounced", "smart_folder"]),
        "date": _past(),
        "subject": pms.get("subject", random.choice(_SUBJECTS_MALICIOUS)) if pms else random.choice(_SUBJECTS_MALICIOUS),
        "fileHash": _sha256(),
        "definition": "Default Attachment Protect Definition",
        "route": "inbound",
        "messageId": _msg_id(),
        "senderIpAddress": generate_ip(),
    }


def generate_ttp_attachment_response(count: int = 25, page_token: str = "") -> dict[str, Any]:
    """POST /api/ttp/attachment/get-logs — TTP Attachment Protect sandbox logs."""
    ctx = profiles.get_context("mimecast")
    count = profiles.scale_count("mimecast", count)
    logs = [_ttp_attachment_log(ctx=ctx) for _ in range(count)]
    logs = inject_detection_events("mimecast", logs)
    total = max(count, random.randint(count, count * 5))
    next_token = _make_token(count) if count >= 10 else None
    return {
        "fail": [],
        "meta": {
            "status": 200,
            "pagination": {"pageSize": count, "next": next_token, "totalCount": total},
        },
        "data": [{"attachmentLogs": logs}],
    }


def _audit_event_log(ctx=None) -> dict[str, Any]:
    """Generate a single Mimecast admin audit event log in the exact format
    returned by POST /api/audit/get-audit-events."""
    pu = ctx.pick_user() if ctx else None
    user = pu.get("email", _internal_email()) if pu else _internal_email()
    audit_types = [
        ("Logon Authentication Passed", "Logon", 20),
        ("Logon Authentication Failed", "Logon", 5),
        ("User Logged Off", "Logon", 10),
        ("Policy Change", "Policy", 8),
        ("Search Message Tracking", "Search", 12),
        ("Impersonation Protection Policy Created", "Policy", 3),
        ("Blocked Sender Policy Updated", "Policy", 4),
        ("Content Examination Policy Updated", "Policy", 3),
        ("User Created", "User Management", 3),
        ("User Deleted", "User Management", 2),
        ("Group Member Added", "User Management", 5),
        ("Group Member Removed", "User Management", 3),
        ("TTP URL Policy Updated", "Policy", 4),
        ("Message Released from Hold Queue", "Message", 6),
        ("Admin Console Access", "Logon", 8),
        ("API Key Created", "API", 2),
        ("Two-Factor Authentication Enabled", "Security", 2),
    ]
    names = [n for n, _, _ in audit_types]
    cats = [c for _, c, _ in audit_types]
    weights = [w for _, _, w in audit_types]
    idx = random.choices(range(len(audit_types)), weights=weights, k=1)[0]
    return {
        "id": generate_uuid(),
        "auditType": names[idx],
        "user": user,
        "eventTime": _past(),
        "eventInfo": f"{names[idx]} by {user}",
        "category": cats[idx],
        "source": random.choice(["Administration Console", "API", "Email Gateway", "System"]),
        "sourceIp": generate_ip(),
    }


def generate_audit_events_response(count: int = 25, page_token: str = "") -> dict[str, Any]:
    """POST /api/audit/get-audit-events — admin audit event logs."""
    ctx = profiles.get_context("mimecast")
    count = profiles.scale_count("mimecast", count)
    logs = [_audit_event_log(ctx=ctx) for _ in range(count)]
    total = max(count, random.randint(count, count * 5))
    next_token = _make_token(count) if count >= 10 else None
    return {
        "fail": [],
        "meta": {
            "status": 200,
            "pagination": {"pageSize": count, "next": next_token, "totalCount": total},
        },
        "data": [{"auditEvents": logs}],
    }
