"""Barracuda Email Security Gateway log generator — spam, virus, policy, audit.

Matches Barracuda ESG syslog/JSON format.
Covers: inbound/outbound email, spam filtering, virus scanning,
DLP, encryption, admin audit, ATP (Advanced Threat Protection).
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_DEVICE_NAMES = ["barracuda-esmg-01", "barracuda-esmg-02"]
_DOMAINS = ["corp.com", "example.com", "partner.org", "vendor.net"]
_USERS = ["jsmith", "agarcia", "mwilson", "lchen", "admin", "ceo", "cfo"]
_EXT_SENDERS = ["newsletter@marketing.com", "invoice@supplier.biz", "alert@bank-secure.com",
                "support@microsoft-update.xyz", "hr@phishing-site.org", "admin@legit-vendor.com",
                "noreply@service.com", "billing@cloud-provider.net"]
_SUBJECTS = [
    "Invoice #12345 - Payment Due", "Your Account Has Been Compromised",
    "Quarterly Report Q2 2026", "Meeting Tomorrow at 3pm",
    "Password Reset Required", "Urgent: Wire Transfer Request",
    "Document Shared: Q3 Budget.xlsx", "RE: Project Update",
    "Action Required: Verify Your Identity", "Delivery Notification",
    "Security Alert: Unusual Sign-in", "Free Gift Card Winner!",
]
_VIRUS_NAMES = ["Trojan.Generic", "W32/Phish.A", "HTML/Phishing.Agent", "JS/Downloader",
                "Win32/Emotet", "Macro/TrickBot", "PDF/Exploit.CVE"]
_ACTIONS = ["Allowed", "Blocked", "Quarantined", "Tagged", "Encrypted", "Redirected"]
_REASONS = ["Clean", "Spam", "Virus", "Policy", "DLP", "ATP Sandbox", "Rate Limited",
            "Spoofed Sender", "Blacklisted Domain", "SPF Fail", "DKIM Fail", "DMARC Fail"]

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z"

def _email_event(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    pms = ctx.pick_mail_sender() if ctx else None
    recipient = pu.get("email", f"{random.choice(_USERS)}@{random.choice(_DOMAINS)}") if pu else f"{random.choice(_USERS)}@{random.choice(_DOMAINS)}"
    sender = pms.get("mail_address", random.choice(_EXT_SENDERS)) if pms else random.choice(_EXT_SENDERS)
    subject = pms.get("subject", random.choice(_SUBJECTS)) if pms else random.choice(_SUBJECTS)
    reason = random.choices(_REASONS, weights=[40, 20, 8, 8, 5, 5, 3, 3, 3, 2, 2, 1])[0]
    if reason == "Clean":
        action = "Allowed"
        score = random.uniform(0, 3)
    elif reason in ["Spam", "Spoofed Sender", "Blacklisted Domain", "SPF Fail", "DKIM Fail", "DMARC Fail"]:
        action = random.choice(["Blocked", "Quarantined", "Tagged"])
        score = random.uniform(5, 10)
    elif reason in ["Virus", "ATP Sandbox"]:
        action = "Blocked"
        score = random.uniform(8, 10)
    else:
        action = random.choice(["Blocked", "Quarantined"])
        score = random.uniform(4, 8)

    return {
        "type": "email", "subtype": "inbound",
        "timestamp": _now(), "device_name": random.choice(_DEVICE_NAMES),
        "message_id": f"<{generate_uuid()}@{sender.split('@')[1]}>",
        "sender": sender, "recipient": recipient,
        "subject": subject,
        "action": action, "reason": reason,
        "spam_score": round(score, 1),
        "virus_name": random.choice(_VIRUS_NAMES) if reason == "Virus" else "",
        "attachment": pms.get("attachment_filename", "") if pms else (random.choice(["invoice.pdf", "report.docx", "payment.xlsx", ""]) if random.random() < 0.3 else ""),
        "attachment_size": random.randint(1024, 10485760) if random.random() < 0.3 else 0,
        "src_ip": generate_ip(),
        "encryption": random.choice(["TLS 1.3", "TLS 1.2", "None"]),
        "spf_result": random.choice(["pass", "fail", "softfail", "neutral", "none"]),
        "dkim_result": random.choice(["pass", "fail", "none"]),
        "dmarc_result": random.choice(["pass", "fail", "none"]),
        "severity": "critical" if reason in ["Virus", "ATP Sandbox"] else "high" if reason == "Spam" else "informational",
        "vendor": "Barracuda", "product": "Email Security Gateway",
    }

def _atp_event(ctx=None) -> dict[str, Any]:
    pmal = ctx.pick_malware() if ctx else None
    filename = pmal.get("filename", random.choice(["malware.exe", "trojan.dll", "payload.ps1"])) if pmal else random.choice(["suspicious.exe", "document.pdf", "macro.xlsm"])
    return {
        "type": "atp", "subtype": "sandbox",
        "timestamp": _now(), "device_name": random.choice(_DEVICE_NAMES),
        "filename": filename,
        "file_hash": pmal.get("hash", generate_uuid().replace("-", "") * 2) if pmal else generate_uuid().replace("-", "") * 2,
        "verdict": random.choice(["malicious", "suspicious", "clean", "malicious"]),
        "analysis_time": random.randint(30, 300),
        "sandbox_score": random.randint(1, 100),
        "action": random.choice(["Blocked", "Quarantined"]),
        "severity": "critical",
        "vendor": "Barracuda", "product": "Email Security Gateway",
    }

def _audit_event(ctx=None) -> dict[str, Any]:
    return {
        "type": "audit", "subtype": "admin",
        "timestamp": _now(), "device_name": random.choice(_DEVICE_NAMES),
        "admin_user": random.choice(["admin", "security-admin"]),
        "admin_ip": generate_ip(),
        "action": random.choice(["login", "logout", "policy-update", "quarantine-release",
                                  "whitelist-add", "blacklist-add", "config-change"]),
        "detail": random.choice(["Updated spam policy", "Released quarantined message",
                                  "Added sender to whitelist", "Configuration backup created"]),
        "severity": "informational",
        "vendor": "Barracuda", "product": "Email Security Gateway",
    }

_GENERATORS = [(_email_event, 65), (_atp_event, 15), (_audit_event, 20)]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
