"""Proofpoint TAP (Targeted Attack Protection) mock data generator."""

import random
from typing import Any

import detection_rules
import profiles
from generators import (
    generate_email,
    generate_ip,
    generate_uuid,
    now_iso,
    now_minus_minutes_iso,
    weighted_choice,
)

_SENDERS = ["attacker@malicious.com", "phish@scam.net", "spam@badactor.org", "noreply@legitimate-spoof.com"]
_RECIPIENTS = ["alice@example.com", "bob@company.com", "carol@corp.net", "dave@enterprise.org"]
_SUBJECTS = [
    "Urgent: Your account has been compromised",
    "Invoice #INV-2024-1234 attached",
    "Password reset required immediately",
    "Click here to claim your prize",
    "Important security update",
    "Your package could not be delivered",
]
_THREATS = [
    ("Malicious URL", "url"),
    ("Ransomware Attachment", "attachment"),
    ("Phishing Page", "url"),
    ("Malware Dropper", "attachment"),
    ("Credential Harvester", "url"),
]
_MALWARE_FAMILIES = ["Emotet", "TrickBot", "QakBot", "Dridex", "AgentTesla", "FormBook"]

_LOG_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "raw_log": (
        {"disposition": "delivered", "phishScore": 0, "spamScore": 5, "action": "delivered"},
        0.60,
    ),
    "ransomware_retro": (
        {"disposition": "quarantine", "phishScore": 90, "spamScore": 70, "action": "quarantine"},
        0.15,
    ),
    "double_wrapped_url": (
        {"disposition": "blocked", "phishScore": 95, "spamScore": 80, "action": "blocked"},
        0.10,
    ),
    "blocked_but_clicked": (
        {"disposition": "blocked", "phishScore": 85, "spamScore": 60, "action": "blocked"},
        0.08,
    ),
    "false_positive": (
        {"disposition": "delivered", "phishScore": 15, "spamScore": 20, "action": "delivered"},
        0.05,
    ),
    "polymorphic": (
        {"disposition": "quarantine", "phishScore": 99, "spamScore": 95, "action": "quarantine"},
        0.02,
    ),
}


def _generate_message(since_seconds: int = 3600, ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    template = weighted_choice(_LOG_TEMPLATES)
    threat_name, threat_type = random.choice(_THREATS)
    pms = ctx.pick_mail_sender() if ctx else None
    pmal = ctx.pick_malware() if ctx else None
    if pms:
        sender = pms.get("mail_address", random.choice(_SENDERS))
        subject_override = pms.get("subject")
    else:
        sender = random.choice(_SENDERS)
        subject_override = None
    if pmal and template.get("phishScore", 0) > 50:
        threat_name = pmal.get("filename", threat_name)
    recipient = random.choice(_RECIPIENTS)
    ts = now_minus_minutes_iso(random.randint(0, since_seconds // 60))

    threats = []
    if template["phishScore"] > 50:
        threats.append(
            {
                "classification": random.choice(["phish", "malware", "spam"]),
                "threat": threat_name,
                "threatId": generate_uuid(),
                "threatStatus": "active",
                "threatTime": ts,
                "threatType": threat_type,
                "threatUrl": f"https://threatinsight.proofpoint.com/threat/{generate_uuid()}",
            }
        )

    msg_id = f"<{generate_uuid()}@{sender.split('@')[1]}>"
    return {
        "GUID": generate_uuid(),
        "QID": f"q{generate_uuid()[:12]}",
        "ccAddresses": [],
        "clusterId": random.choice(["hosted_us", "hosted_eu", "hosted_ap"]),
        "completelyRewritten": template["action"] == "blocked",
        "fromAddress": [sender],
        "headerCC": None,
        "headerFrom": sender,
        "headerReplyTo": None,
        "headerTo": recipient,
        "impostorScore": random.randint(0, 100) if template["phishScore"] > 70 else 0,
        "malwareScore": random.randint(60, 100) if template["phishScore"] > 70 else 0,
        "messageID": msg_id,
        "messageParts": [
            {
                "contentType": "text/html",
                "disposition": "inline",
                "filename": "message.html",
                "md5": generate_uuid().replace("-", ""),
                "oContentType": "text/html",
                "sandboxStatus": "unsupported",
                "sha256": generate_uuid().replace("-", "") + generate_uuid().replace("-", ""),
            }
        ],
        "messageSize": random.randint(5000, 200000),
        "messageTime": ts,
        "modulesRun": ["spam", "pdr", "urldefense", "av", "sandbox"],
        "phishScore": template["phishScore"],
        "policyRoutes": ["default_inbound"],
        "quarantineFolder": "Phish" if template["action"] == "quarantine" else None,
        "quarantineRule": "phish" if template["action"] == "quarantine" else None,
        "recipient": [recipient],
        "replyToAddress": [],
        "sender": sender,
        "senderIP": generate_ip(),
        "spamScore": template["spamScore"],
        "subject": subject_override or random.choice(_SUBJECTS),
        "toAddresses": [recipient],
        "xmailer": None,
        "threats": threats,
    }


def get_logs_response(since_seconds: int = 3600) -> dict[str, Any]:
    ctx = profiles.get_context("proofpoint")
    count = profiles.scale_count("proofpoint", random.randint(5, 30))
    since_ts = now_minus_minutes_iso(since_seconds // 60)
    now = now_iso()

    messages = [_generate_message(since_seconds, ctx) for _ in range(count)]
    messages = detection_rules.inject_detection_events("proofpoint", messages)
    blocked = [m for m in messages if m["quarantineFolder"] or "blocked" in str(m.get("threats", ""))]

    return {
        "queryEndTime": now,
        "queryStartTime": since_ts,
        "messagesBlocked": blocked,
        "messagesDelivered": [m for m in messages if m not in blocked],
        "clicksBlocked": [],
        "clicksPermitted": [],
    }
