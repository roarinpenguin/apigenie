"""Mimecast TTP alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "mimecast"
VENDOR_NAME = "Mimecast"
PRODUCT_NAME = "Mimecast Targeted Threat Protection"

VARIANTS = [
    {"name": "TTP Attachment - Emotet",       "type": "ttp_attachment_protection", "severity": "critical", "weight": 20},
    {"name": "TTP Attachment - Macro Dropper","type": "ttp_attachment_protection", "severity": "high",     "weight": 20},
    {"name": "TTP Impersonation - CEO Fraud", "type": "ttp_impersonation_protect", "severity": "high",     "weight": 25},
    {"name": "TTP Impersonation - BEC",       "type": "ttp_impersonation_protect", "severity": "high",     "weight": 20},
    {"name": "TTP URL - Phishing Link",       "type": "ttp_url_protection",        "severity": "medium",   "weight": 15},
]

_THREAT_FAMILIES = ["Emotet", "TrickBot", "QakBot", "IcedID", "AgentTesla"]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        sender = _pick_sender(ctx)
        user = ctx.pick_user() if ctx else None
        recipient = user.get("email", "recipient@corp.local") if user else "recipient@corp.local"
        malware = ctx.pick_malware() if ctx else None
        threat = malware.get("filename", random.choice(_THREAT_FAMILIES)) if malware else random.choice(_THREAT_FAMILIES)

        alerts.append({
            "finding_uid": f"mimecast_{uuid.uuid4().hex[:16]}",
            "title": f"[Mimecast] {v['name']}",
            "description": f"Mimecast {v['type']}: {v['name']}. Sender: {sender.get('mail_address', 'attacker@evil.com')}, Recipient: {recipient}.",
            "severity": v["severity"],
            "finding_types": [v["type"], "Email Threat Protection"],
            "resources": [{"uid": recipient, "name": recipient, "type": "mailbox"}],
            "observables": [
                {"name": sender.get("mail_address", "attacker@evil.com"), "type": "email"},
                {"name": recipient, "type": "email"},
                {"name": threat, "type": "file" if "." in threat else "threat_name"},
            ],
            "unmapped": {
                "alert_type": v["type"],
                "threat_name": threat,
                "message_subject": sender.get("subject", "Urgent: Invoice Attached"),
                "sender_address": sender.get("mail_address", "attacker@evil.com"),
            },
        })
    return alerts


def _pick_sender(ctx: Any) -> dict:
    if ctx:
        s = ctx.pick_mail_sender()
        if s:
            return s
    return {"mail_address": "attacker@evil.com", "subject": "Urgent: Invoice"}
