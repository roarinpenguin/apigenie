"""Proofpoint TAP alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "proofpoint_tap"
VENDOR_NAME = "Proofpoint"
PRODUCT_NAME = "Proofpoint TAP"

VARIANTS = [
    {"name": "Phishing Email Detected",   "classification": "phish",    "severity": "high",     "weight": 30},
    {"name": "Spam Campaign Detected",    "classification": "spam",     "severity": "low",      "weight": 25},
    {"name": "Impostor/BEC Attempt",      "classification": "impostor", "severity": "high",     "weight": 20},
    {"name": "Malware Attachment Found",  "classification": "malware",  "severity": "critical", "weight": 25},
]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        sender = _pick_sender(ctx)
        user = ctx.pick_user() if ctx else None
        recipient = user.get("email", "employee@corp.local") if user else "employee@corp.local"
        malware = ctx.pick_malware() if ctx else None
        threat = malware.get("filename", "invoice.pdf") if malware else "invoice.pdf"

        alerts.append({
            "finding_uid": str(uuid.uuid4()),
            "title": f"[Proofpoint] {v['name']}",
            "description": f"Proofpoint TAP {v['classification']}: {v['name']}. From: {sender.get('mail_address', 'phish@evil.com')} → {recipient}.",
            "severity": v["severity"],
            "finding_types": [v["classification"], "Email Security"],
            "resources": [{"uid": recipient, "name": recipient, "type": "mailbox"}],
            "observables": [
                {"name": sender.get("mail_address", "phish@evil.com"), "type": "email"},
                {"name": recipient, "type": "email"},
                {"name": threat, "type": "file"},
            ],
            "unmapped": {
                "classification": v["classification"],
                "spamScore": random.randint(60, 100) if v["classification"] == "spam" else 0,
                "phishScore": random.randint(70, 100) if v["classification"] == "phish" else 0,
                "imposterScore": random.randint(80, 100) if v["classification"] == "impostor" else 0,
                "malwareScore": random.randint(80, 100) if v["classification"] == "malware" else 0,
                "subject": sender.get("subject", "Urgent: Action Required"),
            },
        })
    return alerts


def _pick_sender(ctx: Any) -> dict:
    if ctx:
        s = ctx.pick_mail_sender()
        if s:
            return s
    return {"mail_address": "phish@evil.com", "subject": "Urgent: Action Required"}
