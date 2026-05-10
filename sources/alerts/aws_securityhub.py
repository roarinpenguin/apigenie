"""AWS Security Hub alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "aws_securityhub"
VENDOR_NAME = "Amazon Web Services"
PRODUCT_NAME = "AWS Security Hub"

VARIANTS = [
    {"name": "RDS DB Encryption Not Enabled",    "type": "compliance", "severity": "high",   "weight": 20},
    {"name": "Security Group Open RDP",          "type": "compliance", "severity": "critical","weight": 15},
    {"name": "S3 Bucket Public Access",          "type": "compliance", "severity": "high",   "weight": 20},
    {"name": "IAM Root Account MFA Disabled",    "type": "compliance", "severity": "critical","weight": 10},
    {"name": "CloudTrail Logging Disabled",      "type": "compliance", "severity": "high",   "weight": 15},
    {"name": "GuardDuty Detection Finding",      "type": "detection",  "severity": "medium", "weight": 20},
]


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        resource_id = f"arn:aws:ec2:eu-west-1:123456789012:{uuid.uuid4().hex[:12]}"
        alerts.append({
            "finding_uid": f"arn:aws:securityhub:eu-west-1:123456789012:finding/{uuid.uuid4()}",
            "title": f"[Security Hub] {v['name']}",
            "description": f"AWS Security Hub found: {v['name']}. Resource: {resource_id}",
            "severity": v["severity"],
            "finding_types": [
                "Software and Configuration Checks/AWS Security Best Practices"
                if v["type"] == "compliance" else "Detection Finding"
            ],
            "resources": [{"uid": resource_id, "name": resource_id.split(":")[-1], "type": "AwsResource"}],
            "observables": [],
            "unmapped": {
                "AwsAccountId": "123456789012",
                "Region": "eu-west-1",
                "ComplianceStatus": "FAILED" if v["type"] == "compliance" else "N/A",
            },
        })
    return alerts
