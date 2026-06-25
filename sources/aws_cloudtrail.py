"""AWS CloudTrail mock data generator.

Event catalog grounded in the CloudTrail event taxonomy
(``docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html``).
The six templates capture the SecOps-relevant slice: normal API calls,
unauthorized-access denials, privilege escalation, S3 data exfil, root
account usage, console login without MFA. ``EVENT_CATALOG`` ids align 1:1
with ``_EVENT_TEMPLATES`` keys — the catalog-coverage test fails on drift.
"""

import random
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    generate_email,
    generate_ip,
    generate_uuid,
    now_iso,
    weighted_choice,
)

_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "us-east-2"]
_ACCOUNT_IDS = ["123456789012", "210987654321", "112233445566"]
_IAM_USERS = ["john.doe", "jane.smith", "svc-terraform", "svc-deploy", "admin"]
_EVENT_SOURCES = [
    ("ec2.amazonaws.com", ["RunInstances", "TerminateInstances", "DescribeInstances", "StopInstances"]),
    ("s3.amazonaws.com", ["GetObject", "PutObject", "DeleteObject", "ListBuckets", "CreateBucket"]),
    ("iam.amazonaws.com", ["CreateUser", "DeleteUser", "AttachRolePolicy", "CreateAccessKey", "GetUser"]),
    ("sts.amazonaws.com", ["AssumeRole", "GetCallerIdentity", "AssumeRoleWithWebIdentity"]),
    ("lambda.amazonaws.com", ["CreateFunction", "InvokeFunction", "DeleteFunction", "UpdateFunctionCode"]),
    ("rds.amazonaws.com", ["CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance"]),
]

# ── Event catalog ──────────────────────────────────────────────────────
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "normal", "label": "Normal API call (no error)",
     "default_weight": 0.65,
     "docs_anchor": "docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html"},
    {"id": "unauthorized_access", "label": "Unauthorized access (AccessDenied)",
     "default_weight": 0.12,
     "docs_anchor": "docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html"},
    {"id": "privilege_escalation", "label": "Privilege escalation (AttachRolePolicy)",
     "default_weight": 0.10,
     "docs_anchor": "docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html"},
    {"id": "s3_data_exfil", "label": "S3 data exfiltration (GetObject)",
     "default_weight": 0.08,
     "docs_anchor": "docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html"},
    {"id": "root_account_usage", "label": "Root account usage",
     "default_weight": 0.03,
     "docs_anchor": "docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"},
    {"id": "console_login_no_mfa", "label": "Console login without MFA",
     "default_weight": 0.02,
     "docs_anchor": "docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html"},
]

# ── Persona projection ────────────────────────────────────────────────
# CloudTrail's principal lives on ``userIdentity.userName`` (the IAM
# username) and the request origin on ``sourceIPAddress``. We pin
# the victim user via the IAM username (not the full ARN, which
# carries the account id) and the attacker via sourceIPAddress so
# privilege-escalation phases echo Okta's compromised credential
# story end-to-end. NB: root-account events override userName to
# 'root' in code; the projection still writes — that's fine because
# the root template explicitly opts out via ``_isRoot``.
PERSONA_PROJECTION: dict[str, str] = {
    "userIdentity.userName":  "victim_user.username",
    "sourceIPAddress":         "attacker.ip",
}


_EVENT_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "normal": ({"errorCode": None, "errorMessage": None}, 0.65),
    "unauthorized_access": (
        {"errorCode": "AccessDenied", "errorMessage": "User is not authorized to perform this action"},
        0.12,
    ),
    "privilege_escalation": (
        {"errorCode": None, "errorMessage": None, "_intent": "AttachRolePolicy"},
        0.10,
    ),
    "s3_data_exfil": (
        {"errorCode": None, "errorMessage": None, "_intent": "GetObject"},
        0.08,
    ),
    "root_account_usage": ({"errorCode": None, "errorMessage": None, "_isRoot": True}, 0.03),
    "console_login_no_mfa": (
        {"errorCode": None, "errorMessage": None, "_noMFA": True},
        0.02,
    ),
}


def _generate_event(ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    template = weighted_choice(event_mix.apply(_EVENT_TEMPLATES, "aws_cloudtrail"))
    region = random.choice(_REGIONS)
    account_id = random.choice(_ACCOUNT_IDS)
    source, actions = random.choice(_EVENT_SOURCES)

    # Override action for specific intents
    if template.get("_intent"):
        action = template["_intent"]
    else:
        action = random.choice(actions)

    is_root = template.get("_isRoot", False)
    no_mfa = template.get("_noMFA", False)

    pu = ctx.pick_user() if ctx and not is_root else None
    user_name = "root" if is_root else (pu.get("username", random.choice(_IAM_USERS)) if pu else random.choice(_IAM_USERS))
    source_ip = pu.get("workstation_ip") if pu else None
    user_arn = f"arn:aws:iam::{account_id}:{'root' if is_root else f'user/{user_name}'}"

    user_identity: dict[str, Any] = {
        "type": "Root" if is_root else "IAMUser",
        "principalId": account_id if is_root else f"AIDA{generate_uuid()[:16].upper()}",
        "arn": user_arn,
        "accountId": account_id,
        "accessKeyId": f"AKIA{generate_uuid()[:16].upper()}",
        "userName": user_name,
    }
    if not is_root:
        user_identity["sessionContext"] = {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "mfaAuthenticated": "false" if no_mfa else random.choice(["true", "false"]),
                "creationDate": now_iso(),
            },
        }

    return {
        "eventVersion": "1.09",
        "userIdentity": user_identity,
        "eventTime": now_iso(),
        "eventSource": source,
        "eventName": action,
        "awsRegion": region,
        "sourceIPAddress": source_ip or generate_ip(),
        "userAgent": random.choice(
            [
                "aws-cli/2.13.0 Python/3.11.4",
                "Boto3/1.34.0 Python/3.11.4",
                "console.amazonaws.com",
                "Terraform/1.6.0",
            ]
        ),
        "requestParameters": {"region": region},
        "responseElements": None if template["errorCode"] else {"requestId": generate_uuid()},
        "requestID": generate_uuid(),
        "eventID": generate_uuid(),
        "readOnly": action.startswith(("Describe", "Get", "List")),
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": account_id,
        "eventCategory": "Management",
        "errorCode": template.get("errorCode"),
        "errorMessage": template.get("errorMessage"),
    }


def get_events_response(limit: int = 50) -> dict[str, Any]:
    ctx = profiles.get_context("aws_cloudtrail")
    count = profiles.scale_count("aws_cloudtrail", min(limit, 50))
    events = [_generate_event(ctx) for _ in range(count)]
    events = detection_rules.inject_detection_events("aws_cloudtrail", events)
    events.sort(key=lambda x: x["eventTime"], reverse=True)
    return {
        "Events": [
            {
                "EventId": e["eventID"],
                "EventName": e["eventName"],
                "ReadOnly": str(e["readOnly"]).lower(),
                "AccessKeyId": e["userIdentity"].get("accessKeyId", ""),
                "EventTime": e["eventTime"],
                "EventSource": e["eventSource"],
                "Username": e["userIdentity"].get("userName", ""),
                "Resources": [],
                "CloudTrailEvent": str(e),
            }
            for e in events
        ],
        "NextToken": None,
    }
