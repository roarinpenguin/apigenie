"""AWS CloudTrail mock data generator."""

import random
from typing import Any

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


def _generate_event() -> dict[str, Any]:
    template = weighted_choice(_EVENT_TEMPLATES)
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

    user_name = "root" if is_root else random.choice(_IAM_USERS)
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
        "sourceIPAddress": generate_ip(),
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
    count = min(limit, 50)
    events = [_generate_event() for _ in range(count)]
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
