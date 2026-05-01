"""Cloud audit telemetry — multi-cloud control-plane events.

Mixes AWS CloudTrail, Azure Activity Logs, and GCP Cloud Audit shapes,
union-typed in a single record (a `provider` discriminator picks the
flavour). A real Lua collector would route each provider to its own
deserialiser; for the listener feature we just need representative
records that exercise the full pipeline.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

from sources.synthetic import seeded_uuid

# (provider, event_name, weight, resource_type)
_EVENTS = [
    # AWS
    ("aws", "ConsoleLogin",      0.07, "iam"),
    ("aws", "AssumeRole",        0.10, "iam"),
    ("aws", "RunInstances",      0.05, "ec2"),
    ("aws", "TerminateInstances",0.03, "ec2"),
    ("aws", "PutBucketPolicy",   0.02, "s3"),
    ("aws", "GetObject",         0.05, "s3"),
    ("aws", "CreateUser",        0.02, "iam"),
    ("aws", "DeleteUser",        0.01, "iam"),
    # Azure
    ("azure", "Microsoft.Compute/virtualMachines/start/action", 0.04, "vm"),
    ("azure", "Microsoft.Storage/storageAccounts/listKeys/action", 0.03, "storage"),
    ("azure", "Microsoft.KeyVault/vaults/secrets/read", 0.04, "keyvault"),
    ("azure", "Microsoft.Authorization/roleAssignments/write",  0.02, "rbac"),
    ("azure", "Microsoft.Network/networkSecurityGroups/write",  0.02, "nsg"),
    # GCP
    ("gcp", "google.cloud.bigquery.v2.JobService.InsertJob", 0.05, "bigquery"),
    ("gcp", "google.iam.v1.IAMPolicy.SetIamPolicy",          0.04, "iam"),
    ("gcp", "compute.instances.insert",                       0.03, "compute"),
    ("gcp", "storage.objects.get",                            0.06, "storage"),
    ("gcp", "google.cloud.kms.v1.KeyManagementService.Decrypt",0.03,"kms"),
    # Common (generic noise)
    ("aws", "DescribeInstances",  0.10, "ec2"),
    ("azure", "Microsoft.Resources/subscriptions/resourceGroups/read", 0.08, "rg"),
    ("gcp",   "compute.instances.list",   0.11, "compute"),
]

_AWS_REGIONS  = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-2"]
_AZ_REGIONS   = ["eastus", "westeurope", "northeurope", "westus2", "uksouth", "australiaeast"]
_GCP_REGIONS  = ["us-central1", "us-east4", "europe-west1", "europe-west4", "asia-northeast1"]

_PRINCIPALS = [
    "alice.smith", "bob.jones", "charlie.davis", "diana.evans",
    "svc-deployer", "svc-pipeline", "terraform-runner", "github-actions",
]

_ERROR_CODES = [
    None, None, None, None, None, None, None, None,  # 80% no error
    "AccessDenied", "Throttling", "ResourceNotFound", "InvalidParameterValue",
]


def _weighted(rng: random.Random) -> tuple[str, str, str]:
    r = rng.random()
    cum = 0.0
    for prov, name, w, rtype in _EVENTS:
        cum += w
        if r < cum:
            return prov, name, rtype
    last = _EVENTS[-1]
    return last[0], last[1], last[3]


def _aws_record(rng: random.Random, ts: datetime, name: str, rtype: str, principal: str) -> dict:
    region = rng.choice(_AWS_REGIONS)
    err = rng.choice(_ERROR_CODES)
    return {
        "eventVersion": "1.08",
        "eventTime": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "eventSource": f"{rtype}.amazonaws.com",
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "userIdentity": {
            "type": "IAMUser",
            "userName": principal,
            "arn": f"arn:aws:iam::123456789012:user/{principal}",
            "accountId": "123456789012",
        },
        "errorCode": err,
        "requestParameters": {"resourceType": rtype},
        "responseElements": None if err else {"requestId": seeded_uuid(rng).hex},
        "requestID": seeded_uuid(rng).hex,
        "eventID": str(seeded_uuid(rng)),
    }


def _azure_record(rng: random.Random, ts: datetime, name: str, rtype: str, principal: str) -> dict:
    region = rng.choice(_AZ_REGIONS)
    err = rng.choice(_ERROR_CODES)
    return {
        "time": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "operationName": name,
        "category": "Administrative",
        "resultType": "Failure" if err else "Success",
        "resultSignature": err or "",
        "location": region,
        "identity": {
            "claims": {
                "name":  principal,
                "appid": seeded_uuid(rng).hex,
                "tid":   "00000000-0000-0000-0000-000000000001",
            }
        },
        "callerIpAddress": f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "resourceId": f"/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-{rtype}/providers/{rtype}/{seeded_uuid(rng).hex[:12]}",
        "correlationId": str(seeded_uuid(rng)),
    }


def _gcp_record(rng: random.Random, ts: datetime, name: str, rtype: str, principal: str) -> dict:
    region = rng.choice(_GCP_REGIONS)
    err = rng.choice(_ERROR_CODES)
    status: dict = {} if not err else {"code": 7, "message": err}
    return {
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": f"{rtype}.googleapis.com",
            "methodName":  name,
            "resourceName": f"projects/obs-test/{rtype}/{seeded_uuid(rng).hex[:12]}",
            "authenticationInfo": {"principalEmail": f"{principal}@acme.com"},
            "requestMetadata": {
                "callerIp": f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
                "callerSuppliedUserAgent": "google-cloud-sdk gcloud/461.0.0",
            },
            "status": status,
        },
        "insertId":  seeded_uuid(rng).hex[:20],
        "resource":  {"type": f"{rtype}_resource", "labels": {"location": region}},
        "timestamp": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "severity":  "ERROR" if err else "INFO",
        "logName":   f"projects/obs-test/logs/cloudaudit.googleapis.com%2Factivity",
    }


def generate(n: int, seed: int | None = None) -> list[dict]:
    rng = random.Random(seed) if seed is not None else random.Random()
    now = datetime.now(timezone.utc)
    out: list[dict] = []
    for _ in range(max(0, n)):
        ts = now - timedelta(seconds=rng.randint(0, 3600))
        prov, name, rtype = _weighted(rng)
        principal = rng.choice(_PRINCIPALS)
        if prov == "aws":
            rec = _aws_record(rng, ts, name, rtype, principal)
        elif prov == "azure":
            rec = _azure_record(rng, ts, name, rtype, principal)
        else:
            rec = _gcp_record(rng, ts, name, rtype, principal)
        rec["_provider"] = prov  # tag so a Lua collector can route easily
        out.append(rec)
    return out
