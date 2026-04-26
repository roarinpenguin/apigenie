"""AWS-protocol mock for SQS + S3, just enough for CloudTrail-via-S3-via-SQS collectors.

A real AWS CloudTrail collector polls an SQS queue for S3 event notifications,
then GETs the referenced S3 object (a gzipped JSON blob of CloudTrail events).
This module produces both halves:

* SQS responses in either Query API XML or JSON 1.0 protocol
* S3 GET responses with gzipped CloudTrail JSON

SigV4 signatures are accepted but NOT verified (this is a mock for collector
integration testing — the user supplies any access_key/secret_key pair).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import secrets
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

from sources.aws_cloudtrail import _generate_event  # type: ignore[attr-defined]

# Public bucket name and account list — keep stable so generated S3 keys are
# consistent across calls within a single message delivery.
BUCKET = "apigenie-cloudtrail-logs"
_ACCOUNT_IDS = ["123456789012", "210987654321", "112233445566"]
_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]


# =============================================================================
# Helpers
# =============================================================================


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _request_id() -> str:
    return secrets.token_hex(16)


def _new_s3_key(account: str, region: str, ts: datetime) -> str:
    """CloudTrail's canonical S3 layout: AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/<file>."""
    rand = secrets.token_hex(8)
    return (
        f"AWSLogs/{account}/CloudTrail/{region}/"
        f"{ts:%Y/%m/%d}/"
        f"{account}_CloudTrail_{region}_{ts:%Y%m%dT%H%MZ}_{rand}.json.gz"
    )


def _make_s3_event_notification(account: str, region: str, key: str) -> dict[str, Any]:
    """The JSON body of an SQS message when CloudTrail delivers via S3 → SNS → SQS."""
    return {
        "Records": [
            {
                "eventVersion": "2.1",
                "eventSource": "aws:s3",
                "awsRegion": region,
                "eventTime": _now().isoformat(),
                "eventName": "ObjectCreated:Put",
                "userIdentity": {"principalId": f"AWS:AIDA{secrets.token_hex(8).upper()}"},
                "requestParameters": {"sourceIPAddress": "10.0.0.1"},
                "responseElements": {
                    "x-amz-request-id": _request_id().upper()[:16],
                    "x-amz-id-2": secrets.token_urlsafe(40),
                },
                "s3": {
                    "s3SchemaVersion": "1.0",
                    "configurationId": "CloudTrailDelivery",
                    "bucket": {
                        "name": BUCKET,
                        "ownerIdentity": {"principalId": f"A{secrets.token_hex(7).upper()}"},
                        "arn": f"arn:aws:s3:::{BUCKET}",
                    },
                    "object": {
                        "key": key,
                        "size": random.randint(2_000, 50_000),
                        "eTag": secrets.token_hex(16),
                        "sequencer": secrets.token_hex(11).upper(),
                    },
                },
            }
        ]
    }


# =============================================================================
# SQS — Query API (XML) responses
# =============================================================================


_NS = 'xmlns="http://queue.amazonaws.com/doc/2012-11-05/"'


def _xml_message(body: str) -> str:
    md5 = hashlib.md5(body.encode()).hexdigest()
    receipt = secrets.token_urlsafe(80)
    msg_id = secrets.token_hex(16)
    return (
        "<Message>"
        f"<MessageId>{msg_id}</MessageId>"
        f"<ReceiptHandle>{escape(receipt)}</ReceiptHandle>"
        f"<MD5OfBody>{md5}</MD5OfBody>"
        f"<Body>{escape(body)}</Body>"
        f"<Attribute><Name>SentTimestamp</Name><Value>{int(_now().timestamp() * 1000)}</Value></Attribute>"
        "</Message>"
    )


def receive_message_xml(max_messages: int = 1) -> str:
    """Return an SQS ReceiveMessage XML response with up to N messages."""
    n = max(1, min(max_messages, 10))
    messages = []
    for _ in range(n):
        account = random.choice(_ACCOUNT_IDS)
        region = random.choice(_REGIONS)
        key = _new_s3_key(account, region, _now())
        body = json.dumps(_make_s3_event_notification(account, region, key))
        messages.append(_xml_message(body))
    return (
        '<?xml version="1.0"?>'
        f"<ReceiveMessageResponse {_NS}>"
        f"<ReceiveMessageResult>{''.join(messages)}</ReceiveMessageResult>"
        f"<ResponseMetadata><RequestId>{_request_id()}</RequestId></ResponseMetadata>"
        "</ReceiveMessageResponse>"
    )


def delete_message_xml() -> str:
    return (
        '<?xml version="1.0"?>'
        f"<DeleteMessageResponse {_NS}>"
        f"<ResponseMetadata><RequestId>{_request_id()}</RequestId></ResponseMetadata>"
        "</DeleteMessageResponse>"
    )


def delete_message_batch_xml(ids: list[str]) -> str:
    successes = "".join(f"<DeleteMessageBatchResultEntry><Id>{escape(i)}</Id></DeleteMessageBatchResultEntry>" for i in ids)
    return (
        '<?xml version="1.0"?>'
        f"<DeleteMessageBatchResponse {_NS}>"
        f"<DeleteMessageBatchResult>{successes}</DeleteMessageBatchResult>"
        f"<ResponseMetadata><RequestId>{_request_id()}</RequestId></ResponseMetadata>"
        "</DeleteMessageBatchResponse>"
    )


def get_queue_attributes_xml(queue_name: str) -> str:
    attrs = {
        "ApproximateNumberOfMessages": str(random.randint(50, 500)),
        "ApproximateNumberOfMessagesNotVisible": "0",
        "QueueArn": f"arn:aws:sqs:us-east-1:123456789012:{queue_name}",
        "VisibilityTimeout": "30",
    }
    items = "".join(
        f"<Attribute><Name>{k}</Name><Value>{escape(v)}</Value></Attribute>"
        for k, v in attrs.items()
    )
    return (
        '<?xml version="1.0"?>'
        f"<GetQueueAttributesResponse {_NS}>"
        f"<GetQueueAttributesResult>{items}</GetQueueAttributesResult>"
        f"<ResponseMetadata><RequestId>{_request_id()}</RequestId></ResponseMetadata>"
        "</GetQueueAttributesResponse>"
    )


def get_queue_url_xml(queue_name: str, host: str) -> str:
    return (
        '<?xml version="1.0"?>'
        f"<GetQueueUrlResponse {_NS}>"
        f"<GetQueueUrlResult><QueueUrl>https://{escape(host)}/aws/sqs/{escape(queue_name)}</QueueUrl></GetQueueUrlResult>"
        f"<ResponseMetadata><RequestId>{_request_id()}</RequestId></ResponseMetadata>"
        "</GetQueueUrlResponse>"
    )


# =============================================================================
# SQS — JSON 1.0 protocol responses (newer AWS SDKs)
# =============================================================================


def receive_message_json(max_messages: int = 1) -> dict[str, Any]:
    n = max(1, min(max_messages, 10))
    msgs = []
    for _ in range(n):
        account = random.choice(_ACCOUNT_IDS)
        region = random.choice(_REGIONS)
        key = _new_s3_key(account, region, _now())
        body = json.dumps(_make_s3_event_notification(account, region, key))
        msgs.append(
            {
                "MessageId": secrets.token_hex(16),
                "ReceiptHandle": secrets.token_urlsafe(80),
                "MD5OfBody": hashlib.md5(body.encode()).hexdigest(),
                "Body": body,
                "Attributes": {"SentTimestamp": str(int(_now().timestamp() * 1000))},
            }
        )
    return {"Messages": msgs}


# =============================================================================
# S3 GET — CloudTrail blob (gzipped JSON {"Records": [...]})
# =============================================================================


def cloudtrail_blob_gz(num_events: int = 25) -> bytes:
    """Generate a gzipped JSON CloudTrail log file."""
    records = [_generate_event() for _ in range(min(num_events, 100))]
    payload = json.dumps({"Records": records}).encode("utf-8")
    return gzip.compress(payload)
