"""Background publisher: sends Azure Platform events to Kafka (Event Hubs emulator) every N seconds."""

import json
import logging
import os
import random
import threading
import time
from datetime import datetime, timezone

from trace import REQUEST_TRACE

logger = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_stop_event = threading.Event()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "azure-platform-logs")
PUBLISH_INTERVAL = int(os.environ.get("KAFKA_PUBLISH_INTERVAL", "10"))
MESSAGES_PER_BATCH = int(os.environ.get("KAFKA_BATCH_SIZE", "5"))

_AZURE_EVENT_TEMPLATES = [
    # Administrative / Infrastructure
    {
        "category": "Administrative",
        "operationName": "Microsoft.Compute/virtualMachines/write",
        "level": "Informational",
        "resourceType": "VIRTUAL MACHINES",
    },
    {
        "category": "Security",
        "operationName": "Microsoft.Security/securityAlerts/activate/action",
        "level": "Warning",
        "resourceType": "SECURITY ALERTS",
    },
    {
        "category": "Policy",
        "operationName": "Microsoft.Authorization/policyAssignments/write",
        "level": "Informational",
        "resourceType": "POLICY ASSIGNMENTS",
    },
    {
        "category": "ServiceHealth",
        "operationName": "Microsoft.Insights/activityLogs/write",
        "level": "Informational",
        "resourceType": "ACTIVITY LOGS",
    },
    # Entra ID / Azure AD — Sign-in activity
    {
        "category": "SignInLogs",
        "operationName": "Sign-in activity",
        "level": "Informational",
        "resourceType": "SIGN-IN LOGS",
        "_entra": True,
    },
    {
        "category": "SignInLogs",
        "operationName": "Sign-in activity",
        "level": "Warning",
        "resourceType": "SIGN-IN LOGS",
        "_entra": True,
        "_risk": True,
    },
    # Entra ID — Audit / User management
    {
        "category": "AuditLogs",
        "operationName": "Add user",
        "level": "Informational",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    },
    {
        "category": "AuditLogs",
        "operationName": "Update user",
        "level": "Informational",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    },
    {
        "category": "AuditLogs",
        "operationName": "Delete user",
        "level": "Warning",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    },
    {
        "category": "AuditLogs",
        "operationName": "Add member to group",
        "level": "Informational",
        "resourceType": "GROUP MANAGEMENT",
        "_entra": True,
    },
    {
        "category": "AuditLogs",
        "operationName": "Reset user password",
        "level": "Informational",
        "resourceType": "USER MANAGEMENT",
        "_entra": True,
    },
    # Entra ID — Risky sign-ins
    {
        "category": "RiskyUsers",
        "operationName": "Risky user detected",
        "level": "Warning",
        "resourceType": "IDENTITY PROTECTION",
        "_entra": True,
        "_risk": True,
    },
    # Entra ID — App consent / service principal
    {
        "category": "AuditLogs",
        "operationName": "Consent to application",
        "level": "Informational",
        "resourceType": "APPLICATION MANAGEMENT",
        "_entra": True,
    },
    {
        "category": "AuditLogs",
        "operationName": "Add service principal",
        "level": "Informational",
        "resourceType": "SERVICE PRINCIPAL",
        "_entra": True,
    },
]


_ENTRA_USERS = [
    "jsmith@corp.onmicrosoft.com", "agarcia@corp.onmicrosoft.com",
    "mchen@corp.onmicrosoft.com", "kwilson@corp.onmicrosoft.com",
    "rbrown@corp.onmicrosoft.com", "ljohnson@corp.onmicrosoft.com",
    "tlee@corp.onmicrosoft.com", "nkowalski@corp.onmicrosoft.com",
]
_ENTRA_APPS = ["Microsoft Office 365", "Salesforce", "Slack", "AWS Console", "GitHub", "Zoom", "ServiceNow"]
_ENTRA_LOCATIONS = [
    {"city": "New York", "state": "NY", "countryOrRegion": "US"},
    {"city": "London", "countryOrRegion": "GB"},
    {"city": "Berlin", "countryOrRegion": "DE"},
    {"city": "Tokyo", "countryOrRegion": "JP"},
    {"city": "São Paulo", "countryOrRegion": "BR"},
]


def _generate_azure_event() -> dict:
    import uuid
    from datetime import UTC, datetime

    template = random.choice(_AZURE_EVENT_TEMPLATES)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    sub_id = "12345678-1234-1234-1234-123456789012"
    tenant_id = "a5a18162-7e4d-4b85-8f5b-b1e4c8d73d25"

    # Entra ID user activity events
    if template.get("_entra"):
        user = random.choice(_ENTRA_USERS)
        user_id = str(uuid.uuid4())
        location = random.choice(_ENTRA_LOCATIONS)
        is_risk = template.get("_risk", False)

        event = {
            "time": now,
            "tenantId": tenant_id,
            "category": template["category"],
            "operationName": template["operationName"],
            "operationVersion": "1.0",
            "resultType": "failure" if is_risk else random.choice(["success", "failure"]),
            "resultSignature": "None" if is_risk else "None",
            "correlationId": str(uuid.uuid4()),
            "level": template["level"],
            "callerIpAddress": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "identity": user,
            "properties": {
                "id": str(uuid.uuid4()),
                "userDisplayName": user.split("@")[0].replace(".", " ").title(),
                "userPrincipalName": user,
                "userId": user_id,
                "appId": str(uuid.uuid4()),
                "appDisplayName": random.choice(_ENTRA_APPS),
                "ipAddress": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "location": location,
                "clientAppUsed": random.choice(["Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync"]),
                "deviceDetail": {
                    "deviceId": str(uuid.uuid4()),
                    "operatingSystem": random.choice(["Windows 10", "macOS", "iOS", "Android", "Linux"]),
                    "browser": random.choice(["Chrome 130", "Safari 17", "Edge 130", "Firefox 128"]),
                    "isCompliant": random.choice([True, False]),
                    "isManaged": random.choice([True, False]),
                },
                "status": {
                    "errorCode": 50126 if is_risk else 0,
                    "failureReason": "Invalid username or password" if is_risk else None,
                },
                "resourceType": template["resourceType"],
            },
        }
        if is_risk:
            event["properties"]["riskDetail"] = random.choice([
                "unfamiliarFeatures", "anonymizedIPAddress", "impossibleTravel",
                "maliciousIPAddress", "leakedCredentials",
            ])
            event["properties"]["riskLevelDuringSignIn"] = random.choice(["low", "medium", "high"])
        return event

    # Standard Azure platform event (infra/policy/security)
    return {
        "time": now,
        "resourceId": f"/subscriptions/{sub_id}/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-{uuid.uuid4().hex[:8]}",
        "operationName": template["operationName"],
        "category": template["category"],
        "level": template["level"],
        "resultType": random.choice(["Success", "Start", "Failed"]),
        "correlationId": str(uuid.uuid4()),
        "identity": {
            "authorization": {
                "scope": f"/subscriptions/{sub_id}",
                "action": template["operationName"],
            },
            "claims": {"appid": str(uuid.uuid4()), "name": "AzurePortal"},
        },
        "properties": {
            "statusCode": random.choice(["Created", "OK", "Accepted", "BadRequest"]),
            "serviceRequestId": str(uuid.uuid4()),
            "resourceType": template["resourceType"],
        },
    }


def _publisher_loop() -> None:
    try:
        from kafka import KafkaProducer
        from kafka.admin import KafkaAdminClient, NewTopic
        from kafka.errors import TopicAlreadyExistsError

        # Create topic if it doesn't exist
        try:
            admin = KafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, request_timeout_ms=5000)
            admin.create_topics([NewTopic(name=KAFKA_TOPIC, num_partitions=1, replication_factor=1)])
            logger.info(f"[kafka] Created topic: {KAFKA_TOPIC}")
        except TopicAlreadyExistsError:
            logger.info(f"[kafka] Topic already exists: {KAFKA_TOPIC}")
        except Exception as exc:
            logger.warning(f"[kafka] Topic create warning: {exc}")

        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            request_timeout_ms=10000,
            retries=3,
        )

        logger.info(f"[kafka] Publisher started → {KAFKA_TOPIC}@{KAFKA_BOOTSTRAP_SERVERS} (interval={PUBLISH_INTERVAL}s)")

        while not _stop_event.is_set():
            t0 = time.monotonic()
            ok, err = 0, None
            try:
                for _ in range(MESSAGES_PER_BATCH):
                    event = _generate_azure_event()
                    producer.send(KAFKA_TOPIC, value=event)
                    ok += 1
                producer.flush(timeout=10)
                logger.debug(f"[kafka] Published {ok} events")
            except Exception as exc:
                err = str(exc)
                logger.warning(f"[kafka] Publish error: {exc}")
            duration_ms = int((time.monotonic() - t0) * 1000)
            REQUEST_TRACE["azure_platform"].appendleft({
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "method": "PRODUCE",
                "path": f"topic={KAFKA_TOPIC}",
                "query": "",
                "client": "apigenie-publisher",
                "status": 200 if err is None else 500,
                "duration_ms": duration_ms,
                "req_headers": {"transport": "Kafka producer", "bootstrap": KAFKA_BOOTSTRAP_SERVERS},
                "req_body": (f"produced {ok}/{MESSAGES_PER_BATCH} events" if err is None
                              else f"FAILED after {ok}/{MESSAGES_PER_BATCH}: {err}"),
            })
            _stop_event.wait(PUBLISH_INTERVAL)

        producer.close()

    except ImportError as exc:
        logger.warning(f"[kafka] kafka-python not available, publisher disabled: {exc}")
    except Exception as exc:
        logger.error(f"[kafka] Publisher crashed: {exc}")


def start() -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(target=_publisher_loop, name="kafka-publisher", daemon=True)
    _thread.start()


def stop() -> None:
    _stop_event.set()
    if _thread:
        _thread.join(timeout=5)
