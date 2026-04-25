"""Background publisher: sends Azure Platform events to Kafka (Event Hubs emulator) every N seconds."""

import json
import logging
import os
import random
import threading
import time

logger = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_stop_event = threading.Event()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "azure-platform-logs")
PUBLISH_INTERVAL = int(os.environ.get("KAFKA_PUBLISH_INTERVAL", "10"))
MESSAGES_PER_BATCH = int(os.environ.get("KAFKA_BATCH_SIZE", "5"))

_AZURE_EVENT_TEMPLATES = [
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
]


def _generate_azure_event() -> dict:
    import uuid
    from datetime import UTC, datetime

    template = random.choice(_AZURE_EVENT_TEMPLATES)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    sub_id = "12345678-1234-1234-1234-123456789012"

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
            try:
                for _ in range(MESSAGES_PER_BATCH):
                    event = _generate_azure_event()
                    producer.send(KAFKA_TOPIC, value=event)
                producer.flush(timeout=10)
                logger.debug(f"[kafka] Published {MESSAGES_PER_BATCH} events")
            except Exception as exc:
                logger.warning(f"[kafka] Publish error: {exc}")
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
