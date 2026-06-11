"""Background publisher: sends Azure Platform events to Kafka (Event Hubs emulator) every N seconds.

The event templates and the mix-aware per-message generator live in
``sources/azure_platform.py`` so the source can participate in the Event
Mix admin surface. This file only owns the threading + Kafka producer
wiring; payload construction is delegated to that module.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

from sources.azure_platform import generate_azure_event as _generate_azure_event
from trace import REQUEST_TRACE

logger = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_stop_event = threading.Event()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "azure-platform-logs")
PUBLISH_INTERVAL = int(os.environ.get("KAFKA_PUBLISH_INTERVAL", "10"))
MESSAGES_PER_BATCH = int(os.environ.get("KAFKA_BATCH_SIZE", "5"))


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
                events = [_generate_azure_event() for _ in range(MESSAGES_PER_BATCH)]
                try:
                    import detection_rules
                    events = detection_rules.inject_detection_events("azure_platform", events)
                except Exception:
                    pass
                for event in events:
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
