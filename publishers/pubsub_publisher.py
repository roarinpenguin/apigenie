"""Background publisher: sends GCP audit log events to Pub/Sub emulator every N seconds."""

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_stop_event = threading.Event()

PUBSUB_EMULATOR_HOST = os.environ.get("PUBSUB_EMULATOR_HOST", "pubsub-emulator:8085")
PUBSUB_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "apigenie-project")
PUBSUB_TOPIC_ID = os.environ.get("PUBSUB_TOPIC_ID", "audit-logs")
PUBLISH_INTERVAL = int(os.environ.get("PUBSUB_PUBLISH_INTERVAL", "10"))
MESSAGES_PER_BATCH = int(os.environ.get("PUBSUB_BATCH_SIZE", "5"))


def _publisher_loop() -> None:
    # Must set env var before importing pubsub client
    os.environ["PUBSUB_EMULATOR_HOST"] = PUBSUB_EMULATOR_HOST

    try:
        from google.cloud import pubsub_v1
        from sources.gcp_audit import generate_pubsub_message

        publisher = pubsub_v1.PublisherClient()
        topic_path = publisher.topic_path(PUBSUB_PROJECT_ID, PUBSUB_TOPIC_ID)

        # Ensure topic exists
        try:
            publisher.create_topic(request={"name": topic_path})
            logger.info(f"[pubsub] Created topic: {topic_path}")
        except Exception:
            logger.info(f"[pubsub] Topic already exists: {topic_path}")

        logger.info(f"[pubsub] Publisher started → {topic_path} (interval={PUBLISH_INTERVAL}s)")

        while not _stop_event.is_set():
            try:
                futures = []
                for _ in range(MESSAGES_PER_BATCH):
                    data = generate_pubsub_message(PUBSUB_PROJECT_ID)
                    future = publisher.publish(topic_path, data)
                    futures.append(future)
                for f in futures:
                    f.result(timeout=10)
                logger.debug(f"[pubsub] Published {MESSAGES_PER_BATCH} messages")
            except Exception as exc:
                logger.warning(f"[pubsub] Publish error: {exc}")
            _stop_event.wait(PUBLISH_INTERVAL)

    except ImportError as exc:
        logger.warning(f"[pubsub] google-cloud-pubsub not available, publisher disabled: {exc}")
    except Exception as exc:
        logger.error(f"[pubsub] Publisher crashed: {exc}")


def start() -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(target=_publisher_loop, name="pubsub-publisher", daemon=True)
    _thread.start()


def stop() -> None:
    _stop_event.set()
    if _thread:
        _thread.join(timeout=5)
