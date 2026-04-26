"""Background publisher: sends GCP audit log events to Pub/Sub emulator every N seconds."""

import logging
import os
from datetime import datetime, timezone

from trace import REQUEST_TRACE
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
            t0 = time.monotonic()
            ok, err = 0, None
            try:
                futures = []
                for _ in range(MESSAGES_PER_BATCH):
                    data = generate_pubsub_message(PUBSUB_PROJECT_ID)
                    future = publisher.publish(topic_path, data)
                    futures.append(future)
                for f in futures:
                    f.result(timeout=10)
                    ok += 1
                logger.debug(f"[pubsub] Published {ok} messages")
            except Exception as exc:
                err = str(exc)
                logger.warning(f"[pubsub] Publish error: {exc}")
            duration_ms = int((time.monotonic() - t0) * 1000)
            REQUEST_TRACE["gcp_audit"].appendleft({
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "method": "PUBLISH",
                "path": f"projects/{PUBSUB_PROJECT_ID}/topics/{PUBSUB_TOPIC_ID}",
                "query": "",
                "client": "apigenie-publisher",
                "status": 200 if err is None else 500,
                "duration_ms": duration_ms,
                "req_headers": {"transport": "gRPC plaintext", "endpoint": PUBSUB_EMULATOR_HOST},
                "req_body": (f"published {ok}/{MESSAGES_PER_BATCH} messages" if err is None
                              else f"FAILED after {ok}/{MESSAGES_PER_BATCH}: {err}"),
            })
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
