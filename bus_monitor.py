"""Background monitor for bus-based sources (Kafka, Pub/Sub).

Periodically polls Kafka consumer groups and Pub/Sub subscriptions to
extract client IPs of active consumers. Feeds them into the Sankey/GeoMap
aggregation (trace.AGG) and the Usage telemetry (telemetry.record) so
bus consumers appear in all Observability dashboards alongside HTTP sources.
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_stop_event = threading.Event()

POLL_INTERVAL = int(os.environ.get("BUS_MONITOR_INTERVAL", "30"))
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")


def _poll_kafka() -> list[tuple[str, str]]:
    """Return [(client_ip, consumer_group), ...] for active Kafka consumers."""
    results = []
    try:
        from kafka.admin import KafkaAdminClient
        admin = KafkaAdminClient(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            request_timeout_ms=5000,
        )
        group_ids = admin.list_consumer_groups()
        for gid, _ in group_ids[:20]:
            try:
                desc = admin.describe_consumer_groups([gid])
                if not desc:
                    continue
                group = desc[0]
                for member in group.members:
                    host = member.client_host or ""
                    # Kafka returns "/1.2.3.4" format — strip leading slash
                    host = host.lstrip("/").strip()
                    if host and host != "127.0.0.1" and not host.startswith("172."):
                        results.append((host, gid))
            except Exception:
                pass
        admin.close()
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("bus_monitor: Kafka poll error: %s", exc)
    return results


def _poll_pubsub() -> list[str]:
    """Return subscription names from the Pub/Sub emulator."""
    results = []
    try:
        import urllib.request
        import json
        emulator = os.environ.get("PUBSUB_EMULATOR_HOST", "pubsub-emulator:8085")
        url = f"http://{emulator}/v1/projects/obs-test/subscriptions"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
        results = [s.get("name", "?") for s in data.get("subscriptions", [])]
    except Exception:
        pass
    return results


def _monitor_loop() -> None:
    from trace import _agg_observe, REQUEST_TRACE
    import telemetry
    import collections

    logger.info("[bus_monitor] Started (interval=%ds)", POLL_INTERVAL)

    while not _stop_event.is_set():
        ts_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # Kafka consumers
        consumers = _poll_kafka()
        for ip, group in consumers:
            _agg_observe(ip, "azure_platform", 200, ts_iso)
            telemetry.record("azure_platform")
            # Add a synthetic trace entry so the Request Inspector shows consume activity
            REQUEST_TRACE["azure_platform"].appendleft({
                "ts": ts_iso,
                "method": "CONSUME",
                "path": f"group={group}",
                "query": "",
                "client": ip,
                "status": 200,
                "duration_ms": 0,
                "req_headers": {"transport": "Kafka SASL_SSL", "consumer_group": group},
                "req_body": "",
                "resp_size": 0,
                "resp_preview": "",
            })

        # Pub/Sub — we can't get subscriber IPs from the emulator, but we can
        # record that subscriptions exist (helps with Usage chart)
        subs = _poll_pubsub()
        for sub in subs:
            telemetry.record("gcp_audit")

        if consumers:
            logger.debug("[bus_monitor] Kafka: %d active consumers from %s",
                         len(consumers), {ip for ip, _ in consumers})

        _stop_event.wait(POLL_INTERVAL)

    logger.info("[bus_monitor] Stopped")


def start() -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(target=_monitor_loop, name="bus-monitor", daemon=True)
    _thread.start()


def stop() -> None:
    _stop_event.set()
    if _thread:
        _thread.join(timeout=5)
