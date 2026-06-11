"""OTLP egress transport for the Log Push framework.

The Log Push pipeline (log_pusher.py) calls into this module when a push
profile's ``transport`` is ``otlp_http`` or ``otlp_grpc``. We take the
*structured* event dict (not the text-formatted version that JSON / syslog
/ CEF transports use), marshal it into an OpenTelemetry
``ExportLogsServiceRequest``, and ship it to the configured collector.

Why a single signal (logs)
==========================
apigenie's push sources \u2014 the 16 vendor modules, the 4 synthetic topics,
the replay-file source \u2014 are all log-shaped. Metrics and traces are
defined in the OTLP listener side (docs/OTEL_LISTENER.md \u00a72) for
completeness, but the egress path only emits logs in v4.1. The dict-to-
LogRecord adapter below is the only piece that would change if we added
metric / trace emission later.

LogRecord mapping
=================
For each push event dict ``ev``::

    LogRecord.time_unix_nano  := int(ev.timestamp \u00b7 1e9)  if present
                                 else current wall-clock time
    LogRecord.severity_text   := ev.severity \u2192 OpenTelemetry severity word
    LogRecord.severity_number := mapped from severity_text per spec
    LogRecord.body            := JSON-encoded ev (string_value)
    LogRecord.attributes      := whitelisted scalar keys (event_type,
                                 action, src_ip, dst_ip, user, hostname,
                                 process, ...). Nested dicts and lists are
                                 elided to keep the wire shape clean.

The Resource is built per-export from the source_type and optional log-
profile context, so a single collector deployment can distinguish
``apigenie / paloalto`` exports from ``apigenie / synthetic_endpoint``.
"""
from __future__ import annotations

import json
import logging
import os
import time as _time
from typing import Any

logger = logging.getLogger(__name__)

# Where the OTLP/HTTP POST goes when the destination doesn't override.
_DEFAULT_HTTP_PATH = "/v1/logs"

# Cap on attribute count per LogRecord to keep the protobuf small.
_MAX_ATTRS_PER_RECORD = 24
# Cap on attribute string value length \u2014 anything longer is truncated with
# a "..." suffix. Mirrors OTel collector exporter defaults.
_MAX_ATTR_STR = 2048
# Cap on body string length. Same rationale as above.
_MAX_BODY_STR = 16 * 1024


# ── Public entry point ──────────────────────────────────────────────────────

def send(*, transport: str, event: dict[str, Any], dest: dict[str, Any],
         profile: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one push event to an OTLP destination.

    Parameters mirror what ``log_pusher.send_event`` passes us:

    * ``transport``  \u2014 ``otlp_http`` | ``otlp_grpc``.
    * ``event``      \u2014 the structured push event dict (already detection-
                       rule-enriched).
    * ``dest``       \u2014 the profile's ``destination`` sub-dict (host, port,
                       tls, path, auth_*, plus optional OTLP-specific keys:
                       ``listener_id``, ``signal``).
    * ``profile``    \u2014 the full push profile dict, used to populate the
                       resource attributes (service.name, source_type, etc.).
    """
    signal = (dest.get("signal") or profile.get("otlp_signal")
              or "logs").lower().strip()
    if signal != "logs":
        # v4.1 only emits logs (see module docstring).
        return {
            "protocol": transport,
            "status": 0,
            "error": f"unsupported_signal: {signal!r}",
        }
    try:
        req = _build_logs_request(event=event, profile=profile)
    except Exception as exc:  # noqa: BLE001
        logger.warning("OTLP build failed: %s", exc)
        return {"protocol": transport, "status": 0,
                "error": f"build_failed: {exc}"}

    if transport == "otlp_http":
        return _send_http(req, dest, profile)
    if transport == "otlp_grpc":
        return _send_grpc(req, dest, profile)
    return {"protocol": transport, "status": 0,
            "error": f"unknown_transport: {transport}"}


# ── OTLP request builder ────────────────────────────────────────────────────

def _build_logs_request(*, event: dict[str, Any], profile: dict[str, Any]):
    """Build an ExportLogsServiceRequest with a single LogRecord."""
    # Lazy import \u2014 protobuf classes are heavy and only needed here.
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
    from opentelemetry.proto.logs.v1 import logs_pb2
    from opentelemetry.proto.common.v1 import common_pb2

    req = logs_service_pb2.ExportLogsServiceRequest()
    rl = req.resource_logs.add()

    # Resource attributes: service.name (push profile name), source_type,
    # apigenie deployment domain (if set). Keep these stable so a collector
    # can route + group exports without parsing the body.
    for k, v in _resource_attrs(profile).items():
        rl.resource.attributes.append(_kv(common_pb2, k, v))

    sl = rl.scope_logs.add()
    sl.scope.name = "apigenie/log_pusher"
    sl.scope.version = "4.1"

    lr = sl.log_records.add()
    # Timestamp \u2014 prefer the event's ts when parseable, else now.
    ts_ns = _event_time_unix_nano(event)
    lr.time_unix_nano = ts_ns
    lr.observed_time_unix_nano = int(_time.time_ns())
    sev_text, sev_num = _severity(event)
    lr.severity_text = sev_text
    lr.severity_number = sev_num
    # Body: JSON of the full event (truncated). The collector can re-parse
    # if it wants the full structure.
    try:
        body_json = json.dumps(event, default=str, separators=(",", ":"))
    except Exception:
        body_json = str(event)
    if len(body_json) > _MAX_BODY_STR:
        body_json = body_json[: _MAX_BODY_STR - 3] + "..."
    lr.body.string_value = body_json

    # Whitelisted scalar attributes on the record itself \u2014 nice for
    # collector-side filtering / dashboards without re-parsing the JSON body.
    for k, v in _whitelist_attrs(event).items():
        lr.attributes.append(_kv(common_pb2, k, v))

    return req


def _resource_attrs(profile: dict[str, Any]) -> dict[str, Any]:
    """Stable resource-attribute set for every export from this profile."""
    attrs: dict[str, Any] = {
        "service.name":      profile.get("name") or "apigenie-push",
        "service.namespace": "apigenie",
        "service.version":   "4.1.0",
        "source_type":       profile.get("source_type", ""),
    }
    deployment = os.environ.get("APIGENIE_DOMAIN")
    if deployment:
        attrs["deployment.environment"] = deployment
    return {k: v for k, v in attrs.items() if v}


# Keys we lift onto the LogRecord as first-class attributes. Anything not
# in this list stays in the JSON body.
_WHITELIST_KEYS = (
    "type", "subtype", "action", "event_name", "event_type", "category",
    "severity", "vendor", "product",
    "src_ip", "dst_ip", "source_ip", "dest_ip",
    "src_port", "dst_port",
    "user", "username", "user_name", "user_id",
    "hostname", "host", "device_name", "device_id", "serial",
    "process", "process_name", "image_path",
    "url", "domain", "fqdn",
    "rule_id", "rule_name", "signature_id", "policy",
)


def _whitelist_attrs(event: dict[str, Any]) -> dict[str, Any]:
    """Pull out scalar event fields that are useful for routing / filtering."""
    out: dict[str, Any] = {}
    for k in _WHITELIST_KEYS:
        v = event.get(k)
        if v is None:
            continue
        if isinstance(v, (dict, list)):
            # Skip structured values \u2014 they're already inside the JSON body.
            continue
        out[k] = v
        if len(out) >= _MAX_ATTRS_PER_RECORD:
            break
    return out


def _kv(common_pb2, key: str, value: Any):
    """Build an ``opentelemetry.common.v1.KeyValue`` for a Python scalar."""
    kv = common_pb2.KeyValue()
    kv.key = key
    av = kv.value
    if isinstance(value, bool):
        av.bool_value = value
    elif isinstance(value, int) and not isinstance(value, bool):
        av.int_value = value
    elif isinstance(value, float):
        av.double_value = value
    else:
        s = str(value)
        if len(s) > _MAX_ATTR_STR:
            s = s[: _MAX_ATTR_STR - 3] + "..."
        av.string_value = s
    return kv


def _event_time_unix_nano(event: dict[str, Any]) -> int:
    """Best-effort extraction of a unix-nano timestamp from a push event.

    Falls back to wall-clock now if nothing parseable is found.
    """
    for key in ("time_unix_nano", "timestamp_ns", "ts_ns"):
        v = event.get(key)
        if isinstance(v, int) and v > 0:
            return v
    for key in ("timestamp", "time", "receive_time", "@timestamp"):
        v = event.get(key)
        if v is None:
            continue
        if isinstance(v, (int, float)) and v > 0:
            # Heuristic: ten-digit numbers are seconds, thirteen are ms,
            # sixteen are us, more are ns.
            iv = int(v)
            if iv < 10_000_000_000:           # seconds
                return iv * 1_000_000_000
            if iv < 10_000_000_000_000:       # milliseconds
                return iv * 1_000_000
            if iv < 10_000_000_000_000_000:   # microseconds
                return iv * 1_000
            return iv                          # nanoseconds
        if isinstance(v, str):
            try:
                from datetime import datetime as _dt
                # ISO-8601 with optional trailing Z.
                s = v.rstrip("Z")
                t = _dt.fromisoformat(s)
                if t.tzinfo is None:
                    from datetime import timezone as _tz
                    t = t.replace(tzinfo=_tz.utc)
                return int(t.timestamp() * 1e9)
            except Exception:
                pass
    return int(_time.time_ns())


# OTel severity numbers per the OTLP spec:
# 1-4 TRACE, 5-8 DEBUG, 9-12 INFO, 13-16 WARN, 17-20 ERROR, 21-24 FATAL.
_SEVERITY_MAP: dict[str, tuple[str, int]] = {
    "trace":         ("TRACE",  1),
    "debug":         ("DEBUG",  5),
    "info":          ("INFO",   9),
    "informational": ("INFO",   9),
    "notice":        ("INFO",  10),
    "warn":          ("WARN",  13),
    "warning":       ("WARN",  13),
    "medium":        ("WARN",  13),
    "error":         ("ERROR", 17),
    "err":           ("ERROR", 17),
    "high":          ("ERROR", 17),
    "critical":      ("FATAL", 21),
    "fatal":         ("FATAL", 21),
    "emergency":     ("FATAL", 24),
}


def _severity(event: dict[str, Any]) -> tuple[str, int]:
    raw = event.get("severity") or event.get("level") or "info"
    if isinstance(raw, (int, float)):
        # Already a number \u2014 map to the closest OTel band.
        n = max(1, min(24, int(raw)))
        if n <= 4:   return ("TRACE", n)
        if n <= 8:   return ("DEBUG", n)
        if n <= 12:  return ("INFO",  n)
        if n <= 16:  return ("WARN",  n)
        if n <= 20:  return ("ERROR", n)
        return ("FATAL", n)
    key = str(raw).strip().lower()
    return _SEVERITY_MAP.get(key, ("INFO", 9))


# ── Transports ──────────────────────────────────────────────────────────────

def _send_http(req, dest: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """POST the protobuf-encoded ExportLogsServiceRequest to OTLP/HTTP."""
    import http.client
    import ssl as _ssl

    host = _clean_host(dest.get("host", ""))
    port = int(dest.get("port") or (443 if dest.get("tls") else 80))
    path = dest.get("path") or _DEFAULT_HTTP_PATH
    use_tls = bool(dest.get("tls"))
    body = req.SerializeToString()

    headers = {
        "Content-Type":  "application/x-protobuf",
        "Accept":        "application/x-protobuf",
        "User-Agent":    "ApiGenie-OTLP-Pusher/4.1",
        "Content-Length": str(len(body)),
    }
    # Auth: re-use the existing destination auth fields.
    auth_type = dest.get("auth_type", "none")
    if auth_type == "bearer" and dest.get("auth_token"):
        headers["Authorization"] = f"Bearer {dest['auth_token']}"
    elif auth_type == "basic" and dest.get("auth_username"):
        import base64
        cred = base64.b64encode(
            f"{dest['auth_username']}:{dest.get('auth_password','')}".encode()
        ).decode()
        headers["Authorization"] = f"Basic {cred}"
    # Optional in-cluster routing hint \u2014 if the collector is an apigenie
    # push-sink listener, this header steers the export to the right id.
    lid = dest.get("listener_id") or profile.get("otlp_listener_id")
    if lid:
        headers["X-Apigenie-Listener-Id"] = str(lid)
        headers["X-Scope-Orgid"]          = str(lid)

    if use_tls:
        ctx = _ssl.create_default_context()
        if not dest.get("tls_verify", False):
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=10)

    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        return {
            "protocol": "otlp_http",
            "status":   resp.status,
            "bytes":    len(body),
            "url":      f"{'https' if use_tls else 'http'}://{host}:{port}{path}",
            "resp_size": len(resp_body),
        }
    finally:
        conn.close()


def _send_grpc(req, dest: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Send the ExportLogsServiceRequest over a unary OTLP/gRPC call.

    Uses an insecure_channel when ``tls`` is falsy and a secure_channel
    (system trust store) when truthy. apigenie's own gRPC server speaks
    plaintext h2c on port 4317 (TLS termination is handled by nginx on
    public deployments), so the default for the in-cluster smoke is
    ``tls=false`` against ``apigenie:4317``.
    """
    # Lazy imports keep grpc out of the hot path for non-OTLP transports.
    import grpc
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2_grpc

    host = _clean_host(dest.get("host", ""))
    port = int(dest.get("port") or 4317)
    target = f"{host}:{port}"
    use_tls = bool(dest.get("tls"))

    if use_tls:
        creds = grpc.ssl_channel_credentials()
        channel = grpc.secure_channel(target, creds)
    else:
        channel = grpc.insecure_channel(target)

    # Metadata: bearer auth + listener routing hint.
    metadata: list[tuple[str, str]] = []
    if dest.get("auth_type") == "bearer" and dest.get("auth_token"):
        metadata.append(("authorization", f"Bearer {dest['auth_token']}"))
    lid = dest.get("listener_id") or profile.get("otlp_listener_id")
    if lid:
        metadata.append(("x-apigenie-listener-id", str(lid)))
        metadata.append(("x-scope-orgid",          str(lid)))

    body_size = req.ByteSize()
    try:
        stub = logs_service_pb2_grpc.LogsServiceStub(channel)
        try:
            resp = stub.Export(req, metadata=metadata, timeout=10.0)
            rejected = 0
            try:
                rejected = int(resp.partial_success.rejected_log_records)
            except Exception:
                pass
            return {
                "protocol": "otlp_grpc",
                "status":   200,
                "bytes":    body_size,
                "url":      f"grpc://{target}",
                "rejected_records": rejected,
            }
        except grpc.RpcError as exc:
            try:
                code = exc.code().name
            except Exception:
                code = "UNKNOWN"
            return {
                "protocol": "otlp_grpc",
                "status":   0,
                "bytes":    body_size,
                "url":      f"grpc://{target}",
                "error":    f"grpc:{code}",
            }
    finally:
        channel.close()


# ── Helpers ─────────────────────────────────────────────────────────────────

def _clean_host(raw: str) -> str:
    h = (raw or "").strip()
    for prefix in ("https://", "http://", "grpc://", "grpcs://"):
        if h.lower().startswith(prefix):
            h = h[len(prefix):]
    return h.rstrip("/")
