"""OpenTelemetry decoder + ack-body helpers for push-sink listeners.

Pure functions only — no HTTP / gRPC concerns. The HTTP dispatcher
(``app.py``) and the gRPC server (``listeners_grpc.py``) both call into
this module to turn an incoming OTLP body into a compact preview dict
suitable for the per-listener hit history pane.

Design doc: docs/OTEL_LISTENER.md §8 (hit-pane rendering), §10 (security).

The decoder is **best-effort by contract**: any failure becomes a
``{"decode_error": "<reason>"}`` payload — the caller still acks the
export with 200 / empty partial_success so the collector is not blocked
by an apigenie decode bug.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Literal

logger = logging.getLogger(__name__)

# ── Configuration ───────────────────────────────────────────────────────────
# Hard ceiling on how many bytes of an incoming OTLP body we'll attempt to
# decode for preview. Bodies larger than this are still ACKed (200 OK) but
# the preview pane shows a "too_large" stub. Default 4 MiB matches the gRPC
# server-side max_receive_message_length we'll set in listeners_grpc.py.
MAX_BODY_BYTES = int(os.environ.get("APIGENIE_OTLP_MAX_BODY_BYTES", str(4 * 1024 * 1024)))

# How many resource buckets / records to surface in the preview. Bounded
# server-side independently of the per-listener ``max_decode_records`` so
# a misconfigured listener can't ask for ten-thousand records.
HARD_RECORD_CAP = 100

Signal = Literal["logs", "metrics", "traces"]
Codec  = Literal["otlp_proto", "otlp_json"]


# ── Lazy protobuf imports ───────────────────────────────────────────────────
# The opentelemetry-proto package is heavy at import time (it loads ~25
# generated _pb2 modules). Importing here at module top would slow every
# apigenie startup even when no push-sink listener exists. Lazy-load per
# signal instead — the dispatcher only pays the cost once it actually sees
# an OTLP request.

_PROTO_CACHE: dict[Signal, Any] = {}


def _request_proto(signal: Signal):
    """Return the generated ``Export*ServiceRequest`` class for ``signal``."""
    cached = _PROTO_CACHE.get(signal)
    if cached is not None:
        return cached
    if signal == "logs":
        from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
            ExportLogsServiceRequest,
        )
        cls = ExportLogsServiceRequest
    elif signal == "metrics":
        from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
            ExportMetricsServiceRequest,
        )
        cls = ExportMetricsServiceRequest
    elif signal == "traces":
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTraceServiceRequest,
        )
        cls = ExportTraceServiceRequest
    else:
        raise ValueError(f"unknown signal: {signal!r}")
    _PROTO_CACHE[signal] = cls
    return cls


# ── Public entry points ─────────────────────────────────────────────────────

def http_ack_body(signal: Signal) -> dict[str, Any]:
    """Return the OTel-spec-compliant successful-export ack body for ``signal``.

    The spec mandates an empty ``Export*ServiceResponse`` envelope, which
    on the JSON wire is ``{"partialSuccess": {}}`` (or just ``{}``). All
    three signals share the same envelope shape, but we keep the function
    signal-aware so a future per-signal extension stays a one-liner.
    """
    return {"partialSuccess": {}}


def decode_preview(
    *,
    body: bytes,
    codec: Codec,
    signal: Signal,
    max_records: int = 5,
) -> dict[str, Any]:
    """Decode an OTLP export body into a hit-pane preview dict.

    Never raises. On any failure returns ``{"decode_error": "<reason>", ...}``
    so the caller can still ack the export and the operator can see what
    went wrong in the hit pane.

    Returns a dict shaped like (logs example):
        {
          "signal": "logs",
          "codec":  "otlp_proto",
          "resource_count": 2,
          "record_count":   17,
          "resources": [{"service.name": "app", ...}, ...],
          "records":   [{"timestamp": "...", "severity": "...", ...}, ...],
          "truncated": false,
        }
    """
    if not body:
        return {"signal": signal, "codec": codec, "decode_error": "empty_body"}

    n = len(body)
    if n > MAX_BODY_BYTES:
        return {
            "signal": signal, "codec": codec,
            "decode_error": "body_too_large",
            "size_bytes": n, "max_bytes": MAX_BODY_BYTES,
        }

    cap = max(0, min(int(max_records), HARD_RECORD_CAP))

    try:
        req_cls = _request_proto(signal)
        msg = req_cls()
        if codec == "otlp_proto":
            msg.ParseFromString(body)
        elif codec == "otlp_json":
            from google.protobuf import json_format
            try:
                payload_str = body.decode("utf-8")
            except UnicodeDecodeError as exc:
                return {
                    "signal": signal, "codec": codec,
                    "decode_error": f"utf8_decode_failed: {exc}",
                    "size_bytes": n,
                }
            try:
                payload_obj = json.loads(payload_str)
            except json.JSONDecodeError as exc:
                return {
                    "signal": signal, "codec": codec,
                    "decode_error": f"json_decode_failed: {exc.msg}",
                    "size_bytes": n,
                }
            json_format.ParseDict(payload_obj, msg, ignore_unknown_fields=True)
        else:
            return {
                "signal": signal, "codec": codec,
                "decode_error": f"unsupported_codec: {codec!r}",
            }
    except Exception as exc:
        # google.protobuf raises DecodeError, json_format raises ParseError,
        # plus all the import-failure paths. Treat them all the same.
        return {
            "signal": signal, "codec": codec,
            "decode_error": f"{type(exc).__name__}: {exc}",
            "size_bytes": n,
        }

    if signal == "logs":
        return _summarise_logs(msg, codec, cap)
    if signal == "metrics":
        return _summarise_metrics(msg, codec, cap)
    if signal == "traces":
        return _summarise_traces(msg, codec, cap)
    # _request_proto already raised on unknown signal so we never get here.
    return {"signal": signal, "codec": codec, "decode_error": "unreachable"}


# ── Per-signal summarisers ──────────────────────────────────────────────────

def _summarise_logs(msg, codec: Codec, cap: int) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    records:   list[dict[str, Any]] = []
    total_records = 0
    truncated = False

    for rl in msg.resource_logs:
        resources.append(_attrs_to_dict(rl.resource.attributes))
        for sl in rl.scope_logs:
            scope_name = sl.scope.name or ""
            for lr in sl.log_records:
                total_records += 1
                if len(records) >= cap:
                    truncated = True
                    continue
                records.append({
                    "timestamp":  _unix_nano_to_iso(lr.time_unix_nano),
                    "severity":   lr.severity_text or _severity_name(lr.severity_number),
                    "body":       _anyvalue_to_str(lr.body),
                    "attributes": _attrs_to_dict(lr.attributes),
                    "trace_id":   lr.trace_id.hex() if lr.trace_id else "",
                    "span_id":    lr.span_id.hex() if lr.span_id else "",
                    "scope":      scope_name,
                })
    return {
        "signal": "logs", "codec": codec,
        "resource_count": len(msg.resource_logs),
        "record_count":   total_records,
        "resources":      resources[:cap],
        "records":        records,
        "truncated":      truncated,
    }


def _summarise_metrics(msg, codec: Codec, cap: int) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    records:   list[dict[str, Any]] = []
    total_records = 0
    truncated = False

    for rm in msg.resource_metrics:
        resources.append(_attrs_to_dict(rm.resource.attributes))
        for sm in rm.scope_metrics:
            scope_name = sm.scope.name or ""
            for metric in sm.metrics:
                kind, dp_count = _classify_metric(metric)
                total_records += dp_count
                if len(records) >= cap:
                    truncated = True
                    continue
                records.append({
                    "name":        metric.name,
                    "description": metric.description,
                    "unit":        metric.unit,
                    "kind":        kind,
                    "data_points": dp_count,
                    "scope":       scope_name,
                })
    return {
        "signal": "metrics", "codec": codec,
        "resource_count":  len(msg.resource_metrics),
        "record_count":    total_records,    # total data points across all metrics
        "resources":       resources[:cap],
        "records":         records,
        "truncated":       truncated,
    }


def _summarise_traces(msg, codec: Codec, cap: int) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    records:   list[dict[str, Any]] = []
    total_records = 0
    truncated = False

    for rs in msg.resource_spans:
        resources.append(_attrs_to_dict(rs.resource.attributes))
        for ss in rs.scope_spans:
            scope_name = ss.scope.name or ""
            for span in ss.spans:
                total_records += 1
                if len(records) >= cap:
                    truncated = True
                    continue
                records.append({
                    "name":         span.name,
                    "kind":         _span_kind_name(span.kind),
                    "trace_id":     span.trace_id.hex() if span.trace_id else "",
                    "span_id":      span.span_id.hex() if span.span_id else "",
                    "parent_id":    span.parent_span_id.hex() if span.parent_span_id else "",
                    "start":        _unix_nano_to_iso(span.start_time_unix_nano),
                    "end":          _unix_nano_to_iso(span.end_time_unix_nano),
                    "status":       _status_code_name(span.status.code),
                    "attributes":   _attrs_to_dict(span.attributes),
                    "scope":        scope_name,
                })
    return {
        "signal": "traces", "codec": codec,
        "resource_count": len(msg.resource_spans),
        "record_count":   total_records,
        "resources":      resources[:cap],
        "records":        records,
        "truncated":      truncated,
    }


# ── Helpers ─────────────────────────────────────────────────────────────────

def _attrs_to_dict(attrs) -> dict[str, Any]:
    """Convert a ``repeated KeyValue attributes`` field into a flat dict."""
    out: dict[str, Any] = {}
    for kv in attrs:
        out[kv.key] = _anyvalue_to_py(kv.value)
    return out


def _anyvalue_to_py(v) -> Any:
    """OTLP AnyValue oneof → native Python value (best-effort)."""
    which = v.WhichOneof("value")
    if which is None:
        return None
    if which == "string_value":
        return v.string_value
    if which == "bool_value":
        return v.bool_value
    if which == "int_value":
        return v.int_value
    if which == "double_value":
        return v.double_value
    if which == "array_value":
        return [_anyvalue_to_py(x) for x in v.array_value.values]
    if which == "kvlist_value":
        return {kv.key: _anyvalue_to_py(kv.value) for kv in v.kvlist_value.values}
    if which == "bytes_value":
        return v.bytes_value.hex()
    return None


def _anyvalue_to_str(v) -> str:
    """Compact string form of an AnyValue, suitable for the body column."""
    py = _anyvalue_to_py(v)
    if py is None:
        return ""
    if isinstance(py, str):
        return py
    return json.dumps(py, separators=(",", ":"), default=str)


def _unix_nano_to_iso(ns: int) -> str:
    """Convert an OTLP fixed64 unix_nano timestamp to ISO-8601 (UTC).

    Returns ``""`` for the zero / sentinel value because OTLP exporters
    sometimes leave the field unset on synthetic test data.
    """
    if not ns:
        return ""
    try:
        from datetime import datetime, timezone
        # ns → seconds (float). Python datetime handles sub-second precision.
        seconds = ns / 1_000_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="microseconds")
    except Exception:
        return ""


# OTLP severity numbers → text labels (subset that real-world exporters use).
_SEVERITY_LABELS = {
    1: "TRACE", 5: "DEBUG", 9: "INFO", 13: "WARN", 17: "ERROR", 21: "FATAL",
}


def _severity_name(n: int) -> str:
    if n in _SEVERITY_LABELS:
        return _SEVERITY_LABELS[n]
    # OTLP defines 1-24 with TRACE/DEBUG/INFO/WARN/ERROR/FATAL × 4 levels each.
    # Pick the bucket label without trying to be cute about the sub-level.
    if 1 <= n <= 4:    return f"TRACE{n}"
    if 5 <= n <= 8:    return f"DEBUG{n - 4}"
    if 9 <= n <= 12:   return f"INFO{n - 8}"
    if 13 <= n <= 16:  return f"WARN{n - 12}"
    if 17 <= n <= 20:  return f"ERROR{n - 16}"
    if 21 <= n <= 24:  return f"FATAL{n - 20}"
    return ""


_METRIC_KIND_FIELDS = ("gauge", "sum", "histogram", "exponential_histogram", "summary")


def _classify_metric(metric) -> tuple[str, int]:
    """Return (kind_label, data_point_count) for a Metric message."""
    which = metric.WhichOneof("data")
    if which is None:
        return ("unknown", 0)
    sub = getattr(metric, which)
    # Every metric variant carries a `data_points` repeated field of the
    # appropriate sub-type. Just count its length.
    dp = getattr(sub, "data_points", None)
    count = len(dp) if dp is not None else 0
    return (which, count)


_SPAN_KIND_LABELS = {
    0: "UNSPECIFIED", 1: "INTERNAL", 2: "SERVER", 3: "CLIENT", 4: "PRODUCER", 5: "CONSUMER",
}


def _span_kind_name(k: int) -> str:
    return _SPAN_KIND_LABELS.get(k, f"K{k}")


_STATUS_CODE_LABELS = {0: "UNSET", 1: "OK", 2: "ERROR"}


def _status_code_name(c: int) -> str:
    return _STATUS_CODE_LABELS.get(c, f"S{c}")
