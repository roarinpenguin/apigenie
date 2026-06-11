"""Tests for the OpenTelemetry push-sink listener — data-model layer.

Covers the new ``PushSinkSpec`` dataclass, the extended codec / signal /
protocol whitelists in ``listeners.py``, and the three-way XOR rule that
forbids combining ``push_sink`` with ``synthetic`` or ``replay``.

HTTP dispatch, gRPC dispatch, and the decoder are exercised in the later
sections of this module (added as those layers land).

Design doc: docs/OTEL_LISTENER.md
"""
from __future__ import annotations

import pytest


# ── Codec / signal / protocol whitelists ────────────────────────────────────

def test_codecs_extended_with_otlp_variants():
    import listeners as L
    assert "otlp_proto" in L.ALLOWED_CODECS_V1
    assert "otlp_json"  in L.ALLOWED_CODECS_V1
    # The pre-existing pull-style codecs must still be allowed.
    assert {"json", "ndjson", "syslog"}.issubset(L.ALLOWED_CODECS_V1)


def test_push_sink_constants_present():
    import listeners as L
    assert L.PUSH_SINK_CODECS    == {"otlp_proto", "otlp_json"}
    assert L.PUSH_SINK_SIGNALS   == {"logs", "metrics", "traces"}
    assert L.PUSH_SINK_PROTOCOLS == {"otlp_http", "otlp_grpc"}


# ── Dataclass shape ─────────────────────────────────────────────────────────

def test_push_sink_spec_defaults():
    from listeners import PushSinkSpec
    spec = PushSinkSpec()
    assert spec.protocol == "otlp_http"
    assert spec.signal == "logs"
    assert spec.decode_preview is True
    assert spec.ack_partial_success is True
    assert spec.max_decode_records == 5


def test_listener_from_dict_roundtrip_with_push_sink():
    """``Listener.from_dict(to_dict(L))`` must reconstruct push_sink."""
    from listeners import Listener
    payload = {
        "id": "otel-logs",
        "name": "OTLP logs sink",
        "path": "/v1/logs",
        "method": "POST",
        "codec": "otlp_proto",
        "push_sink": {
            "protocol": "otlp_http",
            "signal": "logs",
            "decode_preview": True,
            "ack_partial_success": True,
            "max_decode_records": 3,
        },
    }
    listener = Listener.from_dict(payload)
    assert listener.push_sink is not None
    assert listener.push_sink.protocol == "otlp_http"
    assert listener.push_sink.signal == "logs"
    assert listener.push_sink.max_decode_records == 3
    # Round-trip through to_dict() → from_dict() must be lossless.
    again = Listener.from_dict(listener.to_dict())
    assert again.push_sink == listener.push_sink
    # Mutually exclusive kinds remain unset.
    assert again.synthetic is None
    assert again.replay is None


# ── validate_listener_payload — happy paths ─────────────────────────────────

def _base_push_sink_payload(**overrides):
    p = {
        "id": "otel-logs",
        "name": "OTLP logs sink",
        "path": "/v1/logs",
        "method": "POST",
        "codec": "otlp_proto",
        "push_sink": {
            "protocol": "otlp_http",
            "signal": "logs",
            "decode_preview": True,
            "ack_partial_success": True,
            "max_decode_records": 5,
        },
    }
    p.update(overrides)
    return p


def test_validate_push_sink_otlp_http_proto():
    from listeners import validate_listener_payload
    ok, err = validate_listener_payload(_base_push_sink_payload())
    assert ok, f"expected valid, got err={err!r}"


def test_validate_push_sink_otlp_http_json():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload(codec="otlp_json")
    p["push_sink"] = {**p["push_sink"], "protocol": "otlp_http"}
    ok, err = validate_listener_payload(p)
    assert ok, f"expected valid, got err={err!r}"


def test_validate_push_sink_otlp_grpc_requires_proto():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload(codec="otlp_proto")
    p["push_sink"]["protocol"] = "otlp_grpc"
    ok, err = validate_listener_payload(p)
    assert ok, f"expected valid, got err={err!r}"


# ── validate_listener_payload — rejections ──────────────────────────────────

def test_three_way_xor_forbids_push_sink_plus_synthetic():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload()
    p["synthetic"] = {"topic": "endpoint"}
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "exactly one" in err.lower()


def test_three_way_xor_forbids_push_sink_plus_replay():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload()
    p["replay"] = {"file_id": "f1", "format": "jsonl"}
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "exactly one" in err.lower()


def test_three_way_xor_requires_at_least_one_data_source():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload()
    p.pop("push_sink")
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "exactly one" in err.lower()


def test_push_sink_method_must_be_post():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload(method="GET")
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "method=POST" in err or "POST" in err


def test_push_sink_codec_must_be_otlp_variant():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload(codec="json")
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "codec" in err.lower()


def test_push_sink_grpc_rejects_json_codec():
    """OTLP/gRPC traffic is always protobuf on the wire — no JSON variant."""
    from listeners import validate_listener_payload
    p = _base_push_sink_payload(codec="otlp_json")
    p["push_sink"]["protocol"] = "otlp_grpc"
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "otlp_grpc" in err and "otlp_proto" in err


def test_push_sink_invalid_signal_rejected():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload()
    p["push_sink"]["signal"] = "events"  # not a real OTLP signal
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "signal" in err.lower()


def test_push_sink_invalid_protocol_rejected():
    from listeners import validate_listener_payload
    p = _base_push_sink_payload()
    p["push_sink"]["protocol"] = "otlp_tcp"  # not a real OTLP protocol
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "protocol" in err.lower()


@pytest.mark.parametrize("bad", [-1, 101, "five", None])
def test_push_sink_max_decode_records_bounds(bad):
    from listeners import validate_listener_payload
    p = _base_push_sink_payload()
    p["push_sink"]["max_decode_records"] = bad
    ok, err = validate_listener_payload(p)
    assert not ok
    assert "max_decode_records" in err


# ── Backward compatibility — synthetic/replay still validate ───────────────

def test_synthetic_only_still_valid():
    from listeners import validate_listener_payload
    p = {
        "id": "syn",
        "name": "synthetic",
        "path": "/syn",
        "method": "GET",
        "codec": "json",
        "synthetic": {"topic": "endpoint"},
    }
    ok, err = validate_listener_payload(p)
    assert ok, f"expected valid, got err={err!r}"


def test_replay_only_still_valid():
    from listeners import validate_listener_payload
    p = {
        "id": "rep",
        "name": "replay",
        "path": "/rep",
        "method": "GET",
        "codec": "ndjson",
        "replay": {"file_id": "f1", "format": "jsonl"},
    }
    ok, err = validate_listener_payload(p)
    assert ok, f"expected valid, got err={err!r}"


# ── Decoder (listeners_otlp.decode_preview) ─────────────────────────────────
# Crafts real OTLP protobuf messages via the opentelemetry-proto stubs and
# round-trips them through the decoder. Same machinery a stock collector uses.

def _build_logs_request(*, n_resources: int = 1, n_records: int = 3):
    """Return an ExportLogsServiceRequest with deterministic test data."""
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
        ExportLogsServiceRequest,
    )
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
    from opentelemetry.proto.logs.v1.logs_pb2 import (
        LogRecord, ResourceLogs, ScopeLogs,
    )

    req = ExportLogsServiceRequest()
    for r in range(n_resources):
        rl = req.resource_logs.add()
        rl.resource.attributes.append(
            KeyValue(key="service.name", value=AnyValue(string_value=f"app-{r}"))
        )
        rl.resource.attributes.append(
            KeyValue(key="deployment.environment", value=AnyValue(string_value="test"))
        )
        sl = rl.scope_logs.add()
        sl.scope.name = "apigenie.tests"
        for i in range(n_records):
            lr = LogRecord()
            lr.time_unix_nano = 1_700_000_000_000_000_000 + i * 1_000_000_000
            lr.severity_number = 9    # INFO
            lr.severity_text = "INFO"
            lr.body.string_value = f"hello world {r}-{i}"
            lr.attributes.append(
                KeyValue(key="http.status_code", value=AnyValue(int_value=200))
            )
            sl.log_records.append(lr)
    return req


def test_decode_preview_logs_proto():
    from listeners_otlp import decode_preview
    req = _build_logs_request(n_resources=2, n_records=3)
    body = req.SerializeToString()
    out = decode_preview(body=body, codec="otlp_proto", signal="logs", max_records=10)
    assert out["signal"] == "logs"
    assert out["codec"] == "otlp_proto"
    assert out["resource_count"] == 2
    assert out["record_count"] == 6                   # 2 res × 3 records
    assert out["truncated"] is False                  # cap (10) > total (6)
    assert out["resources"][0]["service.name"] == "app-0"
    assert out["resources"][0]["deployment.environment"] == "test"
    assert out["records"][0]["severity"] == "INFO"
    assert out["records"][0]["body"].startswith("hello world")
    assert out["records"][0]["attributes"] == {"http.status_code": 200}
    assert out["records"][0]["scope"] == "apigenie.tests"


def test_decode_preview_logs_truncates_records():
    from listeners_otlp import decode_preview
    req = _build_logs_request(n_resources=1, n_records=12)
    body = req.SerializeToString()
    out = decode_preview(body=body, codec="otlp_proto", signal="logs", max_records=4)
    assert out["truncated"] is True
    assert len(out["records"]) == 4
    assert out["record_count"] == 12                  # total, not capped


def test_decode_preview_logs_json():
    """OTLP/HTTP JSON variant — round-trip through ParseDict."""
    from google.protobuf import json_format
    from listeners_otlp import decode_preview
    req = _build_logs_request(n_resources=1, n_records=2)
    # OTLP/HTTP-JSON wire form uses camelCase; MessageToDict emits exactly that.
    obj = json_format.MessageToDict(req, preserving_proto_field_name=False)
    import json as _json
    body = _json.dumps(obj).encode("utf-8")
    out = decode_preview(body=body, codec="otlp_json", signal="logs", max_records=5)
    assert out["codec"] == "otlp_json"
    assert out["record_count"] == 2
    assert out["records"][0]["body"].startswith("hello world")


def test_decode_preview_empty_body_is_safe():
    from listeners_otlp import decode_preview
    out = decode_preview(body=b"", codec="otlp_proto", signal="logs", max_records=5)
    assert out["decode_error"] == "empty_body"
    # Never raises, signal/codec echoed for the UI.
    assert out["signal"] == "logs"


def test_decode_preview_oversize_body_is_safe(monkeypatch):
    import listeners_otlp
    monkeypatch.setattr(listeners_otlp, "MAX_BODY_BYTES", 10)
    out = listeners_otlp.decode_preview(
        body=b"x" * 1024, codec="otlp_proto", signal="logs", max_records=5,
    )
    assert out["decode_error"] == "body_too_large"
    assert out["size_bytes"] == 1024
    assert out["max_bytes"] == 10


def test_decode_preview_malformed_proto_is_safe():
    from listeners_otlp import decode_preview
    out = decode_preview(
        body=b"\xff\xff\xffnot a real proto",
        codec="otlp_proto", signal="logs", max_records=5,
    )
    assert "decode_error" in out
    assert out["signal"] == "logs"


def test_decode_preview_malformed_json_is_safe():
    from listeners_otlp import decode_preview
    out = decode_preview(
        body=b"{not valid json",
        codec="otlp_json", signal="logs", max_records=5,
    )
    assert "decode_error" in out and "json_decode_failed" in out["decode_error"]


def test_decode_preview_metrics_proto():
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
        ExportMetricsServiceRequest,
    )
    from opentelemetry.proto.metrics.v1.metrics_pb2 import (
        Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics,
    )
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
    from listeners_otlp import decode_preview

    req = ExportMetricsServiceRequest()
    rm = req.resource_metrics.add()
    rm.resource.attributes.append(
        KeyValue(key="service.name", value=AnyValue(string_value="metricsd"))
    )
    sm = rm.scope_metrics.add()
    sm.scope.name = "tests"
    # Build a gauge with 4 data points.
    m = Metric(name="cpu.utilisation", description="CPU %", unit="1")
    for i in range(4):
        dp = NumberDataPoint()
        dp.time_unix_nano = 1_700_000_000_000_000_000 + i
        dp.as_double = 0.25 * (i + 1)
        m.gauge.data_points.append(dp)
    sm.metrics.append(m)

    out = decode_preview(
        body=req.SerializeToString(),
        codec="otlp_proto", signal="metrics", max_records=5,
    )
    assert out["signal"] == "metrics"
    assert out["resource_count"] == 1
    assert out["record_count"] == 4                  # 4 data points total
    assert out["records"][0]["name"] == "cpu.utilisation"
    assert out["records"][0]["kind"] == "gauge"
    assert out["records"][0]["data_points"] == 4


def test_decode_preview_traces_proto():
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )
    from opentelemetry.proto.trace.v1.trace_pb2 import (
        ResourceSpans, ScopeSpans, Span,
    )
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
    from listeners_otlp import decode_preview

    req = ExportTraceServiceRequest()
    rs = req.resource_spans.add()
    rs.resource.attributes.append(
        KeyValue(key="service.name", value=AnyValue(string_value="tracerd"))
    )
    ss = rs.scope_spans.add()
    ss.scope.name = "tests"
    span = Span()
    span.name = "do.work"
    span.kind = 2  # SERVER
    span.trace_id = b"\x01" * 16
    span.span_id = b"\x02" * 8
    span.start_time_unix_nano = 1_700_000_000_000_000_000
    span.end_time_unix_nano   = 1_700_000_001_000_000_000
    span.status.code = 1   # OK
    ss.spans.append(span)

    out = decode_preview(
        body=req.SerializeToString(),
        codec="otlp_proto", signal="traces", max_records=5,
    )
    assert out["signal"] == "traces"
    assert out["record_count"] == 1
    rec = out["records"][0]
    assert rec["name"] == "do.work"
    assert rec["kind"] == "SERVER"
    assert rec["trace_id"] == "01" * 16
    assert rec["span_id"]  == "02" * 8
    assert rec["status"]   == "OK"


# ── ack body ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("signal", ["logs", "metrics", "traces"])
def test_http_ack_body_shape(signal):
    from listeners_otlp import http_ack_body
    body = http_ack_body(signal)
    # OTLP spec: empty Export*ServiceResponse encodes as {"partialSuccess": {}}.
    assert body == {"partialSuccess": {}}


# ── HTTP dispatcher (FastAPI TestClient) ────────────────────────────────────
# Exercises @app.api_route("/listener/{lid}/{rest:path}") with the new
# push_sink branch. The listener is registered directly in _listeners.LISTENERS
# because the admin CRUD goes through cookie auth which is out of scope here.

@pytest.fixture
def http_client():
    """Yield a FastAPI TestClient against the real app."""
    from fastapi.testclient import TestClient
    from app import app
    with TestClient(app) as c:
        yield c


@pytest.fixture
def register_push_sink():
    """Factory: register a push_sink listener directly into the LISTENERS dict.

    Cleans up after the test so the global state stays tidy across the
    rest of the suite.
    """
    import listeners as L
    registered: list[str] = []

    def _make(*, lid: str = "otel-test",
              signal: str = "logs",
              codec: str = "otlp_proto",
              auth: dict | None = None,
              path: str | None = None,
              max_decode_records: int = 5,
              decode_preview: bool = True) -> L.Listener:
        listener = L.Listener.from_dict({
            "id": lid,
            "name": f"OTLP {signal} test sink",
            "path": path or f"/v1/{signal}",
            "method": "POST",
            "codec": codec,
            "enabled": True,
            "auth": auth or {"kind": "none"},
            "push_sink": {
                "protocol": "otlp_http",
                "signal": signal,
                "decode_preview": decode_preview,
                "ack_partial_success": True,
                "max_decode_records": max_decode_records,
            },
        })
        L.LISTENERS[lid] = listener
        L.LISTENER_HITS[lid] = __import__("collections").deque(maxlen=L.HITS_MEM_CAP)
        registered.append(lid)
        return listener

    yield _make

    for lid in registered:
        L.LISTENERS.pop(lid, None)
        L.LISTENER_HITS.pop(lid, None)


def test_http_dispatch_otlp_proto_logs_acked(http_client, register_push_sink):
    register_push_sink(lid="otel-h1", signal="logs", codec="otlp_proto")
    req = _build_logs_request(n_resources=1, n_records=2)
    r = http_client.post(
        "/listener/otel-h1/v1/logs",
        content=req.SerializeToString(),
        headers={"content-type": "application/x-protobuf"},
    )
    assert r.status_code == 200
    assert r.json() == {"partialSuccess": {}}
    # Hit recorded with otlp_preview populated.
    import listeners as L
    hits = list(L.LISTENER_HITS["otel-h1"])
    assert len(hits) == 1
    hit = hits[0]
    assert hit["status"] == 200
    assert hit["method"] == "POST"
    assert hit["path"] == "/v1/logs"
    assert "otlp_preview" in hit
    assert hit["otlp_preview"]["signal"] == "logs"
    assert hit["otlp_preview"]["record_count"] == 2
    assert hit["otlp_preview"]["resources"][0]["service.name"] == "app-0"


def test_http_dispatch_otlp_json_logs_acked(http_client, register_push_sink):
    register_push_sink(lid="otel-h2", signal="logs", codec="otlp_json")
    from google.protobuf import json_format
    import json as _json
    req = _build_logs_request(n_resources=1, n_records=1)
    obj = json_format.MessageToDict(req, preserving_proto_field_name=False)
    r = http_client.post(
        "/listener/otel-h2/v1/logs",
        content=_json.dumps(obj).encode("utf-8"),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 200
    assert r.json() == {"partialSuccess": {}}
    import listeners as L
    hit = list(L.LISTENER_HITS["otel-h2"])[0]
    assert hit["otlp_preview"]["codec"] == "otlp_json"
    assert hit["otlp_preview"]["record_count"] == 1


def test_http_dispatch_bearer_auth_rejects_anon(http_client, register_push_sink):
    register_push_sink(
        lid="otel-h3", signal="logs", codec="otlp_proto",
        auth={"kind": "bearer", "token": "s3cret"},
    )
    req = _build_logs_request(n_resources=1, n_records=1)
    body = req.SerializeToString()
    # No Authorization header → 401.
    r = http_client.post(
        "/listener/otel-h3/v1/logs",
        content=body,
        headers={"content-type": "application/x-protobuf"},
    )
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"
    # Right token → 200.
    r = http_client.post(
        "/listener/otel-h3/v1/logs",
        content=body,
        headers={
            "content-type": "application/x-protobuf",
            "authorization": "s3cret",  # default auth header / prefix in AuthSpec
        },
    )
    assert r.status_code == 200, r.text


def test_http_dispatch_path_mismatch_404(http_client, register_push_sink):
    register_push_sink(lid="otel-h4", signal="logs", codec="otlp_proto",
                       path="/v1/logs")
    r = http_client.post(
        "/listener/otel-h4/v1/metrics",      # listener configured for /v1/logs
        content=b"\x00",
        headers={"content-type": "application/x-protobuf"},
    )
    assert r.status_code == 404
    assert r.json()["error"] == "path_mismatch"


def test_http_dispatch_decode_preview_disabled(http_client, register_push_sink):
    """``decode_preview=False`` → hit recorded WITHOUT an ``otlp_preview`` key."""
    register_push_sink(lid="otel-h5", signal="logs", codec="otlp_proto",
                       decode_preview=False)
    req = _build_logs_request(n_resources=1, n_records=3)
    r = http_client.post(
        "/listener/otel-h5/v1/logs",
        content=req.SerializeToString(),
        headers={"content-type": "application/x-protobuf"},
    )
    assert r.status_code == 200
    import listeners as L
    hit = list(L.LISTENER_HITS["otel-h5"])[0]
    assert "otlp_preview" not in hit


def test_http_dispatch_oversize_body_still_acked(http_client, register_push_sink, monkeypatch):
    """Body > MAX_BODY_BYTES is still acked 200; preview shows the guard."""
    import listeners_otlp
    monkeypatch.setattr(listeners_otlp, "MAX_BODY_BYTES", 16)
    register_push_sink(lid="otel-h6", signal="logs", codec="otlp_proto")
    req = _build_logs_request(n_resources=1, n_records=5)
    r = http_client.post(
        "/listener/otel-h6/v1/logs",
        content=req.SerializeToString(),
        headers={"content-type": "application/x-protobuf"},
    )
    assert r.status_code == 200
    assert r.json() == {"partialSuccess": {}}
    import listeners as L
    hit = list(L.LISTENER_HITS["otel-h6"])[0]
    assert hit["otlp_preview"]["decode_error"] == "body_too_large"


# ── gRPC server (listeners_grpc) ────────────────────────────────────────────
# Spins the real grpc.aio.Server on an ephemeral port, then drives it through
# a generated stub. Exercises routing, auth, hit recording, and the spec-
# compliant ack envelope.

def _free_port() -> int:
    """Return a port number currently free on localhost."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def grpc_server():
    """Start the OTLP/gRPC server on a free ephemeral port for one test."""
    import listeners_grpc
    port = _free_port()
    ok = listeners_grpc.start(port=port)
    if not ok:
        pytest.skip("OTLP gRPC server failed to start (deps missing?)")
    try:
        yield port
    finally:
        listeners_grpc.stop()


def _grpc_logs_stub(port: int):
    """Open a plaintext-h2c gRPC channel + LogsServiceStub at 127.0.0.1:port."""
    import grpc
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2_grpc
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    return channel, logs_service_pb2_grpc.LogsServiceStub(channel)


def test_grpc_export_logs_routed_via_explicit_listener_id(grpc_server, register_push_sink):
    register_push_sink(lid="otel-g1", signal="logs", codec="otlp_proto")
    req = _build_logs_request(n_resources=1, n_records=2)
    channel, stub = _grpc_logs_stub(grpc_server)
    try:
        resp = stub.Export(req, metadata=[("x-apigenie-listener-id", "otel-g1")], timeout=5.0)
    finally:
        channel.close()
    # OTLP spec: empty Export*ServiceResponse on success.
    assert resp.partial_success.rejected_log_records == 0
    import listeners as L
    hits = list(L.LISTENER_HITS["otel-g1"])
    assert len(hits) == 1
    hit = hits[0]
    assert hit["method"] == "gRPC"
    assert hit["status"] == 200
    assert "LogsService/Export" in hit["path"]
    assert hit["otlp_preview"]["signal"] == "logs"
    assert hit["otlp_preview"]["record_count"] == 2


def test_grpc_export_routed_via_x_scope_orgid(grpc_server, register_push_sink):
    """The Grafana Loki/Mimir/Tempo convention should be honoured too."""
    register_push_sink(lid="otel-g2", signal="logs", codec="otlp_proto")
    req = _build_logs_request(n_resources=1, n_records=1)
    channel, stub = _grpc_logs_stub(grpc_server)
    try:
        resp = stub.Export(req, metadata=[("x-scope-orgid", "otel-g2")], timeout=5.0)
    finally:
        channel.close()
    assert resp is not None
    import listeners as L
    assert len(L.LISTENER_HITS["otel-g2"]) == 1


def test_grpc_export_unknown_listener_id_not_found(grpc_server, register_push_sink):
    register_push_sink(lid="otel-g3", signal="logs", codec="otlp_proto")
    req = _build_logs_request(n_resources=1, n_records=1)
    channel, stub = _grpc_logs_stub(grpc_server)
    import grpc as _grpc
    with pytest.raises(_grpc.RpcError) as exc_info:
        try:
            stub.Export(
                req,
                metadata=[("x-apigenie-listener-id", "no-such-listener")],
                timeout=5.0,
            )
        finally:
            channel.close()
    assert exc_info.value.code() == _grpc.StatusCode.NOT_FOUND


def test_grpc_export_bearer_token_routes_to_matching_listener(grpc_server, register_push_sink):
    register_push_sink(
        lid="otel-g4", signal="logs", codec="otlp_proto",
        auth={"kind": "bearer", "token": "tok-grpc-001"},
    )
    req = _build_logs_request(n_resources=1, n_records=1)
    channel, stub = _grpc_logs_stub(grpc_server)
    try:
        resp = stub.Export(
            req,
            # Lower-case gRPC metadata + Bearer prefix (most exporters).
            metadata=[("authorization", "Bearer tok-grpc-001")],
            timeout=5.0,
        )
    finally:
        channel.close()
    assert resp is not None
    import listeners as L
    hits = list(L.LISTENER_HITS["otel-g4"])
    assert len(hits) == 1
    assert hits[0]["status"] == 200


def test_grpc_export_bearer_wrong_token_unauthenticated(grpc_server, register_push_sink):
    register_push_sink(
        lid="otel-g5", signal="logs", codec="otlp_proto",
        auth={"kind": "bearer", "token": "correct"},
    )
    req = _build_logs_request(n_resources=1, n_records=1)
    channel, stub = _grpc_logs_stub(grpc_server)
    import grpc as _grpc
    with pytest.raises(_grpc.RpcError) as exc_info:
        try:
            stub.Export(
                req,
                metadata=[
                    ("x-apigenie-listener-id", "otel-g5"),
                    ("authorization", "Bearer WRONG"),
                ],
                timeout=5.0,
            )
        finally:
            channel.close()
    # Routed to the right listener but auth check rejected the token.
    assert exc_info.value.code() == _grpc.StatusCode.UNAUTHENTICATED
    # The 401 hit should still be recorded for the operator.
    import listeners as L
    hits = list(L.LISTENER_HITS["otel-g5"])
    assert len(hits) == 1
    assert hits[0]["status"] == 401


def test_grpc_export_sole_push_sink_auto_routes(grpc_server, register_push_sink):
    """If exactly one push_sink listener exists for the signal, route there."""
    register_push_sink(lid="otel-g6-only", signal="logs", codec="otlp_proto")
    req = _build_logs_request(n_resources=1, n_records=1)
    channel, stub = _grpc_logs_stub(grpc_server)
    try:
        resp = stub.Export(req, timeout=5.0)         # no metadata at all
    finally:
        channel.close()
    assert resp is not None
    import listeners as L
    assert len(L.LISTENER_HITS["otel-g6-only"]) == 1


def test_grpc_export_ambiguous_no_metadata_not_found(grpc_server, register_push_sink):
    """Two push_sinks for the same signal + no metadata → NOT_FOUND."""
    register_push_sink(lid="otel-g7a", signal="logs", codec="otlp_proto")
    register_push_sink(lid="otel-g7b", signal="logs", codec="otlp_proto")
    req = _build_logs_request(n_resources=1, n_records=1)
    channel, stub = _grpc_logs_stub(grpc_server)
    import grpc as _grpc
    with pytest.raises(_grpc.RpcError) as exc_info:
        try:
            stub.Export(req, timeout=5.0)
        finally:
            channel.close()
    assert exc_info.value.code() == _grpc.StatusCode.NOT_FOUND


def test_grpc_export_signal_must_match(grpc_server, register_push_sink):
    """A `logs` push_sink must NOT match a TraceService.Export call."""
    register_push_sink(lid="otel-g8", signal="logs", codec="otlp_proto")
    # Build a traces request and try to route it to the logs listener.
    from opentelemetry.proto.collector.trace.v1 import (
        trace_service_pb2, trace_service_pb2_grpc,
    )
    from opentelemetry.proto.trace.v1.trace_pb2 import Span
    treq = trace_service_pb2.ExportTraceServiceRequest()
    rs = treq.resource_spans.add()
    ss = rs.scope_spans.add()
    sp = Span()
    sp.name = "ignored"
    ss.spans.append(sp)
    import grpc as _grpc
    channel = _grpc.insecure_channel(f"127.0.0.1:{grpc_server}")
    stub = trace_service_pb2_grpc.TraceServiceStub(channel)
    with pytest.raises(_grpc.RpcError) as exc_info:
        try:
            stub.Export(
                treq,
                metadata=[("x-apigenie-listener-id", "otel-g8")],
                timeout=5.0,
            )
        finally:
            channel.close()
    assert exc_info.value.code() == _grpc.StatusCode.NOT_FOUND
