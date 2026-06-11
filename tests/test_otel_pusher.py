"""Tests for the OpenTelemetry push-egress side (v4.1).

This file covers the *outbound* half of the OTLP story \u2014 ``otlp_pusher.py``,
the 4 synthetic-topic push sources, the replay-file push source, and the
new fields on ``PushProfile``. The *inbound* half (push-sink listener) is
covered by ``tests/test_otel_listener.py``; together they exercise every
piece of the round-trip.

Layers, top-down
================

1. **Registry** \u2014 confirm the 5 new sources show up in
   ``log_pusher.PUSH_SOURCE_TYPES`` once ``push_sources`` is imported.
2. **Data model** \u2014 the 3 new profile fields (``replay_file_id``,
   ``otlp_signal``, ``otlp_listener_id``) round-trip through create /
   update.
3. **Source modules** \u2014 each ``generate_event`` returns a dict, and the
   replay-file ``make_iterator`` enforces the required ``replay_file_id``.
4. **OTLP request builder** \u2014 ``_build_logs_request`` produces a valid
   ``ExportLogsServiceRequest`` with the resource attributes, scope, and
   single LogRecord we expect.
5. **OTLP/HTTP transport** \u2014 a tiny stub HTTP server captures the wire
   bytes; we assert path, headers, content-type, and that the body parses
   back as the same protobuf message.
6. **OTLP/gRPC transport** \u2014 start the listeners_grpc server on an
   ephemeral port, send via ``otlp_pusher.send``, and confirm the listener
   hit pane sees the decoded export.

Design doc: docs/OTEL_LISTENER.md \u00a76.
"""
from __future__ import annotations

import collections
import json
import socket
import threading
import time

import pytest


# ── 1) Registry ─────────────────────────────────────────────────────────────

def test_push_registry_has_5_new_sources():
    """After importing push_sources the registry must include the 4 synthetic
    topics plus the replay-file source."""
    import push_sources  # noqa: F401
    import log_pusher
    expected = {
        "synthetic_endpoint",
        "synthetic_identity",
        "synthetic_cloud",
        "synthetic_network",
        "replay_file",
    }
    missing = expected - set(log_pusher.PUSH_SOURCE_TYPES)
    assert not missing, f"sources not registered: {missing}"


def test_push_registry_preserves_16_vendor_sources():
    """Adding the egress sources must not break any existing registrations."""
    import push_sources  # noqa: F401
    import log_pusher
    # Sample a handful of the v3 vendor sources \u2014 they all must still be
    # there and pointing at the same modules.
    for key, module in (
        ("paloalto",    "push_sources.paloalto"),
        ("fortigate",   "push_sources.fortigate"),
        ("sentinelone", "push_sources.sentinelone"),
        ("corelight",   "push_sources.corelight"),
        ("stamus",      "push_sources.stamus"),
    ):
        assert key in log_pusher.PUSH_SOURCE_TYPES
        assert log_pusher.PUSH_SOURCE_TYPES[key]["module"] == module


# ── 2) Data model ───────────────────────────────────────────────────────────

def test_create_profile_persists_otlp_fields(tmp_path, monkeypatch):
    """The new ``replay_file_id`` / ``otlp_signal`` / ``otlp_listener_id``
    fields must be persisted through ``create_profile``."""
    import log_pusher as lp
    monkeypatch.setattr(lp, "_PROFILES_FILE", tmp_path / "p.json")

    p = lp.create_profile({
        "name": "egress test",
        "source_type": "synthetic_endpoint",
        "transport": "otlp_http",
        "destination": {"host": "collector.example", "port": 4318, "tls": True},
        "otlp_signal": "logs",
        "otlp_listener_id": "lst_abc",
        "replay_file_id": None,
    })
    assert p["otlp_signal"] == "logs"
    assert p["otlp_listener_id"] == "lst_abc"
    assert p["replay_file_id"] is None
    # Round-trip through get_profile (re-reads from disk).
    again = lp.get_profile(p["id"])
    assert again["otlp_signal"] == "logs"
    assert again["otlp_listener_id"] == "lst_abc"


def test_update_profile_allows_changing_otlp_fields(tmp_path, monkeypatch):
    import log_pusher as lp
    monkeypatch.setattr(lp, "_PROFILES_FILE", tmp_path / "p.json")
    p = lp.create_profile({"name": "x", "source_type": "synthetic_endpoint",
                           "transport": "otlp_http"})
    upd = lp.update_profile(p["id"], {
        "otlp_listener_id": "lst_zzz",
        "replay_file_id":   "f-replay-1",
    })
    assert upd["otlp_listener_id"] == "lst_zzz"
    assert upd["replay_file_id"]   == "f-replay-1"


# ── 3) Source modules ───────────────────────────────────────────────────────

@pytest.mark.parametrize("topic", ["endpoint", "identity", "cloud", "network"])
def test_synthetic_source_modules_yield_dict(topic):
    import importlib
    mod = importlib.import_module(f"push_sources.synthetic_{topic}")
    ev = mod.generate_event()
    assert isinstance(ev, dict) and ev, f"synthetic_{topic} produced empty dict"


def test_replay_source_requires_file_id():
    import push_sources.replay_file as rf
    with pytest.raises(ValueError, match="replay_file_id"):
        list(rf.make_iterator({}))   # no file_id at all
    with pytest.raises(ValueError, match="replay file not found"):
        list(rf.make_iterator({"replay_file_id": "does-not-exist"}))


def test_replay_source_module_exposes_make_iterator():
    """Stateful source contract: must expose make_iterator AND not be usable
    via generate_event (which would silently emit the wrong file)."""
    import push_sources.replay_file as rf
    assert hasattr(rf, "make_iterator")
    with pytest.raises(NotImplementedError):
        rf.generate_event()


# ── 4) OTLP request builder ─────────────────────────────────────────────────

def test_build_logs_request_returns_valid_export_request():
    import otlp_pusher
    event = {
        "type":      "process_create",
        "severity":  "warning",
        "src_ip":    "10.1.2.3",
        "user":      "alice",
        "host":      "edr-host-01",
        "deeply": {"nested": "value"},
        "timestamp": "2026-01-15T12:34:56Z",
    }
    profile = {
        "name":        "edr-export",
        "source_type": "synthetic_endpoint",
        "otlp_signal": "logs",
    }
    req = otlp_pusher._build_logs_request(event=event, profile=profile)

    # Round-trip through the protobuf wire format \u2014 if any field is mis-
    # set the SerializeToString / ParseFromString chain would raise.
    blob = req.SerializeToString()
    assert blob, "ExportLogsServiceRequest serialised to empty bytes"

    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
    parsed = logs_service_pb2.ExportLogsServiceRequest()
    parsed.ParseFromString(blob)
    assert len(parsed.resource_logs) == 1
    rl = parsed.resource_logs[0]
    res_attrs = {kv.key: kv.value for kv in rl.resource.attributes}
    assert res_attrs["service.name"].string_value == "edr-export"
    assert res_attrs["source_type"].string_value == "synthetic_endpoint"
    assert len(rl.scope_logs) == 1
    sl = rl.scope_logs[0]
    assert sl.scope.name == "apigenie/log_pusher"
    assert len(sl.log_records) == 1
    lr = sl.log_records[0]
    assert lr.severity_text == "WARN"
    assert lr.severity_number == 13
    # Whitelisted scalar attrs land on the record itself.
    rec_attrs = {kv.key: kv.value for kv in lr.attributes}
    assert "src_ip" in rec_attrs and rec_attrs["src_ip"].string_value == "10.1.2.3"
    assert "user"   in rec_attrs and rec_attrs["user"].string_value   == "alice"
    # The "deeply" key is structured \u2014 it must NOT be promoted to an attr
    # (it's still inside the JSON body).
    assert "deeply" not in rec_attrs
    # Body is the JSON-encoded event.
    body = json.loads(lr.body.string_value)
    assert body["src_ip"] == "10.1.2.3"
    assert body["deeply"] == {"nested": "value"}
    # Timestamp parsed from the ISO field (2026-01-15T12:34:56Z = 1768480496s).
    assert 1_700_000_000 * 10**9 < lr.time_unix_nano < 2_000_000_000 * 10**9


def test_build_logs_request_truncates_giant_body():
    """Body strings longer than _MAX_BODY_STR get the ``...`` suffix."""
    import otlp_pusher
    big = "x" * (otlp_pusher._MAX_BODY_STR + 2048)
    ev = {"type": "huge", "payload": big}
    req = otlp_pusher._build_logs_request(event=ev, profile={"name": "t"})
    lr = req.resource_logs[0].scope_logs[0].log_records[0]
    assert len(lr.body.string_value) <= otlp_pusher._MAX_BODY_STR
    assert lr.body.string_value.endswith("...")


@pytest.mark.parametrize("inp,expected", [
    ("info",          ("INFO",   9)),
    ("INFORMATIONAL", ("INFO",   9)),
    ("warning",       ("WARN",  13)),
    ("error",         ("ERROR", 17)),
    ("critical",      ("FATAL", 21)),
    ("debug",         ("DEBUG",  5)),
    ("notalevel",     ("INFO",   9)),
    (3,               ("TRACE",  3)),
    (15,              ("WARN",  15)),
])
def test_severity_mapping(inp, expected):
    import otlp_pusher
    assert otlp_pusher._severity({"severity": inp}) == expected


@pytest.mark.parametrize("inp,low,high", [
    # 10-digit seconds
    (1_758_400_000,              1_758_400_000 * 10**9, 1_758_400_000 * 10**9),
    # 13-digit milliseconds
    (1_758_400_000_000,          1_758_400_000 * 10**9, 1_758_400_000 * 10**9),
    # 16-digit microseconds
    (1_758_400_000_000_000,      1_758_400_000 * 10**9, 1_758_400_000 * 10**9),
    # 19-digit nanoseconds
    (1_758_400_000_000_000_000,  1_758_400_000 * 10**9, 1_758_400_000 * 10**9),
])
def test_timestamp_unit_autodetect(inp, low, high):
    import otlp_pusher
    got = otlp_pusher._event_time_unix_nano({"timestamp": inp})
    assert low <= got <= high


def test_send_rejects_unsupported_signal():
    import otlp_pusher
    out = otlp_pusher.send(
        transport="otlp_http",
        event={"x": 1},
        dest={"host": "127.0.0.1", "port": 65535, "signal": "metrics"},
        profile={"name": "p"},
    )
    assert out["status"] == 0
    assert "unsupported_signal" in out.get("error", "")


# ── 5) OTLP/HTTP transport \u2014 stub server ─────────────────────────────────

class _StubOTLPHttpServer:
    """A throwaway HTTP server that captures one POST and ACKs it."""

    def __init__(self):
        import http.server
        self._captured: list[dict] = []
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                outer._captured.append({
                    "path":    self.path,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body":    body,
                })
                # OTLP-spec-compliant empty ack
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_a, **_kw):  # quiet
                pass

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def captured(self):
        return self._captured

    def close(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def stub_otlp_http():
    srv = _StubOTLPHttpServer()
    try:
        yield srv
    finally:
        srv.close()


def test_otlp_http_transport_posts_to_v1_logs_with_protobuf(stub_otlp_http):
    import otlp_pusher
    event = {"type": "auth.login", "severity": "info", "user": "bob"}
    out = otlp_pusher.send(
        transport="otlp_http",
        event=event,
        dest={
            "host": "127.0.0.1",
            "port": stub_otlp_http.port,
            "tls":  False,
            "path": "/v1/logs",
        },
        profile={"name": "egress", "source_type": "synthetic_identity"},
    )
    assert out["status"] == 200, out
    assert out["protocol"] == "otlp_http"
    assert out["bytes"] > 0

    assert len(stub_otlp_http.captured) == 1
    cap = stub_otlp_http.captured[0]
    assert cap["path"] == "/v1/logs"
    assert cap["headers"]["Content-Type"] == "application/x-protobuf"
    # The body must round-trip back into a valid ExportLogsServiceRequest.
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
    parsed = logs_service_pb2.ExportLogsServiceRequest()
    parsed.ParseFromString(cap["body"])
    assert len(parsed.resource_logs) == 1
    body_json = parsed.resource_logs[0].scope_logs[0].log_records[0].body.string_value
    assert json.loads(body_json)["user"] == "bob"


def test_otlp_http_transport_includes_listener_id_headers(stub_otlp_http):
    import otlp_pusher
    otlp_pusher.send(
        transport="otlp_http",
        event={"type": "x"},
        dest={
            "host": "127.0.0.1",
            "port": stub_otlp_http.port,
            "tls":  False,
            "listener_id": "lst_abc",
        },
        profile={"name": "p"},
    )
    cap = stub_otlp_http.captured[0]
    assert cap["headers"].get("X-Apigenie-Listener-Id") == "lst_abc"
    assert cap["headers"].get("X-Scope-Orgid")          == "lst_abc"


def test_otlp_http_transport_bearer_auth(stub_otlp_http):
    import otlp_pusher
    otlp_pusher.send(
        transport="otlp_http",
        event={"type": "x"},
        dest={
            "host": "127.0.0.1",
            "port": stub_otlp_http.port,
            "tls":  False,
            "auth_type":  "bearer",
            "auth_token": "tok-xyz-001",
        },
        profile={"name": "p"},
    )
    cap = stub_otlp_http.captured[0]
    assert cap["headers"].get("Authorization") == "Bearer tok-xyz-001"


# ── 6) OTLP/gRPC transport \u2014 against the real listeners_grpc server ─────

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture
def grpc_listener_server():
    """Start the real OTLP/gRPC server on an ephemeral port.

    Mirrors the fixture in tests/test_otel_listener.py so we can drive the
    push-sink listener with our outbound transport. Skipped if grpcio isn't
    installed.
    """
    import listeners_grpc
    port = _free_port()
    ok = listeners_grpc.start(port=port)
    if not ok:
        pytest.skip("OTLP gRPC server failed to start (deps missing?)")
    try:
        yield port
    finally:
        listeners_grpc.stop()


@pytest.fixture
def push_sink_listener():
    """Factory: register a push_sink listener and tear it down on exit."""
    import listeners as L
    registered: list[str] = []

    def _make(lid: str, signal: str = "logs", auth: dict | None = None):
        listener = L.Listener.from_dict({
            "id":     lid,
            "name":   f"egress-test {lid}",
            "path":   f"/v1/{signal}",
            "method": "POST",
            "codec":  "otlp_proto",
            "enabled": True,
            "auth":   auth or {"kind": "none"},
            "push_sink": {
                "protocol":            "otlp_grpc",
                "signal":              signal,
                "decode_preview":      True,
                "ack_partial_success": True,
                "max_decode_records":  5,
            },
        })
        L.LISTENERS[lid] = listener
        L.LISTENER_HITS[lid] = collections.deque(maxlen=L.HITS_MEM_CAP)
        registered.append(lid)
        return listener

    yield _make

    for lid in registered:
        import listeners as L
        L.LISTENERS.pop(lid, None)
        L.LISTENER_HITS.pop(lid, None)


def test_otlp_grpc_transport_lands_on_listener_via_metadata(
        grpc_listener_server, push_sink_listener):
    """The full outbound \u2192 inbound chain over gRPC."""
    push_sink_listener("egress-roundtrip-g1")
    import otlp_pusher
    out = otlp_pusher.send(
        transport="otlp_grpc",
        event={"type": "alert", "severity": "high", "src_ip": "10.0.0.7"},
        dest={
            "host": "127.0.0.1",
            "port": grpc_listener_server,
            "tls":  False,
            "listener_id": "egress-roundtrip-g1",
        },
        profile={"name": "roundtrip", "source_type": "synthetic_endpoint"},
    )
    assert out["status"] == 200, out
    assert out["protocol"] == "otlp_grpc"
    assert out["bytes"] > 0

    # The listener must have one decoded hit with our record.
    import listeners as L
    hits = list(L.LISTENER_HITS["egress-roundtrip-g1"])
    assert len(hits) == 1
    preview = hits[0]["otlp_preview"]
    assert preview["signal"] == "logs"
    assert preview["record_count"] == 1
    rec = preview["records"][0]
    # Severity propagated through the mapping. The decoder exposes the
    # severity_text we set on the LogRecord under the ``severity`` key
    # (see listeners_otlp.decode_preview, "logs" branch).
    assert rec["severity"] == "ERROR"   # "high" \u2192 ERROR per _SEVERITY_MAP
    # Our whitelisted attribute survived the round-trip.
    attrs = rec.get("attributes") or {}
    assert attrs.get("src_ip") == "10.0.0.7"


def test_otlp_grpc_transport_routes_via_bearer_token(
        grpc_listener_server, push_sink_listener):
    """Outbound bearer token must route the export to the matching listener."""
    push_sink_listener(
        "egress-roundtrip-g2",
        auth={"kind": "bearer", "token": "tok-egress-001"},
    )
    import otlp_pusher
    out = otlp_pusher.send(
        transport="otlp_grpc",
        event={"type": "x"},
        dest={
            "host": "127.0.0.1",
            "port": grpc_listener_server,
            "tls":  False,
            "auth_type":  "bearer",
            "auth_token": "tok-egress-001",
            # No listener_id \u2014 bearer alone must be enough to route.
        },
        profile={"name": "roundtrip", "source_type": "synthetic_endpoint"},
    )
    assert out["status"] == 200, out
    import listeners as L
    assert len(L.LISTENER_HITS["egress-roundtrip-g2"]) == 1


def test_otlp_grpc_transport_returns_status_0_when_target_dead():
    """Unreachable gRPC target must produce a structured failure, not a raise."""
    import otlp_pusher
    out = otlp_pusher.send(
        transport="otlp_grpc",
        event={"type": "x"},
        dest={
            "host": "127.0.0.1",
            "port": 1,        # almost certainly closed
            "tls":  False,
        },
        profile={"name": "p"},
    )
    assert out["status"] == 0
    assert out.get("error", "").startswith("grpc:")
    assert out["protocol"] == "otlp_grpc"


# ── End-to-end via the Log Push framework ────────────────────────────────────

def test_log_pusher_send_event_dispatches_to_otlp_pusher(stub_otlp_http):
    """``log_pusher.send_event`` must route otlp_* transports to otlp_pusher.

    This guards against future refactors silently dropping the OTLP arm of
    the dispatcher.
    """
    import log_pusher
    delivery = log_pusher.send_event(
        formatted="ignored-by-otlp",
        transport="otlp_http",
        dest={
            "host": "127.0.0.1",
            "port": stub_otlp_http.port,
            "tls":  False,
            "path": "/v1/logs",
        },
        event={"type": "from-log-pusher", "severity": "info"},
        profile={"name": "dispatch-check", "source_type": "synthetic_endpoint"},
    )
    assert delivery["protocol"] == "otlp_http"
    assert delivery["status"] == 200

    assert len(stub_otlp_http.captured) == 1
    body = stub_otlp_http.captured[0]["body"]
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
    parsed = logs_service_pb2.ExportLogsServiceRequest()
    parsed.ParseFromString(body)
    body_json = parsed.resource_logs[0].scope_logs[0].log_records[0].body.string_value
    assert json.loads(body_json)["type"] == "from-log-pusher"
