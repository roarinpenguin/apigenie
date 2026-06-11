"""End-to-end smoke for the OTLP push-sink listener.

Run inside the apigenie container:

    docker exec apigenie python /app/scripts/smoke_otlp.py

The script:
  1. Logs in to /admin as the built-in admin (reads /var/lib/apigenie/admin_pass).
  2. Creates a `push_sink` listener (smoke-otlp) for the `logs` signal.
  3. Sends an OTLP/HTTP protobuf export to /listener/smoke-otlp/v1/logs.
  4. Sends an OTLP/gRPC export to apigenie:4317 with `x-apigenie-listener-id`.
  5. Reads back /admin/api/listeners/smoke-otlp/hits and verifies both hits
     decoded into otlp_preview blocks.
  6. Deletes the listener so the smoke is idempotent.

Exit code 0 on success, non-zero on any check failure.
"""
import json
import os
import sys
import time

import requests

BASE = os.environ.get("APIGENIE_SMOKE_BASE", "http://127.0.0.1:8000")
GRPC_TARGET = os.environ.get("APIGENIE_SMOKE_GRPC", "127.0.0.1:4317")
LID = "smoke-otlp"


def _build_logs_request(n: int = 3):
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
    from opentelemetry.proto.common.v1 import common_pb2

    req = logs_service_pb2.ExportLogsServiceRequest()
    rl = req.resource_logs.add()
    rl.resource.attributes.append(
        common_pb2.KeyValue(key="service.name",
                            value=common_pb2.AnyValue(string_value="smoke-test-svc"))
    )
    rl.resource.attributes.append(
        common_pb2.KeyValue(key="deployment.environment",
                            value=common_pb2.AnyValue(string_value="dev"))
    )
    sl = rl.scope_logs.add()
    for i in range(n):
        lr = sl.log_records.add()
        lr.time_unix_nano = int(time.time() * 1e9)
        lr.severity_text = "INFO"
        lr.body.string_value = f"hello otlp #{i}"
    return req


def _admin_session():
    """Return an authenticated requests.Session for the built-in admin.

    Password resolution mirrors what app.py does at startup:
      1. ``ADMIN_PASSWORD_FILE`` if present and non-empty.
      2. ``ADMIN_PASSWORD`` env var.
      3. The literal "apigenie" (docker-compose default).
    """
    s = requests.Session()
    pwd = None
    pwd_file = os.environ.get("ADMIN_PASSWORD_FILE", "/var/lib/apigenie/admin_pass")
    try:
        with open(pwd_file) as f:
            v = f.read().strip()
            if v:
                pwd = v
    except FileNotFoundError:
        pass
    if pwd is None:
        pwd = os.environ.get("ADMIN_PASSWORD", "apigenie")
    user = os.environ.get("ADMIN_USERNAME", "admin")
    r = s.post(f"{BASE}/admin/login",
               data={"username": user, "password": pwd},
               allow_redirects=False)
    if r.status_code not in (200, 302, 303):
        raise SystemExit(f"login failed: {r.status_code} {r.text[:200]}")
    return s


def step_create_listener(s):
    # Pre-clean any leftover from a previous smoke run.
    s.delete(f"{BASE}/admin/api/listeners/{LID}")
    spec = {
        "id": LID, "name": "Smoke OTLP", "path": "/v1/logs", "method": "POST",
        "codec": "otlp_proto", "enabled": True, "auth": {"kind": "none"},
        "push_sink": {
            "protocol": "otlp_http", "signal": "logs",
            "decode_preview": True, "ack_partial_success": True,
            "max_decode_records": 5,
        },
    }
    r = s.post(f"{BASE}/admin/api/listeners",
               headers={"Content-Type": "application/json"},
               data=json.dumps(spec))
    print(f"[1] create listener: HTTP {r.status_code}")
    if r.status_code not in (200, 201):
        raise SystemExit(f"    body: {r.text[:300]}")


def step_push_http(s):
    req = _build_logs_request(n=3)
    body = req.SerializeToString()
    r = s.post(f"{BASE}/listener/{LID}/v1/logs",
               data=body,
               headers={"Content-Type": "application/x-protobuf"})
    print(f"[2] OTLP/HTTP push: HTTP {r.status_code}  size={len(body)}B  body={r.json()}")
    if r.status_code != 200 or r.json() != {"partialSuccess": {}}:
        raise SystemExit("    OTLP/HTTP ack mismatch")


def step_push_grpc():
    import grpc
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2_grpc
    req = _build_logs_request(n=2)
    channel = grpc.insecure_channel(GRPC_TARGET)
    stub = logs_service_pb2_grpc.LogsServiceStub(channel)
    try:
        resp = stub.Export(req,
                           metadata=[("x-apigenie-listener-id", LID)],
                           timeout=5.0)
        print(f"[3] OTLP/gRPC push: ack received (rejected={resp.partial_success.rejected_log_records})")
    finally:
        channel.close()


def step_verify_hits(s):
    r = s.get(f"{BASE}/admin/api/listeners/{LID}/hits")
    hits = r.json().get("hits", [])
    print(f"[4] hits recorded: {len(hits)}")
    if len(hits) < 2:
        raise SystemExit(f"    expected >=2 hits, got {len(hits)}")
    # Hits are ordered newest-first.
    methods = [h.get("method") for h in hits[:2]]
    print(f"    methods: {methods}")
    if "gRPC" not in methods or "POST" not in methods:
        raise SystemExit(f"    expected one POST and one gRPC, got {methods}")
    for h in hits[:2]:
        p = h.get("otlp_preview") or {}
        print(f"    - {h['method']:6s} status={h['status']} "
              f"signal={p.get('signal')!r} rec={p.get('record_count')} "
              f"resources[0]={p.get('resources',[{}])[0]}")
        if p.get("signal") != "logs":
            raise SystemExit("    otlp_preview.signal mismatch")
        if p.get("record_count", 0) < 1:
            raise SystemExit("    otlp_preview.record_count is zero")


def step_cleanup(s):
    s.delete(f"{BASE}/admin/api/listeners/{LID}")
    print(f"[5] cleanup: listener {LID} deleted")


def main():
    print(f"target: BASE={BASE}  GRPC={GRPC_TARGET}")
    s = _admin_session()
    step_create_listener(s)
    step_push_http(s)
    step_push_grpc()
    step_verify_hits(s)
    step_cleanup(s)
    print("SMOKE OK")


if __name__ == "__main__":
    main()
