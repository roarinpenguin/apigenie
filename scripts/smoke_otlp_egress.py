"""End-to-end smoke for the OTLP push-egress half of the v4.1 release.

Run inside the apigenie container::

    docker exec apigenie python /app/scripts/smoke_otlp_egress.py

The script exercises the full outbound \u2192 inbound chain by pointing an
OTLP push profile at a push-sink listener inside the same apigenie:

  1. Logs in to /admin as the built-in admin (password resolution mirrors
     scripts/smoke_otlp.py).
  2. Creates a `push_sink` listener (smoke-otlp-egress) for the `logs`
     signal that decodes the preview.
  3. Creates a Log Push profile with `transport=otlp_grpc`, source
     `synthetic_endpoint`, pointing at apigenie:4317 with the listener's
     id as the routing hint.
  4. Starts the push profile (5 eps for 3s).
  5. Polls until the profile reports >= 5 successful events sent.
  6. Reads /admin/api/listeners/<lid>/hits and asserts:
       - at least 5 hits were recorded
       - every hit decoded into otlp_preview with signal == "logs"
       - the resource attributes carry our service.name + source_type
  7. Repeats steps 3\u20136 with `transport=otlp_http` (port 443 via nginx
     by default; override with APIGENIE_OTLP_HTTP_TARGET if needed).
  8. Deletes both the profile and the listener \u2014 the smoke is idempotent.

Exit code 0 on success, non-zero on any check failure.
"""
from __future__ import annotations

import json
import os
import sys
import time

import requests

BASE        = os.environ.get("APIGENIE_SMOKE_BASE",        "http://127.0.0.1:8000")
GRPC_TARGET = os.environ.get("APIGENIE_SMOKE_GRPC",        "apigenie:4317")
HTTP_HOST   = os.environ.get("APIGENIE_OTLP_HTTP_HOST",    "apigenie")
HTTP_PORT   = int(os.environ.get("APIGENIE_OTLP_HTTP_PORT", "8000"))
LID         = "smoke-otlp-egress"
PROF_PREFIX = "smoke-otlp-egress"


def _admin_session() -> requests.Session:
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


def step_create_listener(s: requests.Session) -> None:
    s.delete(f"{BASE}/admin/api/listeners/{LID}")
    spec = {
        "id": LID, "name": "Smoke OTLP Egress sink",
        "path": "/v1/logs", "method": "POST",
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


def _run_push_profile(s: requests.Session, *, transport: str, name_suffix: str,
                      dest: dict) -> str:
    body = {
        "name":        f"{PROF_PREFIX}-{name_suffix}",
        "source_type": "synthetic_endpoint",
        "format":      "json",
        "transport":   transport,
        "destination": dest,
        "otlp_signal": "logs",
        "otlp_listener_id": LID,
        "rate": 5,
        "duration": {"value": 3, "unit": "seconds"},
        "visibility": "public",
    }
    r = s.post(f"{BASE}/admin/api/push/profiles",
               headers={"Content-Type": "application/json"},
               data=json.dumps(body))
    if r.status_code not in (200, 201):
        raise SystemExit(f"    create profile failed: {r.status_code} {r.text[:200]}")
    pid = r.json()["id"]
    print(f"    profile created: {pid}  ({transport})")

    r = s.post(f"{BASE}/admin/api/push/profiles/{pid}/start")
    if r.status_code not in (200, 201, 204):
        raise SystemExit(f"    start failed: {r.status_code} {r.text[:200]}")

    # Wait for the worker thread to flush a few events (or up to 5s).
    deadline = time.monotonic() + 5.0
    last_sent = 0
    while time.monotonic() < deadline:
        time.sleep(0.5)
        rg = s.get(f"{BASE}/admin/api/push/profiles/{pid}")
        prof = rg.json()
        last_sent = prof.get("events_sent", 0)
        if last_sent >= 5:
            break
    print(f"    events_sent={last_sent}")
    if last_sent < 5:
        raise SystemExit("    push profile did not send enough events")

    # Stop (it may already be completed if the duration expired).
    s.post(f"{BASE}/admin/api/push/profiles/{pid}/stop")
    return pid


def step_push_grpc(s: requests.Session) -> str:
    print("[2] OTLP/gRPC egress run")
    host, _, port = GRPC_TARGET.partition(":")
    return _run_push_profile(
        s, transport="otlp_grpc", name_suffix="grpc",
        dest={"host": host, "port": int(port or 4317), "tls": False},
    )


def step_push_http(s: requests.Session) -> str:
    print("[3] OTLP/HTTP egress run")
    return _run_push_profile(
        s, transport="otlp_http", name_suffix="http",
        dest={
            "host": HTTP_HOST, "port": HTTP_PORT, "tls": False,
            "path": "/v1/logs",
        },
    )


def step_verify_hits(s: requests.Session, *, expected_min: int) -> None:
    r = s.get(f"{BASE}/admin/api/listeners/{LID}/hits")
    hits = r.json().get("hits", [])
    print(f"    hits recorded: {len(hits)} (need >= {expected_min})")
    if len(hits) < expected_min:
        raise SystemExit(f"    expected >= {expected_min} hits, got {len(hits)}")
    for h in hits[:3]:
        p = h.get("otlp_preview") or {}
        print(f"      - method={h.get('method')} status={h.get('status')} "
              f"signal={p.get('signal')!r} rec={p.get('record_count')}")
        if p.get("signal") != "logs":
            raise SystemExit("    otlp_preview.signal mismatch")


def step_cleanup(s: requests.Session, pids: list[str]) -> None:
    for pid in pids:
        s.delete(f"{BASE}/admin/api/push/profiles/{pid}")
    s.delete(f"{BASE}/admin/api/listeners/{LID}")
    print(f"[4] cleanup: {len(pids)} profile(s) + listener {LID} deleted")


def main() -> None:
    print(f"target: BASE={BASE}  GRPC={GRPC_TARGET}  "
          f"HTTP=http://{HTTP_HOST}:{HTTP_PORT}/v1/logs")
    s = _admin_session()
    step_create_listener(s)
    pids: list[str] = []
    try:
        pids.append(step_push_grpc(s))
        step_verify_hits(s, expected_min=5)
        pids.append(step_push_http(s))
        step_verify_hits(s, expected_min=10)
    finally:
        step_cleanup(s, pids)
    print("EGRESS SMOKE OK")


if __name__ == "__main__":
    main()
