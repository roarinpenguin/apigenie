"""Log Push Framework — actively sends generated logs to external destinations.

Supports three formats (JSON, Syslog RFC5424, CEF) and three transports
(HTTP POST, Splunk HEC, Syslog TCP/UDP). Each push profile defines a source
type, format, transport, destination, duration, and rate. Profiles are
persisted to disk and can be started/stopped at runtime.

Push profiles integrate with Log Profiles and Detection Rules — generated
events are blended with profile entities and detection patterns.
"""

from __future__ import annotations

import collections
import copy
import json
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DATA_ROOT = Path(os.getenv("APIGENIE_DATA_ROOT", "/var/lib/apigenie"))
_PROFILES_FILE = _DATA_ROOT / "push_profiles.json"
_CERTS_DIR = _DATA_ROOT / "push_certs"
_lock = threading.Lock()

# Active push threads keyed by profile ID
_active_threads: dict[str, threading.Thread] = {}
_stop_events: dict[str, threading.Event] = {}

# Per-profile event log (ring buffer, newest first)
_MAX_EVENT_LOG = 100
_event_logs: dict[str, collections.deque] = {}


def _log_event(profile_id: str, event: dict, formatted: str, success: bool,
               error: str = "", delivery: dict | None = None) -> None:
    """Record a sent event in the profile's ring buffer."""
    if profile_id not in _event_logs:
        _event_logs[profile_id] = collections.deque(maxlen=_MAX_EVENT_LOG)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "type": event.get("type", "?"),
        "subtype": event.get("subtype", ""),
        "formatted_preview": formatted[:500],
        "success": success,
        "error": error,
    }
    if delivery:
        entry["delivery"] = delivery
    _event_logs[profile_id].appendleft(entry)


def get_event_log(profile_id: str, limit: int = 50) -> list[dict]:
    """Return the last N sent events for a profile."""
    buf = _event_logs.get(profile_id, [])
    return list(buf)[:limit]


# ── Available source types (registry) ────────────────────────────────────────
# Each entry maps a key to a module path and display name.
# The module must expose: generate_event(ctx) -> dict
PUSH_SOURCE_TYPES: dict[str, dict[str, str]] = {}


def register_source(key: str, name: str, module: str, description: str = "") -> None:
    """Register a push source type."""
    PUSH_SOURCE_TYPES[key] = {"name": name, "module": module, "description": description}


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class PushDestination:
    host: str = "127.0.0.1"
    port: int = 514
    protocol: str = "tcp"          # tcp | udp (syslog transport only)
    tls: bool = False
    tls_verify: bool = False
    tls_cert_id: str | None = None  # uploaded cert ID or None for default
    path: str = "/"                 # HTTP/HEC endpoint path
    auth_type: str = "none"         # none | bearer | basic
    auth_token: str = ""
    auth_username: str = ""
    auth_password: str = ""
    hec_token: str = ""             # Splunk HEC token


@dataclass
class PushDuration:
    value: int = 1
    unit: str = "hours"             # seconds | minutes | hours | days | weeks

    def to_seconds(self) -> int:
        multipliers = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}
        return self.value * multipliers.get(self.unit, 3600)


@dataclass
class PushProfile:
    id: str = ""
    name: str = ""
    source_type: str = ""           # key into PUSH_SOURCE_TYPES
    format: str = "json"            # json | syslog | cef
    transport: str = "http"         # http | hec | syslog
    destination: PushDestination = field(default_factory=PushDestination)
    duration: PushDuration = field(default_factory=PushDuration)
    rate: int = 10                  # events per second
    profile_id: str | None = None   # Log Profile binding
    password: str | None = None     # optional protection
    status: str = "stopped"         # stopped | running | completed | error
    error: str = ""
    events_sent: int = 0
    started_at: str = ""
    created: str = ""


# ── Storage ──────────────────────────────────────────────────────────────────

def _load_profiles() -> list[dict[str, Any]]:
    try:
        if _PROFILES_FILE.is_file():
            return json.loads(_PROFILES_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("push profiles: corrupt file: %s", exc)
    return []


def _save_profiles(profiles: list[dict[str, Any]]) -> None:
    _DATA_ROOT.mkdir(parents=True, exist_ok=True)
    tmp = _PROFILES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(profiles, indent=2, default=str))
    tmp.replace(_PROFILES_FILE)


def _find_profile(profiles: list[dict], profile_id: str) -> dict | None:
    for p in profiles:
        if p["id"] == profile_id:
            return p
    return None


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_profile(data: dict[str, Any]) -> dict[str, Any]:
    profile = {
        "id": str(uuid.uuid4()),
        "name": data.get("name", "Untitled"),
        "source_type": data.get("source_type", ""),
        "format": data.get("format", "json"),
        "transport": data.get("transport", "http"),
        "destination": data.get("destination", {}),
        "duration": data.get("duration", {"value": 1, "unit": "hours"}),
        "rate": max(1, min(1000, int(data.get("rate", 10)))),
        "profile_id": data.get("profile_id"),
        "password": data.get("password") or None,
        "status": "stopped",
        "error": "",
        "events_sent": 0,
        "started_at": "",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with _lock:
        profiles = _load_profiles()
        profiles.append(profile)
        _save_profiles(profiles)
    log.info("Push profile created: %s (%s)", profile["name"], profile["id"])
    return profile


def get_profile(profile_id: str) -> dict[str, Any] | None:
    for p in _load_profiles():
        if p["id"] == profile_id:
            return p
    return None


def update_profile(profile_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
    with _lock:
        profiles = _load_profiles()
        p = _find_profile(profiles, profile_id)
        if not p:
            return None
        for key in ("name", "source_type", "format", "transport", "destination",
                     "duration", "rate", "profile_id", "password"):
            if key in data:
                p[key] = data[key]
        if "rate" in data:
            p["rate"] = max(1, min(1000, int(data["rate"])))
        _save_profiles(profiles)
    return p


def delete_profile(profile_id: str) -> bool:
    stop_push(profile_id)
    with _lock:
        profiles = _load_profiles()
        before = len(profiles)
        profiles = [p for p in profiles if p["id"] != profile_id]
        if len(profiles) == before:
            return False
        _save_profiles(profiles)
    return True


def list_profiles() -> list[dict[str, Any]]:
    profiles = _load_profiles()
    # Sync runtime status
    for p in profiles:
        pid = p["id"]
        if pid in _active_threads and _active_threads[pid].is_alive():
            p["status"] = "running"
        elif p["status"] == "running":
            p["status"] = "completed"
    return profiles


# ── Certificate management ───────────────────────────────────────────────────

def upload_cert(cert_data: bytes, name: str = "custom") -> str:
    """Store a TLS certificate. Returns the cert ID."""
    _CERTS_DIR.mkdir(parents=True, exist_ok=True)
    cert_id = str(uuid.uuid4())[:8]
    cert_path = _CERTS_DIR / f"{cert_id}.pem"
    cert_path.write_bytes(cert_data)
    log.info("Push cert uploaded: %s (%s)", name, cert_id)
    return cert_id


def get_cert_path(cert_id: str | None) -> str | None:
    if not cert_id:
        return None
    p = _CERTS_DIR / f"{cert_id}.pem"
    return str(p) if p.is_file() else None


def get_tls_info(profile_id: str) -> dict[str, Any]:
    """Return TLS certificate details for a push profile."""
    profile = get_profile(profile_id)
    if not profile:
        return {"error": "profile not found"}
    dest = profile.get("destination", {})
    if not dest.get("tls"):
        return {"tls_enabled": False}
    cert_id = dest.get("tls_cert_id")
    cert_path = get_cert_path(cert_id)
    info: dict[str, Any] = {"tls_enabled": True, "cert_type": "uploaded" if cert_id else "system-default"}
    if cert_path:
        try:
            import subprocess
            out = subprocess.check_output(
                ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-dates", "-fingerprint"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode()
            for line in out.strip().split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip().lower().replace(" ", "_")] = v.strip()
        except Exception:
            info["cert_file"] = cert_path
    return info


# ── Formatters ───────────────────────────────────────────────────────────────

def _format_json(event: dict[str, Any]) -> str:
    """Format event as JSON line."""
    return json.dumps(event, default=str)


def _format_syslog_rfc5424(event: dict[str, Any], source_type: str = "") -> str:
    """Format event as RFC5424 syslog message.

    <priority>version timestamp hostname app-name procid msgid structured-data msg
    """
    severity = event.get("severity", "informational")
    sev_map = {"critical": 2, "high": 3, "error": 3, "warning": 4, "medium": 4,
               "low": 5, "notice": 5, "informational": 6, "info": 6, "debug": 7}
    sev_num = sev_map.get(str(severity).lower(), 6)
    facility = 1  # user-level
    pri = facility * 8 + sev_num

    ts = event.get("timestamp") or event.get("receive_time") or datetime.now(timezone.utc).isoformat()
    if isinstance(ts, (int, float)):
        ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    hostname = event.get("hostname") or event.get("device_name") or event.get("serial") or "-"
    app_name = source_type or event.get("type", "apigenie")
    procid = str(event.get("pid", os.getpid()))
    msgid = event.get("subtype") or event.get("eventType") or "-"

    # Structured data
    sd = '-'
    msg = json.dumps(event, default=str)

    return f"<{pri}>1 {ts} {hostname} {app_name} {procid} {msgid} {sd} {msg}"


def _format_cef(event: dict[str, Any], source_type: str = "") -> str:
    """Format event as CEF (Common Event Format).

    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    vendor = event.get("vendor", "ApiGenie")
    product = event.get("product") or source_type or "MockDevice"
    version = event.get("device_version", "1.0")
    sig_id = event.get("signature_id") or event.get("threat_id") or event.get("subtype") or "0"
    name = event.get("event_name") or event.get("type") or event.get("action") or "event"
    severity_raw = event.get("severity", "5")
    sev_map = {"critical": 10, "high": 8, "error": 7, "warning": 5, "medium": 5,
               "low": 3, "informational": 1, "info": 1}
    if isinstance(severity_raw, str):
        severity = sev_map.get(severity_raw.lower(), 5)
    else:
        severity = int(severity_raw)

    # Build extension key=value pairs
    skip_keys = {"vendor", "product", "device_version", "signature_id", "event_name", "severity"}
    ext_parts = []
    for k, v in event.items():
        if k in skip_keys or v is None:
            continue
        # CEF key mapping
        ck = k.replace(" ", "")
        if isinstance(v, dict):
            v = json.dumps(v, default=str)
        sv = str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")
        ext_parts.append(f"{ck}={sv}")

    ext = " ".join(ext_parts)

    # Escape pipe chars in header fields
    def esc(s):
        return str(s).replace("\\", "\\\\").replace("|", "\\|")

    return f"CEF:0|{esc(vendor)}|{esc(product)}|{esc(version)}|{esc(sig_id)}|{esc(name)}|{severity}|{ext}"


def format_event(event: dict[str, Any], fmt: str, source_type: str = "") -> str:
    """Format an event dict into the specified format string."""
    if fmt == "syslog":
        return _format_syslog_rfc5424(event, source_type)
    elif fmt == "cef":
        return _format_cef(event, source_type)
    else:
        return _format_json(event)


# ── Transports ───────────────────────────────────────────────────────────────

def _clean_host(raw: str) -> str:
    """Strip scheme and trailing slash from a host that may contain https://."""
    h = raw.strip()
    for prefix in ("https://", "http://"):
        if h.lower().startswith(prefix):
            h = h[len(prefix):]
    return h.rstrip("/")


def _send_http(payload: str, dest: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Send payload via HTTP POST. Returns delivery confirmation.

    Uses http.client for reliable TLS handling (urllib.request has issues
    with some envoy-fronted endpoints like Observo HEC).
    """
    import http.client

    host = _clean_host(dest["host"])
    port = int(dest.get("port", 443))
    path = dest.get("path", "/")
    use_tls = dest.get("tls", False)
    url = f"{'https' if use_tls else 'http'}://{host}:{port}{path}"

    hdrs = {"Content-Type": "application/json", "User-Agent": "ApiGenie-LogPusher/1.0"}
    if headers:
        hdrs.update(headers)

    auth_type = dest.get("auth_type", "none")
    if auth_type == "bearer" and dest.get("auth_token"):
        hdrs["Authorization"] = f"Bearer {dest['auth_token']}"
    elif auth_type == "basic" and dest.get("auth_username"):
        import base64
        cred = base64.b64encode(f"{dest['auth_username']}:{dest['auth_password']}".encode()).decode()
        hdrs["Authorization"] = f"Basic {cred}"

    data = payload.encode("utf-8")

    if use_tls:
        ctx = ssl.create_default_context()
        cert_path = get_cert_path(dest.get("tls_cert_id"))
        if cert_path:
            ctx.load_verify_locations(cert_path)
        if not dest.get("tls_verify", False):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=10)

    try:
        conn.request("POST", path, body=data, headers=hdrs)
        resp = conn.getresponse()
        resp.read()  # drain response body
        return {"protocol": "http", "status": resp.status, "bytes": len(data), "url": url}
    finally:
        conn.close()


def _send_hec(payload: str, dest: dict[str, Any]) -> dict[str, Any]:
    """Send payload via HTTP Event Collector (Splunk, S1, Observo, generic).

    Auto-detects the HEC flavour from the host or path and adjusts
    auth scheme and payload wrapping accordingly:
      - sentinelone.net  → Bearer auth, raw JSON body (newline-delimited)
      - observo.ai       → Bearer auth, raw JSON body
      - everything else  → Splunk auth, {"event": ..., "sourcetype": ...}
    """
    token = dest.get("hec_token") or dest.get("auth_token") or ""
    host = dest.get("host", "").lower().strip()
    for _p in ("https://", "http://"):
        if host.startswith(_p):
            host = host[len(_p):]
    host = host.rstrip("/")
    path = dest.get("path", "/")

    # Determine HEC flavour from stored preference, fallback to host detection
    flavour = dest.get("hec_flavour", "")
    if not flavour:
        if "sentinelone" in host and "ingest." not in host:
            flavour = "s1_siem"
        elif "sentinelone" in host and "ingest." in host:
            flavour = "s1_dpm"
        else:
            flavour = "splunk"

    # Auth header — S1 AI SIEM uses Bearer + S1-Scope; everything else uses Splunk
    if flavour == "s1_siem":
        hec_headers = {"Authorization": f"Bearer {token}"}
        try:
            import s1_detection_library
            acct = s1_detection_library.get_account_id()
            if acct:
                hec_headers["S1-Scope"] = acct
        except Exception:
            pass
    else:
        # Splunk auth for S1 DPM (Observo), Splunk, and generic HEC
        hec_headers = {"Authorization": f"Splunk {token}"}

    # Path defaults — S1 HEC is Splunk-compatible (accepts /services/collector/event and /raw)
    if path == "/" or not path:
        path = "/services/collector/event"

    # Payload wrapping — Splunk envelope for all HEC targets
    hec_body = json.dumps({"event": payload, "sourcetype": "_json", "time": time.time()})

    hec_dest = dict(dest, path=path, auth_type="none")
    result = _send_http(hec_body, hec_dest, headers=hec_headers)
    result["protocol"] = "hec"
    result["hec_flavour"] = flavour
    return result


def _send_syslog(payload: str, dest: dict[str, Any]) -> dict[str, Any]:
    """Send payload via syslog (TCP or UDP). Returns delivery confirmation."""
    host = dest["host"]
    port = dest["port"]
    protocol = dest.get("protocol", "tcp")
    use_tls = dest.get("tls", False)

    msg = payload.encode("utf-8") + b"\n"

    if protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(msg, (host, port))
        return {"protocol": "udp", "bytes": len(msg), "confirmed": False, "note": "UDP is fire-and-forget"}
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        if use_tls:
            ctx = ssl.create_default_context()
            cert_path = get_cert_path(dest.get("tls_cert_id"))
            if cert_path:
                ctx.load_verify_locations(cert_path)
            if not dest.get("tls_verify", False):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        try:
            sock.connect((host, port))
            sock.sendall(msg)
            return {"protocol": f"tcp{'+tls' if use_tls else ''}", "bytes": len(msg), "confirmed": True}
        finally:
            sock.close()


def send_event(formatted: str, transport: str, dest: dict[str, Any]) -> dict[str, Any]:
    """Send a formatted event string via the specified transport. Returns delivery info."""
    if transport == "hec":
        return _send_hec(formatted, dest)
    elif transport == "syslog":
        return _send_syslog(formatted, dest)
    else:
        return _send_http(formatted, dest)


# ── Push execution engine ────────────────────────────────────────────────────

def _load_source_module(source_type: str):
    """Dynamically import and return the push source module."""
    info = PUSH_SOURCE_TYPES.get(source_type)
    if not info:
        raise ValueError(f"Unknown push source type: {source_type}")
    import importlib
    return importlib.import_module(info["module"])


def _push_loop(profile_id: str) -> None:
    """Main push loop for a profile. Runs in a background thread."""
    import detection_rules
    import profiles as log_profiles

    # Observability hooks — import lazily to avoid circular deps
    try:
        from trace import REQUEST_TRACE, AGG
        import telemetry
        _obs = True
    except Exception:
        _obs = False

    profile = get_profile(profile_id)
    if not profile:
        return

    source_type = profile["source_type"]
    source_key = f"push_{source_type}"
    fmt = profile["format"]
    transport = profile["transport"]
    dest = profile["destination"]
    rate = max(1, profile.get("rate", 10))
    duration_secs = PushDuration(**profile.get("duration", {})).to_seconds()
    stop_event = _stop_events.get(profile_id)

    try:
        mod = _load_source_module(source_type)
    except Exception as exc:
        log.error("Push %s: failed to load source %s: %s", profile_id, source_type, exc)
        _update_status(profile_id, "error", error=str(exc))
        return

    # Get log profile context if bound
    ctx = None
    if profile.get("profile_id"):
        ctx = log_profiles.get_context(source_type)

    # Ensure trace deque exists for this push source
    if _obs and source_key not in REQUEST_TRACE:
        REQUEST_TRACE[source_key] = collections.deque(maxlen=200)

    interval = 1.0 / rate
    deadline = time.monotonic() + duration_secs
    events_sent = 0
    errors = 0
    dest_label = f"{dest.get('host', '?')}:{dest.get('port', '?')}"

    log.info("Push %s started: %s → %s (%s/%s, %d eps, %ds)",
             profile_id[:8], source_type, dest_label, fmt, transport, rate, duration_secs)

    _update_status(profile_id, "running", started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    while time.monotonic() < deadline:
        if stop_event and stop_event.is_set():
            break

        t0 = time.monotonic()
        try:
            event = mod.generate_event(ctx=ctx)
            batch = detection_rules.inject_detection_events(source_type, [event])
            for ev in batch:
                formatted = format_event(ev, fmt, source_type)
                delivery = send_event(formatted, transport, dest)
                events_sent += 1
                _log_event(profile_id, ev, formatted, True, delivery=delivery)

                # Record in observability
                if _obs:
                    ts_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    duration_ms = int((time.monotonic() - t0) * 1000)
                    REQUEST_TRACE[source_key].appendleft({
                        "ts": ts_iso,
                        "method": "PUSH",
                        "path": f"→ {dest_label}",
                        "query": "",
                        "status": 200,
                        "duration_ms": duration_ms,
                        "client": dest.get("host", "?"),
                        "req_headers": {"transport": transport, "format": fmt},
                        "req_body": "",
                        "resp_size": len(formatted),
                        "resp_preview": formatted[:200],
                        "user_agent": f"push/{source_type}",
                    })
                    telemetry.record(source_key)
                    agg_key = (dest.get("host", "0.0.0.0"), source_key)
                    if agg_key not in AGG:
                        AGG[agg_key] = {"total": 0}
                    AGG[agg_key]["total"] += 1

        except Exception as exc:
            errors += 1
            _log_event(profile_id, event if 'event' in dir() else {}, "", False, str(exc))
            log.warning("Push %s send error: %s", profile_id[:8], exc)
            if stop_event:
                stop_event.wait(2)
            else:
                time.sleep(2)
            continue

        if stop_event:
            stop_event.wait(interval)
        else:
            time.sleep(interval)

    status = "stopped" if (stop_event and stop_event.is_set()) else "completed"
    _update_status(profile_id, status, events_sent=events_sent)
    log.info("Push %s %s after %d events (%d errors)", profile_id[:8], status, events_sent, errors)


def _update_status(profile_id: str, status: str, **kwargs) -> None:
    """Update a profile's runtime status in the persisted file."""
    with _lock:
        profiles = _load_profiles()
        p = _find_profile(profiles, profile_id)
        if p:
            p["status"] = status
            for k, v in kwargs.items():
                p[k] = v
            _save_profiles(profiles)


# ── Start / Stop ─────────────────────────────────────────────────────────────

def start_push(profile_id: str, password: str | None = None) -> dict[str, Any] | str:
    """Start pushing logs for a profile. Returns the profile or an error string."""
    profile = get_profile(profile_id)
    if not profile:
        return "Profile not found"
    if profile.get("password") and profile["password"] != password:
        return "Invalid password"
    if profile_id in _active_threads and _active_threads[profile_id].is_alive():
        return "Already running"

    stop_event = threading.Event()
    _stop_events[profile_id] = stop_event
    t = threading.Thread(target=_push_loop, args=(profile_id,), daemon=True,
                         name=f"push-{profile_id[:8]}")
    _active_threads[profile_id] = t
    t.start()
    return profile


def stop_push(profile_id: str) -> bool:
    """Stop a running push. Returns True if it was running."""
    ev = _stop_events.pop(profile_id, None)
    if ev:
        ev.set()
    t = _active_threads.pop(profile_id, None)
    if t and t.is_alive():
        t.join(timeout=5)
        _update_status(profile_id, "stopped")
        return True
    return False


def get_status(profile_id: str) -> dict[str, Any]:
    """Return runtime status for a profile."""
    profile = get_profile(profile_id)
    if not profile:
        return {"error": "not found"}
    running = profile_id in _active_threads and _active_threads[profile_id].is_alive()
    return {
        "id": profile_id,
        "status": "running" if running else profile.get("status", "stopped"),
        "events_sent": profile.get("events_sent", 0),
        "started_at": profile.get("started_at", ""),
    }
