"""System resource monitor — collects CPU, memory, disk, and container stats.

Uses /proc for host metrics and the Docker socket for per-container stats.
No external dependencies (no psutil). Stores a rolling window of samples
in memory for the admin UI time-series charts.
"""

import json
import logging
import os
import socket
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_stop_event = threading.Event()

POLL_INTERVAL = int(os.environ.get("SYSMON_INTERVAL", "30"))
MAX_SAMPLES = int(os.environ.get("SYSMON_MAX_SAMPLES", "2880"))  # ~24h at 30s

# Ring buffer: list of {ts, cpu, memory, disk, containers}
SAMPLES: deque[dict[str, Any]] = deque(maxlen=MAX_SAMPLES)

DOCKER_SOCKET = "/var/run/docker.sock"


# ── /proc-based host metrics (works inside containers if /proc is host's) ────

def _read_proc_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


_prev_cpu: dict[str, int] = {}


def _cpu_percent() -> float:
    """Calculate CPU usage % from /proc/stat delta."""
    global _prev_cpu
    raw = _read_proc_file("/proc/stat")
    if not raw:
        return 0.0
    first_line = raw.split("\n")[0]  # "cpu  user nice system idle iowait irq softirq ..."
    parts = first_line.split()
    if len(parts) < 5:
        return 0.0
    vals = [int(x) for x in parts[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    total = sum(vals)

    if not _prev_cpu:
        _prev_cpu = {"idle": idle, "total": total}
        return 0.0

    d_idle = idle - _prev_cpu["idle"]
    d_total = total - _prev_cpu["total"]
    _prev_cpu = {"idle": idle, "total": total}

    if d_total == 0:
        return 0.0
    return round((1.0 - d_idle / d_total) * 100, 1)


def _memory_info() -> dict[str, Any]:
    """Parse /proc/meminfo for total, available, used."""
    raw = _read_proc_file("/proc/meminfo")
    if not raw:
        return {"total_mb": 0, "used_mb": 0, "available_mb": 0, "percent": 0}
    info: dict[str, int] = {}
    for line in raw.split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0].rstrip(":")
            try:
                info[key] = int(parts[1])  # kB
            except ValueError:
                pass
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    used = total - available
    pct = round(used / total * 100, 1) if total > 0 else 0
    return {
        "total_mb": round(total / 1024),
        "used_mb": round(used / 1024),
        "available_mb": round(available / 1024),
        "percent": pct,
    }


def _disk_info() -> dict[str, Any]:
    """Get disk usage for the data volume."""
    try:
        stat = os.statvfs("/var/lib/apigenie")
        total = stat.f_frsize * stat.f_blocks
        free = stat.f_frsize * stat.f_bavail
        used = total - free
        pct = round(used / total * 100, 1) if total > 0 else 0
        return {
            "total_gb": round(total / (1024 ** 3), 1),
            "used_gb": round(used / (1024 ** 3), 1),
            "free_gb": round(free / (1024 ** 3), 1),
            "percent": pct,
        }
    except OSError:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}


# ── Docker API via Unix socket ───────────────────────────────────────────────

class _DockerSocketHandler(urllib.request.AbstractHTTPHandler):
    """urllib handler that speaks HTTP over a Unix domain socket."""

    def http_open(self, req):
        return self.do_open(_DockerHTTPConnection, req)


class _DockerHTTPConnection:
    """Minimal HTTP connection over a Unix socket."""

    def __init__(self, host, **kwargs):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(DOCKER_SOCKET)
        self._sock.settimeout(5)

    def request(self, method, url, body=None, headers=None):
        req = f"{method} {url} HTTP/1.0\r\nHost: localhost\r\n"
        if headers:
            for k, v in headers.items():
                req += f"{k}: {v}\r\n"
        req += "\r\n"
        self._sock.sendall(req.encode())
        if body:
            self._sock.sendall(body if isinstance(body, bytes) else body.encode())

    def getresponse(self):
        data = b""
        while True:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            data += chunk
        self._sock.close()
        return _DockerResponse(data)


class _DockerResponse:
    def __init__(self, raw: bytes):
        text = raw.decode("utf-8", errors="replace")
        parts = text.split("\r\n\r\n", 1)
        self.status = 200
        self.body = parts[1] if len(parts) > 1 else ""
        # Parse status from first line
        first_line = parts[0].split("\r\n")[0] if parts else ""
        if "200" in first_line:
            self.status = 200
        elif "404" in first_line:
            self.status = 404
        elif "500" in first_line:
            self.status = 500


def _docker_get(path: str) -> dict | list | None:
    """Make a GET request to the Docker daemon via Unix socket."""
    if not os.path.exists(DOCKER_SOCKET):
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(DOCKER_SOCKET)
        sock.settimeout(5)
        req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode())
        data = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
        sock.close()
        text = data.decode("utf-8", errors="replace")
        body = text.split("\r\n\r\n", 1)[-1]
        # Handle chunked transfer encoding
        if "Transfer-Encoding: chunked" in text.split("\r\n\r\n")[0]:
            decoded = []
            while body:
                line_end = body.find("\r\n")
                if line_end < 0:
                    break
                size_str = body[:line_end].strip()
                if not size_str:
                    body = body[line_end + 2:]
                    continue
                chunk_size = int(size_str, 16)
                if chunk_size == 0:
                    break
                decoded.append(body[line_end + 2:line_end + 2 + chunk_size])
                body = body[line_end + 2 + chunk_size + 2:]
            body = "".join(decoded)
        return json.loads(body)
    except Exception:
        return None


def _container_stats() -> list[dict[str, Any]]:
    """Get per-container resource usage from Docker API (apigenie containers only)."""
    containers = _docker_get("/containers/json")
    if not containers or not isinstance(containers, list):
        return []
    results = []
    for c in containers:
        name = (c.get("Names") or ["/unknown"])[0].lstrip("/")
        # Only include apigenie-related containers
        if not name.startswith("apigenie"):
            continue
        state = c.get("State", "unknown")
        cid = c.get("Id", "")[:12]
        # Get stats (one-shot, not streaming)
        stats = _docker_get(f"/containers/{cid}/stats?stream=false")
        mem_usage = 0
        mem_limit = 0
        cpu_pct = 0.0
        if stats and isinstance(stats, dict):
            mem = stats.get("memory_stats", {})
            mem_usage = mem.get("usage", 0)
            mem_limit = mem.get("limit", 0)
            # CPU calculation
            cpu = stats.get("cpu_stats", {})
            precpu = stats.get("precpu_stats", {})
            cpu_total = cpu.get("cpu_usage", {}).get("total_usage", 0)
            precpu_total = precpu.get("cpu_usage", {}).get("total_usage", 0)
            sys_total = cpu.get("system_cpu_usage", 0)
            presys_total = precpu.get("system_cpu_usage", 0)
            num_cpus = cpu.get("online_cpus", 1) or 1
            d_cpu = cpu_total - precpu_total
            d_sys = sys_total - presys_total
            if d_sys > 0 and d_cpu > 0:
                cpu_pct = round((d_cpu / d_sys) * num_cpus * 100, 2)

        results.append({
            "name": name,
            "state": state,
            "cpu_percent": cpu_pct,
            "memory_mb": round(mem_usage / (1024 * 1024), 1),
            "memory_limit_mb": round(mem_limit / (1024 * 1024)) if mem_limit else 0,
            "memory_percent": round(mem_usage / mem_limit * 100, 1) if mem_limit else 0,
        })
    return results


# ── Collector loop ────────────────────────────────────────────────────────────

def _collect() -> dict[str, Any]:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "ts": ts,
        "cpu_percent": _cpu_percent(),
        "memory": _memory_info(),
        "disk": _disk_info(),
        "containers": _container_stats(),
    }


def _monitor_loop() -> None:
    logger.info("[sysmon] Started (interval=%ds, max_samples=%d)", POLL_INTERVAL, MAX_SAMPLES)
    # Initial CPU read (needs two reads for delta)
    _cpu_percent()
    time.sleep(1)

    while not _stop_event.is_set():
        try:
            sample = _collect()
            SAMPLES.append(sample)
        except Exception as exc:
            logger.debug("[sysmon] Collection error: %s", exc)
        _stop_event.wait(POLL_INTERVAL)

    logger.info("[sysmon] Stopped")


def start() -> None:
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(target=_monitor_loop, name="sysmon", daemon=True)
    _thread.start()


def stop() -> None:
    _stop_event.set()
    if _thread:
        _thread.join(timeout=5)


def get_samples(limit: int = 0) -> list[dict[str, Any]]:
    """Return samples, optionally limited to the most recent N."""
    data = list(SAMPLES)
    if limit > 0:
        data = data[-limit:]
    return data


def get_latest() -> dict[str, Any] | None:
    """Return the most recent sample."""
    return SAMPLES[-1] if SAMPLES else None
