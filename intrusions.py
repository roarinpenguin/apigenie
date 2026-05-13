"""Intrusion tracking — captures requests to unrecognised paths.

Scanners, bots, and attackers that probe paths like /wp-admin, /.env,
/actuator, /phpmyadmin etc. are logged here with full request details,
reverse DNS, and geo info.  The admin UI "Intrusions" tab surfaces this
data and offers one-click IP banning.
"""

from __future__ import annotations

import collections
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ── Ring buffer of intrusion entries (newest first) ──────────────────────────
_MAX_ENTRIES = 500
INTRUSION_LOG: collections.deque[dict[str, Any]] = collections.deque(maxlen=_MAX_ENTRIES)

# ── Per-IP aggregation ───────────────────────────────────────────────────────
# ip → {count, first_ts, last_ts, paths: set, rdns, geo, user_agents: set}
_IP_AGG_CAP = 1000
IP_AGG: collections.OrderedDict[str, dict[str, Any]] = collections.OrderedDict()
_AGG_LOCK = threading.Lock()

# ── Reverse DNS cache ────────────────────────────────────────────────────────
_RDNS_CACHE: dict[str, str] = {}
_RDNS_LOCK = threading.Lock()


def _reverse_dns(ip: str) -> str:
    """Cached reverse DNS lookup. Returns hostname or '' on failure."""
    with _RDNS_LOCK:
        if ip in _RDNS_CACHE:
            return _RDNS_CACHE[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        host = ""
    with _RDNS_LOCK:
        # Cap cache size
        if len(_RDNS_CACHE) > 5000:
            _RDNS_CACHE.clear()
        _RDNS_CACHE[ip] = host
    return host


# ── Known suspicious path patterns ──────────────────────────────────────────
EXPLOIT_PATTERNS = [
    "/.env", "/.git", "/.aws", "/.ssh", "/.docker",
    "/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "/wordpress",
    "/phpmyadmin", "/pma", "/myadmin", "/mysql",
    "/actuator", "/jolokia", "/metrics", "/debug",
    "/cgi-bin", "/shell", "/cmd", "/exec",
    "/config", "/backup", "/.htaccess", "/.htpasswd",
    "/phpinfo", "/info.php", "/test.php",
    "/vendor", "/node_modules", "/package.json",
    "/xmlrpc", "/wp-json",
    "/solr", "/admin/console", "/manager/html",
    "/telescope", "/laravel", "/artisan",
    "/api/v1/pods", "/api/v1/namespaces",  # k8s
    "/login.action", "/struts",  # Java
    "/.well-known/security.txt",
]


def classify_path(path: str) -> str:
    """Return a threat category for the path, or 'unknown' if unclassified."""
    pl = path.lower()
    if any(pl.startswith(p) or pl == p for p in [
        "/.env", "/.git", "/.aws", "/.ssh", "/.docker",
        "/.htaccess", "/.htpasswd",
    ]):
        return "credential_theft"
    if any(pl.startswith(p) for p in [
        "/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "/wordpress",
        "/xmlrpc", "/wp-json",
    ]):
        return "wordpress_scan"
    if any(pl.startswith(p) for p in [
        "/phpmyadmin", "/pma", "/myadmin", "/mysql",
        "/phpinfo", "/info.php", "/test.php",
    ]):
        return "php_scan"
    if any(pl.startswith(p) for p in [
        "/actuator", "/jolokia", "/metrics", "/debug",
        "/telescope", "/laravel", "/artisan",
    ]):
        return "framework_probe"
    if any(pl.startswith(p) for p in [
        "/cgi-bin", "/shell", "/cmd", "/exec",
        "/login.action", "/struts",
    ]):
        return "rce_attempt"
    if any(pl.startswith(p) for p in [
        "/solr", "/admin/console", "/manager/html",
    ]):
        return "admin_panel_scan"
    if any(pl.startswith(p) for p in [
        "/api/v1/pods", "/api/v1/namespaces",
    ]):
        return "k8s_probe"
    if any(pl.startswith(p) for p in [
        "/config", "/backup", "/vendor", "/node_modules", "/package.json",
    ]):
        return "info_disclosure"
    return "unknown_path"


def record(*, ip: str, method: str, path: str, query: str,
           status: int, headers: dict[str, str], body: str,
           duration_ms: int, user_agent: str) -> None:
    """Record an intrusion attempt."""
    ts_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    category = classify_path(path)
    rdns = _reverse_dns(ip)

    # Try geo lookup if available
    geo = ""
    try:
        import geoip
        info = geoip.lookup(ip)
        if info:
            parts = []
            if info.get("city"):
                parts.append(info["city"])
            if info.get("country"):
                parts.append(info["country"])
            geo = ", ".join(parts) if parts else ""
    except Exception:
        pass

    entry = {
        "ts": ts_iso,
        "ip": ip,
        "method": method,
        "path": path,
        "query": query,
        "status": status,
        "user_agent": user_agent,
        "category": category,
        "rdns": rdns,
        "geo": geo,
        "headers": headers,
        "body": body[:500],
        "duration_ms": duration_ms,
    }
    INTRUSION_LOG.appendleft(entry)

    # Aggregate per IP
    with _AGG_LOCK:
        agg = IP_AGG.get(ip)
        if agg is None:
            agg = {
                "count": 0, "first_ts": ts_iso, "last_ts": ts_iso,
                "paths": set(), "user_agents": set(),
                "categories": set(),
                "rdns": rdns, "geo": geo,
            }
            IP_AGG[ip] = agg
            while len(IP_AGG) > _IP_AGG_CAP:
                IP_AGG.popitem(last=False)
        else:
            IP_AGG.move_to_end(ip)
        agg["count"] += 1
        agg["last_ts"] = ts_iso
        agg["paths"].add(path)
        agg["user_agents"].add(user_agent[:100])
        agg["categories"].add(category)
        if rdns and not agg["rdns"]:
            agg["rdns"] = rdns
        if geo and not agg["geo"]:
            agg["geo"] = geo


def get_log(limit: int = 200) -> list[dict[str, Any]]:
    """Return the most recent intrusion entries."""
    return list(INTRUSION_LOG)[:limit]


def get_top_offenders(limit: int = 50) -> list[dict[str, Any]]:
    """Return IPs sorted by attempt count (descending)."""
    with _AGG_LOCK:
        items = []
        for ip, agg in IP_AGG.items():
            items.append({
                "ip": ip,
                "count": agg["count"],
                "first_ts": agg["first_ts"],
                "last_ts": agg["last_ts"],
                "rdns": agg["rdns"],
                "geo": agg["geo"],
                "paths": sorted(agg["paths"])[:20],
                "user_agents": sorted(agg["user_agents"])[:5],
                "categories": sorted(agg["categories"]),
            })
    items.sort(key=lambda x: x["count"], reverse=True)
    return items[:limit]


def get_stats() -> dict[str, Any]:
    """Summary statistics."""
    with _AGG_LOCK:
        total_ips = len(IP_AGG)
        total_attempts = sum(a["count"] for a in IP_AGG.values())
        cats: dict[str, int] = {}
        for a in IP_AGG.values():
            for c in a["categories"]:
                cats[c] = cats.get(c, 0) + a["count"]
    return {
        "total_unique_ips": total_ips,
        "total_attempts": total_attempts,
        "log_entries": len(INTRUSION_LOG),
        "categories": dict(sorted(cats.items(), key=lambda x: -x[1])),
    }
