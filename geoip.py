"""Geo-IP resolution for the admin GeoMap tab.

Hybrid lookup strategy:

  1. If ``./data/geoip/GeoLite2-City.mmdb`` is present, use the offline
     MaxMind reader (fast, no rate limits, no outbound traffic).
  2. Otherwise fall back to the public ``ip-api.com`` JSON endpoint
     (free, 45 req/min, requires outbound https). Each public IP is
     looked up at most once per process.

Loopback / RFC1918 / unparseable addresses short-circuit and are tagged
``private=True`` without ever hitting the network.

The module is import-safe even if ``maxminddb`` isn't installed: the
.mmdb path simply won't be exercised. ``httpx`` is already a project
dependency.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

_MMDB_PATH = Path(os.environ.get(
    "APIGENIE_GEOIP_DB",
    "/var/lib/apigenie/geoip/GeoLite2-City.mmdb",  # matches docker-compose ./data:/var/lib/apigenie mount
))
_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon"
_API_TIMEOUT = 4.0

# ip → resolved record (or sentinel error record); never expires within process.
_CACHE: dict[str, dict[str, Any]] = {}
_INFLIGHT: dict[str, asyncio.Event] = {}
_LOCK = asyncio.Lock()

_mmdb_reader = None  # lazy: maxminddb.Reader instance, or False if unavailable


def _load_mmdb() -> Any:
    """Return the maxminddb Reader, or False if not usable."""
    global _mmdb_reader
    if _mmdb_reader is not None:
        return _mmdb_reader
    if not _MMDB_PATH.is_file():
        _mmdb_reader = False
        return False
    try:
        import maxminddb  # type: ignore
        _mmdb_reader = maxminddb.open_database(str(_MMDB_PATH))
        log.info("geoip: using offline MaxMind DB at %s", _MMDB_PATH)
    except Exception as exc:  # noqa: BLE001 — broad on purpose
        log.warning("geoip: failed to open %s (%s) — falling back to ip-api", _MMDB_PATH, exc)
        _mmdb_reader = False
    return _mmdb_reader


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _from_mmdb(ip: str) -> dict[str, Any] | None:
    reader = _load_mmdb()
    if not reader:
        return None
    try:
        rec = reader.get(ip)
    except Exception as exc:  # noqa: BLE001
        log.debug("geoip: mmdb lookup failed for %s: %s", ip, exc)
        return None
    if not rec:
        return {"status": "unknown", "source": "mmdb"}
    country = (rec.get("country") or {}).get("names", {}).get("en")
    country_code = (rec.get("country") or {}).get("iso_code")
    city = (rec.get("city") or {}).get("names", {}).get("en")
    loc = rec.get("location") or {}
    lat = loc.get("latitude")
    lon = loc.get("longitude")
    if lat is None or lon is None:
        return {"status": "unknown", "source": "mmdb"}
    return {
        "status": "ok",
        "source": "mmdb",
        "country": country,
        "country_code": country_code,
        "city": city,
        "lat": float(lat),
        "lon": float(lon),
    }


async def _from_ipapi(ip: str) -> dict[str, Any] | None:
    try:
        async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
            r = await client.get(_API_URL.format(ip=ip))
            j = r.json()
    except Exception as exc:  # noqa: BLE001
        log.debug("geoip: ip-api lookup failed for %s: %s", ip, exc)
        return {"status": "error", "source": "ip-api", "error": str(exc)}
    if j.get("status") != "success":
        return {"status": "unknown", "source": "ip-api", "error": j.get("message")}
    return {
        "status": "ok",
        "source": "ip-api",
        "country": j.get("country"),
        "country_code": j.get("countryCode"),
        "city": j.get("city"),
        "lat": float(j["lat"]),
        "lon": float(j["lon"]),
    }


async def lookup(ip: str) -> dict[str, Any]:
    """Resolve ``ip`` to a geolocation record. Cached per-process."""
    if ip in _CACHE:
        return _CACHE[ip]
    if not _is_public(ip):
        rec = {"status": "private", "source": "local"}
        _CACHE[ip] = rec
        return rec

    # Coalesce concurrent lookups for the same IP into a single upstream call.
    async with _LOCK:
        if ip in _CACHE:
            return _CACHE[ip]
        ev = _INFLIGHT.get(ip)
        if ev is None:
            ev = asyncio.Event()
            _INFLIGHT[ip] = ev
            owner = True
        else:
            owner = False

    if not owner:
        await ev.wait()
        return _CACHE.get(ip, {"status": "unknown", "source": "coalesced"})

    try:
        rec = _from_mmdb(ip)
        if rec is None or rec.get("status") != "ok":
            api_rec = await _from_ipapi(ip)
            if api_rec is not None:
                rec = api_rec
        if rec is None:
            rec = {"status": "unknown", "source": "none"}
        _CACHE[ip] = rec
        return rec
    finally:
        async with _LOCK:
            ev = _INFLIGHT.pop(ip, None)
        if ev is not None:
            ev.set()


def cache_snapshot() -> dict[str, dict[str, Any]]:
    """Return a shallow copy of the resolution cache (for diagnostics)."""
    return dict(_CACHE)
