"""Network telemetry — Zeek-style flow + protocol events.

Each record is a connection log enriched with one of the common Zeek
protocol logs (dns / http / ssl / ssh) when applicable. Field names match
Zeek's TSV/JSON output so a Lua collector parsing real Zeek logs can be
pointed at this listener with no schema changes.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

from sources.synthetic import seeded_uuid

# (service, dest_port, weight)
_SERVICES = [
    ("http",   80,    0.20),
    ("ssl",    443,   0.42),
    ("dns",    53,    0.18),
    ("ssh",    22,    0.05),
    ("smb",    445,   0.04),
    ("rdp",    3389,  0.02),
    ("ftp",    21,    0.01),
    ("ldap",   389,   0.02),
    ("ntp",    123,   0.03),
    ("smtp",   25,    0.03),
]
_PROTOS = ["tcp", "tcp", "tcp", "udp"]  # heavily TCP-biased

_INTERNAL_PREFIX = ("10.0.", "10.1.", "192.168.", "172.16.")
_HTTP_HOSTS = [
    "api.acme.com", "www.acme.com", "github.com", "raw.githubusercontent.com",
    "registry.npmjs.org", "pypi.org", "auth.okta.com", "login.microsoftonline.com",
    "graph.microsoft.com", "s3.amazonaws.com", "storage.googleapis.com",
]
_DNS_QUERIES = [
    "api.acme.com", "telemetry.acme.com", "evil.example.invalid",
    "google.com", "cdn.example.com", "update.microsoft.com",
    "sentinelone.net", "okta.com", "github.io",
]
_SSL_SNIS = _HTTP_HOSTS  # SNIs match the same set
_SSH_VERSIONS = ["SSH-2.0-OpenSSH_8.9p1", "SSH-2.0-OpenSSH_9.6p1", "SSH-2.0-libssh_0.10.5"]


def _weighted_service(rng: random.Random) -> tuple[str, int]:
    r = rng.random()
    cum = 0.0
    for svc, port, w in _SERVICES:
        cum += w
        if r < cum:
            return svc, port
    return _SERVICES[-1][0], _SERVICES[-1][1]


def _internal_ip(rng: random.Random) -> str:
    pfx = rng.choice(_INTERNAL_PREFIX)
    return pfx + f"{rng.randint(0,255)}.{rng.randint(1,254)}"


def _public_ip(rng: random.Random) -> str:
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def generate(n: int, seed: int | None = None) -> list[dict]:
    rng = random.Random(seed) if seed is not None else random.Random()
    now = datetime.now(timezone.utc)
    out: list[dict] = []
    for _ in range(max(0, n)):
        ts = now - timedelta(seconds=rng.randint(0, 600))
        svc, port = _weighted_service(rng)
        proto = rng.choice(_PROTOS) if svc != "dns" else "udp"
        orig_h = _internal_ip(rng)
        resp_h = _public_ip(rng) if rng.random() < 0.65 else _internal_ip(rng)
        duration = round(rng.expovariate(1.0 / 8.0), 3)
        bytes_in  = rng.randint(64, 50_000)
        bytes_out = rng.randint(64, 200_000)

        rec: dict = {
            "ts":          ts.isoformat(timespec="milliseconds"),
            "uid":         f"C{seeded_uuid(rng).hex[:18]}",
            "id.orig_h":   orig_h,
            "id.orig_p":   rng.randint(1024, 65535),
            "id.resp_h":   resp_h,
            "id.resp_p":   port,
            "proto":       proto,
            "service":     svc,
            "duration":    duration,
            "orig_bytes":  bytes_in,
            "resp_bytes":  bytes_out,
            "conn_state":  rng.choice(["S0","SF","REJ","RSTO","RSTR","SHR","S1","OTH"]),
            "local_orig":  orig_h.startswith(_INTERNAL_PREFIX),
            "local_resp":  resp_h.startswith(_INTERNAL_PREFIX),
        }

        # Protocol enrichment
        if svc == "http":
            rec["http"] = {
                "method":      rng.choice(["GET","POST","PUT","DELETE","HEAD"]),
                "host":        rng.choice(_HTTP_HOSTS),
                "uri":         rng.choice(["/", "/api/v1/items", "/login", "/health", "/metrics"]),
                "status_code": rng.choices([200,301,302,401,403,404,500,503], weights=[60,5,8,7,4,8,5,3])[0],
                "user_agent":  rng.choice([
                    "curl/8.4.0", "python-requests/2.31.0",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                ]),
            }
        elif svc == "ssl":
            rec["ssl"] = {
                "version":      "TLSv1.3",
                "cipher":       "TLS_AES_256_GCM_SHA384",
                "server_name":  rng.choice(_SSL_SNIS),
                "established":  rng.random() < 0.95,
            }
        elif svc == "dns":
            q = rng.choice(_DNS_QUERIES)
            rec["dns"] = {
                "query":   q,
                "qtype_name": rng.choice(["A","AAAA","CNAME","MX","TXT","NS"]),
                "rcode_name": rng.choices(["NOERROR","NXDOMAIN","SERVFAIL"], weights=[88,9,3])[0],
                "answers": [_public_ip(rng)] if rng.random() < 0.85 else [],
            }
        elif svc == "ssh":
            rec["ssh"] = {
                "client":     rng.choice(_SSH_VERSIONS),
                "server":     rng.choice(_SSH_VERSIONS),
                "auth_success": rng.random() < 0.7,
            }
        out.append(rec)
    return out
