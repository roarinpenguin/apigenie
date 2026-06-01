"""Stamus Networks SSP log generator — Suricata-based NDR events.

Matches Suricata EVE JSON output as exported by Stamus Security Platform.
Covers: alert, flow, dns, http, tls, fileinfo, anomaly, stats.
"""

from __future__ import annotations
import random
import hashlib
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_SENSOR_NAMES = ["stamus-ssp-01", "stamus-ssp-02", "stamus-ssp-dmz"]
_INTERFACES = ["eth0", "eth1", "bond0", "ens192"]

_SIG_CATEGORIES = [
    "Attempted Administrator Privilege Gain", "A Network Trojan was detected",
    "Potentially Bad Traffic", "Attempted Information Leak", "Web Application Attack",
    "Misc Attack", "Attempted Denial of Service", "Attempted User Privilege Gain",
    "Detection of a Network Scan", "Malware Command and Control Activity Detected",
    "Not Suspicious Traffic", "Policy Violation", "Executable Code was Detected",
    "A suspicious filename was detected", "Crypto Currency Mining Activity Detected",
]
_SIGNATURES = [
    (2100498, "GPL ATTACK_RESPONSE id check returned root", 1, "Attempted Administrator Privilege Gain"),
    (2013028, "ET POLICY curl User-Agent Outbound", 3, "Not Suspicious Traffic"),
    (2024218, "ET TROJAN Possible Metasploit Payload Detected", 1, "A Network Trojan was detected"),
    (2028765, "ET MALWARE Win32/Emotet CnC Activity", 1, "Malware Command and Control Activity Detected"),
    (2019401, "ET DNS Query to .onion proxy", 2, "Potentially Bad Traffic"),
    (2210054, "SURICATA STREAM Excessive Retransmissions", 3, "Potentially Bad Traffic"),
    (2100366, "GPL ICMP_INFO PING *NIX", 3, "Misc Attack"),
    (2027757, "ET SCAN Behavioral Unusual Port 445 traffic", 2, "Detection of a Network Scan"),
    (2032081, "ET EXPLOIT CVE-2021-44228 Log4j RCE Attempt", 1, "Web Application Attack"),
    (2035595, "ET CRYPTO_MINING CoinMiner Domain", 2, "Crypto Currency Mining Activity Detected"),
    (2025648, "ET INFO Executable Retrieved With Minimal HTTP Headers", 2, "Executable Code was Detected"),
    (2009358, "ET SCAN Nmap Scripting Engine User-Agent Detected", 2, "Detection of a Network Scan"),
    (2014520, "ET POLICY Outbound SSH Connection to Non-Standard Port", 3, "Policy Violation"),
]
_FLOW_STATES = ["new", "established", "closed"]
_APP_PROTOS = ["http", "tls", "dns", "ssh", "smtp", "ftp", "smb", "rdp", "ntp", "dhcp"]
_DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA"]
_DNS_RCODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"]
_HTTP_METHODS = ["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS"]
_HTTP_STATUS = [200, 200, 200, 301, 302, 400, 401, 403, 404, 500]
_TLS_VERSIONS = ["TLS 1.3", "TLS 1.2", "TLS 1.2", "TLS 1.1"]
_TLS_SUBJECTS = ["CN=example.com", "CN=*.cloudflare.com", "CN=api.github.com",
                  "CN=login.microsoft.com", "CN=suspicious.xyz"]
_DOMAINS = ["example.com", "cdn.cloudflare.net", "api.github.com",
            "suspicious-c2.xyz", "legit-corp.com", "update.windows.com",
            "malware-drop.ru", "login.microsoftonline.com"]
_FILE_TYPES = ["PE", "PDF", "HTML", "JavaScript", "ZIP", "ELF", "Mach-O"]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds") + "+0000"


def _flow_id() -> int:
    return random.randint(10**17, 10**18)


def _base(event_type: str) -> dict[str, Any]:
    return {
        "timestamp": _ts(),
        "flow_id": _flow_id(),
        "in_iface": random.choice(_INTERFACES),
        "event_type": event_type,
        "src_ip": generate_ip(),
        "src_port": random.randint(1024, 65535),
        "dest_ip": generate_ip(),
        "dest_port": random.choice([80, 443, 22, 25, 53, 3389, 445, 8080]),
        "proto": random.choice(["TCP", "UDP", "TCP", "TCP"]),
        "host": random.choice(_SENSOR_NAMES),
        "community_id": f"1:{generate_uuid()[:20]}=",
    }


def _alert(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    sid, msg, severity, category = random.choice(_SIGNATURES)
    e = _base("alert")
    if pc2:
        e["dest_ip"] = pc2.get("ip_c2", e["dest_ip"])
    e["alert"] = {
        "action": random.choice(["allowed", "allowed", "blocked"]),
        "gid": 1,
        "signature_id": sid,
        "rev": random.randint(1, 15),
        "signature": msg,
        "category": category,
        "severity": severity,
        "metadata": {
            "attack_target": [random.choice(["Client_and_Server", "Server", "Client"])],
            "deployment": [random.choice(["Internal", "Perimeter", "Datacenter"])],
            "created_at": ["2024_01_15"],
            "updated_at": ["2026_05_01"],
        },
    }
    e["app_proto"] = random.choice(_APP_PROTOS[:4])
    e["stamus"] = {
        "asset_tracking": True,
        "kill_chain": random.choice(["reconnaissance", "delivery", "exploitation",
                                      "command_and_control", "lateral_movement", "exfiltration"]),
        "threat_score": random.randint(1, 100),
    }
    return e


def _flow(ctx=None) -> dict[str, Any]:
    e = _base("flow")
    age = random.uniform(0.01, 600)
    e["flow"] = {
        "pkts_toserver": random.randint(1, 10000),
        "pkts_toclient": random.randint(1, 10000),
        "bytes_toserver": random.randint(40, 1000000),
        "bytes_toclient": random.randint(40, 5000000),
        "start": _ts(),
        "end": _ts(),
        "age": round(age, 3),
        "state": random.choice(_FLOW_STATES),
        "reason": random.choice(["timeout", "forced", "shutdown"]),
        "alerted": random.choice([True, False, False]),
    }
    e["app_proto"] = random.choice(_APP_PROTOS)
    return e


def _dns_event(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    qname = pc2.get("fqdn", random.choice(_DOMAINS)) if pc2 else random.choice(_DOMAINS)
    e = _base("dns")
    e["dest_port"] = 53
    e["dns"] = {
        "type": random.choice(["query", "answer"]),
        "id": random.randint(1, 65535),
        "rrname": qname,
        "rrtype": random.choice(_DNS_TYPES),
        "rcode": random.choice(_DNS_RCODES),
        "answers": [{"rrname": qname, "rrtype": "A", "rdata": generate_ip(), "ttl": random.randint(30, 86400)}]
        if random.random() > 0.3 else [],
        "tx_id": random.randint(0, 100),
    }
    return e


def _http_event(ctx=None) -> dict[str, Any]:
    e = _base("http")
    e["dest_port"] = random.choice([80, 8080, 443])
    e["http"] = {
        "hostname": random.choice(_DOMAINS),
        "url": random.choice(["/", "/api/v1/data", "/login", "/admin/config",
                               "/wp-login.php", "/.env", "/shell.php"]),
        "http_user_agent": random.choice([
            "Mozilla/5.0 Chrome/125.0", "curl/8.7.1", "python-requests/2.32",
            "Go-http-client/2.0", "Wget/1.21"]),
        "http_content_type": random.choice(["text/html", "application/json", "text/plain"]),
        "http_method": random.choice(_HTTP_METHODS),
        "protocol": "HTTP/1.1",
        "status": random.choice(_HTTP_STATUS),
        "length": random.randint(0, 500000),
        "http_refer": random.choice(["", "https://example.com/", "https://google.com/"]),
    }
    return e


def _tls_event(ctx=None) -> dict[str, Any]:
    e = _base("tls")
    e["dest_port"] = 443
    e["tls"] = {
        "subject": random.choice(_TLS_SUBJECTS),
        "issuerdn": random.choice(["C=US, O=Let's Encrypt, CN=R13",
                                     "C=US, O=DigiCert Inc, CN=DigiCert Global G2"]),
        "serial": hex(random.randint(10**15, 10**18))[2:],
        "fingerprint": hashlib.sha256(generate_uuid().encode()).hexdigest()[:40],
        "version": random.choice(_TLS_VERSIONS),
        "sni": random.choice(_DOMAINS),
        "ja3": hashlib.md5(generate_uuid().encode()).hexdigest(),
        "ja3s": hashlib.md5(generate_uuid().encode()).hexdigest(),
        "notbefore": "2025-01-01T00:00:00",
        "notafter": "2027-01-01T00:00:00",
    }
    return e


def _fileinfo(ctx=None) -> dict[str, Any]:
    pmal = ctx.pick_malware() if ctx else None
    fname = pmal.get("filename", f"file_{random.randint(1000,9999)}.exe") if pmal else f"doc_{random.randint(100,999)}.{random.choice(['pdf','exe','dll','zip','docx'])}"
    e = _base("fileinfo")
    e["fileinfo"] = {
        "filename": fname,
        "magic": random.choice(["PE32 executable", "PDF document", "HTML document",
                                 "Zip archive", "ELF 64-bit LSB executable"]),
        "md5": hashlib.md5(fname.encode()).hexdigest(),
        "sha256": hashlib.sha256(fname.encode()).hexdigest(),
        "size": random.randint(100, 10000000),
        "tx_id": random.randint(0, 10),
        "state": "CLOSED",
        "stored": random.choice([True, False]),
        "gaps": False,
    }
    e["app_proto"] = random.choice(["http", "smtp", "ftp"])
    return e


def _anomaly(ctx=None) -> dict[str, Any]:
    e = _base("anomaly")
    anomalies = [
        ("applayer", "http", "HTTP request too long"),
        ("applayer", "tls", "Invalid TLS record"),
        ("stream", "tcp", "Stream reassembly overlap"),
        ("decode", "ipv4", "IPv4 truncated packet"),
        ("applayer", "dns", "DNS response flood detected"),
        ("stream", "tcp", "SYN flood detected"),
    ]
    layer, proto, msg = random.choice(anomalies)
    e["anomaly"] = {
        "type": layer,
        "event": msg,
        "layer": proto,
        "code": random.randint(1, 100),
    }
    return e


def _stats(ctx=None) -> dict[str, Any]:
    return {
        "timestamp": _ts(),
        "event_type": "stats",
        "host": random.choice(_SENSOR_NAMES),
        "stats": {
            "uptime": random.randint(3600, 8640000),
            "capture": {
                "kernel_packets": random.randint(10**6, 10**9),
                "kernel_drops": random.randint(0, 1000),
                "kernel_ifdrops": 0,
            },
            "decoder": {
                "pkts": random.randint(10**6, 10**9),
                "bytes": random.randint(10**9, 10**12),
                "invalid": random.randint(0, 100),
                "ipv4": random.randint(10**6, 10**9),
                "ipv6": random.randint(10**4, 10**7),
                "tcp": random.randint(10**6, 10**9),
                "udp": random.randint(10**5, 10**8),
            },
            "detect": {
                "alert": random.randint(100, 100000),
            },
            "flow": {
                "tcp": random.randint(10**4, 10**7),
                "udp": random.randint(10**3, 10**6),
            },
        },
    }


_GENERATORS = [
    (_alert, 25), (_flow, 20), (_dns_event, 15), (_http_event, 12),
    (_tls_event, 10), (_fileinfo, 7), (_anomaly, 6), (_stats, 5),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]


def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
