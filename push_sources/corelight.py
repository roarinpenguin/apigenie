"""Corelight / Zeek NDR log generator — network traffic analysis events.

Matches Corelight Sensor JSON export format (Zeek JSON logs).
Covers: conn.log, dns.log, http.log, ssl.log, files.log, notice.log,
weird.log, x509.log, smtp.log, dpd.log.
"""

from __future__ import annotations
import random
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_SENSOR_NAMES = ["corelight-sensor-01", "corelight-sensor-02", "corelight-dmz-01"]
_COMMUNITIES = ["internal", "dmz", "external", "datacenter"]
_PROTOS = ["tcp", "udp", "icmp"]
_SERVICES = ["http", "ssl", "dns", "ssh", "smtp", "ftp", "irc", "rdp", "smb", "ntp"]
_CONN_STATES = [
    ("SF", "Normal established and terminated"),
    ("S0", "Connection attempt seen, no reply"),
    ("REJ", "Connection attempt rejected"),
    ("RSTO", "Connection reset by originator"),
    ("RSTR", "Connection reset by responder"),
    ("S1", "Connection established, not terminated"),
    ("SH", "Originator sent a SYN followed by a FIN"),
    ("OTH", "No SYN seen, just midstream traffic"),
]
_QUERY_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "PTR", "SOA", "SRV"]
_RCODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "NOERROR", "NOERROR"]
_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
_HTTP_STATUS = [200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "curl/8.7.1", "python-requests/2.32.3", "Go-http-client/2.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]
_MIME_TYPES = ["text/html", "application/json", "text/javascript", "image/png",
               "application/octet-stream", "text/css", "application/xml", "text/plain"]
_TLS_VERSIONS = ["TLSv13", "TLSv12", "TLSv12", "TLSv12", "TLSv11"]
_CIPHERS = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
_NOTICE_TYPES = [
    ("SSL::Invalid_Server_Cert", "SSL certificate validation failed", "high"),
    ("Scan::Port_Scan", "Port scan detected", "high"),
    ("HTTP::SQL_Injection_Attacker", "SQL injection attempt detected", "critical"),
    ("TeamCymruMalwareHashRegistry::Match", "Malware hash match", "critical"),
    ("Traceroute::Detected", "Traceroute detected", "low"),
    ("SSH::Password_Guessing", "SSH password guessing detected", "high"),
    ("DNS::External_Name", "External DNS query from internal host", "medium"),
    ("Weird::Activity", "Unusual network activity", "medium"),
    ("Intel::Notice", "Threat intelligence match", "critical"),
    ("PacketFilter::Dropped_Packets", "Packet filter dropped packets", "low"),
]
_WEIRD_NAMES = [
    "dns_unmatched_reply", "above_hole_data_without_any_acks",
    "bad_TCP_checksum", "possible_split_routing", "truncated_header",
    "connection_originator_SYN_ack", "data_before_established",
    "FIN_advanced_last_seq", "SYN_after_close", "window_recision",
]
_FILE_TYPES = ["PE", "PDF", "JPEG", "PNG", "ZIP", "GZIP", "HTML", "JavaScript", "ELF", "Mach-O"]
_DOMAINS = ["example.com", "cdn.cloudflare.net", "api.github.com", "login.microsoftonline.com",
            "update.googleapis.com", "suspicious-domain.xyz", "malware-c2.ru",
            "legit-corp.com", "internal.local", "mail.company.com"]


def _uid() -> str:
    return "C" + generate_uuid().replace("-", "")[:17]


def _ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def _base(path: str) -> dict[str, Any]:
    return {
        "_path": path,
        "_system_name": random.choice(_SENSOR_NAMES),
        "_write_ts": datetime.now(timezone.utc).isoformat(timespec="microseconds") + "Z",
        "ts": _ts(),
        "uid": _uid(),
    }


def _conn(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    state, state_msg = random.choice(_CONN_STATES)
    proto = random.choice(_PROTOS)
    service = random.choice(_SERVICES) if proto == "tcp" else ("dns" if proto == "udp" else "-")
    duration = round(random.uniform(0.001, 300.0), 6) if state == "SF" else round(random.uniform(0, 5), 6)
    e = _base("conn")
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": pc2.get("ip_c2", generate_ip()) if pc2 else generate_ip(),
        "id.resp_p": random.choice([80, 443, 22, 25, 53, 3389, 445, 8080, 8443, 993]),
        "proto": proto,
        "service": service,
        "duration": duration,
        "orig_bytes": random.randint(40, 500000),
        "resp_bytes": random.randint(40, 5000000),
        "conn_state": state,
        "conn_state_msg": state_msg,
        "missed_bytes": 0,
        "history": random.choice(["ShADadFf", "ShADadfF", "S", "ShR", "ShADadR", "Sh"]),
        "orig_pkts": random.randint(1, 5000),
        "resp_pkts": random.randint(1, 5000),
        "orig_ip_bytes": random.randint(100, 600000),
        "resp_ip_bytes": random.randint(100, 6000000),
        "community_id": f"1:{generate_uuid()[:20]}=",
    })
    return e


def _dns(ctx=None) -> dict[str, Any]:
    pc2 = ctx.pick_c2() if ctx else None
    qtype = random.choice(_QUERY_TYPES)
    domain = pc2.get("fqdn", random.choice(_DOMAINS)) if pc2 else random.choice(_DOMAINS)
    e = _base("dns")
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": random.choice(["10.0.0.1", "10.0.0.2", "8.8.8.8", "1.1.1.1"]),
        "id.resp_p": 53,
        "proto": random.choice(["udp", "udp", "tcp"]),
        "trans_id": random.randint(1, 65535),
        "query": domain,
        "qclass": 1, "qclass_name": "C_INTERNET",
        "qtype": _QUERY_TYPES.index(qtype) + 1 if qtype in ["A", "AAAA"] else random.randint(1, 30),
        "qtype_name": qtype,
        "rcode": random.randint(0, 5),
        "rcode_name": random.choice(_RCODES),
        "AA": random.choice([True, False]),
        "TC": False, "RD": True, "RA": True,
        "Z": 0, "answers": [generate_ip()] if qtype == "A" else [domain],
        "TTLs": [random.randint(30, 86400)],
        "rejected": False,
    })
    return e


def _http(ctx=None) -> dict[str, Any]:
    e = _base("http")
    host = random.choice(_DOMAINS)
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": generate_ip(),
        "id.resp_p": random.choice([80, 443, 8080, 8443]),
        "trans_depth": 1,
        "method": random.choice(_HTTP_METHODS),
        "host": host,
        "uri": random.choice(["/", "/api/v1/data", "/login", "/admin", "/index.html",
                              "/wp-admin/", "/search?q=test", "/.env", "/robots.txt"]),
        "version": random.choice(["1.1", "2"]),
        "user_agent": random.choice(_USER_AGENTS),
        "request_body_len": random.randint(0, 50000),
        "response_body_len": random.randint(0, 500000),
        "status_code": random.choice(_HTTP_STATUS),
        "status_msg": "OK",
        "resp_mime_types": [random.choice(_MIME_TYPES)],
        "tags": [],
    })
    return e


def _ssl(ctx=None) -> dict[str, Any]:
    e = _base("ssl")
    domain = random.choice(_DOMAINS)
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": generate_ip(),
        "id.resp_p": 443,
        "version": random.choice(_TLS_VERSIONS),
        "cipher": random.choice(_CIPHERS),
        "curve": random.choice(["x25519", "secp256r1", "secp384r1"]),
        "server_name": domain,
        "resumed": random.choice([True, False, False]),
        "established": True,
        "ssl_history": "CsShHh",
        "cert_chain_fps": [hashlib.sha256(domain.encode()).hexdigest()],
        "subject": f"CN={domain},O=Example Inc,L=San Francisco,ST=CA,C=US",
        "issuer": random.choice(["CN=R13,O=Let's Encrypt,C=US",
                                  "CN=DigiCert Global G2,O=DigiCert Inc,C=US"]),
        "validation_status": random.choice(["ok", "ok", "ok", "self signed certificate"]),
    })
    return e


def _files(ctx=None) -> dict[str, Any]:
    pmal = ctx.pick_malware() if ctx else None
    fname = pmal.get("filename", f"document.{random.choice(['pdf','exe','dll','zip','docx'])}") if pmal else f"file_{random.randint(1000,9999)}.{random.choice(['pdf','exe','dll','zip','docx','jpg'])}"
    e = _base("files")
    e.update({
        "fuid": "F" + generate_uuid().replace("-", "")[:17],
        "tx_hosts": [generate_ip()],
        "rx_hosts": [generate_ip()],
        "source": random.choice(["HTTP", "SSL", "SMTP", "FTP_DATA"]),
        "depth": 0,
        "analyzers": random.sample(["SHA256", "MD5", "PE", "EXTRACT"], k=random.randint(1, 3)),
        "mime_type": random.choice(_MIME_TYPES),
        "filename": fname,
        "duration": round(random.uniform(0.01, 30), 6),
        "is_orig": random.choice([True, False]),
        "seen_bytes": random.randint(100, 10000000),
        "total_bytes": random.randint(100, 10000000),
        "missing_bytes": 0,
        "overflow_bytes": 0,
        "timedout": False,
        "md5": hashlib.md5(fname.encode()).hexdigest(),
        "sha256": hashlib.sha256(fname.encode()).hexdigest(),
        "extracted": random.choice([None, f"/extract/{fname}"]),
    })
    return e


def _notice(ctx=None) -> dict[str, Any]:
    note_type, msg, severity = random.choice(_NOTICE_TYPES)
    e = _base("notice")
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": generate_ip(),
        "id.resp_p": random.choice([80, 443, 22, 25]),
        "note": note_type,
        "msg": msg,
        "sub": f"Host {generate_ip()} triggered {note_type}",
        "src": generate_ip(),
        "dst": generate_ip(),
        "p": random.choice([80, 443, 22, 25, 3389]),
        "actions": [random.choice(["Notice::ACTION_LOG", "Notice::ACTION_EMAIL",
                                    "Notice::ACTION_ALARM", "Notice::ACTION_DROP"])],
        "severity": severity,
        "suppress_for": 3600.0,
        "dropped": random.choice([True, False, False]),
    })
    return e


def _weird(ctx=None) -> dict[str, Any]:
    e = _base("weird")
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": generate_ip(),
        "id.resp_p": random.choice([80, 443, 22]),
        "name": random.choice(_WEIRD_NAMES),
        "addl": random.choice(["", "unexpected data", "invalid checksum", "protocol violation"]),
        "notice": random.choice([True, False, False]),
        "peer": random.choice(_SENSOR_NAMES),
    })
    return e


def _x509(ctx=None) -> dict[str, Any]:
    domain = random.choice(_DOMAINS)
    now = datetime.now(timezone.utc)
    e = _base("x509")
    e.update({
        "id": hashlib.sha256(domain.encode()).hexdigest()[:20],
        "certificate.version": 3,
        "certificate.serial": hex(random.randint(10**15, 10**18))[2:],
        "certificate.subject": f"CN={domain},O=Example Inc,C=US",
        "certificate.issuer": f"CN=R13,O=Let's Encrypt,C=US",
        "certificate.not_valid_before": (now - timedelta(days=random.randint(10, 300))).isoformat(timespec="seconds") + "Z",
        "certificate.not_valid_after": (now + timedelta(days=random.randint(10, 365))).isoformat(timespec="seconds") + "Z",
        "certificate.key_alg": "rsaEncryption",
        "certificate.sig_alg": "sha256WithRSAEncryption",
        "certificate.key_type": "rsa",
        "certificate.key_length": random.choice([2048, 4096]),
        "san.dns": [domain, f"*.{domain}"],
        "basic_constraints.ca": False,
    })
    return e


def _smtp(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    user = pu.get("email", f"user{random.randint(1,50)}@company.com") if pu else f"user{random.randint(1,50)}@company.com"
    e = _base("smtp")
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": generate_ip(),
        "id.resp_p": 25,
        "trans_depth": 1,
        "helo": random.choice(["mail.company.com", "smtp.external.org", "mx1.attacker.xyz"]),
        "mailfrom": user,
        "rcptto": [f"recipient{random.randint(1,20)}@target.com"],
        "date": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z"),
        "from": user,
        "to": [f"recipient{random.randint(1,20)}@target.com"],
        "subject": random.choice(["Invoice #" + str(random.randint(1000,9999)),
                                   "Meeting Tomorrow", "Urgent: Action Required",
                                   "Re: Project Update", "Shared Document"]),
        "last_reply": random.choice(["250 2.0.0 Ok: queued", "550 5.1.1 User unknown",
                                      "421 4.7.0 Try again later"]),
        "path": [generate_ip()],
        "tls": random.choice([True, True, False]),
    })
    return e


def _dpd(ctx=None) -> dict[str, Any]:
    e = _base("dpd")
    e.update({
        "id.orig_h": generate_ip(),
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": generate_ip(),
        "id.resp_p": random.choice([80, 443, 22, 8080]),
        "proto": "tcp",
        "analyzer": random.choice(["HTTP", "SSL", "SSH", "SMTP", "FTP", "IRC", "DNS"]),
        "failure_reason": random.choice(["not a http request line",
                                          "no SSL/TLS version found",
                                          "Protocol detection failed"]),
    })
    return e


_GENERATORS = [
    (_conn, 30), (_dns, 20), (_http, 15), (_ssl, 10), (_files, 7),
    (_notice, 6), (_weird, 4), (_x509, 3), (_smtp, 3), (_dpd, 2),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]


def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
