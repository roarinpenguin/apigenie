"""Palo Alto Firewall (PAN-OS) log generator for the Log Push framework.

Generates realistic log events across all major PAN-OS log types:
- Traffic (sessions, drops, denies)
- Threat (vulnerability, spyware, virus, wildfire, flood)
- URL Filtering (allowed, blocked, continued, alert)
- WildFire (malware verdicts)
- GlobalProtect (VPN connections, disconnections, auth)
- System (general, ha, routing, vpn, user-id)
- Config (admin changes)
- Authentication (successes, failures)
- HIP Match (host information profile)
- Decryption (SSL/TLS inspection)
- Tunnel Inspection (GRE, IPSec)
- UserID (login, logout, group mapping)
"""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from generators import (
    generate_ip,
    generate_hostname,
    generate_uuid,
    generate_country_code,
)

# ── Constants ────────────────────────────────────────────────────────────────

_SERIALS = ["007200012345", "007200067890", "007200011111", "007200099999"]
_DEVICE_NAMES = ["PA-5260-HQ", "PA-3260-DC1", "PA-850-BRANCH1", "PA-450-REMOTE2", "PA-VM-AWS-01"]
_VSYS = ["vsys1", "vsys2"]
_ZONES = ["trust", "untrust", "dmz", "vpn", "mgmt", "guest-wifi", "iot", "server", "internet"]
_INTERFACES = ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4", "ethernet1/5",
               "tunnel.1", "tunnel.2", "loopback.1", "ae1", "ae2", "vlan.100", "vlan.200"]
_RULES = ["allow-outbound", "allow-inbound-web", "deny-all", "allow-dns", "allow-vpn",
          "block-malware", "allow-internal", "dmz-to-server", "guest-internet-only",
          "allow-sslvpn", "block-tor", "allow-o365", "allow-teams", "block-crypto-mining"]
_USERS = ["jsmith", "agarcia", "mwilson", "lchen", "rbrown", "tlee", "nparker",
          "svc-backup", "svc-monitor", "admin", "network-admin", "security-admin"]
_DOMAINS = ["corp.example.com", "branch.example.com", "example.com"]
_APPS = ["web-browsing", "ssl", "dns", "ms-office365", "ms-teams", "zoom", "slack",
         "ssh", "rdp", "ftp", "smtp", "pop3", "imap", "ntp", "snmp", "ldap",
         "youtube-base", "facebook-base", "twitter-base", "linkedin-base",
         "netflix-base", "google-base", "aws-console", "azure-portal", "salesforce",
         "sap", "oracle-db", "mysql", "mssql", "redis", "elasticsearch",
         "apt-get", "yum", "git", "docker", "kubernetes", "jenkins", "github-base"]
_APP_CATEGORIES = ["business-systems", "collaboration", "general-internet", "media",
                   "networking", "saas", "social-networking", "cloud-infra", "database",
                   "development", "devops"]
_URL_CATEGORIES = ["business-and-economy", "computer-and-internet-info", "content-delivery-networks",
                   "educational-institutions", "financial-services", "government", "health-and-medicine",
                   "high-risk", "malware", "phishing", "social-networking", "streaming-media",
                   "unknown", "web-advertisements", "web-based-email", "hacking", "proxy-avoidance-and-anonymizers",
                   "gambling", "adult", "newly-registered-domain", "grayware", "command-and-control"]
_THREAT_NAMES = [
    "Apache Log4j Remote Code Execution Vulnerability",
    "Microsoft Exchange Server ProxyShell Vulnerability",
    "SQL Injection Attempt",
    "Cross-Site Scripting (XSS) Attempt",
    "Remote Code Execution via Deserialization",
    "Buffer Overflow in OpenSSL",
    "DNS Tunneling Detected",
    "Brute Force Authentication Attempt",
    "SMB Exploit (EternalBlue)",
    "Cobalt Strike Beacon Communication",
    "Mimikatz Credential Harvesting",
    "PowerShell Empire C2 Activity",
    "Suspicious TLS Certificate",
    "DGA Domain Activity",
    "Crypto Mining Activity Detected",
    "Lateral Movement via PsExec",
    "Kerberoasting Attempt",
    "LDAP Injection Attempt",
    "Directory Traversal Attempt",
    "Command Injection Attempt",
]
_WILDFIRE_VERDICTS = ["malicious", "grayware", "phishing", "benign", "malicious"]
_FILE_TYPES = ["pe", "pdf", "doc", "xls", "jar", "apk", "elf", "script", "archive", "flash"]
_GP_GATEWAYS = ["gp-hq-01", "gp-dc1-01", "gp-branch-01", "gp-aws-01"]
_OS_TYPES = ["Windows 11", "Windows 10", "macOS 14.4", "macOS 13.6", "Ubuntu 22.04", "RHEL 9",
             "iOS 17.4", "Android 14", "ChromeOS"]
_ADMIN_ACTIONS = ["set", "edit", "delete", "commit", "revert", "clone", "import", "export",
                  "move", "rename", "override"]
_CONFIG_PATHS = [
    "devices/entry/vsys/entry/rulebase/security/rules/entry",
    "devices/entry/vsys/entry/address/entry",
    "devices/entry/vsys/entry/address-group/entry",
    "devices/entry/network/interface/ethernet/entry",
    "devices/entry/vsys/entry/profiles/vulnerability/entry",
    "devices/entry/vsys/entry/profiles/url-filtering/entry",
    "shared/certificate/entry",
    "devices/entry/vsys/entry/tag/entry",
]
_SEVERITIES = ["critical", "high", "medium", "low", "informational"]


# ── Timestamp helpers ────────────────────────────────────────────────────────

def _now_pan() -> str:
    """PAN-OS timestamp format: 2026/05/15 12:34:56"""
    return datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _recent_ts() -> str:
    """Timestamp within the last few minutes."""
    delta = random.randint(0, 300)
    t = datetime.now(timezone.utc) - timedelta(seconds=delta)
    return t.strftime("%Y/%m/%d %H:%M:%S")


# ── Shared fields ────────────────────────────────────────────────────────────

def _base_fields() -> dict[str, Any]:
    serial = random.choice(_SERIALS)
    return {
        "serial": serial,
        "device_name": random.choice(_DEVICE_NAMES),
        "vsys": random.choice(_VSYS),
        "vsys_id": random.randint(1, 2),
        "receive_time": _now_pan(),
        "generated_time": _recent_ts(),
        "sequence_number": random.randint(100000, 99999999),
        "action_flags": "0x0",
        "device_group_hierarchy_l1": random.randint(10, 20),
        "device_group_hierarchy_l2": random.randint(0, 5),
        "device_group_hierarchy_l3": 0,
        "device_group_hierarchy_l4": 0,
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "device_version": random.choice(["11.1.2-h3", "11.0.4", "10.2.9-h1", "10.1.12"]),
    }


def _session_fields(ctx=None) -> dict[str, Any]:
    """Fields common to traffic/threat/url logs."""
    pu = ctx.pick_user() if ctx else None
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None

    src_ip = pm.get("ip") if pm else generate_ip()
    dst_ip = pc2.get("ip_c2") if pc2 else generate_ip()
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    domain = pu.get("domain", random.choice(_DOMAINS)) if pu else random.choice(_DOMAINS)

    src_zone = random.choice(["trust", "vpn", "server"])
    dst_zone = random.choice(["untrust", "dmz", "internet"])
    app = random.choice(_APPS)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "nat_src_ip": generate_ip() if random.random() < 0.6 else "0.0.0.0",
        "nat_dst_ip": dst_ip if random.random() < 0.3 else "0.0.0.0",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 53, 8080, 8443, 22, 3389, 25, 993, 3306, 5432]),
        "nat_src_port": random.randint(1024, 65535),
        "nat_dst_port": random.choice([80, 443, 53, 8080]),
        "protocol": random.choice(["tcp", "udp", "icmp"]),
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "inbound_if": random.choice(_INTERFACES),
        "outbound_if": random.choice(_INTERFACES),
        "rule": random.choice(_RULES),
        "src_user": f"{domain}\\{user}",
        "dst_user": "",
        "application": app,
        "app_category": random.choice(_APP_CATEGORIES),
        "session_id": random.randint(10000, 9999999),
        "repeat_count": random.choice([1, 1, 1, 1, 2, 3]),
        "src_country": generate_country_code(),
        "dst_country": generate_country_code(),
        "hostname": random.choice(_DEVICE_NAMES),
    }


# ── Log type generators ──────────────────────────────────────────────────────

def _traffic_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    sess = _session_fields(ctx)
    action = random.choices(
        ["allow", "allow", "allow", "allow", "deny", "drop", "reset-both", "reset-client"],
        weights=[50, 20, 15, 10, 2, 1, 1, 1]
    )[0]
    subtype = random.choices(["end", "start", "drop", "deny"], weights=[60, 20, 10, 10])[0]
    bytes_sent = random.randint(200, 5000000)
    bytes_recv = random.randint(200, 8000000)
    packets_sent = max(1, bytes_sent // random.randint(100, 1500))
    packets_recv = max(1, bytes_recv // random.randint(100, 1500))

    return {**base, **sess,
        "type": "TRAFFIC",
        "subtype": subtype,
        "action": action,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_recv,
        "packets_sent": packets_sent,
        "packets_received": packets_recv,
        "elapsed_time": random.randint(0, 3600),
        "category": random.choice(_URL_CATEGORIES[:8]),
        "session_end_reason": random.choice([
            "tcp-fin", "tcp-rst-from-client", "tcp-rst-from-server",
            "aged-out", "policy-deny", "threat", "n/a"
        ]),
        "flags": "0x64",
        "severity": "informational",
    }


def _threat_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    sess = _session_fields(ctx)
    subtype = random.choices(
        ["vulnerability", "spyware", "virus", "wildfire", "flood", "scan", "data"],
        weights=[35, 20, 15, 10, 5, 10, 5]
    )[0]
    severity = random.choices(_SEVERITIES, weights=[5, 15, 40, 25, 15])[0]
    action = random.choice(["alert", "drop", "reset-both", "reset-client", "block-ip",
                            "block-url", "sinkhole", "allow"])
    threat = random.choice(_THREAT_NAMES)
    threat_id = random.randint(30000, 99999)

    return {**base, **sess,
        "type": "THREAT",
        "subtype": subtype,
        "action": action,
        "severity": severity,
        "threat_name": threat,
        "threat_id": threat_id,
        "threat_category": subtype,
        "direction": random.choice(["client-to-server", "server-to-client"]),
        "url": f"https://{generate_hostname()}/{random.choice(['login', 'api/v1/data', 'wp-admin', 'shell.php', 'cmd.exe', '.env'])}",
        "content_type": random.choice(["application/octet-stream", "text/html", "application/javascript", "application/pdf"]),
        "pcap_id": random.randint(0, 999999),
        "file_digest": generate_uuid().replace("-", "") + generate_uuid().replace("-", "")[:32],
        "cloud_action": random.choice(["allow", "deny", ""]),
        "url_category_list": random.choice(_URL_CATEGORIES),
    }


def _url_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    sess = _session_fields(ctx)
    action = random.choices(
        ["allow", "block-url", "alert", "continue", "block-override"],
        weights=[50, 20, 15, 10, 5]
    )[0]
    category = random.choice(_URL_CATEGORIES)
    domains = ["example.com", "malware-site.bad", "phishing-page.evil", "news.example.org",
               "social.network.com", "bank.example.com", "shop.example.com", "vpn-proxy.xyz",
               "streaming.video.com", "crypto-exchange.io", "gambling-site.bet"]
    domain = random.choice(domains)
    paths = ["/", "/login", "/index.html", "/api/data", "/download/file.exe",
             "/wp-admin/", "/.env", "/shell.php", "/search?q=test"]

    return {**base, **sess,
        "type": "URL",
        "subtype": "url",
        "action": action,
        "severity": "informational" if action == "allow" else "medium",
        "url": f"https://{domain}{random.choice(paths)}",
        "url_category": category,
        "content_type": random.choice(["text/html", "application/json", "image/png"]),
        "http_method": random.choice(["GET", "POST", "GET", "GET", "PUT"]),
        "user_agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1",
            "curl/8.7.1",
            "python-requests/2.31.0",
        ]),
        "referer": f"https://{random.choice(domains)}/",
        "http2_connection": random.randint(0, 999),
    }


def _wildfire_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    sess = _session_fields(ctx)
    verdict = random.choice(_WILDFIRE_VERDICTS)
    file_type = random.choice(_FILE_TYPES)
    filenames = ["invoice.pdf", "report.docx", "update.exe", "payload.dll", "document.xls",
                 "installer.msi", "photo.jpg.exe", "resume.pdf.scr", "script.ps1", "archive.zip"]

    return {**base, **sess,
        "type": "WILDFIRE",
        "subtype": "wildfire",
        "action": "allow" if verdict == "benign" else "block",
        "severity": "critical" if verdict == "malicious" else "informational",
        "verdict": verdict,
        "filename": random.choice(filenames),
        "file_type": file_type,
        "file_size": random.randint(1024, 52428800),
        "file_digest": generate_uuid().replace("-", "") + generate_uuid().replace("-", "")[:32],
        "cloud_report_id": random.randint(100000, 999999),
        "sample_sha256": generate_uuid().replace("-", "") + generate_uuid().replace("-", ""),
        "analysis_time": random.randint(5, 300),
    }


def _globalprotect_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    domain = pu.get("domain", random.choice(_DOMAINS)) if pu else random.choice(_DOMAINS)
    subtype = random.choices(
        ["connected", "disconnected", "auth-success", "auth-fail", "config-update", "hip-report"],
        weights=[30, 25, 20, 10, 10, 5]
    )[0]

    return {**base,
        "type": "GLOBALPROTECT",
        "subtype": subtype,
        "severity": "informational" if "success" in subtype or "connected" in subtype else "warning",
        "src_user": f"{domain}\\{user}",
        "src_ip": generate_ip(),
        "public_ip": generate_ip(),
        "gateway": random.choice(_GP_GATEWAYS),
        "client_os": random.choice(_OS_TYPES),
        "client_version": f"{random.randint(5, 6)}.{random.randint(0, 3)}.{random.randint(0, 9)}",
        "vpn_type": random.choice(["ssl-vpn", "ipsec", "ssl-vpn"]),
        "tunnel_type": random.choice(["full-tunnel", "split-tunnel"]),
        "connect_method": random.choice(["pre-logon", "user-logon", "on-demand"]),
        "error_code": 0 if "success" in subtype or "connected" in subtype else random.choice([0, 1, 10, 12, 15]),
        "reason": "" if "success" in subtype else random.choice(["Authentication failed", "Certificate expired", "Timeout", "User canceled", ""]),
        "hostname": f"{user}-laptop",
        "machine_name": f"{user.upper()}-PC",
        "mac_address": ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)]),
        "src_region": generate_country_code(),
    }


def _system_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    subtype = random.choices(
        ["general", "ha", "routing", "vpn", "user-id", "dhcp", "dnsproxy", "dos", "sslmgr"],
        weights=[30, 15, 15, 10, 10, 5, 5, 5, 5]
    )[0]
    severity = random.choices(_SEVERITIES, weights=[2, 8, 20, 40, 30])[0]
    messages = {
        "general": ["Configuration committed successfully", "System restart initiated",
                     "Disk usage threshold exceeded", "License expiring in 30 days",
                     "NTP synchronization successful", "PAN-DB update completed",
                     "Anti-virus signature update completed", "Content update installed"],
        "ha": ["HA state changed to active", "HA state changed to passive",
                "HA peer connection established", "HA synchronization completed",
                "HA heartbeat timeout detected", "HA failover initiated"],
        "routing": ["BGP peer established", "BGP peer down", "OSPF adjacency formed",
                     "Static route installed", "Route table updated", "PBF rule matched"],
        "vpn": ["IKEv2 SA established", "IKEv2 SA deleted", "IPSec tunnel established",
                 "IPSec tunnel down", "Phase 1 negotiation failed", "DPD timeout"],
        "user-id": ["User mapping added", "User mapping deleted", "Agent connected",
                     "Agent disconnected", "Group mapping updated", "LDAP query completed"],
    }
    msg_pool = messages.get(subtype, messages["general"])

    return {**base,
        "type": "SYSTEM",
        "subtype": subtype,
        "severity": severity,
        "event_id": random.randint(1, 9999),
        "message": random.choice(msg_pool),
        "object_name": random.choice(["System", "HA", "VPN", "Routing", "Certificate", "License"]),
        "module": subtype,
        "description": random.choice(msg_pool),
    }


def _config_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    admin = random.choice(["admin", "network-admin", "security-admin", "svc-automation"])
    action = random.choice(_ADMIN_ACTIONS)
    path = random.choice(_CONFIG_PATHS)

    return {**base,
        "type": "CONFIG",
        "subtype": "config",
        "severity": "informational",
        "action": action,
        "admin": admin,
        "client_type": random.choice(["Web", "CLI", "API", "Panorama"]),
        "client_ip": generate_ip(),
        "command": f"{action} {path}",
        "path": path,
        "before_change": "",
        "after_change": f"{action} applied by {admin}",
        "result": random.choice(["Submitted", "Succeeded", "Succeeded", "Failed"]),
        "comment": random.choice(["", "Scheduled maintenance", "Security update", "Policy change", "Ticket #" + str(random.randint(1000, 9999))]),
    }


def _auth_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    success = random.random() < 0.85

    return {**base,
        "type": "AUTH",
        "subtype": random.choice(["auth", "radius", "tacplus", "ldap", "saml", "kerberos"]),
        "severity": "informational" if success else "warning",
        "action": "success" if success else random.choice(["failure", "timeout", "lockout"]),
        "src_user": user,
        "src_ip": generate_ip(),
        "server_profile": random.choice(["corp-radius", "azure-ad-saml", "ldap-dc1", "tacacs-mgmt"]),
        "auth_method": random.choice(["RADIUS", "SAML", "LDAP", "TACACS+", "Kerberos", "Local"]),
        "auth_factor": random.choice(["password", "certificate", "mfa", "token"]),
        "description": f"Authentication {'succeeded' if success else 'failed'} for user {user}",
        "object_name": random.choice(["portal-auth", "admin-auth", "vpn-auth", "captive-portal"]),
    }


def _hip_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    match = random.random() < 0.7

    return {**base,
        "type": "HIP-MATCH",
        "subtype": "hip-match",
        "severity": "informational" if match else "warning",
        "src_user": user,
        "src_ip": generate_ip(),
        "machine_name": f"{user.upper()}-PC",
        "os": random.choice(_OS_TYPES),
        "hip_profile": random.choice(["corporate-compliant", "byod-minimum", "high-security", "contractor-baseline"]),
        "match_result": "matched" if match else "not-matched",
        "disk_encryption": random.choice(["encrypted", "not-encrypted", "partial"]),
        "firewall_enabled": random.choice(["yes", "no", "yes", "yes"]),
        "antivirus": random.choice(["installed-updated", "installed-outdated", "not-installed"]),
        "patch_management": random.choice(["up-to-date", "missing-critical", "missing-optional"]),
    }


def _decryption_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    sess = _session_fields(ctx)

    return {**base, **sess,
        "type": "DECRYPTION",
        "subtype": random.choice(["ssl-forward-proxy", "ssl-inbound-inspection", "ssh-proxy"]),
        "severity": "informational",
        "action": random.choice(["allow", "deny", "no-decrypt", "decrypt"]),
        "tls_version": random.choice(["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"]),
        "tls_cipher": random.choice([
            "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
        ]),
        "server_cert_status": random.choice(["valid", "expired", "revoked", "self-signed", "untrusted-ca"]),
        "server_cert_cn": generate_hostname(),
        "sni": generate_hostname(),
        "decryption_profile": random.choice(["standard-decrypt", "strict-decrypt", "no-decrypt-finance"]),
        "error": random.choice(["", "", "", "Unsupported cipher", "Certificate pinning detected"]),
    }


def _tunnel_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    sess = _session_fields(ctx)

    return {**base, **sess,
        "type": "TUNNEL",
        "subtype": random.choice(["gre", "ipsec", "vxlan"]),
        "severity": "informational",
        "action": random.choice(["allow", "deny", "drop"]),
        "tunnel_id": random.randint(1, 999),
        "monitor_tag": random.choice(["", "tunnel-monitor-1", "tunnel-monitor-2"]),
        "parent_session_id": random.randint(10000, 9999999),
        "tunnel_type": random.choice(["GRE", "IPSec-ESP", "VXLAN"]),
        "max_encapsulation": random.choice([1, 2, 3]),
        "strict_check": random.choice(["yes", "no"]),
    }


def _userid_log(ctx=None) -> dict[str, Any]:
    base = _base_fields()
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    domain = pu.get("domain", random.choice(_DOMAINS)) if pu else random.choice(_DOMAINS)

    return {**base,
        "type": "USERID",
        "subtype": random.choice(["login", "logout", "group-mapping"]),
        "severity": "informational",
        "src_user": f"{domain}\\{user}",
        "src_ip": generate_ip(),
        "data_source": random.choice(["syslog-sender", "ad-agent", "xml-api", "captive-portal",
                                       "globalprotect", "ts-agent", "ldap-query"]),
        "data_source_name": random.choice(["DC-01", "dc-branch-02", "syslog-server-01", "GP-gateway"]),
        "data_source_type": random.choice(["active-directory", "syslog", "xml-api", "globalprotect"]),
        "timeout": random.choice([0, 0, 0, 3600, 7200, 43200]),
        "begin_port": 0,
        "end_port": 0,
    }


# ── Event type weights ───────────────────────────────────────────────────────

_EVENT_GENERATORS = [
    (_traffic_log,       45),
    (_threat_log,        15),
    (_url_log,           12),
    (_system_log,         8),
    (_auth_log,           5),
    (_config_log,         4),
    (_globalprotect_log,  3),
    (_wildfire_log,       3),
    (_hip_log,            2),
    (_decryption_log,     1),
    (_tunnel_log,         1),
    (_userid_log,         1),
]

_GENERATORS = [g for g, _ in _EVENT_GENERATORS]
_WEIGHTS = [w for _, w in _EVENT_GENERATORS]


# ── Public API ───────────────────────────────────────────────────────────────

def generate_event(ctx=None) -> dict[str, Any]:
    """Generate a single PAN-OS log event.

    Uses weighted random selection across all log types to produce a realistic
    distribution of events (45% traffic, 15% threat, 12% URL, etc.).

    Args:
        ctx: Optional ProfileContext for entity blending.
    """
    gen = random.choices(_GENERATORS, weights=_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
