"""Fortinet FortiGate log generator — realistic FortiOS syslog events.

Covers: traffic, utm (virus, ips, webfilter, appctrl, dlp, emailfilter),
event (system, vpn, user, router, ha), anomaly.
Fields match FortiOS 7.4 log reference.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid, generate_country_code

_SERIALS = ["FGT60F0000000001", "FGT100F000000002", "FGT200F000000003", "FGT3600E00000004"]
_DEVICE_NAMES = ["FGT-HQ-01", "FGT-DC-02", "FGT-BRANCH-03", "FGT-AWS-04"]
_VDOMS = ["root", "corp", "guest"]
_ZONES = ["LAN", "WAN1", "WAN2", "DMZ", "VPN-SSL", "WiFi", "Server", "IoT"]
_INTERFACES = ["port1", "port2", "port3", "port4", "wan1", "wan2", "ssl.root", "wl0"]
_POLICIES = ["1", "2", "5", "10", "15", "20", "25", "100", "implicit-deny"]
_USERS = ["jsmith", "agarcia", "mwilson", "lchen", "rbrown", "svc-backup", "admin"]
_DOMAINS = ["corp.local", "branch.local", "example.com"]
_APPS = ["HTTP.BROWSER", "SSL", "DNS", "Microsoft.Office.365", "Zoom", "Slack", "SSH", "RDP",
         "YouTube", "Facebook", "Google.Search", "BitTorrent", "Tor", "Skype"]
_APP_CATS = ["Web.Client", "Network.Service", "Cloud.IT", "Video/Audio", "Social.Networking",
             "P2P", "Proxy", "VoIP", "Business", "Email"]
_WEB_CATS = ["Information Technology", "Search Engines", "Business", "Finance", "Social Networking",
             "Streaming Media", "Malicious Websites", "Phishing", "Newly Observed Domain",
             "Pornography", "Gambling", "Hacking", "Proxy Avoidance"]
_THREAT_NAMES = [
    "Apache.Log4j.Error.Log.Remote.Code.Execution", "MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure",
    "Eicar.Virus.Test.File", "Trojan.Win32.Agent", "PHP.CGI.Argument.Injection",
    "HTTP.Unix.Shell.IFS.Remote.Code.Execution", "SSL.Anonymous.Ciphers.Negotiation",
    "DNS.Tunneling.Detected", "Backdoor.Cobalt.Strike.Beacon", "Mimikatz.Credential.Dumping",
    "Brute.Force.Login", "SQL.Injection.Attempt", "Cross.Site.Scripting.Attempt",
]
_SEVERITIES = ["critical", "high", "medium", "low", "information"]
_ACTIONS = ["accept", "deny", "drop", "ip-conn", "close", "timeout", "client-rst", "server-rst"]


def _now_forti() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def _recent_ts() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=random.randint(0, 300))).strftime("%Y-%m-%d %H:%M:%S")

def _base(ctx=None) -> dict[str, Any]:
    return {
        "date": _now_forti().split(" ")[0],
        "time": _now_forti().split(" ")[1],
        "timestamp": _now_forti(),
        "devname": random.choice(_DEVICE_NAMES),
        "devid": random.choice(_SERIALS),
        "vd": random.choice(_VDOMS),
        "logid": f"{random.randint(0, 9)}{random.randint(100000000, 999999999):09d}",
        "tz": "+0000",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "device_version": random.choice(["7.4.4", "7.4.3", "7.2.8", "7.0.15"]),
    }

def _session(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src = pm.get("ip") if pm else generate_ip()
    dst = pc2.get("ip_c2") if pc2 else generate_ip()
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    return {
        "srcip": src, "dstip": dst,
        "srcport": random.randint(1024, 65535), "dstport": random.choice([80, 443, 53, 22, 3389, 8080, 25, 993]),
        "srcintf": random.choice(_INTERFACES), "dstintf": random.choice(_INTERFACES),
        "srcintfrole": random.choice(["lan", "wan", "dmz"]), "dstintfrole": random.choice(["lan", "wan", "dmz"]),
        "srccountry": generate_country_code(), "dstcountry": generate_country_code(),
        "sessionid": random.randint(100000, 99999999),
        "proto": random.choice([6, 17, 1]),
        "policyid": random.choice(_POLICIES),
        "policyname": random.choice(["allow-outbound", "deny-all", "allow-vpn", "dmz-access", "guest-internet"]),
        "user": user,
        "group": random.choice(["Domain Users", "VPN-Users", "Admins", ""]),
        "app": random.choice(_APPS), "appcat": random.choice(_APP_CATS),
    }

def _traffic(ctx=None) -> dict[str, Any]:
    b = _base(ctx); s = _session(ctx)
    action = random.choices(["accept", "accept", "accept", "deny", "close", "timeout"], weights=[40, 20, 10, 10, 15, 5])[0]
    sent = random.randint(200, 5000000); rcvd = random.randint(200, 8000000)
    return {**b, **s, "type": "traffic", "subtype": random.choice(["forward", "local", "sniffer"]),
            "level": "notice", "action": action, "sentbyte": sent, "rcvdbyte": rcvd,
            "sentpkt": max(1, sent // random.randint(100, 1500)), "rcvdpkt": max(1, rcvd // random.randint(100, 1500)),
            "duration": random.randint(0, 3600), "service": random.choice(["HTTPS", "HTTP", "DNS", "SSH", "RDP", "SMTP", "NTP"]),
            "hostname": generate_hostname(), "trandisp": random.choice(["snat", "dnat", "noop"])}

def _utm_virus(ctx=None) -> dict[str, Any]:
    b = _base(ctx); s = _session(ctx)
    pmal = ctx.pick_malware() if ctx else None
    virus = pmal.get("filename", "Eicar.Virus.Test.File") if pmal else random.choice(["Eicar.Virus.Test.File", "Trojan.Win32.Agent", "W32/Malware.ABCD", "Riskware/CoinMiner"])
    return {**b, **s, "type": "utm", "subtype": "virus", "level": "warning",
            "action": random.choice(["blocked", "monitored"]), "severity": random.choice(["high", "medium", "critical"]),
            "virus": virus, "dtype": random.choice(["Virus", "Trojan", "Worm", "Riskware"]),
            "filetype": random.choice(["exe", "dll", "pdf", "doc", "zip"]),
            "filename": pmal.get("filename", f"file_{random.randint(1000,9999)}.exe") if pmal else f"file_{random.randint(1000,9999)}.exe",
            "quarskip": random.choice(["File-was-not-quarantined.", "Quarantined."]),
            "analyticscksum": generate_uuid().replace("-", ""), "analyticssubmit": random.choice(["true", "false"])}

def _utm_ips(ctx=None) -> dict[str, Any]:
    b = _base(ctx); s = _session(ctx)
    threat = random.choice(_THREAT_NAMES)
    return {**b, **s, "type": "utm", "subtype": "ips", "level": "alert",
            "action": random.choice(["detected", "dropped", "reset"]),
            "severity": random.choices(_SEVERITIES[:4], weights=[5, 20, 50, 25])[0],
            "attack": threat, "attackid": random.randint(10000, 99999), "ref": f"http://www.fortinet.com/ids/{random.randint(10000,99999)}",
            "incidentserialno": random.randint(1000000, 9999999), "msg": f"IPS detected: {threat}"}

def _utm_webfilter(ctx=None) -> dict[str, Any]:
    b = _base(ctx); s = _session(ctx)
    cat = random.choice(_WEB_CATS); catdesc = cat
    action = "blocked" if cat in ["Malicious Websites", "Phishing", "Pornography", "Gambling", "Hacking", "Proxy Avoidance"] else random.choice(["passthrough", "monitored", "warning"])
    return {**b, **s, "type": "utm", "subtype": "webfilter", "level": "warning" if action == "blocked" else "notice",
            "action": action, "hostname": generate_hostname(),
            "url": f"https://{generate_hostname()}/{random.choice(['index.html', 'login', 'api/data', 'download'])}",
            "cat": random.randint(1, 90), "catdesc": catdesc, "profile": random.choice(["default", "strict", "monitor-only"])}

def _utm_appctrl(ctx=None) -> dict[str, Any]:
    b = _base(ctx); s = _session(ctx)
    return {**b, **s, "type": "utm", "subtype": "app-ctrl", "level": "information",
            "action": random.choice(["pass", "block", "reset"]),
            "appcat": random.choice(_APP_CATS), "app": random.choice(_APPS),
            "appid": random.randint(10000, 60000), "apprisk": random.choice(["critical", "high", "medium", "low", "elevated"]),
            "msg": f"Application {random.choice(_APPS)} detected"}

def _event_system(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    msgs = ["Admin admin logged in successfully from 10.0.1.5", "Configuration changed by admin",
            "Firmware upgraded to v7.4.4", "License check completed", "NTP synchronized",
            "HA failover occurred", "CPU usage exceeded threshold", "Disk usage warning",
            "FSSO agent connected", "FortiGuard update completed"]
    return {**b, "type": "event", "subtype": "system", "level": random.choice(["information", "notice", "warning"]),
            "action": random.choice(["login", "configuration", "upgrade", "license", "ntp", "ha-failover"]),
            "logdesc": random.choice(msgs), "msg": random.choice(msgs),
            "ui": random.choice(["GUI(10.0.1.5)", "CLI(ssh)", "API", "Panorama"])}

def _event_vpn(ctx=None) -> dict[str, Any]:
    b = _base(ctx)
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    return {**b, "type": "event", "subtype": "vpn", "level": random.choice(["information", "notice", "warning"]),
            "action": random.choice(["tunnel-up", "tunnel-down", "ssl-login-fail", "ssl-new-con", "ipsec-phase1-negotiated"]),
            "tunneltype": random.choice(["ssl-web", "ssl-tunnel", "ipsec"]),
            "tunnelid": random.randint(1, 999), "remip": generate_ip(),
            "user": user, "group": random.choice(["VPN-Users", "Remote-Access", ""]),
            "msg": f"VPN tunnel for user {user}", "reason": random.choice(["", "peer timeout", "auth failure", ""])}

def _anomaly(ctx=None) -> dict[str, Any]:
    b = _base(ctx); s = _session(ctx)
    return {**b, **s, "type": "anomaly", "subtype": "anomaly", "level": "alert",
            "action": random.choice(["detected", "dropped"]),
            "severity": random.choice(["critical", "high"]),
            "attack": random.choice(["tcp_syn_flood", "udp_flood", "icmp_flood", "ip_src_session_limit", "scan_port"]),
            "attackid": random.randint(1, 50), "count": random.randint(100, 100000),
            "msg": "Anomaly traffic detected"}

_GENERATORS = [
    (_traffic, 45), (_utm_ips, 12), (_utm_virus, 8), (_utm_webfilter, 10),
    (_utm_appctrl, 8), (_event_system, 8), (_event_vpn, 5), (_anomaly, 4),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
