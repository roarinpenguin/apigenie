"""Cisco ASA/FTD log generator — realistic syslog with ASA- message IDs.

Covers: connection built/teardown (302013-302021), denied (106001-106023),
threat detection (733100), failover (105032-105043), VPN (722022-722051),
AAA auth (109005-109012), ACL (106100), NAT, system messages.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_HOSTNAMES = ["ASA-HQ-01", "ASA-DC-02", "FTD-DMZ-03", "ASA-BRANCH-04"]
_INTERFACES = ["inside", "outside", "dmz", "management", "vpn-tunnel", "outside-2"]
_USERS = ["jsmith", "agarcia", "admin", "mwilson", "svc-vpn"]
_ACL_NAMES = ["OUTSIDE-IN", "INSIDE-OUT", "DMZ-ACCESS", "VPN-FILTER", "MGMT-ONLY"]
_GROUP_POLICIES = ["DfltGrpPolicy", "CorpVPN", "RemoteAccess", "SiteToSite"]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S")

def _base() -> dict[str, Any]:
    return {"timestamp": _now(), "hostname": random.choice(_HOSTNAMES),
            "vendor": "Cisco", "product": "ASA", "device_version": random.choice(["9.18.4", "9.16.4", "7.2.1"])}

def _conn_built(ctx=None) -> dict[str, Any]:
    b = _base()
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src = pm.get("ip") if pm else generate_ip()
    dst = pc2.get("ip_c2") if pc2 else generate_ip()
    proto = random.choice(["TCP", "UDP"])
    mid = random.choice(["302013", "302015"])
    sp = random.randint(1024, 65535); dp = random.choice([80, 443, 53, 22, 3389, 8080])
    iif = random.choice(["inside", "vpn-tunnel"]); oif = random.choice(["outside", "dmz"])
    return {**b, "type": "connection", "subtype": "built", "severity": "informational",
            "message_id": mid, "action": "Built",
            "message": f"%ASA-6-{mid}: Built {'inbound' if random.random() < 0.3 else 'outbound'} {proto} connection {random.randint(100000,9999999)} for {iif}:{src}/{sp} ({src}/{sp}) to {oif}:{dst}/{dp} ({dst}/{dp})",
            "src_ip": src, "dst_ip": dst, "src_port": sp, "dst_port": dp,
            "protocol": proto, "src_interface": iif, "dst_interface": oif,
            "connection_id": random.randint(100000, 9999999)}

def _conn_teardown(ctx=None) -> dict[str, Any]:
    b = _base()
    mid = random.choice(["302014", "302016"])
    reason = random.choice(["TCP FINs", "TCP Reset-O", "TCP Reset-I", "Idle Timeout", "SYN Timeout", "Deny Terminate"])
    return {**b, "type": "connection", "subtype": "teardown", "severity": "informational",
            "message_id": mid, "action": "Teardown",
            "message": f"%ASA-6-{mid}: Teardown {random.choice(['TCP', 'UDP'])} connection {random.randint(100000,9999999)} for {random.choice(_INTERFACES)}:{generate_ip()}/{random.randint(1024,65535)} to {random.choice(_INTERFACES)}:{generate_ip()}/{random.choice([80,443,22])} duration 0:{random.randint(0,59):02d}:{random.randint(0,59):02d} bytes {random.randint(100,500000)} {reason}",
            "reason": reason, "bytes": random.randint(100, 500000), "duration": f"0:{random.randint(0,59):02d}:{random.randint(0,59):02d}"}

def _denied(ctx=None) -> dict[str, Any]:
    b = _base()
    mid = random.choice(["106001", "106006", "106007", "106014", "106015", "106023"])
    src = generate_ip(); dst = generate_ip()
    return {**b, "type": "firewall", "subtype": "denied", "severity": "warning",
            "message_id": mid, "action": "Deny",
            "message": f"%ASA-4-{mid}: Deny {random.choice(['TCP', 'UDP', 'ICMP'])} src {random.choice(_INTERFACES)}:{src} dst {random.choice(_INTERFACES)}:{dst} by access-group \"{random.choice(_ACL_NAMES)}\"",
            "src_ip": src, "dst_ip": dst, "acl": random.choice(_ACL_NAMES)}

def _threat(ctx=None) -> dict[str, Any]:
    b = _base()
    return {**b, "type": "threat", "subtype": "threat-detection", "severity": "high",
            "message_id": "733100", "action": "Drop",
            "message": f"%ASA-4-733100: [{random.choice(['Scanning', 'SYN Attack', 'Firewall', 'TCP Intercept'])}] drop rate-1 exceeded. Current burst rate is {random.randint(10,1000)} per second, max configured rate is {random.randint(100,500)}; Current average rate is {random.randint(5,200)} per second, max configured rate is {random.randint(50,200)}; Cumulative total count is {random.randint(1000,50000)}",
            "threat_type": random.choice(["Scanning", "SYN Attack", "Firewall", "TCP Intercept"])}

def _vpn(ctx=None) -> dict[str, Any]:
    b = _base()
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    mid = random.choice(["722022", "722023", "722028", "722032", "722034", "722051"])
    return {**b, "type": "vpn", "subtype": random.choice(["session-start", "session-end", "auth"]),
            "severity": "informational", "message_id": mid, "action": random.choice(["connected", "disconnected", "authenticated"]),
            "message": f"%ASA-4-{mid}: Group <{random.choice(_GROUP_POLICIES)}> User <{user}> IP <{generate_ip()}> {'SVC Session' if random.random() < 0.5 else 'WebVPN'} {'started' if '22' in mid else 'terminated'}",
            "user": user, "remote_ip": generate_ip(), "group_policy": random.choice(_GROUP_POLICIES)}

def _aaa(ctx=None) -> dict[str, Any]:
    b = _base()
    user = random.choice(_USERS)
    success = random.random() < 0.85
    mid = "109005" if success else "109006"
    return {**b, "type": "auth", "subtype": "aaa", "severity": "informational" if success else "warning",
            "message_id": mid, "action": "success" if success else "failure",
            "message": f"%ASA-6-{mid}: Authentication {'succeeded' if success else 'rejected'} for user '{user}' from {generate_ip()}/{random.randint(1024,65535)} to {random.choice(_INTERFACES)}:{generate_ip()}/{random.choice([22, 443, 8443])} on interface {random.choice(_INTERFACES)}",
            "user": user}

def _system(ctx=None) -> dict[str, Any]:
    b = _base()
    msgs = [("%ASA-1-105032", "Failover mate is not responding", "critical"),
            ("%ASA-5-111008", "User admin executed command: show running-config", "informational"),
            ("%ASA-6-605005", "Login permitted from 10.0.1.5/22 to inside:10.0.1.1/22 for user admin", "informational"),
            ("%ASA-4-410001", "Dropped UDP DNS response from outside:8.8.8.8/53 to inside", "warning"),
            ("%ASA-2-106001", "Memory allocation error", "critical")]
    code, msg, sev = random.choice(msgs)
    return {**b, "type": "system", "subtype": "system", "severity": sev,
            "message_id": code.split("-")[2], "message": f"{code}: {msg}"}

_GENERATORS = [
    (_conn_built, 30), (_conn_teardown, 25), (_denied, 15), (_threat, 5),
    (_vpn, 10), (_aaa, 8), (_system, 7),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
