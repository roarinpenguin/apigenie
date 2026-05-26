"""HPE Aruba Switch (AOS-CX / ProCurve) log generator — realistic syslog events.

Covers: port-access (802.1X, MAC-auth), RADIUS auth, STP, LLDP neighbor,
ACL logging, DHCP snooping, ARP protection, loop protection, management
audit (config changes, firmware), VSF/stacking, PoE, environmental,
link up/down, VLAN, LACP, DAI, BPDU protection.
Fields match real AOS-CX 10.12+ and ProCurve syslog format.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_HOSTNAMES = ["ARUBA-CORE-01", "ARUBA-CORE-02", "ARUBA-DIST-01", "ARUBA-ACC-01",
              "ARUBA-ACC-02", "ARUBA-ACC-03", "PROCURVE-DC-01", "CX6300-STACK-01"]
_MODELS = ["Aruba 6300M", "Aruba 6200F", "Aruba 6100", "Aruba 8320", "Aruba 8400",
           "ProCurve 2930F", "ProCurve 5412R", "CX 10000"]
_INTERFACES = [f"1/1/{i}" for i in range(1, 49)] + \
              [f"1/1/{i}" for i in range(49, 53)] + \
              ["lag1", "lag2", "lag3", "lag4", "vlan1", "vlan10", "vlan20",
               "vlan100", "vlan200", "loopback0", "mgmt"]
_ACCESS_PORTS = [f"1/1/{i}" for i in range(1, 49)]
_UPLINK_PORTS = [f"1/1/{i}" for i in range(49, 53)] + ["lag1", "lag2"]
_VLANS = [1, 10, 20, 30, 50, 100, 200, 300, 999]
_VLAN_NAMES = {1: "DEFAULT", 10: "MGMT", 20: "SERVERS", 30: "USERS", 50: "VOICE",
               100: "DMZ", 200: "GUEST", 300: "IOT", 999: "QUARANTINE"}
_USERS = ["admin", "netops", "svc-nms", "jsmith", "agarcia", "radius-user"]
_RADIUS_SERVERS = ["10.0.1.50", "10.0.1.51", "radius.corp.local"]
_MAC_VENDORS = ["00:1A:2B", "00:50:56", "AC:DE:48", "3C:22:FB", "F4:8E:38",
                "00:0C:29", "B8:27:EB", "DC:A6:32", "70:B3:D5", "48:21:0B"]
_DOT1X_ROLES = ["employee", "contractor", "guest", "iot-device", "voice", "quarantine"]
_AUTH_METHODS = ["dot1x", "mac-auth", "captive-portal", "local"]


def _mac() -> str:
    vendor = random.choice(_MAC_VENDORS)
    suffix = ":".join(f"{random.randint(0,255):02x}" for _ in range(3))
    return f"{vendor}:{suffix}"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _syslog_ts() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")


def _base() -> dict[str, Any]:
    hostname = random.choice(_HOSTNAMES)
    model = random.choice(_MODELS)
    return {
        "timestamp": _ts(), "hostname": hostname,
        "vendor": "HPE Aruba", "product": model,
        "device_version": random.choice(["10.12.1010", "10.11.1030", "10.10.1080",
                                          "16.11.0012", "16.10.0021", "KB.16.11.0012"]),
        "serial": f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10))}",
    }


def _link_state(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_INTERFACES[:52])
    state = random.choices(["up", "down"], weights=[70, 30])[0]
    speed = random.choice(["1000", "10000", "25000", "100"]) if state == "up" else ""
    return {**b, "type": "link", "subtype": state, "severity": "informational" if state == "up" else "warning",
            "module": "hpe-port-mgr",
            "message": f"Port {iface} is now {'on-line' if state == 'up' else 'off-line'}. Speed = {speed} Duplex = {'Full' if state == 'up' else 'N/A'}",
            "interface": iface, "state": state, "speed": speed}


def _port_access(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_ACCESS_PORTS)
    mac = _mac()
    method = random.choice(_AUTH_METHODS[:2])
    success = random.random() < 0.8
    role = random.choice(_DOT1X_ROLES) if success else "quarantine"
    vlan = random.choice(_VLANS[:6]) if success else 999
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    if method == "dot1x":
        msg = f"Port-access {'authenticator' if method == 'dot1x' else 'mac-auth'} {'authenticated' if success else 'rejected'} client {mac} on port {iface} {'for role {}'.format(role) if success else '- RADIUS reject'}"
    else:
        msg = f"Port-access mac-auth {'authenticated' if success else 'rejected'} client {mac} on port {iface}"
    return {**b, "type": "port-access", "subtype": method, "severity": "informational" if success else "warning",
            "module": "hpe-port-access",
            "message": msg,
            "interface": iface, "mac_address": mac, "auth_method": method,
            "result": "success" if success else "failure",
            "assigned_role": role, "assigned_vlan": vlan,
            "user": user if method == "dot1x" else "",
            "radius_server": random.choice(_RADIUS_SERVERS)}


def _radius_auth(ctx=None) -> dict[str, Any]:
    b = _base()
    server = random.choice(_RADIUS_SERVERS)
    success = random.random() < 0.85
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    return {**b, "type": "auth", "subtype": "radius", "severity": "informational" if success else "warning",
            "module": "hpe-radius",
            "message": f"RADIUS {'authentication succeeded' if success else 'authentication failed'} for user {user} from server {server}" + ("" if success else f" reason: {random.choice(['Access-Reject', 'Timeout', 'Shared-secret mismatch'])}"),
            "user": user, "radius_server": server,
            "result": "Access-Accept" if success else random.choice(["Access-Reject", "Timeout"]),
            "auth_type": random.choice(["EAP-TLS", "PEAP-MSCHAPv2", "MAB", "EAP-TTLS"])}


def _stp_event(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_INTERFACES[:30])
    vlan = random.choice(_VLANS)
    event = random.choices(
        ["topology_change", "root_change", "port_role", "bpdu_protection", "loop_protection"],
        weights=[30, 10, 25, 20, 15]
    )[0]
    msgs = {
        "topology_change": f"MSTP Topology Change on VLAN {vlan}, port {iface}",
        "root_change": f"MSTP Root bridge changed on instance {random.randint(0,15)} - new root priority {random.choice([4096, 8192, 32768, 61440])}",
        "port_role": f"MSTP port {iface} VLAN {vlan} role changed to {random.choice(['Designated', 'Root', 'Alternate', 'Backup', 'Disabled'])}",
        "bpdu_protection": f"BPDU Protection: port {iface} disabled - BPDU received on edge port",
        "loop_protection": f"Loop Protection: port {iface} blocked - loop detected on VLAN {vlan}",
    }
    sev = "critical" if event in ("bpdu_protection", "loop_protection", "root_change") else "informational"
    return {**b, "type": "stp", "subtype": event, "severity": sev,
            "module": "hpe-mstp",
            "message": msgs[event], "interface": iface, "vlan": vlan}


def _lldp_neighbor(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_INTERFACES[:30])
    event = random.choice(["add", "remove", "update"])
    neighbor = random.choice(_HOSTNAMES + ["AP-FLOOR2-01", "IP-PHONE-EXT4821", "PRINTER-3RD-FLOOR"])
    neighbor_port = random.choice([f"1/1/{random.randint(1,48)}", "GigabitEthernet0/1", "eth0"])
    return {**b, "type": "lldp", "subtype": event, "severity": "informational",
            "module": "hpe-lldp",
            "message": f"LLDP neighbor {'added' if event == 'add' else 'removed' if event == 'remove' else 'updated'}: {neighbor} on port {iface}",
            "interface": iface, "neighbor_name": neighbor, "neighbor_port": neighbor_port,
            "neighbor_ip": generate_ip() if random.random() < 0.7 else "",
            "neighbor_capabilities": random.choice(["Bridge, Router", "Bridge", "Station", "Telephone", "WLAN AP"])}


def _acl_log(ctx=None) -> dict[str, Any]:
    b = _base()
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src = pm.get("ip") if pm else generate_ip()
    dst = pc2.get("ip_c2") if pc2 else generate_ip()
    action = random.choices(["deny", "permit"], weights=[60, 40])[0]
    proto = random.choice(["tcp", "udp", "icmp"])
    dp = random.choice([22, 23, 80, 443, 3389, 161, 445, 135, 53, 8080])
    acl_name = random.choice(["MGMT-IN", "USER-OUT", "GUEST-RESTRICT", "IOT-QUARANTINE", "SERVER-ACL"])
    return {**b, "type": "acl", "subtype": action, "severity": "warning" if action == "deny" else "informational",
            "module": "hpe-acl",
            "message": f"ACL {acl_name}: {action} {proto} {src} -> {dst} port {dp}",
            "acl_name": acl_name, "action": action, "protocol": proto,
            "src_ip": src, "dst_ip": dst, "dst_port": dp}


def _dhcp_snoop(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_ACCESS_PORTS)
    mac = _mac()
    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    event = random.choices(
        ["binding_add", "drop_untrusted", "rate_limit"], weights=[50, 35, 15]
    )[0]
    msgs = {
        "binding_add": f"DHCP Snooping: binding added - IP {ip} MAC {mac} VLAN {random.choice(_VLANS[:5])} Port {iface}",
        "drop_untrusted": f"DHCP Snooping: dropped DHCP {'server' if random.random() < 0.5 else 'reply'} packet on untrusted port {iface} from {mac}",
        "rate_limit": f"DHCP Snooping: rate limit exceeded on port {iface} - port disabled",
    }
    sev = "high" if event in ("drop_untrusted", "rate_limit") else "informational"
    return {**b, "type": "dhcp_snooping", "subtype": event, "severity": sev,
            "module": "hpe-dhcpsnoop",
            "message": msgs[event], "interface": iface, "mac_address": mac, "ip": ip}


def _mgmt_audit(ctx=None) -> dict[str, Any]:
    b = _base()
    user = random.choice(_USERS[:3])
    events = [
        (f"User '{user}' logged in via {random.choice(['SSH', 'console', 'REST API', 'SNMP'])}", "login", "informational"),
        (f"User '{user}' logged out", "logout", "informational"),
        (f"Configuration changed by '{user}' via {random.choice(['CLI', 'REST', 'SNMP', 'NetEdit'])}", "config_change", "informational"),
        (f"Configuration checkpoint created by '{user}'", "checkpoint", "informational"),
        (f"Firmware upload initiated by '{user}': {random.choice(['AOS-CX_10.12.1020', 'AOS-CX_10.11.1040'])}", "firmware", "warning"),
        (f"Configuration rollback performed by '{user}'", "rollback", "warning"),
        (f"VSF member {random.randint(1,4)} {'joined' if random.random() < 0.7 else 'removed from'} stack", "vsf", "warning"),
        (f"Password policy: failed login attempt for '{user}' from {generate_ip()} - account {'locked' if random.random() < 0.2 else 'warning'}", "auth_failure", "high"),
    ]
    msg, subtype, sev = random.choice(events)
    return {**b, "type": "mgmt", "subtype": subtype, "severity": sev,
            "module": "hpe-mgmt",
            "message": msg, "user": user,
            "source": random.choice(["SSH", "console", "REST", "SNMP", "NetEdit"])}


def _loop_protection(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_ACCESS_PORTS)
    return {**b, "type": "security", "subtype": "loop-protection", "severity": "critical",
            "module": "hpe-loop-protect",
            "message": f"Loop Protection: port {iface} disabled - loop detected. Received trap PDU from self.",
            "interface": iface, "action": "port-disable"}


def _poe_event(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_ACCESS_PORTS[:24])
    event = random.choices(
        ["power_granted", "power_denied", "overload", "disconnect"], weights=[50, 15, 10, 25]
    )[0]
    watts = random.choice([15.4, 30.0, 60.0, 90.0])
    msgs = {
        "power_granted": f"PoE: Port {iface} - power enabled, allocated {watts}W, class {random.randint(0,8)}",
        "power_denied": f"PoE: Port {iface} - power denied, insufficient power budget ({random.randint(300,700)}W/{random.randint(740,1440)}W used)",
        "overload": f"PoE: Port {iface} - overload detected, current draw {watts + random.uniform(1,10):.1f}W exceeds allocated {watts}W",
        "disconnect": f"PoE: Port {iface} - powered device disconnected",
    }
    sev = "warning" if event in ("power_denied", "overload") else "informational"
    return {**b, "type": "poe", "subtype": event, "severity": sev,
            "module": "hpe-poe",
            "message": msgs[event], "interface": iface, "watts": watts}


def _environment(ctx=None) -> dict[str, Any]:
    b = _base()
    events = [
        (f"Fan tray {random.randint(1,4)}: status {'OK' if random.random() < 0.8 else 'FAILED'}", "fan", "critical" if random.random() < 0.2 else "informational"),
        (f"PSU {random.randint(1,2)}: status {'OK' if random.random() < 0.85 else 'FAULT'}", "psu", "critical" if random.random() < 0.15 else "informational"),
        (f"Temperature sensor {random.randint(1,3)}: {random.randint(25,75)}C {'(normal)' if random.random() < 0.8 else '(WARNING - threshold exceeded)'}", "temperature", "warning" if random.random() < 0.2 else "informational"),
        (f"VSF member {random.randint(1,4)} heartbeat {'OK' if random.random() < 0.9 else 'LOST'}", "vsf", "critical" if random.random() < 0.1 else "informational"),
    ]
    msg, subtype, sev = random.choice(events)
    return {**b, "type": "environment", "subtype": subtype, "severity": sev,
            "module": "hpe-env", "message": msg}


_GENERATORS = [
    (_link_state,      18), (_port_access,    15), (_radius_auth,    10),
    (_stp_event,        8), (_acl_log,        10), (_dhcp_snoop,      7),
    (_mgmt_audit,       8), (_lldp_neighbor,   5), (_loop_protection,  3),
    (_poe_event,        5), (_environment,     5), (_mgmt_audit,       6),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
