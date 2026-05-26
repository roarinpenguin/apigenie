"""Cisco Switch (IOS/IOS-XE/NX-OS) log generator — realistic syslog events.

Covers: port security violations, STP topology changes, ACL hits, AAA
authentication, SNMP traps, CDP/LLDP neighbor changes, DHCP snooping,
dynamic ARP inspection, MAC flap, link up/down, VLAN changes, config
changes, stack events, PoE, environmental (fans, PSU, temperature).
Fields match real Cisco IOS 17.x / NX-OS 10.x syslog format.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone, timedelta
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid

_HOSTNAMES = ["CORE-SW01", "CORE-SW02", "DIST-SW01", "DIST-SW02",
              "ACCESS-SW01", "ACCESS-SW02", "ACCESS-SW03", "DC-NEXUS01"]
_INTERFACES = [f"GigabitEthernet1/0/{i}" for i in range(1, 49)] + \
              [f"TenGigabitEthernet1/1/{i}" for i in range(1, 5)] + \
              ["Port-channel1", "Port-channel2", "Vlan1", "Vlan10", "Vlan20",
               "Vlan100", "Vlan200", "Loopback0", "mgmt0"]
_ACCESS_PORTS = [f"GigabitEthernet1/0/{i}" for i in range(1, 49)]
_UPLINKS = ["TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/2", "Port-channel1", "Port-channel2"]
_VLANS = [1, 10, 20, 30, 50, 100, 200, 300, 999]
_VLAN_NAMES = {1: "default", 10: "MGMT", 20: "SERVERS", 30: "USERS", 50: "VOICE",
               100: "DMZ", 200: "GUEST", 300: "IOT", 999: "QUARANTINE"}
_USERS = ["admin", "netops", "svc-monitor", "jsmith", "agarcia", "tacacs-user"]
_SNMP_COMMUNITIES = ["public", "private", "monitoring-RO"]
_ACL_NAMES = ["MGMT-ACCESS", "DENY-TELNET", "PERMIT-ICMP", "BLOCK-RFC1918", "VLAN10-IN"]
_STP_MODES = ["rstp", "mstp", "pvst+"]
_MAC_VENDORS = ["00:1A:2B", "00:50:56", "AC:DE:48", "3C:22:FB", "F4:8E:38",
                "00:0C:29", "B8:27:EB", "DC:A6:32"]


def _mac() -> str:
    vendor = random.choice(_MAC_VENDORS)
    suffix = ":".join(f"{random.randint(0,255):02X}" for _ in range(3))
    return f"{vendor}:{suffix}"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S.%f")[:-3]


def _base() -> dict[str, Any]:
    hostname = random.choice(_HOSTNAMES)
    return {
        "timestamp": _ts(), "hostname": hostname,
        "vendor": "Cisco", "product": "IOS",
        "device_version": random.choice(["17.9.4a", "17.6.6", "16.12.10", "10.3(4a)", "9.3(12)"]),
        "serial": f"FCW{random.randint(2000,2999)}{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))}",
    }


def _link_updown(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_INTERFACES)
    state = random.choices(["up", "down"], weights=[70, 30])[0]
    speed = random.choice(["100Mbps", "1Gbps", "10Gbps", "auto"]) if state == "up" else ""
    duplex = random.choice(["full", "half", "auto"]) if state == "up" else ""
    mid = "LINK-3-UPDOWN" if state == "up" else "LINK-3-UPDOWN"
    return {**b, "type": "link", "subtype": state, "severity": "informational" if state == "up" else "warning",
            "facility": "LINK", "mnemonic": "UPDOWN",
            "message": f"%{mid}: Interface {iface}, changed state to {state}",
            "interface": iface, "state": state, "speed": speed, "duplex": duplex}


def _port_security(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_ACCESS_PORTS)
    mac = _mac()
    vlan = random.choice(_VLANS[:6])
    action = random.choice(["restrict", "shutdown", "protect"])
    return {**b, "type": "security", "subtype": "port-security", "severity": "high",
            "facility": "PM", "mnemonic": "ERR_DISABLE",
            "message": f"%PM-4-ERR_DISABLE: psecure-violation error detected on {iface}, putting {iface} in err-disable state",
            "interface": iface, "mac_address": mac, "vlan": vlan, "action": action,
            "violation_count": random.randint(1, 50),
            "max_mac": random.choice([1, 2, 3, 5])}


def _stp_event(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_INTERFACES[:20])
    vlan = random.choice(_VLANS)
    event = random.choices(
        ["topology_change", "root_change", "port_state", "bpdu_guard", "loop_guard"],
        weights=[30, 10, 30, 20, 10]
    )[0]
    msgs = {
        "topology_change": f"%SPANTREE-5-TOPOTRAP: Topology change Trap for vlan {vlan}",
        "root_change": f"%SPANTREE-2-ROOTBRIDGE_CHANGE: Root bridge changed for vlan {vlan}. Old root: {random.randint(1,65535)}. New root: {random.randint(1,65535)}",
        "port_state": f"%SPANTREE-5-EXTENDED_SYSID: {iface} Vlan{vlan} state changed to {'forwarding' if random.random() < 0.7 else 'blocking'}",
        "bpdu_guard": f"%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port {iface} with BPDU Guard enabled. Disabling port.",
        "loop_guard": f"%SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocking port {iface} on Vlan{vlan}.",
    }
    sev = "critical" if event in ("root_change", "bpdu_guard", "loop_guard") else "informational"
    return {**b, "type": "stp", "subtype": event, "severity": sev,
            "facility": "SPANTREE", "mnemonic": event.upper(),
            "message": msgs[event], "interface": iface, "vlan": vlan}


def _acl_hit(ctx=None) -> dict[str, Any]:
    b = _base()
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src = pm.get("ip") if pm else generate_ip()
    dst = pc2.get("ip_c2") if pc2 else generate_ip()
    action = random.choices(["denied", "permitted"], weights=[60, 40])[0]
    acl = random.choice(_ACL_NAMES)
    proto = random.choice(["tcp", "udp", "icmp", "ip"])
    sp = random.randint(1024, 65535)
    dp = random.choice([22, 23, 80, 443, 3389, 161, 445, 135, 53])
    return {**b, "type": "acl", "subtype": action, "severity": "warning" if action == "denied" else "informational",
            "facility": "SEC", "mnemonic": f"IPACCESSLOG{'D' if action == 'denied' else 'P'}",
            "message": f"%SEC-6-IPACCESSLOG{'D' if action == 'denied' else 'P'}: list {acl} {action} {proto} {src}({sp}) -> {dst}({dp}), {random.randint(1,100)} packet{'s' if random.random() > 0.5 else ''}",
            "acl_name": acl, "action": action, "protocol": proto,
            "src_ip": src, "dst_ip": dst, "src_port": sp, "dst_port": dp,
            "hit_count": random.randint(1, 1000)}


def _aaa_auth(ctx=None) -> dict[str, Any]:
    b = _base()
    pu = ctx.pick_user() if ctx else None
    user = pu.get("username", random.choice(_USERS)) if pu else random.choice(_USERS)
    success = random.random() < 0.85
    method = random.choice(["TACACS+", "RADIUS", "LOCAL", "LDAP"])
    src_ip = generate_ip()
    line = random.choice(["vty0", "vty1", "vty2", "con0", "aux0"])
    return {**b, "type": "auth", "subtype": "aaa", "severity": "informational" if success else "warning",
            "facility": "SEC_LOGIN", "mnemonic": "LOGIN_SUCCESS" if success else "LOGIN_FAILED",
            "message": f"%SEC_LOGIN-{'5' if success else '4'}-{'LOGIN_SUCCESS' if success else 'LOGIN_FAILED'}: Login {'Success' if success else 'Failed'} [user: {user}] [Source: {src_ip}] [localport: {random.choice([22,23,443])}] [Reason: {'Login Successful' if success else random.choice(['Invalid Password', 'Account Locked', 'Timeout', 'No Such User'])}]",
            "user": user, "src_ip": src_ip, "method": method, "line": line,
            "result": "success" if success else "failure"}


def _dhcp_snooping(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_ACCESS_PORTS)
    mac = _mac()
    event = random.choices(
        ["binding_add", "binding_remove", "drop_untrusted", "rate_limit"],
        weights=[40, 20, 30, 10]
    )[0]
    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    msgs = {
        "binding_add": f"%DHCP_SNOOPING-6-BINDADD: DHCP snooping binding added: MAC {mac} IP {ip} VLAN {random.choice(_VLANS[:5])} Interface {iface}",
        "binding_remove": f"%DHCP_SNOOPING-6-BINDREMOVE: DHCP snooping binding removed: MAC {mac} VLAN {random.choice(_VLANS[:5])} Interface {iface}",
        "drop_untrusted": f"%DHCP_SNOOPING-5-DHCP_SNOOPING_ERRDISABLE_WARNING: DHCP Snooping received {random.randint(10,100)} DHCP packets on untrusted port {iface}",
        "rate_limit": f"%DHCP_SNOOPING-4-DHCP_SNOOPING_RATE_LIMIT_EXCEEDED: Rate limit exceeded on interface {iface}. The interface is being error disabled.",
    }
    sev = "high" if event in ("drop_untrusted", "rate_limit") else "informational"
    return {**b, "type": "dhcp_snooping", "subtype": event, "severity": sev,
            "facility": "DHCP_SNOOPING", "message": msgs[event],
            "interface": iface, "mac_address": mac, "ip": ip}


def _arp_inspection(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_ACCESS_PORTS)
    mac = _mac()
    ip = generate_ip()
    return {**b, "type": "security", "subtype": "dai", "severity": "high",
            "facility": "SW_DAI", "mnemonic": "DHCP_SNOOPING_DENY",
            "message": f"%SW_DAI-4-DHCP_SNOOPING_DENY: {random.randint(1,50)} Invalid ARPs (Req) on {iface}, vlan {random.choice(_VLANS[:5])}([{mac}/{ip}/0.0.0.0/00:00:00:00:00:00/{random.choice(['00:00:00','12:34:56'])}])",
            "interface": iface, "mac_address": mac, "src_ip": ip,
            "drop_count": random.randint(1, 100)}


def _mac_flap(ctx=None) -> dict[str, Any]:
    b = _base()
    mac = _mac()
    vlan = random.choice(_VLANS[:6])
    old_port = random.choice(_ACCESS_PORTS[:24])
    new_port = random.choice(_ACCESS_PORTS[24:])
    return {**b, "type": "switching", "subtype": "mac-flap", "severity": "warning",
            "facility": "SW_MATM", "mnemonic": "MACFLAP_NOTIF",
            "message": f"%SW_MATM-4-MACFLAP_NOTIF: Host {mac} in vlan {vlan} is flapping between port {old_port} and port {new_port}",
            "mac_address": mac, "vlan": vlan, "old_port": old_port, "new_port": new_port,
            "flap_count": random.randint(2, 50)}


def _config_change(ctx=None) -> dict[str, Any]:
    b = _base()
    user = random.choice(_USERS[:3])
    return {**b, "type": "config", "subtype": "change", "severity": "informational",
            "facility": "SYS", "mnemonic": "CONFIG_I",
            "message": f"%SYS-5-CONFIG_I: Configured from {random.choice(['console', 'vty0', 'vty1'])} by {user} on {random.choice(['console', f'vty0 ({generate_ip()})'])}",
            "user": user, "source": random.choice(["console", "ssh", "telnet", "snmp"]),
            "config_action": random.choice(["write memory", "interface config", "vlan add", "acl modify",
                                             "snmp community change", "ntp config", "aaa config"])}


def _snmp_trap(ctx=None) -> dict[str, Any]:
    b = _base()
    trap = random.choice([
        ("SNMP-5-COLDSTART", "SNMP agent restarting - cold start", "informational"),
        ("SNMP-4-NOTRAPIP", f"SNMP trap destination {generate_ip()} unreachable", "warning"),
        ("SNMP-3-AUTHFAIL", f"Authentication failure for SNMP community from {generate_ip()}", "high"),
        ("SNMP-5-LINK_TRAP", f"LinkDown Trap for interface {random.choice(_INTERFACES)}", "informational"),
        ("SNMP-5-LINK_TRAP", f"LinkUp Trap for interface {random.choice(_INTERFACES)}", "informational"),
    ])
    return {**b, "type": "snmp", "subtype": "trap", "severity": trap[2],
            "facility": "SNMP", "message": f"%{trap[0]}: {trap[1]}"}


def _cdp_neighbor(ctx=None) -> dict[str, Any]:
    b = _base()
    iface = random.choice(_INTERFACES[:20])
    neighbor = random.choice(_HOSTNAMES + ["UNKNOWN-DEVICE", "AP-FLOOR3", "IP-PHONE-4821"])
    event = random.choice(["add", "remove", "change"])
    return {**b, "type": "cdp", "subtype": event, "severity": "informational",
            "facility": "CDP", "mnemonic": f"NEIGHBOR_{'ADD' if event == 'add' else 'REMOVE' if event == 'remove' else 'CHANGE'}",
            "message": f"%CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch on {iface} ({random.choice(_VLANS)}), with {neighbor} ({random.choice(_VLANS)})" if event == "change" else f"%CDP-4-DUPLEX_MISMATCH: duplex mismatch on {iface}",
            "interface": iface, "neighbor": neighbor,
            "neighbor_platform": random.choice(["WS-C3850-48U", "WS-C9300-48U", "N9K-C93180YC-EX", "AIR-AP2802I", "CP-8845"])}


def _environment(ctx=None) -> dict[str, Any]:
    b = _base()
    events = [
        ("FAN-3-FAN_FAILED", "Fan 1 has failed", "critical"),
        ("PLATFORM_ENV-1-FAN", "Fan tray status changed to OK", "informational"),
        ("PLATFORM_ENV-6-MODULE_TEMPERATURE", f"Module temperature {random.randint(35,85)}C", "warning" if random.random() < 0.3 else "informational"),
        ("PLATFORM_ENV-1-PSU", f"Power supply {random.randint(1,2)} {'OK' if random.random() < 0.8 else 'FAILED'}", "critical" if random.random() < 0.2 else "informational"),
        ("STACKMGR-4-STACK_LINK_CHANGE", f"Stack port 1 on switch {random.randint(1,4)} is {'UP' if random.random() < 0.7 else 'DOWN'}", "warning"),
        ("ILPOWER-5-POWER_GRANTED", f"Interface {random.choice(_ACCESS_PORTS)}: Power granted, watts {random.choice([15.4, 30.0, 60.0])}", "informational"),
    ]
    code, msg, sev = random.choice(events)
    return {**b, "type": "environment", "subtype": code.split("-")[0].lower(), "severity": sev,
            "facility": code.split("-")[0], "message": f"%{code}: {msg}"}


_GENERATORS = [
    (_link_updown,     20), (_acl_hit,         15), (_aaa_auth,       12),
    (_stp_event,       10), (_port_security,    8), (_dhcp_snooping,   8),
    (_config_change,    7), (_mac_flap,         5), (_snmp_trap,       4),
    (_cdp_neighbor,     3), (_arp_inspection,   3), (_environment,     5),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]

def generate_event(ctx=None) -> dict[str, Any]:
    gen = random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0]
    return gen(ctx=ctx)
