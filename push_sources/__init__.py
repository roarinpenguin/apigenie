"""Push source generators for the Log Push framework.

Each module exposes ``generate_event(ctx=None) -> dict`` returning a single
structured log event. The framework handles formatting (JSON/syslog/CEF) and
transport (HTTP/HEC/syslog).
"""

import log_pusher


def _register_all() -> None:
    """Register all available push source types."""
    log_pusher.register_source(
        key="paloalto", name="Palo Alto Firewall (PAN-OS)", module="push_sources.paloalto",
        description="Traffic, Threat, URL, WildFire, GlobalProtect, System, Config, Auth, HIP, Decryption, Tunnel, UserID logs")
    log_pusher.register_source(
        key="fortigate", name="Fortinet FortiGate", module="push_sources.fortigate",
        description="Traffic, UTM (virus, IPS, webfilter, appctrl), Event (system, VPN), Anomaly logs")
    log_pusher.register_source(
        key="checkpoint", name="Check Point NGFW", module="push_sources.checkpoint",
        description="Firewall, IPS, Anti-Bot, Anti-Virus, Threat Emulation, URL Filtering, Application Control")
    log_pusher.register_source(
        key="cisco_asa", name="Cisco ASA / FTD", module="push_sources.cisco_asa",
        description="Connection built/teardown, denied, threat detection, VPN, AAA, system messages")
    log_pusher.register_source(
        key="crowdstrike", name="CrowdStrike Falcon (EDR)", module="push_sources.crowdstrike",
        description="DetectionSummary, IncidentSummary, AuthActivity audit events with MITRE ATT&CK mapping")
    log_pusher.register_source(
        key="carbonblack", name="Carbon Black Cloud (EDR)", module="push_sources.carbonblack",
        description="CB_ANALYTICS alerts, WATCHLIST hits, process events, network connections")
    log_pusher.register_source(
        key="zscaler", name="Zscaler Internet Access (ZIA)", module="push_sources.zscaler",
        description="Web transactions, firewall, DNS, tunnel logs via NSS format")
    log_pusher.register_source(
        key="imperva", name="Imperva Cloud WAF", module="push_sources.imperva",
        description="WAF security events, bot detection, ACL violations, DDoS mitigation")
    log_pusher.register_source(
        key="barracuda", name="Barracuda Email Security Gateway", module="push_sources.barracuda",
        description="Email filtering (spam, virus, DLP), ATP sandbox, admin audit")
    log_pusher.register_source(
        key="infoblox", name="Infoblox DDI (DNS/DHCP)", module="push_sources.infoblox",
        description="DNS queries, RPZ hits, DHCP events, threat intelligence (C2, DGA, tunneling)")
    log_pusher.register_source(
        key="cisco_switch", name="Cisco Switch (IOS/NX-OS)", module="push_sources.cisco_switch",
        description="Port security, STP, ACL, AAA, SNMP, CDP, DHCP snooping, ARP inspection, MAC flap, PoE, environmental")
    log_pusher.register_source(
        key="hpe_switch", name="HPE Aruba Switch (AOS-CX)", module="push_sources.hpe_switch",
        description="802.1X port-access, RADIUS, STP, LLDP, ACL, DHCP snooping, loop protection, PoE, VSF stacking, mgmt audit")


_register_all()
