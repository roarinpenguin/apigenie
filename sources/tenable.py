"""Tenable Vulnerability Management mock data generator."""

import random
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    epoch_to_iso,
    generate_hostname,
    generate_ip,
    generate_uuid,
    now_epoch,
    now_iso,
    weighted_choice,
)

VULNS_CHUNK_SIZE = 50
ASSETS_CHUNK_SIZE = 25
VULNS_TOTAL = 150
ASSETS_TOTAL = 75

_VULN_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "critical_log4shell": (
        {
            "plugin_name": "Apache Log4Shell RCE (Log4j) (CVE-2021-44228)",
            "severity": "critical",
            "cvss_base_score": 10.0,
            "cve": "CVE-2021-44228",
            "plugin_id": 156032,
            "solution": "Upgrade Apache Log4j2 to version 2.17.1 or later.",
        },
        0.40,
    ),
    "high_apache": (
        {
            "plugin_name": "Apache HTTP Server Vulnerabilities",
            "severity": "high",
            "cvss_base_score": 7.5,
            "cve": "CVE-2023-25690",
            "plugin_id": 173163,
            "solution": "Upgrade Apache HTTP Server to a patched version.",
        },
        0.35,
    ),
    "medium_smb": (
        {
            "plugin_name": "SMB Signing Not Required",
            "severity": "medium",
            "cvss_base_score": 5.3,
            "cve": None,
            "plugin_id": 57608,
            "solution": "Enable SMB signing on the remote host.",
        },
        0.20,
    ),
    "low_informational": (
        {
            "plugin_name": "SSL Certificate Cannot Be Trusted",
            "severity": "low",
            "cvss_base_score": 2.6,
            "cve": None,
            "plugin_id": 51192,
            "solution": "Purchase or generate a proper SSL certificate for this service.",
        },
        0.05,
    ),
}


# ── Event catalog ──────────────────────────────────────────────────────
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "critical_log4shell", "label": "Critical: Log4Shell (CVE-2021-44228)",
     "default_weight": 0.40,
     "docs_anchor": "www.tenable.com/plugins/nessus/156032"},
    {"id": "high_apache", "label": "High: Apache HTTP Server vulnerabilities",
     "default_weight": 0.35,
     "docs_anchor": "www.tenable.com/plugins/nessus/173163"},
    {"id": "medium_smb", "label": "Medium: SMB Signing Not Required",
     "default_weight": 0.20,
     "docs_anchor": "www.tenable.com/plugins/nessus/57608"},
    {"id": "low_informational", "label": "Low: SSL Certificate Cannot Be Trusted",
     "default_weight": 0.05,
     "docs_anchor": "www.tenable.com/plugins/nessus/51192"},
]


def _generate_vuln(ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    template = weighted_choice(event_mix.apply(_VULN_TEMPLATES, "tenable"))
    ts = now_epoch() - random.randint(0, 86400 * 30)
    pm = ctx.pick_machine() if ctx else None
    if pm:
        asset_hostname = pm.get("primary_workstation", generate_hostname().split(".")[0])
        asset_fqdn = f"{asset_hostname}.internal.net"
        asset_ip = pm.get("ip") or generate_ip()
        asset_os = {"windows": "Windows Server 2019", "linux": "Ubuntu 20.04"}.get(pm.get("os_type", ""), random.choice(["Windows Server 2019", "Ubuntu 20.04", "CentOS 7", "RHEL 8"]))
    else:
        asset_fqdn = generate_hostname()
        asset_hostname = asset_fqdn.split(".")[0]
        asset_ip = generate_ip()
        asset_os = random.choice(["Windows Server 2019", "Ubuntu 20.04", "CentOS 7", "RHEL 8"])
    return {
        "asset": {
            "agent_uuid": generate_uuid(),
            "device_type": random.choice(["general-purpose", "hypervisor", "router"]),
            "fqdn": asset_fqdn,
            "hostname": asset_hostname,
            "ipv4": asset_ip,
            "last_unauthenticated_results": now_iso(),
            "operating_system": [asset_os],
            "uuid": generate_uuid(),
        },
        "output": f"Port {random.choice([80, 443, 445, 8080, 22, 3389])} was found to be vulnerable.",
        "plugin": {
            "id": template["plugin_id"],
            "name": template["plugin_name"],
            "cvss_base_score": template["cvss_base_score"],
            "cvss_temporal_score": template["cvss_base_score"] - random.uniform(0, 1),
            "family": random.choice(["Web Servers", "Windows", "General", "Misc.", "Denial of Service"]),
            "risk_factor": template["severity"].title(),
            "solution": template["solution"],
            "synopsis": f"The remote host is affected by {template['plugin_name']}.",
            "see_also": ["https://nvd.nist.gov/vuln/detail/" + (template["cve"] or "N/A")],
            "cve": [template["cve"]] if template["cve"] else [],
            "publication_date": "2023-01-15",
        },
        "port": {
            "port": random.choice([80, 443, 445, 8080, 22, 3389]),
            "protocol": "TCP",
            "service": random.choice(["www", "https", "microsoft-ds", "ssh", "rdp"]),
        },
        "scan": {
            "completed_at": now_iso(),
            "schedule_uuid": generate_uuid(),
            "started_at": now_iso(),
            "uuid": generate_uuid(),
        },
        "severity": template["severity"],
        "severity_id": {"critical": 4, "high": 3, "medium": 2, "low": 1}[template["severity"]],
        "severity_default_id": {"critical": 4, "high": 3, "medium": 2, "low": 1}[template["severity"]],
        "first_found": now_iso(),
        "last_found": now_iso(),
        "state": random.choice(["open", "reopened"]),
    }


def _generate_asset() -> dict[str, Any]:
    return {
        "id": generate_uuid(),
        "has_agent": random.random() < 0.6,
        "has_plugin_results": True,
        "created_at": now_iso(),
        "terminated_at": None,
        "terminated_by": None,
        "updated_at": now_iso(),
        "deleted_at": None,
        "deleted_by": None,
        "first_seen": now_iso(),
        "last_seen": now_iso(),
        "last_scan_target": generate_ip(),
        "last_authenticated_scan_date": now_iso(),
        "last_licensed_scan_date": now_iso(),
        "last_scan_id": generate_uuid(),
        "last_schedule_id": generate_uuid(),
        "azure_vm_id": None,
        "azure_resource_id": None,
        "gcp_project_id": None,
        "gcp_zone": None,
        "gcp_instance_id": None,
        "aws_ec2_instance_ami_id": None,
        "aws_ec2_instance_id": None,
        "agent_uuid": generate_uuid(),
        "bios_uuid": generate_uuid(),
        "network_id": generate_uuid(),
        "network_name": "Default",
        "aws_owner_id": [],
        "aws_availability_zone": [],
        "aws_region": [],
        "aws_vpc_id": [],
        "aws_ec2_instance_group_name": [],
        "aws_ec2_instance_state_name": [],
        "aws_ec2_instance_type": [],
        "aws_ec2_name": [],
        "aws_ec2_product_code": [],
        "aws_subnet_id": [],
        "aws_ec2_instance_ami_id_val": [],
        "fqdns": [generate_hostname()],
        "hostnames": [generate_hostname().split(".")[0]],
        "ipv4s": [generate_ip()],
        "ipv6s": [],
        "macs": [f"00:11:22:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"],
        "operating_systems": [random.choice(["Windows Server 2019", "Ubuntu 20.04", "CentOS 7"])],
        "system_types": [random.choice(["general-purpose", "hypervisor"])],
        "tags": [{"tag_key": "Environment", "tag_value": random.choice(["Production", "Staging", "Dev"])}],
        "sources": [{"name": "NESSUS_SCAN", "first_seen": now_iso(), "last_seen": now_iso()}],
    }


def generate_vuln_chunks() -> list[list[dict[str, Any]]]:
    ctx = profiles.get_context("tenable")
    all_vulns = [_generate_vuln(ctx) for _ in range(VULNS_TOTAL)]
    chunks = []
    for i in range(0, len(all_vulns), VULNS_CHUNK_SIZE):
        chunks.append(all_vulns[i : i + VULNS_CHUNK_SIZE])
    return chunks


def generate_asset_chunks() -> list[list[dict[str, Any]]]:
    all_assets = [_generate_asset() for _ in range(ASSETS_TOTAL)]
    chunks = []
    for i in range(0, len(all_assets), ASSETS_CHUNK_SIZE):
        chunks.append(all_assets[i : i + ASSETS_CHUNK_SIZE])
    return chunks


def get_audit_logs_response(limit: int = 100, offset: int = 0) -> dict[str, Any]:
    count = profiles.scale_count("tenable", min(limit, 50))
    events = []
    actions = [
        ("scan.create", "Scan created", "info"),
        ("scan.launch", "Scan launched", "info"),
        ("policy.update", "Policy updated", "warning"),
        ("user.login.failed", "Login attempt failed", "critical"),
        ("user.login", "User logged in", "info"),
        ("plugin.update", "Plugins updated", "info"),
    ]
    for _ in range(count):
        action, description, severity = random.choice(actions)
        ts = now_epoch() - random.randint(0, 86400)
        events.append(
            {
                "id": generate_uuid(),
                "action": action,
                "cli": False,
                "crud": random.choice(["c", "r", "u", "d"]),
                "description": description,
                "is_anonymous": False,
                "is_failure": "failed" in action,
                # Real Tenable returns 'fields' as a list of {key, value} objects,
                # not a flat dict. Observo's parser unmarshals it as such.
                "fields": [
                    {"key": "Severity",     "value": severity},
                    {"key": "Source",       "value": random.choice(["web-ui", "api", "scanner"])},
                    {"key": "Source IP",    "value": generate_ip()},
                ],
                # Real Tenable returns 'received' as ISO 8601 string with millisecond
                # precision and a 'Z' suffix, not an integer epoch.
                "received": epoch_to_iso(ts).replace("+00:00", "Z"),
                "actor":  {"id": generate_uuid(), "name": f"user-{random.randint(1, 10)}@example.com"},
                "target": {"id": generate_uuid(), "name": "Vulnerability Scan", "type": "Scan"},
            }
        )
    return {"events": events, "pagination": {"total": 200, "offset": offset, "limit": limit}}
