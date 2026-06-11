"""AWS GuardDuty mock data generator.

Event catalog grounded in the GuardDuty findings type matrix
(``docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html``).
Seven category-representative templates: C2 traffic, crypto mining, SSH
brute force, port reconnaissance, S3 data exfil, DNS data exfil, IAM
persistence. ``EVENT_CATALOG`` ids align 1:1 with ``_FINDING_TEMPLATES``
keys.
"""

import random
from typing import Any

import detection_rules
import event_mix
import profiles
from generators import (
    generate_ip,
    generate_uuid,
    now_iso,
    weighted_choice,
)

_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
_ACCOUNT_IDS = ["123456789012", "210987654321", "112233445566"]

# ── Event catalog ──────────────────────────────────────────────────────
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "c2_activity", "label": "C2 traffic (Trojan:EC2/BlackholeTraffic)",
     "default_weight": 0.35,
     "docs_anchor": "docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#trojan-ec2-blackholetraffic"},
    {"id": "crypto_mining", "label": "Crypto mining (CryptoCurrency:EC2/BitcoinTool.B!DNS)",
     "default_weight": 0.20,
     "docs_anchor": "docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#cryptocurrency-ec2-bitcointoolb"},
    {"id": "unauthorized_access", "label": "SSH brute force (UnauthorizedAccess:EC2/SSHBruteForce)",
     "default_weight": 0.15,
     "docs_anchor": "docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#unauthorizedaccess-ec2-sshbruteforce"},
    {"id": "recon", "label": "Port probe reconnaissance",
     "default_weight": 0.10,
     "docs_anchor": "docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#recon-ec2-portprobeunprotectedport"},
    {"id": "data_exfiltration", "label": "S3 data exfiltration (Exfiltration:S3/ObjectRead.Unusual)",
     "default_weight": 0.10,
     "docs_anchor": "docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#exfiltration-s3-objectreadunusual"},
    {"id": "malware", "label": "DNS exfiltration (Trojan:EC2/DNSDataExfiltration)",
     "default_weight": 0.05,
     "docs_anchor": "docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#trojan-ec2-dnsdataexfiltration"},
    {"id": "persistence", "label": "IAM persistence (Persistence:IAM/AnomalousBehavior)",
     "default_weight": 0.05,
     "docs_anchor": "docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html#persistence-iam-anomalousbehavior"},
]

_FINDING_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "c2_activity": (
        {
            "type": "Trojan:EC2/BlackholeTraffic",
            "title": "EC2 instance is communicating with a known Command and Control server",
            "description": "EC2 instance is querying a domain name associated with a known threat intelligence feed.",
            "severity": 8.9,
            "category": "Trojan",
        },
        0.35,
    ),
    "crypto_mining": (
        {
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "title": "EC2 instance is querying domain name associated with cryptocurrency mining activity",
            "description": "This finding informs you that an EC2 instance in your AWS environment is communicating with a cryptocurrency mining pool.",
            "severity": 5.5,
            "category": "CryptoCurrency",
        },
        0.20,
    ),
    "unauthorized_access": (
        {
            "type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "title": "EC2 instance is performing outbound SSH brute force attacks",
            "description": "An EC2 instance is performing outbound brute force attacks on port 22 (SSH).",
            "severity": 5.0,
            "category": "UnauthorizedAccess",
        },
        0.15,
    ),
    "recon": (
        {
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "title": "EC2 instance has an unprotected port which is being probed by a known scanner",
            "description": "One or more unprotected ports on an EC2 instance are being probed by a known malicious host.",
            "severity": 2.0,
            "category": "Recon",
        },
        0.10,
    ),
    "data_exfiltration": (
        {
            "type": "Exfiltration:S3/ObjectRead.Unusual",
            "title": "An unusual number of objects were retrieved from S3 bucket",
            "description": "This finding informs you that an IAM entity has retrieved an unusual number of objects from an S3 bucket.",
            "severity": 7.0,
            "category": "Exfiltration",
        },
        0.10,
    ),
    "malware": (
        {
            "type": "Trojan:EC2/DNSDataExfiltration",
            "title": "EC2 instance is exfiltrating data through DNS queries",
            "description": "An EC2 instance is performing DNS look-ups that have been identified as exfiltrating data.",
            "severity": 8.0,
            "category": "Trojan",
        },
        0.05,
    ),
    "persistence": (
        {
            "type": "Persistence:IAM/AnomalousBehavior",
            "title": "An API was invoked that is commonly associated with persistence tactics",
            "description": "An API associated with persistence tactics was invoked in a manner consistent with anomalous behavior.",
            "severity": 7.5,
            "category": "Persistence",
        },
        0.05,
    ),
}


def _generate_finding(ctx: profiles.ProfileContext | None = None) -> dict[str, Any]:
    template = weighted_choice(event_mix.apply(_FINDING_TEMPLATES, "aws_guardduty"))
    region = random.choice(_REGIONS)
    account_id = random.choice(_ACCOUNT_IDS)
    finding_id = generate_uuid().replace("-", "")
    instance_id = f"i-{generate_uuid()[:17]}"
    pm = ctx.pick_machine() if ctx else None
    pc2 = ctx.pick_c2() if ctx else None
    src_ip = pm.get("ip") if pm else generate_ip()
    dst_ip = pc2.get("ip_c2") if pc2 else generate_ip()

    return {
        "AccountId": account_id,
        "Arn": f"arn:aws:guardduty:{region}:{account_id}:detector/{generate_uuid()[:32]}/finding/{finding_id}",
        "CreatedAt": now_iso(),
        "Description": template["description"],
        "Id": finding_id,
        "Region": region,
        "Severity": template["severity"],
        "Title": template["title"],
        "Type": template["type"],
        "UpdatedAt": now_iso(),
        "Service": {
            "Action": {
                "ActionType": random.choice(["NETWORK_CONNECTION", "AWS_API_CALL", "DNS_REQUEST", "PORT_PROBE"]),
                "NetworkConnectionAction": {
                    "Blocked": False,
                    "ConnectionDirection": random.choice(["INBOUND", "OUTBOUND"]),
                    "LocalPortDetails": {
                        "Port": random.choice([22, 3389, 80, 443, 3306, 8080]),
                        "PortName": random.choice(["SSH", "RDP", "HTTP", "HTTPS", "MYSQL", "HTTP_8080"]),
                    },
                    "Protocol": random.choice(["TCP", "UDP"]),
                    "RemoteIpDetails": {
                        "City": {"CityName": random.choice(["Beijing", "Moscow", "Lagos", "Pyongyang"])},
                        "Country": {"CountryCode": random.choice(["CN", "RU", "NG", "KP"]), "CountryName": "Unknown"},
                        "IpAddressV4": dst_ip,
                        "Organization": {"Asn": str(random.randint(10000, 99999)), "AsnOrg": "Unknown ISP"},
                    },
                    "LocalIpDetails": {"IpAddressV4": src_ip},
                },
            },
            "Archived": False,
            "Count": random.randint(1, 50),
            "DetectorId": generate_uuid()[:32],
            "EventFirstSeen": now_iso(),
            "EventLastSeen": now_iso(),
            "ResourceRole": "TARGET",
            "ServiceName": "guardduty",
        },
        "Resource": {
            "InstanceDetails": {
                "AvailabilityZone": f"{region}a",
                "ImageId": f"ami-{generate_uuid()[:8]}",
                "InstanceId": instance_id,
                "InstanceState": "running",
                "InstanceType": random.choice(["t3.micro", "m5.large", "c5.xlarge"]),
                "LaunchTime": now_iso(),
                "NetworkInterfaces": [
                    {
                        "Ipv6Addresses": [],
                        "NetworkInterfaceId": f"eni-{generate_uuid()[:8]}",
                        "PrivateDnsName": f"ip-10-0-{random.randint(0,255)}-{random.randint(0,255)}.{region}.compute.internal",
                        "PrivateIpAddress": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                        "PrivateIpAddresses": [],
                        "PublicDnsName": "",
                        "PublicIp": src_ip,
                        "SecurityGroups": [{"GroupId": f"sg-{generate_uuid()[:8]}", "GroupName": "default"}],
                        "SubnetId": f"subnet-{generate_uuid()[:8]}",
                        "VpcId": f"vpc-{generate_uuid()[:8]}",
                    }
                ],
                "Tags": [{"Key": "Environment", "Value": random.choice(["Production", "Staging"])}],
            },
            "ResourceType": "Instance",
        },
        "SchemaVersion": "2.0",
    }


def get_findings_response(limit: int = 50) -> dict[str, Any]:
    ctx = profiles.get_context("aws_guardduty")
    count = profiles.scale_count("aws_guardduty", min(limit, 50))
    findings = [_generate_finding(ctx) for _ in range(count)]
    findings = detection_rules.inject_detection_events("aws_guardduty", findings)
    findings.sort(key=lambda x: x["UpdatedAt"], reverse=True)
    return {"Findings": findings}
