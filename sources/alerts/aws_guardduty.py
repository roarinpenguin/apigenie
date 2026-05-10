"""AWS GuardDuty alert adapter."""
from __future__ import annotations
import random, uuid
from typing import Any

SOURCE_KEY = "aws_guardduty"
VENDOR_NAME = "Amazon Web Services"
PRODUCT_NAME = "Amazon GuardDuty"

VARIANTS = [
    {"name": "Backdoor:EC2/DenialOfService.Tcp",   "severity": "high",     "weight": 20},
    {"name": "Trojan:EC2/BitcoinTool.B!DNS",        "severity": "critical", "weight": 10},
    {"name": "UnauthorizedAccess:IAMUser/ConsoleLogin", "severity": "medium", "weight": 25},
    {"name": "Recon:EC2/PortProbeUnprotectedPort",  "severity": "low",      "weight": 25},
    {"name": "CryptoCurrency:EC2/BitcoinTool.B",    "severity": "high",     "weight": 10},
    {"name": "Impact:EC2/WinRMBruteForce",          "severity": "high",     "weight": 10},
]

_DESCRIPTIONS = {
    "Backdoor:EC2/DenialOfService.Tcp": "EC2 instance {instance} is performing a DoS attack using TCP against {dst_ip}.",
    "Trojan:EC2/BitcoinTool.B!DNS": "EC2 instance {instance} is querying a domain associated with Bitcoin-related activity.",
    "UnauthorizedAccess:IAMUser/ConsoleLogin": "An API was invoked from IP {src_ip} that is on a threat list.",
    "Recon:EC2/PortProbeUnprotectedPort": "An unprotected port on EC2 instance {instance} is being probed.",
    "CryptoCurrency:EC2/BitcoinTool.B": "EC2 instance {instance} is communicating with Bitcoin mining pool.",
    "Impact:EC2/WinRMBruteForce": "EC2 instance {instance} is under WinRM brute-force attack from {src_ip}.",
}


def generate(n: int, ctx: Any = None) -> list[dict]:
    weights = [v["weight"] for v in VARIANTS]
    alerts = []
    for _ in range(n):
        v = random.choices(VARIANTS, weights=weights, k=1)[0]
        instance_id = f"i-{uuid.uuid4().hex[:17]}"
        src_ip = _pick_ip(ctx, "c2")
        dst_ip = _pick_ip(ctx, "c2")
        machine = _pick_machine(ctx)
        hostname = machine.get("primary_workstation", f"ip-10-0-{random.randint(1,254)}-{random.randint(1,254)}") if machine else f"ip-10-0-{random.randint(1,254)}-{random.randint(1,254)}"

        desc = _DESCRIPTIONS.get(v["name"], "GuardDuty finding detected.").format(
            instance=instance_id, dst_ip=dst_ip, src_ip=src_ip
        )
        alerts.append({
            "finding_uid": str(uuid.uuid4()),
            "title": f"[GuardDuty] {v['name']}",
            "description": desc,
            "severity": v["severity"],
            "finding_types": ["Detection Finding", v["name"].split(":")[0]],
            "resources": [{"uid": instance_id, "name": hostname, "type": "AwsEc2Instance"}],
            "observables": [
                {"name": src_ip, "type": "ip"},
                {"name": dst_ip, "type": "ip"},
            ],
            "unmapped": {
                "accountId": "123456789012",
                "region": "eu-west-1",
                "guardduty_type": v["name"],
            },
        })
    return alerts


def _pick_ip(ctx: Any, kind: str = "c2") -> str:
    if ctx:
        c2 = ctx.pick_c2()
        if c2:
            return c2.get("ip_c2", f"198.51.100.{random.randint(1,254)}")
    return f"198.51.100.{random.randint(1,254)}"


def _pick_machine(ctx: Any) -> dict | None:
    if ctx:
        return ctx.pick_machine()
    return None
