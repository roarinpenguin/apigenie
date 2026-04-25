"""Microsoft Defender for Cloud mock data generator."""

import random
from typing import Any

from generators import (
    generate_hostname,
    generate_ip,
    generate_uuid,
    now_iso,
    weighted_choice,
)

_ALERT_TEMPLATES: dict[str, tuple[dict[str, Any], float]] = {
    "security_alert": (
        {
            "alertDisplayName": "Suspicious process executed",
            "description": "A suspicious process was executed on the virtual machine.",
            "severity": "Medium",
            "intent": "Execution",
            "compromisedEntity": "VirtualMachine",
        },
        0.40,
    ),
    "brute_force_rdp": (
        {
            "alertDisplayName": "Suspicious RDP login from external IP",
            "description": "Multiple failed RDP login attempts followed by a successful login.",
            "severity": "High",
            "intent": "PreAttack",
            "compromisedEntity": "VirtualMachine",
        },
        0.25,
    ),
    "suspicious_powershell": (
        {
            "alertDisplayName": "Suspicious PowerShell Activity Detected",
            "description": "Encoded PowerShell command executed that may indicate malicious activity.",
            "severity": "High",
            "intent": "Execution",
            "compromisedEntity": "VirtualMachine",
        },
        0.20,
    ),
    "lsass_dump": (
        {
            "alertDisplayName": "Suspicious LSASS Memory Access",
            "description": "A process attempted to access LSASS process memory.",
            "severity": "High",
            "intent": "CredentialAccess",
            "compromisedEntity": "VirtualMachine",
        },
        0.10,
    ),
    "cryptominer": (
        {
            "alertDisplayName": "Possible crypto mining activity",
            "description": "Process behavior consistent with cryptocurrency mining was detected.",
            "severity": "Medium",
            "intent": "Impact",
            "compromisedEntity": "VirtualMachine",
        },
        0.05,
    ),
}

_RESOURCE_GROUPS = ["rg-production", "rg-staging", "rg-dev", "rg-security"]
_SUBSCRIPTIONS = [generate_uuid() for _ in range(3)]


def get_alerts_response(limit: int = 50) -> dict[str, Any]:
    count = min(limit, 50)
    alerts = []
    for _ in range(count):
        template = weighted_choice(_ALERT_TEMPLATES)
        sub = random.choice(_SUBSCRIPTIONS)
        rg = random.choice(_RESOURCE_GROUPS)
        hostname = generate_hostname().split(".")[0]
        alert_id = generate_uuid()
        alerts.append(
            {
                "id": f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Security/locations/centralus/alerts/{alert_id}",
                "name": alert_id,
                "type": "Microsoft.Security/Locations/alerts",
                "properties": {
                    "alertDisplayName": template["alertDisplayName"],
                    "alertType": template["alertDisplayName"].replace(" ", "_").upper(),
                    "compromisedEntity": hostname,
                    "description": template["description"],
                    "detectedTimeUtc": now_iso(),
                    "entities": [
                        {"$id": "1", "type": "host", "hostName": hostname, "omsAgentId": generate_uuid()},
                        {"$id": "2", "type": "ip", "address": generate_ip()},
                    ],
                    "extendedProperties": {
                        "resourceType": "Virtual Machine",
                        "compromisedHost": hostname,
                        "attackedHost": hostname,
                    },
                    "intent": template["intent"],
                    "isIncident": False,
                    "productComponentName": "VirtualMachines",
                    "productName": "Azure Security Center",
                    "remediationSteps": ["Review the process tree", "Isolate the VM if compromised"],
                    "reportedSeverity": template["severity"],
                    "reportedTimeUtc": now_iso(),
                    "state": random.choice(["Active", "Dismissed", "Resolved"]),
                    "subscriptionId": sub,
                    "vendorName": "Microsoft",
                },
            }
        )
    return {"value": alerts, "nextLink": None}


def get_recommendations_response(limit: int = 25) -> dict[str, Any]:
    count = min(limit, 25)
    recs = []
    rec_names = [
        "MFA should be enabled on accounts with owner permissions on your subscription",
        "Vulnerabilities in security configuration on your machines should be remediated",
        "Endpoint protection solution should be installed on your virtual machines",
        "System updates should be installed on your machines",
        "Network security groups should restrict inbound traffic on management ports",
    ]
    for _ in range(count):
        sub = random.choice(_SUBSCRIPTIONS)
        rg = random.choice(_RESOURCE_GROUPS)
        rec_id = generate_uuid()
        recs.append(
            {
                "id": f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Security/assessments/{rec_id}",
                "name": rec_id,
                "type": "Microsoft.Security/assessments",
                "properties": {
                    "displayName": random.choice(rec_names),
                    "status": {"code": random.choice(["Unhealthy", "Healthy", "NotApplicable"])},
                    "severity": random.choice(["High", "Medium", "Low"]),
                    "resourceDetails": {
                        "Source": "Azure",
                        "ResourceId": f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/vm-{generate_uuid()[:8]}",
                    },
                    "timeGenerated": now_iso(),
                },
            }
        )
    return {"value": recs, "nextLink": None}
