"""Zscaler Private Access (ZPA) log generator — user activity, connector, policy events.

Matches ZPA User Activity Logs API (GET /mgmtconfig/v1/admin/auditLogs).
Auth: Bearer token (OAuth2 client credentials).
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Any
from generators import generate_ip, generate_hostname, generate_uuid
from detection_rules import inject_detection_events
import profiles

_CUSTOMER_IDS = ["12345678901234567", "98765432109876543"]
_CONNECTOR_GROUPS = ["DC-Connectors", "AWS-Connectors", "Azure-Connectors", "Branch-Connectors"]
_CONNECTORS = [
    {"id": "conn-001", "name": "zpa-connector-dc01", "group": "DC-Connectors"},
    {"id": "conn-002", "name": "zpa-connector-dc02", "group": "DC-Connectors"},
    {"id": "conn-003", "name": "zpa-connector-aws01", "group": "AWS-Connectors"},
    {"id": "conn-004", "name": "zpa-connector-azure01", "group": "Azure-Connectors"},
]
_APP_SEGMENTS = [
    {"id": "app-001", "name": "Internal Wiki", "domain": "wiki.corp.local"},
    {"id": "app-002", "name": "HR Portal", "domain": "hr.corp.local"},
    {"id": "app-003", "name": "Dev Environment", "domain": "dev.corp.local:8080"},
    {"id": "app-004", "name": "ERP System", "domain": "erp.corp.local"},
    {"id": "app-005", "name": "Database Admin", "domain": "dba.corp.local:3306"},
    {"id": "app-006", "name": "SSH Bastion", "domain": "bastion.corp.local:22"},
]
_SERVER_GROUPS = ["DC-Servers", "Cloud-Servers", "DMZ-Servers"]
_USERS = ["jsmith@corp.com", "agarcia@corp.com", "mwilson@corp.com",
          "lchen@corp.com", "admin@corp.com", "devops@corp.com"]
_POLICY_NAMES = ["Allow-Engineering", "Allow-HR", "Allow-Admin", "Default-Deny",
                  "Allow-DevOps-SSH", "Allow-DBA", "Block-Contractors"]
_IDP_NAMES = ["Okta-SSO", "Azure AD", "OneLogin"]
_OS_TYPES = ["Windows", "macOS", "Linux", "iOS", "Android"]
_CLIENT_TYPES = ["zpn_client_type_zapp", "zpn_client_type_browser", "zpn_client_type_ip_anchoring"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds") + "Z"


def _user_activity(ctx=None) -> dict[str, Any]:
    pu = ctx.pick_user() if ctx else None
    user = pu.get("email", random.choice(_USERS)) if pu else random.choice(_USERS)
    app = random.choice(_APP_SEGMENTS)
    connector = random.choice(_CONNECTORS)
    return {
        "event_type": "user_activity",
        "LogTimestamp": _now_iso(),
        "Customer": random.choice(_CUSTOMER_IDS),
        "SessionID": generate_uuid(),
        "ConnectionID": generate_uuid(),
        "User": user,
        "Idp": random.choice(_IDP_NAMES),
        "ClientPublicIP": generate_ip(),
        "ClientPrivateIP": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "ClientLatitude": round(random.uniform(25, 60), 4),
        "ClientLongitude": round(random.uniform(-120, 20), 4),
        "ClientCountryCode": random.choice(["US", "GB", "DE", "JP", "FR"]),
        "ClientZEN": random.choice(["US-East", "EU-West", "AP-Southeast"]),
        "Policy": random.choice(_POLICY_NAMES),
        "PolicyDecision": random.choice(["ALLOW", "ALLOW", "ALLOW", "DENY"]),
        "Connector": connector["name"],
        "ConnectorGroup": connector["group"],
        "ConnectorIP": generate_ip(),
        "ConnectorPort": random.choice([443, 8443]),
        "Application": app["name"],
        "AppGroup": "Default",
        "ServerIP": generate_ip(),
        "ServerPort": random.choice([80, 443, 22, 3306, 5432, 8080, 3389]),
        "InternalReason": "",
        "ConnectionStatus": random.choice(["active", "closed", "closed", "closed"]),
        "ClientType": random.choice(_CLIENT_TYPES),
        "ClientOS": random.choice(_OS_TYPES),
        "ClientVersion": f"4.{random.randint(1,5)}.0.{random.randint(100,999)}",
        "BytesRx": random.randint(100, 5000000),
        "BytesTx": random.randint(100, 1000000),
        "Duration": random.randint(1, 28800),
        "DoubleEncryption": random.choice(["0", "1"]),
    }


def _connector_status(ctx=None) -> dict[str, Any]:
    connector = random.choice(_CONNECTORS)
    return {
        "event_type": "connector_status",
        "LogTimestamp": _now_iso(),
        "Customer": random.choice(_CUSTOMER_IDS),
        "Connector": connector["name"],
        "ConnectorGroup": connector["group"],
        "PrivateIP": generate_ip(),
        "PublicIP": generate_ip(),
        "Latitude": round(random.uniform(25, 60), 4),
        "Longitude": round(random.uniform(-120, 20), 4),
        "CountryCode": random.choice(["US", "GB", "DE"]),
        "Platform": random.choice(["Linux", "Linux", "Windows"]),
        "Version": f"24.{random.randint(1,4)}.{random.randint(0,9)}",
        "ZEN": random.choice(["US-East-1", "EU-West-1", "AP-Southeast-1"]),
        "SessionStatus": random.choice(["ZPN_STATUS_AUTHENTICATED", "ZPN_STATUS_AUTHENTICATED",
                                          "ZPN_STATUS_DISCONNECTED"]),
        "CurrentActiveConnections": random.randint(0, 500),
        "TotalBytesRx": random.randint(10**6, 10**10),
        "TotalBytesTx": random.randint(10**6, 10**10),
    }


def _policy_event(ctx=None) -> dict[str, Any]:
    actions = [
        ("POLICY_CREATED", "Access policy created"),
        ("POLICY_UPDATED", "Access policy modified"),
        ("POLICY_DELETED", "Access policy deleted"),
        ("APP_SEGMENT_CREATED", "Application segment added"),
        ("APP_SEGMENT_UPDATED", "Application segment modified"),
        ("CONNECTOR_GROUP_UPDATED", "Connector group settings changed"),
        ("SERVER_GROUP_UPDATED", "Server group updated"),
    ]
    action, desc = random.choice(actions)
    return {
        "event_type": "policy_event",
        "LogTimestamp": _now_iso(),
        "Customer": random.choice(_CUSTOMER_IDS),
        "ModifiedBy": random.choice(["admin@corp.com", "secops@corp.com"]),
        "ModifiedByIP": generate_ip(),
        "ObjectType": action.split("_")[0].lower(),
        "ObjectName": random.choice(_POLICY_NAMES + [a["name"] for a in _APP_SEGMENTS]),
        "Action": action,
        "AuditOldValue": '{"enabled": true}' if "UPDATED" in action else "",
        "AuditNewValue": '{"enabled": false}' if "UPDATED" in action else "",
        "Description": desc,
    }


def _audit_event(ctx=None) -> dict[str, Any]:
    actions = [
        ("ADMIN_LOGIN", "Admin logged in"),
        ("ADMIN_LOGOUT", "Admin logged out"),
        ("API_KEY_CREATED", "API key created"),
        ("API_KEY_DELETED", "API key deleted"),
        ("IDP_CONFIG_UPDATED", "IdP configuration updated"),
        ("CERTIFICATE_UPLOADED", "TLS certificate uploaded"),
        ("SAML_ATTRIBUTE_UPDATED", "SAML attribute mapping updated"),
    ]
    action, desc = random.choice(actions)
    return {
        "event_type": "audit_event",
        "LogTimestamp": _now_iso(),
        "Customer": random.choice(_CUSTOMER_IDS),
        "AdminUser": random.choice(["admin@corp.com", "superadmin@corp.com"]),
        "AdminIP": generate_ip(),
        "Action": action,
        "Result": random.choice(["SUCCESS", "SUCCESS", "SUCCESS", "FAILURE"]),
        "Description": desc,
        "ClientUserAgent": random.choice(["Mozilla/5.0 Chrome/125.0", "ApiClient/1.0"]),
    }


def _health_event(ctx=None) -> dict[str, Any]:
    connector = random.choice(_CONNECTORS)
    return {
        "event_type": "health",
        "LogTimestamp": _now_iso(),
        "Customer": random.choice(_CUSTOMER_IDS),
        "Connector": connector["name"],
        "ConnectorGroup": connector["group"],
        "Status": random.choices(["UP", "UP", "UP", "DEGRADED", "DOWN"], weights=[60,15,10,10,5])[0],
        "CPUUtilization": round(random.uniform(5, 95), 1),
        "MemoryUtilization": round(random.uniform(20, 90), 1),
        "ServiceCount": random.randint(1, 20),
        "SessionCount": random.randint(0, 500),
        "LastUpTime": _now_iso(),
    }


_GENERATORS = [
    (_user_activity, 40), (_connector_status, 15), (_policy_event, 15),
    (_audit_event, 15), (_health_event, 15),
]
_GEN_FUNCS = [g for g, _ in _GENERATORS]
_GEN_WEIGHTS = [w for _, w in _GENERATORS]


def generate_events(count: int = 20) -> list[dict[str, Any]]:
    ctx = profiles.get_context("zscaler_zpa")
    count = profiles.scale_count("zscaler_zpa", count)
    events = [random.choices(_GEN_FUNCS, weights=_GEN_WEIGHTS, k=1)[0](ctx) for _ in range(count)]
    events = inject_detection_events("zscaler_zpa", events)
    return events
