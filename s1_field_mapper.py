"""S1 OCSF → vendor field mapper for detection rule import.

Parses S1 detection rule queries (s1ql, subQueries) and maps OCSF field
names back to the original vendor log field names used by ApiGenie generators.

Two mapping layers:
  1. unmapped.* fields → strip prefix (these ARE the original vendor fields)
  2. OCSF-native fields → per-source lookup table
"""

from __future__ import annotations

import re
from typing import Any

# ── OCSF → Vendor field mapping (per source) ────────────────────────────────

_OCSF_TO_VENDOR: dict[str, dict[str, str]] = {
    "okta": {
        "status": "outcome.result",
        "actor.user.name": "actor.displayName",
        "actor.user.email_addr": "actor.alternateId",
        "src.ip": "client.ipAddress",
        "src.ip.address": "client.ipAddress",
        "device.name": "client.device",
        "http_request.user_agent": "client.userAgent.rawUserAgent",
        "metadata.event_code": "eventType",
        "activity_name": "eventType",
    },
    "entra_id": {
        "status": "resultType",
        "status_detail": "resultDescription",
        "actor.user.name": "initiatedBy.user.displayName",
        "actor.user.uid": "initiatedBy.user.id",
        "src.ip": "initiatedBy.user.ipAddress",
        "activity_name": "operationName",
        "metadata.event_code": "operationName",
        "dst.user.name": "targetResources.0.displayName",
    },
    "m365": {
        "activity_name": "Operation",
        "metadata.event_code": "Operation",
        "actor.user.name": "UserId",
        "actor.user.email_addr": "UserId",
        "src.ip": "ClientIP",
        "src.ip.address": "ClientIP",
        "metadata.product.feature.name": "Workload",
    },
    "sentinelone": {
        "finding_info.title": "threatInfo.threatName",
        "finding_info.types": "threatInfo.classification",
        "severity": "severity",
        "src.process.name": "threatInfo.originatorProcess",
        "src.process.cmd_line": "threatInfo.commandLineArguments",
        "device.name": "agentRealtimeInfo.computerName",
        "device.ip": "agentRealtimeInfo.externalIp",
    },
    "paloalto": {
        "severity": "severity",
        "activity_name": "subtype",
        "metadata.event_code": "type",
        "src.ip": "src_ip",
        "src.ip.address": "src_ip",
        "dst.ip": "dst_ip",
        "dst.ip.address": "dst_ip",
        "src.port": "src_port",
        "dst.port": "dst_port",
        "src.zone": "src_zone",
        "dst.zone": "dst_zone",
    },
    "fortigate": {
        "severity": "level",
        "activity_name": "subtype",
        "metadata.event_code": "type",
        "src.ip": "srcip",
        "src.ip.address": "srcip",
        "dst.ip": "dstip",
        "dst.ip.address": "dstip",
    },
    "cisco_duo": {
        "status": "result",
        "actor.user.name": "user.name",
        "src.ip": "access_device.ip",
        "device.name": "access_device.hostname",
        "activity_name": "eventtype",
    },
    "netskope": {
        "activity_name": "activity",
        "actor.user.name": "user",
        "actor.user.email_addr": "user",
        "src.ip": "srcip",
        "dst.ip": "dstip",
        "severity": "severity",
    },
    "proofpoint": {
        "actor.user.email_addr": "sender",
        "dst.user.email_addr": "recipient",
        "severity": "spamScore",
        "activity_name": "action",
    },
    "cloudflare": {
        "src.ip": "ClientIP",
        "src.ip.address": "ClientIP",
        "activity_name": "Action",
        "http_request.http_method": "ClientRequestMethod",
        "http_request.url.path": "ClientRequestPath",
    },
    "cato": {
        "src.ip": "source_ip",
        "dst.ip": "destination_ip",
        "activity_name": "action",
        "severity": "severity",
        "actor.user.name": "user_name",
    },
    "zscaler_zpa": {
        "actor.user.name": "User",
        "actor.user.email_addr": "User",
        "src.ip": "ClientPublicIP",
        "src.ip.address": "ClientPublicIP",
        "activity_name": "PolicyDecision",
    },
    "darktrace": {
        "severity": "score",
        "activity_name": "type",
    },
    "wiz": {
        "severity": "severity",
        "finding_info.title": "name",
        "activity_name": "type",
    },
    "snyk": {
        "severity": "issueData.severity",
        "finding_info.title": "issueData.title",
    },
}


# ── SubQuery / S1QL parser ───────────────────────────────────────────────────

def _parse_conditions(query: str) -> list[dict[str, str]]:
    """Parse a subQuery or s1ql string into a list of field=value conditions.

    Handles operators: =, ==, contains, matches, in ('a','b'), ContainsCIS, etc.
    """
    conditions = []
    def _clean_field(f: str) -> str:
        return f.strip("()")
    # 1. field = 'value' or field == 'value'
    for m in re.finditer(r'(\S+)\s*={1,2}\s*["\']([^"\']*)["\']', query):
        conditions.append({"ocsf_field": _clean_field(m.group(1)), "value": m.group(2).strip(), "op": "="})
    # 2. field contains 'value' / field ContainsCIS 'value' / field matches 'value'
    for m in re.finditer(r'(\S+)\s+(?:contains|ContainsCIS|matches|startswith|endswith)\s+["\']([^"\']*)["\']', query, re.IGNORECASE):
        field = _clean_field(m.group(1))
        value = m.group(2).strip()
        # Avoid duplicates from = matches above
        if not any(c["ocsf_field"] == field and c["value"] == value for c in conditions):
            conditions.append({"ocsf_field": field, "value": value, "op": "contains"})
    # 3. field in ('value1', 'value2') — take first value as representative
    for m in re.finditer(r'(\S+)\s+in\s*\(([^)]+)\)', query, re.IGNORECASE):
        field = _clean_field(m.group(1))
        values_raw = m.group(2)
        values = re.findall(r'["\']([^"\']*)["\']', values_raw)
        if values:
            for v in values:
                if not any(c["ocsf_field"] == field and c["value"] == v for c in conditions):
                    conditions.append({"ocsf_field": field, "value": v, "op": "in"})
    return conditions


# S1 PowerQuery native fields — these are the actual field names used in s1ql
# queries for SentinelOne data. They are NOT OCSF fields and need no reverse mapping.
_S1_NATIVE_FIELDS = {
    "endpoint.os", "endpoint.name", "endpoint.type",
    "event.type", "event.category", "event.time",
    "src.process.name", "src.process.cmdline", "src.process.image.path",
    "src.process.image.sha256", "src.process.image.sha1",
    "src.process.parent.name", "src.process.parent.cmdline",
    "src.process.user", "src.process.pid", "src.process.storyline.id",
    "src.process.image.signedStatus", "src.process.crossProcess.target",
    "tgt.process.name", "tgt.process.cmdline", "tgt.process.image.path",
    "tgt.process.pid", "tgt.process.user",
    "tgt.file.path", "tgt.file.sha256", "tgt.file.sha1",
    "tgt.file.extension", "tgt.file.name", "tgt.file.oldPath",
    "url.address", "url.action",
    "registry.keyPath", "registry.valueName", "registry.valueData",
    "dns.request", "dns.response",
    "indicator.name", "indicator.category", "indicator.description",
    "src.ip.address", "dst.ip.address", "dst.port.number",
    "src.port.number", "event.network.direction",
    "site.name", "group.name",
    "task.name", "task.path",
    "module.path", "module.sha256",
    "dataSource.name", "dataSource.category",
}


def _map_field_to_vendor(ocsf_field: str, source: str) -> tuple[str, str]:
    """Map an OCSF field name to the vendor field name.

    Returns (vendor_field, mapping_type) where mapping_type is:
      'unmapped' — stripped unmapped.* prefix
      'native'  — S1 PowerQuery native field (no mapping needed)
      'mapped'  — found in lookup table
      'unknown' — no mapping found, kept as-is
    """
    # Layer 0: S1 native PowerQuery fields — pass through as-is
    if source == "sentinelone" and ocsf_field in _S1_NATIVE_FIELDS:
        return ocsf_field, "native"
    # Also treat any dotted field for sentinelone source as native if it looks
    # like an S1 PowerQuery field (category.subcategory pattern)
    if source == "sentinelone" and "." in ocsf_field and not ocsf_field.startswith("unmapped."):
        return ocsf_field, "native"

    # Layer 1: unmapped.* → strip prefix
    if ocsf_field.startswith("unmapped."):
        return ocsf_field[len("unmapped."):], "unmapped"

    # Layer 2: OCSF lookup table
    source_map = _OCSF_TO_VENDOR.get(source, {})
    if ocsf_field in source_map:
        return source_map[ocsf_field], "mapped"

    # Layer 3: common fields that are the same across sources
    common = {
        "severity": "severity",
        "message": "message",
        "timestamp": "timestamp",
    }
    if ocsf_field in common:
        return common[ocsf_field], "mapped"

    return ocsf_field, "unknown"


def parse_rule_for_import(rule: dict[str, Any], source_key: str) -> dict[str, Any]:
    """Parse an S1 detection rule and return import-ready field overrides.

    Args:
        rule: S1 cloud-detection rule dict (with correlationParams or s1ql)
        source_key: ApiGenie source key (e.g. 'okta')

    Returns dict with:
        importable: bool
        name: str
        source: str
        field_overrides: dict of vendor_field → value
        field_mappings: list of {ocsf_field, vendor_field, value, mapping_type}
        conditions_raw: list of raw query strings
        correlation: dict with matchesRequired, windowMinutes if applicable
    """
    result: dict[str, Any] = {
        "importable": False,
        "name": f"[S1] {rule.get('name', 'Untitled')}",
        "source": source_key,
        "description": rule.get("description", ""),
        "severity": rule.get("severity", "Medium"),
        "field_overrides": {},
        "field_mappings": [],
        "conditions_raw": [],
        "correlation": None,
        "s1_rule_id": str(rule.get("id", "")),
        "mitre": rule.get("mitreTechniqueIds", rule.get("mitre", [])),
    }

    # Check if logic is visible — catalog rules may have s1ql without hideLogic field
    has_query = bool(rule.get("s1ql")) or bool(rule.get("correlationParams", {}).get("subQueries")) or bool(rule.get("scheduledParams", {}).get("query"))
    if rule.get("hideLogic") is True or (not has_query and rule.get("hideLogic") is not False):
        return result

    # Parse correlation rules (subQueries)
    corr = rule.get("correlationParams", {})
    sub_queries = corr.get("subQueries", [])
    if sub_queries:
        result["correlation"] = {
            "entity": corr.get("entity", ""),
            "matchInOrder": corr.get("matchInOrder", False),
            "windowMinutes": corr.get("timeWindow", {}).get("windowMinutes", 0),
        }
        # Use the first subQuery as the primary detection condition
        for sq in sub_queries:
            query = sq.get("subQuery", "")
            result["conditions_raw"].append(query)
            conditions = _parse_conditions(query)
            for cond in conditions:
                # Skip dataSource.name — it's routing, not a log field
                if cond["ocsf_field"] == "dataSource.name":
                    # Extract source hint
                    continue
                vendor_field, mapping_type = _map_field_to_vendor(cond["ocsf_field"], source_key)
                result["field_mappings"].append({
                    "ocsf_field": cond["ocsf_field"],
                    "vendor_field": vendor_field,
                    "value": cond["value"],
                    "mapping_type": mapping_type,
                })
                result["field_overrides"][vendor_field] = cond["value"]
            if sq.get("matchesRequired"):
                result["correlation"]["matchesRequired"] = sq["matchesRequired"]

    # Parse s1ql (STAR rules)
    s1ql = rule.get("s1ql", "")
    if s1ql and not sub_queries:
        result["conditions_raw"].append(s1ql)
        conditions = _parse_conditions(s1ql)
        for cond in conditions:
            if cond["ocsf_field"] == "dataSource.name":
                continue
            vendor_field, mapping_type = _map_field_to_vendor(cond["ocsf_field"], source_key)
            result["field_mappings"].append({
                "ocsf_field": cond["ocsf_field"],
                "vendor_field": vendor_field,
                "value": cond["value"],
                "mapping_type": mapping_type,
            })
            result["field_overrides"][vendor_field] = cond["value"]

    # Parse scheduledParams (PowerQuery rules)
    sched = rule.get("scheduledParams", {})
    if sched and not sub_queries and not s1ql:
        query = sched.get("query", "")
        if query:
            result["conditions_raw"].append(query)
            conditions = _parse_conditions(query)
            for cond in conditions:
                if cond["ocsf_field"] == "dataSource.name":
                    continue
                vendor_field, mapping_type = _map_field_to_vendor(cond["ocsf_field"], source_key)
                result["field_mappings"].append({
                    "ocsf_field": cond["ocsf_field"],
                    "vendor_field": vendor_field,
                    "value": cond["value"],
                    "mapping_type": mapping_type,
                })
                result["field_overrides"][vendor_field] = cond["value"]

    result["importable"] = len(result["field_overrides"]) > 0
    return result
