#!/usr/bin/env python3
"""Dump the live shipped definition (status + real s1ql + thresholds) of the 6
insider_threat platform rules, so we can compare the tenant's actual rule logic
against what attack_scenarios_library.py records.

  APIGENIE_DATA_ROOT="$(pwd)/data" .venv/bin/python scripts/inspect_insider_rules.py
  APIGENIE_DATA_ROOT="$(pwd)/data" .venv/bin/python scripts/inspect_insider_rules.py --only persistence

No secrets are printed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import s1_detection_library as s1

RULES = [
    ("collection",        "Office 365 Bulk File Download",                              "2426879488223447370"),
    ("exfiltration",      "Office 365 Creation of Mail Transport Rule",                "1948788857810956431"),
    ("exfiltration-2",    "Netskope Malware Upload",                                   "2184096624764239069"),
    ("persistence",       "Cisco Duo Authentication Attempt from Untrusted Endpoint",  "2264071526218353464"),
    ("defense-evasion",   "Office 365 Mailbox Audit Logging Bypass",                   "1948788857802567820"),
    ("credential-access", "Okta High Severity Threat Detected",                        "2406746351552083042"),
]

# Candidate keys that may hold the detection logic / threshold across API shapes.
QUERY_KEYS = ("s1ql", "query", "expression", "queryLang", "ruleContent",
              "queryType", "filter")
THRESH_KEYS = ("severity", "status", "scopeLevel", "scope", "type",
               "correlation", "threshold", "thresholdValue", "windowMinutes",
               "aggregation", "groupBy", "frequency", "cooldownSeconds")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="phase id to dump in full JSON")
    args = ap.parse_args()

    if not s1.is_configured():
        print("ERROR: S1 console settings not configured (data/s1_settings.json).")
        return 2
    st = s1.get_settings()
    print(f"console: {st.get('console_url')}")
    print(f"scope:   {s1.discover_token_scope()}\n")

    for phase, name, rid in RULES:
        rule = s1.get_platform_rule(rid) or {}
        if not rule:
            print(f"== {phase} :: {name} (id {rid}) -> NOT FOUND / no access\n")
            continue
        print(f"== {phase} :: {name} (id {rid})")
        print(f"   keys: {sorted(rule.keys())}")
        for k in THRESH_KEYS:
            if k in rule:
                print(f"   {k}: {rule[k]}")
        for k in QUERY_KEYS:
            if k in rule and rule[k]:
                print(f"   {k}: {rule[k]}")
        if args.only and args.only == phase:
            print("   --- FULL JSON ---")
            print(json.dumps(rule, indent=2, default=str))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
