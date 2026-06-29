#!/usr/bin/env python3
"""Enable (or disable) the 6 shipped S1 platform rules targeted by the
insider_threat scenario, using the saved admin-global console settings.

  Enable  (default):  .venv/bin/python scripts/toggle_insider_rules.py
  Disable (teardown):  .venv/bin/python scripts/toggle_insider_rules.py --disable

Reversible: --disable restores every rule to its shipped Disabled state.
No secrets are printed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import s1_detection_library as s1

# (phase, rule name, rule id) — grounded against usea1-purple 2026-06-29.
RULES: list[tuple[str, str, str]] = [
    ("collection",        "Office 365 Bulk File Download",                            "2426879488223447370"),
    ("exfiltration",      "Office 365 Creation of Mail Transport Rule",               "1948788857810956431"),
    ("exfiltration-2",    "Netskope Insider Threat Suspicious Activity",             "2193712804726176570"),
    ("persistence",       "Cisco Duo Authentication Attempt from Untrusted Endpoint", "2264071526218353464"),
    ("defense-evasion",   "Office 365 Mailbox Audit Logging Bypass",                  "1948788857802567820"),
    ("credential-access", "Okta High Severity Threat Detected",                      "2406746351552083042"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--disable", action="store_true",
                    help="disable the rules (teardown) instead of enabling")
    ap.add_argument("--status", action="store_true",
                    help="only report each rule's current status, change nothing")
    args = ap.parse_args()

    if not s1.is_configured():
        print("ERROR: S1 console settings not configured (data/s1_settings.json).")
        return 2

    st = s1.get_settings()
    print(f"console: {st.get('console_url')}")
    print(f"scope:   {s1.discover_token_scope()}")

    if args.status:
        print("action:  STATUS (read-only)\n")
        for phase, name, rid in RULES:
            rule = s1.get_platform_rule(rid) or {}
            print(f"  {rule.get('status','?'):<10} {phase:<17} {name}")
        return 0

    action = "DISABLE" if args.disable else "ENABLE"
    print(f"action:  {action}\n")

    fn = s1.disable_rule if args.disable else s1.enable_rule
    ok = 0
    for phase, name, rid in RULES:
        try:
            resp = fn(rid)
        except Exception as exc:  # pragma: no cover — surface, don't crash
            print(f"  [ERR ] {phase:<17} {name}\n         {exc}")
            continue
        err = resp.get("error") if isinstance(resp, dict) else None
        if err:
            print(f"  [FAIL] {phase:<17} {name}\n         {err} {resp.get('detail','')}")
        else:
            ok += 1
            print(f"  [ OK ] {phase:<17} {name}  (id {rid})")
    print(f"\n{action} complete: {ok}/{len(RULES)} succeeded.")
    return 0 if ok == len(RULES) else 1


if __name__ == "__main__":
    sys.exit(main())
