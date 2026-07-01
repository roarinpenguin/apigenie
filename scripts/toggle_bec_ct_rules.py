#!/usr/bin/env python3
"""Enable (or disable) the BEC + Cloud Takeover shipped S1 platform rules that
were found Disabled on the tenant, using the saved admin-global console settings.

Run inside the ApiGenie container (settings come from the mounted data volume):

  Enable  (default):  docker exec apigenie python scripts/toggle_bec_ct_rules.py
  Disable (rollback):  docker exec apigenie python scripts/toggle_bec_ct_rules.py --disable
  Status  (read-only): docker exec apigenie python scripts/toggle_bec_ct_rules.py --status

Reversible. No secrets are printed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import s1_detection_library as s1

# (scenario/phase, rule name, rule id) — grounded against usea1-purple 2026-06-30.
RULES: list[tuple[str, str, str]] = [
    ("BEC ph1 (Proofpoint)", "Proofpoint Impostor Email Unblocked",                  "2103847956794032742"),
    ("BEC ph2 (Okta)",       "Okta Impersonation Session Initiated",                 "1949916817668719706"),
    ("CT  ph4 (Entra)",      "Azure User Added to a Highly Privileged Built-in Role", "2012256314953575214"),
    ("CT  ph6 (M365)",       "Office 365 Service Principal Addition",                "2203626882283120129"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--disable", action="store_true", help="disable (rollback) instead of enabling")
    ap.add_argument("--status", action="store_true", help="report status only, change nothing")
    args = ap.parse_args()

    if not s1.is_configured():
        print("ERROR: S1 console settings not configured (data/s1_settings.json).")
        return 2

    st = s1.get_settings()
    print(f"console: {st.get('console_url')}")
    print(f"scope:   {s1.discover_token_scope()}")

    if args.status:
        print("action:  STATUS (read-only)\n")
        for tag, name, rid in RULES:
            rule = s1.get_platform_rule(rid) or {}
            print(f"  {rule.get('status','?'):<10} {tag:<22} {name}")
        return 0

    action = "DISABLE" if args.disable else "ENABLE"
    print(f"action:  {action}\n")

    fn = s1.disable_rule if args.disable else s1.enable_rule
    ok = 0
    for tag, name, rid in RULES:
        try:
            resp = fn(rid)
        except Exception as exc:  # pragma: no cover
            print(f"  [ERR ] {tag:<22} {name}\n         {exc}")
            continue
        err = resp.get("error") if isinstance(resp, dict) else None
        if err:
            print(f"  [FAIL] {tag:<22} {name}\n         {err} {resp.get('detail','')}")
        else:
            ok += 1
            print(f"  [ OK ] {tag:<22} {name}  (id {rid})")
    print(f"\n{action} complete: {ok}/{len(RULES)} succeeded.")
    return 0 if ok == len(RULES) else 1


if __name__ == "__main__":
    sys.exit(main())
