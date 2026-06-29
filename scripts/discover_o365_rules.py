#!/usr/bin/env python3
"""Discover shipped O365 platform rules and flag which ones are FIREABLE on this
tenant — i.e. whose s1ql does NOT depend on unmapped.Parameters /
unmapped.OperationProperties (both proven to never land here, run
att-20260629-2392). Used to re-target the insider_threat forwarding +
inbox-delete phases to array-free rules.

  APIGENIE_DATA_ROOT="$(pwd)/data" .venv/bin/python scripts/discover_o365_rules.py
  APIGENIE_DATA_ROOT="$(pwd)/data" .venv/bin/python scripts/discover_o365_rules.py --kw forward inbox delete

No secrets are printed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import s1_detection_library as s1

ARRAY_FIELDS = ("unmapped.Parameters", "unmapped.OperationProperties")
DEFAULT_KW = ["forward", "inbox", "delete", "transport", "mailbox",
              "rule", "exfiltrat", "evidence", "audit"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kw", nargs="*", default=DEFAULT_KW,
                    help="free-text keywords to search the O365 catalog")
    ap.add_argument("--all", action="store_true",
                    help="dump every O365 rule (ignore keywords)")
    args = ap.parse_args()

    if not s1.is_configured():
        print("ERROR: S1 console settings not configured (data/s1_settings.json).")
        return 2
    print(f"console: {s1.get_settings().get('console_url')}")
    print(f"scope:   {s1.discover_token_scope()}\n")

    seen: dict[str, dict] = {}
    if args.all:
        res = s1.query_rules(source="m365", limit=500)
        for r in res.get("rules", []):
            rid = str(r.get("id") or "")
            if rid:
                seen[rid] = r
    else:
        for kw in args.kw:
            res = s1.query_rules(source="m365", query=kw, limit=200)
            for r in res.get("rules", []):
                rid = str(r.get("id") or "")
                if rid:
                    seen[rid] = r

    print(f"{len(seen)} unique O365 rules matched. Fetching s1ql...\n")

    fireable, blocked = [], []
    for rid, r in seen.items():
        full = s1.get_platform_rule(rid) or {}
        s1ql = (full.get("s1ql") or "").strip()
        name = r.get("name") or full.get("name") or "?"
        sev = full.get("severity") or r.get("severity") or "?"
        status = full.get("status") or "?"
        dep = [f for f in ARRAY_FIELDS if f in s1ql]
        entry = (name, rid, sev, status, dep, s1ql)
        (blocked if dep else fireable).append(entry)

    def dump(title, rows):
        print(f"\n{'='*78}\n# {title} ({len(rows)})\n{'='*78}")
        for name, rid, sev, status, dep, s1ql in sorted(rows, key=lambda e: e[0]):
            tag = f" [needs {','.join(dep)}]" if dep else ""
            print(f"\n- {name}  (id {rid}, {sev}, {status}){tag}")
            print(f"    {s1ql}")

    dump("FIREABLE on this tenant (no array deps)", fireable)
    dump("BLOCKED (depend on array fields that never land)", blocked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
