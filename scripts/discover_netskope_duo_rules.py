#!/usr/bin/env python3
"""Discover shipped Netskope + Cisco Duo platform rules and flag which ones are
FIREABLE on this tenant given what apigenie's generators provably LAND.

Run att-20260629-7121 proved the injected discriminator overrides for these two
pull sources do NOT surface in the lake — only natural-vocabulary values land:

  Netskope  activity_name ∈ {Malware, DLP, Policy, quarantine, uba, malsite,
                              Security Assessment, Compromised Credential,
                              anomaly, watchlist, Remediation}
            unmapped.action ∈ {block, alert, quarantine, remediate}
            unmapped.activity = NEVER lands (no raw->unmapped.activity mapping)
  Cisco Duo status ∈ {SUCCESS, FAILURE, FRAUD, ERROR}
            status_detail ∈ {user_approved, valid_passcode, remembered_device,
                             user_denied, no_response, invalid_passcode,
                             factor_disabled, user_marked_fraud, user_not_enrolled,
                             locked_out, no_active_auth_methods}
            unmapped.event_type = 'authentication'
            unmapped.result / unmapped.reason = NEVER land (mapped away)

So a rule is re-target-worthy iff its s1ql discriminators are satisfiable using
ONLY these landing fields+values. This script dumps every rule's s1ql and flags
the never-landing fields so the operator can pick.

  APIGENIE_DATA_ROOT="$(pwd)/data" .venv/bin/python scripts/discover_netskope_duo_rules.py

No secrets are printed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import s1_detection_library as s1

# Fields that never reach the lake for each source (value-blind, field-level).
NEVER_LAND = {
    "netskope": ("unmapped.activity",),
    "cisco_duo": ("unmapped.result", "unmapped.reason"),
}

# Natural landing vocab — printed alongside so the operator can eyeball whether a
# rule's literal values are satisfiable.
LANDING = {
    "netskope": "activity_name∈{Malware,DLP,Policy,quarantine,uba,malsite,Security Assessment,"
                "Compromised Credential,anomaly,watchlist,Remediation}  "
                "unmapped.action∈{block,alert,quarantine,remediate}",
    "cisco_duo": "status∈{SUCCESS,FAILURE,FRAUD,ERROR}  "
                 "status_detail∈{user_approved,valid_passcode,remembered_device,user_denied,"
                 "no_response,invalid_passcode,factor_disabled,user_marked_fraud,"
                 "user_not_enrolled,locked_out,no_active_auth_methods}  "
                 "unmapped.event_type='authentication'",
}


def discover(source: str) -> None:
    print(f"\n{'#'*78}\n# {source}  (data source: {s1.SOURCE_KEY_TO_S1.get(source)})\n{'#'*78}")
    print(f"LANDS: {LANDING[source]}\n")

    res = s1.query_rules(source=source, limit=500)
    rules = res.get("rules", [])
    print(f"{len(rules)} {source} rules in catalog (total={res.get('total')}). Fetching s1ql...\n")

    rows = []
    for r in rules:
        rid = str(r.get("id") or "")
        if not rid:
            continue
        full = s1.get_platform_rule(rid) or {}
        s1ql = (full.get("s1ql") or "").strip()
        name = r.get("name") or full.get("name") or "?"
        sev = full.get("severity") or r.get("severity") or "?"
        status = full.get("status") or "?"
        dep = [f for f in NEVER_LAND[source] if f in s1ql]
        rows.append((name, rid, sev, status, dep, s1ql))

    clean = [e for e in rows if not e[4]]
    flagged = [e for e in rows if e[4]]

    def dump(title, items):
        print(f"\n{'='*78}\n# {title} ({len(items)})\n{'='*78}")
        for name, rid, sev, status, dep, s1ql in sorted(items, key=lambda e: e[0]):
            tag = f"  [needs {','.join(dep)}]" if dep else ""
            print(f"\n- {name}  (id {rid}, {sev}, {status}){tag}")
            print(f"    {s1ql or '(no s1ql / threshold rule)'}")

    dump(f"{source}: no never-land field deps (CANDIDATES — verify values vs LANDS)", clean)
    dump(f"{source}: depend on never-land fields (AVOID)", flagged)


def main() -> int:
    if not s1.is_configured():
        print("ERROR: S1 console settings not configured (data/s1_settings.json).")
        return 2
    print(f"console: {s1.get_settings().get('console_url')}")
    print(f"scope:   {s1.discover_token_scope()}")
    for src in ("netskope", "cisco_duo"):
        discover(src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
