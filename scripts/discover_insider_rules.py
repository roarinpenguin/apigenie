#!/usr/bin/env python3
"""One-off discovery: dump shipped S1 platform rules relevant to the
insider_threat scenario phases so we can ground each phase's target_rules
+ field_overrides against rules that actually exist on the tenant.

Run from the repo root:  .venv/bin/python scripts/discover_insider_rules.py

Reads the saved admin-global S1 console settings (data/s1_settings.json,
decrypted by s1_detection_library) — no secrets are printed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import s1_detection_library as s1


def _short(rule: dict) -> dict:
    """Pull the fields we care about; keep the raw query body verbatim."""
    out = {
        "id":       rule.get("id"),
        "name":     rule.get("name"),
        "severity": rule.get("severity"),
        "status":   rule.get("status"),
        "mitre":    rule.get("mitreTactics") or rule.get("mitre"),
        "source":   rule.get("source") or rule.get("dataSource"),
    }
    # The s1ql body lives under one of several keys depending on console
    # version — surface whichever is present.
    for k in ("queryString", "query", "s1ql", "expression", "queryDetails"):
        if rule.get(k):
            out["query"] = rule[k]
            break
    return out


def dump(label: str, **kwargs) -> None:
    print(f"\n{'='*78}\n# {label}\n#   query={kwargs}\n{'='*78}")
    res = s1.query_rules(limit=25, **kwargs)
    if res.get("error"):
        print(f"  ERROR: {res['error']}  detail={res.get('detail','')}")
        return
    rules = res.get("rules", [])
    print(f"  total={res.get('total')}  shown={len(rules)}")
    for r in rules:
        print("  " + json.dumps(_short(r), ensure_ascii=False))


def main() -> int:
    print("configured:", s1.is_configured())
    st = s1.get_settings()
    print("console_url:", st.get("console_url"))
    print("scope:", s1.discover_token_scope())

    # First: dump ALL the raw keys of one rule so we know where s1ql lives.
    probe = s1.query_rules(source="netskope", limit=1)
    if probe.get("rules"):
        print("\n--- RAW KEYS of a sample rule ---")
        print(sorted(probe["rules"][0].keys()))

    # Netskope — DLP / exfiltration cloud upload
    dump("NETSKOPE — Exfiltration", source="netskope", mitre_tactic="Exfiltration")
    dump("NETSKOPE — free-text 'DLP'", source="netskope", query="DLP")
    dump("NETSKOPE — free-text 'upload'", source="netskope", query="upload")

    # Cisco Duo — off-hours / foreign-IP VPN auth
    dump("CISCO DUO — all", source="cisco_duo")
    dump("CISCO DUO — free-text 'location'", source="cisco_duo", query="location")
    dump("CISCO DUO — free-text 'anomalous'", source="cisco_duo", query="anomalous")

    # M365 — email forwarding to external
    dump("M365 — free-text 'forward'", source="m365", query="forward")
    dump("M365 — free-text 'inbox rule'", source="m365", query="inbox rule")
    dump("M365 — Defense Evasion", source="m365", mitre_tactic="Defense Evasion")
    dump("M365 — Exfiltration", source="m365", mitre_tactic="Exfiltration")

    # Okta — high severity threat (reuse target, confirm it still exists)
    dump("OKTA — free-text 'threat'", source="okta", query="threat")
    return 0


if __name__ == "__main__":
    sys.exit(main())
