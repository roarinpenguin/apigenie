#!/usr/bin/env python3
"""Live lake validation for the insider_threat scenario.

Pulls the decrypted S1 console URL + API token from apigenie's saved
settings IN-PROCESS (never printed), then drives the sentinelone-mgmt-console-api
skill's pq.py + unified_alerts.py to:

  A) confirm Netskope phase field-landing   (the unconfirmed activity_name='Uba'
     + unmapped.scenario/activity + count/file_size shape),
  B) confirm Cisco Duo phase field-landing  (status / status_detail),
  C) confirm the 6 shipped rules produced alerts for the run.

Run from repo root (creds live under ./data):

  APIGENIE_DATA_ROOT="$(pwd)/data" .venv/bin/python scripts/verify_insider_lake.py \
      --attack-id att-20260629-2392 --hours 6
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILL = Path.home() / ".claude" / "skills" / "sentinelone-mgmt-console-api" / "scripts"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(SKILL))

import s1_detection_library as s1  # noqa: E402

# Phase -> (rule name) for the alert check. Order mirrors the kill chain.
RULE_NAMES = [
    "Office 365 Bulk File Download",
    "Office 365 New Mailbox Forwarding Rule",
    "Netskope Insider Threat Suspicious Activity",
    "Cisco Duo Authentication Attempt from Untrusted Endpoint",
    "Office 365 Inbox Rule to Automatically Delete All Messages",
    "Okta High Severity Threat Detected",
]


def _bootstrap_creds() -> tuple[str, str]:
    """Resolve console URL + token from apigenie settings; export to env for
    the skill's S1Client. Token is never printed."""
    if not s1.is_configured():
        sys.exit("ERROR: S1 console settings not configured "
                 "(set APIGENIE_DATA_ROOT to the dir holding s1_settings.json).")
    st = s1.get_settings()
    url, tok = st.get("console_url", "").rstrip("/"), st.get("api_token", "")
    os.environ["S1_CONSOLE_URL"] = url
    os.environ["S1_CONSOLE_API_TOKEN"] = tok
    return url, tok


def _hr(title: str) -> None:
    print(f"\n{'='*78}\n# {title}\n{'='*78}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack-id", default="att-20260629-2392")
    ap.add_argument("--hours", type=int, default=6)
    args = ap.parse_args()

    url, _ = _bootstrap_creds()
    print(f"console: {url}")
    print(f"attack:  {args.attack_id}   window: last {args.hours}h")

    from s1_client import S1Client
    from pq import run_pq, list_data_sources
    c = S1Client()

    aid = args.attack_id

    # ── A) Netskope field-landing ────────────────────────────────────────────
    _hr("A) Netskope — activity_name breakdown (does 'Uba' land?)")
    r = run_pq(c, "dataSource.name = 'Netskope' "
                  "| group n = count() by activity_name | sort -n", hours=args.hours)
    print(f"matchCount={r.get('matchCount')} rows={r.get('row_count')}")
    for row in r.get("rows", []):
        print("  ", row)

    _hr("A) Netskope — rule-shaped query (exact shipped s1ql discriminators)")
    rq = ("dataSource.name = 'Netskope' and activity_name = 'Uba' and "
          "unmapped.scenario = 'Insider threat' and unmapped.activity = 'Upload' and "
          "count > 1 and unmapped.file_size > 1000000")
    r = run_pq(c, rq + " | columns activity_name, unmapped.scenario, unmapped.activity, "
                       "count, unmapped.file_size | limit 5", hours=args.hours)
    print(f"RULE WOULD FIRE: {'YES' if r.get('row_count') else 'NO'}  "
          f"(matchCount={r.get('matchCount')} rows={r.get('row_count')})")
    for row in r.get("rows", []):
        print("  ", row)

    _hr("A) Netskope — raw sample (where do scenario/activity/file_size land?)")
    r = run_pq(c, f"dataSource.name = 'Netskope' | columns activity_name, "
                  f"unmapped.scenario, unmapped.activity, unmapped.file_size, "
                  f"count, unmapped.attack.id | limit 5", hours=args.hours)
    for row in r.get("rows", []):
        print("  ", row)

    # ── B) Cisco Duo field-landing ───────────────────────────────────────────
    _hr("B) Cisco Duo — rule-shaped query (status / status_detail)")
    dq = ("dataSource.name = 'Cisco Duo' and unmapped.event_type = 'authentication' and "
          "status_detail contains ('endpoint_is_not_trusted') and status = 'success'")
    r = run_pq(c, dq + " | columns status, status_detail, unmapped.event_type | limit 5",
               hours=args.hours)
    print(f"RULE WOULD FIRE: {'YES' if r.get('row_count') else 'NO'}  "
          f"(matchCount={r.get('matchCount')} rows={r.get('row_count')})")
    for row in r.get("rows", []):
        print("  ", row)

    _hr("B) Cisco Duo — raw sample (auth events, status fields)")
    r = run_pq(c, "dataSource.name = 'Cisco Duo' | columns unmapped.event_type, "
                  "status, status_detail, unmapped.attack.id | limit 5", hours=args.hours)
    for row in r.get("rows", []):
        print("  ", row)

    # ── C) Did the 6 alerts fire? ────────────────────────────────────────────
    _hr("C) UAM alerts in window — matching the 6 shipped insider_threat rules")
    try:
        import unified_alerts as uam
        page = uam.list_alerts(c, first=200)
        edges = page.get("edges") or page.get("data", {}).get("edges") or []
        seen: dict[str, list] = {n: [] for n in RULE_NAMES}
        for e in edges:
            node = e.get("node", e)
            name = (node.get("name") or node.get("ruleName") or "")
            for rn in RULE_NAMES:
                if rn.lower() in name.lower():
                    seen[rn].append(node)
        for rn in RULE_NAMES:
            hits = seen[rn]
            mark = "FIRED" if hits else "----"
            extra = ""
            if hits:
                h = hits[0]
                extra = f" e.g. status={h.get('status')} sev={h.get('severity')} at={h.get('createdAt') or h.get('detectedAt')}"
            print(f"  [{mark}] {rn} (x{len(hits)}){extra}")
    except Exception as exc:
        print(f"  UAM check failed: {exc}")

    print("\nDone. Lines marked 'NO' / '----' are the ones to investigate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
