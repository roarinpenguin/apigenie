#!/usr/bin/env python3
"""Live lake validation for the insider_threat scenario.

Pulls the decrypted S1 console URL + API token from apigenie's saved
settings IN-PROCESS (never printed), then drives the sentinelone-mgmt-console-api
skill's pq.py + unified_alerts.py to:

  0) bucket THIS run's events by phase + source (proves landing),
  1) per-phase rule-shaped checks (does each shipped s1ql's discriminator land?),
  2) confirm which of the 6 shipped rules produced alerts (UAM).

All queries are scoped to a single run via unmapped.attack.id, so concurrent
scenarios on the tenant don't pollute the result.

Run from repo root (creds live under ./data):

  APIGENIE_DATA_ROOT="$(pwd)/data" .venv/bin/python scripts/verify_insider_lake.py \
      --attack-id att-20260629-7121 --hours 6
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

# v5.2.2 phase -> shipped rule names for the UAM alert check. Order = kill chain.
RULE_NAMES = [
    "Office 365 Bulk File Download",
    "Office 365 Creation of Mail Transport Rule",
    "Netskope Malware Upload",
    "Cisco Duo MFA Login via Bypass Code",
    "Office 365 Mailbox Audit Logging Bypass",
    "Okta High Severity Threat Detected",
]

# (label, phase.id, extra discriminator s1ql or None, extra columns or None).
# Scoped by unmapped.attack.id + unmapped.phase.id so landing is provable even
# if a discriminator field name drifts; the discriminator then proves the exact
# shipped-rule s1ql is satisfiable for this run.
PHASE_CHECKS = [
    ("collection      — Office 365 Bulk File Download", "collection", None, None),
    ("exfiltration    — Office 365 Creation of Mail Transport Rule", "exfiltration",
     "activity_name = 'New-TransportRule'", "activity_name"),
    ("exfiltration-2  — Netskope Malware Upload", "exfiltration-2",
     "activity_name = 'Malware' and unmapped.action = 'Detection' and unmapped.activity = 'Upload'",
     "activity_name, unmapped.action, unmapped.activity"),
    ("persistence     — Cisco Duo MFA Login via Bypass Code", "persistence",
     "unmapped.event_type = 'authentication' and unmapped.factor = 'bypass_code' and status_detail = 'valid_passcode'",
     "unmapped.factor, status_detail, status"),
    ("defense-evasion — Office 365 Mailbox Audit Logging Bypass", "defense-evasion",
     "activity_name = 'Set-MailboxAuditBypassAssociation'", "activity_name, metadata.product.name"),
    ("credential-access — Okta High Severity Threat Detected", "credential-access", None, None),
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
    ap.add_argument("--attack-id", default="att-20260629-7121")
    ap.add_argument("--hours", type=int, default=6)
    args = ap.parse_args()

    url, _ = _bootstrap_creds()
    print(f"console: {url}")
    print(f"attack:  {args.attack_id}   window: last {args.hours}h")

    from s1_client import S1Client
    from pq import run_pq, list_data_sources
    c = S1Client()

    aid = args.attack_id

    # ── 0) Per-phase landing for THIS run ────────────────────────────────────
    _hr("0) Events landed for this run, by phase + source")
    r = run_pq(c, f"unmapped.attack.id = '{aid}' "
                  f"| group n = count() by unmapped.phase.id, dataSource.name | sort -n",
               hours=args.hours)
    print(f"matchCount={r.get('matchCount')} rows={r.get('row_count')}")
    for row in r.get("rows", []):
        print("  ", row)

    # ── 1) Per-phase rule-shaped checks (scoped to this run) ─────────────────
    for label, phase_id, discr, cols in PHASE_CHECKS:
        _hr(f"1) {label}")
        q = f"unmapped.attack.id = '{aid}' and unmapped.phase.id = '{phase_id}'"
        if discr:
            q += " and " + discr
        colspec = "unmapped.phase.id" + (", " + cols if cols else "")
        r = run_pq(c, q + f" | columns {colspec} | limit 5", hours=args.hours)
        n = r.get("row_count") or 0
        verdict = "YES" if n else "NO"
        tag = "rule-shaped events present" if discr else "phase events present"
        print(f"{tag.upper()}: {verdict}  (matchCount={r.get('matchCount')} rows={n})")
        for row in r.get("rows", [])[:5]:
            print("  ", row)

    # ── 2) Did the 6 shipped rules produce alerts? ───────────────────────────
    _hr("2) UAM alerts — matching the 6 shipped insider_threat rules (newest first)")
    try:
        import unified_alerts as uam
        page = uam.list_alerts(c, first=1000)
        edges = page.get("edges") or page.get("data", {}).get("edges") or []

        def _ts(node):
            return node.get("detectedAt") or node.get("createdAt") or ""

        edges.sort(key=lambda e: _ts(e.get("node", e)), reverse=True)
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
                extra = f" latest={_ts(h)} status={h.get('status')} sev={h.get('severity')}"
            print(f"  [{mark}] {rn} (x{len(hits)}){extra}")
    except Exception as exc:
        print(f"  UAM check failed: {exc}")

    print("\nDone. 'NO' = events/discriminators didn't land for this run;")
    print("'----' = shipped rule produced no alert (the firing gap to chase).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
