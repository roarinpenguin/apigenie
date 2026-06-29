#!/usr/bin/env python3
"""Functional sanity check: confirm the insider_threat Netskope + Cisco Duo
phases actually emit events carrying each target rule's discriminator fields
through the REAL source generators + detection injection.

Run from the repo root:  .venv/bin/python scripts/verify_insider_emit.py
(Field→lake mapping is still confirmed live; this only proves the emit path.)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import attack_scenarios_library as L
import detection_rules as dr


def _phase(key: str, pid: str) -> dict:
    for p in L.get_template(key)["phases"]:
        if p["phase_id"] == pid:
            return p
    raise SystemExit(f"phase {pid} not found")


def main() -> int:
    # ── Netskope insider-threat upload ───────────────────────────────────
    dr._save_rules([])
    dr._injected_total.clear()
    p = _phase("insider_threat", "exfiltration-2")
    dr.create_rule({
        "name": "verify-netskope", "source": "netskope",
        "field_overrides": p["field_overrides"], "periodicity": 1,
        "max_events": 3, "visibility": "public",
    })
    from sources import netskope
    res = netskope.get_alerts_response(limit=20)
    hit = [e for e in res["result"] if e.get("scenario") == "Insider threat"]
    print("NETSKOPE emitted:", bool(hit))
    if hit:
        e = hit[0]
        print("  fields:", {k: e.get(k) for k in
                            ("alert_type", "scenario", "activity", "count", "file_size")})

    # ── Cisco Duo untrusted endpoint ─────────────────────────────────────
    dr._save_rules([])
    dr._injected_total.clear()
    p = _phase("insider_threat", "persistence")
    dr.create_rule({
        "name": "verify-duo", "source": "cisco_duo",
        "field_overrides": p["field_overrides"], "periodicity": 1,
        "max_events": 2, "visibility": "public",
    })
    from sources import cisco_duo
    res = cisco_duo.get_auth_logs_response(limit=20)
    hit = [e for e in res["response"] if e.get("reason") == "endpoint_is_not_trusted"]
    print("DUO emitted:", bool(hit))
    if hit:
        e = hit[0]
        print("  fields:", {k: e.get(k) for k in ("event_type", "result", "reason")})
        print("  access_country:", e["access_device"]["location"]["country"])

    dr._save_rules([])
    dr._injected_total.clear()
    return 0


if __name__ == "__main__":
    sys.exit(main())
