"""M365 two-step poll must deliver a capped scenario event to the collector.

Regression for the "events in the lake but no alert" symptom observed on
2026-06-28 with the BEC scenario against usea1-purple:

The O365 Management Activity API is a TWO-STEP poll —
``GET /subscriptions/content`` returns a *listing* of content blobs, then the
collector ``GET``s every ``contentUri`` to fetch the actual audit records.

Before v5.1.24, :func:`sources.m365.get_content_response` ran on BOTH steps,
each call invoking :func:`detection_rules.inject_detection_events`. For a
scenario phase rule carrying ``max_events`` (e.g. a single ``New-TransportRule``
for the BEC persistence phase) the budget was consumed on the *listing* call —
whose events are DISCARDED (only blob metadata is returned) — leaving the blob
fetch (which the collector actually ingests) starved of budget. The capped
alert event was recorded in apigenie's timeline but NEVER reached the lake,
while uncapped narrative-fill events sailed through. Lake evidence: 74
attack-tagged O365 events, all benign (``UpdateInboxRules`` / ``Remove-InboxRule``),
zero ``New-TransportRule`` / ``Remove-AntiPhishRule`` / consent ops.

The fix: generate+inject ONCE at listing time, stash the events per blob id,
serve them on the blob fetch. This suite locks in that the capped event reaches
the blob fetch exactly once and the cap is still globally respected.
"""
from __future__ import annotations

from urllib.parse import urlparse

import pytest


# The three M365 BEC phases that carry max_events, with the exact
# field_overrides the scenario library ships (attack_scenarios_library.py).
# Each entry: (Operation, field_overrides) — these are the events that must
# survive the two-step content→audit poll so the corresponding ACTIVE shipped
# STAR rule can fire (verified on usea1-purple 2026-06-28):
#   consent    → "Office 365 Admin Consent Granted for All Principals"
#   anti-phish → "Office 365 Deactivation or Removal of Anti-Phish Rule"
#   transport  → "Office 365 Creation of Mail Transport Rule"
_BEC_M365_PHASES = [
    pytest.param(
        "Consent to application.",
        {
            "Operation": "Consent to application.",
            "Workload": "AzureActiveDirectory",
            "ResultStatus": "Success",
            "ExternalAccess": True,
            "ModifiedProperties": (
                "ConsentAction.Permissions: "
                "[Scope: Mail.Read,Mail.Send,offline_access ConsentType: AllPrincipals]"
            ),
            "ObjectId": "OAuth-App-Phishing-Toolkit",
        },
        id="consent-privilege-escalation",
    ),
    pytest.param(
        "Remove-AntiPhishRule",
        {
            "Operation": "Remove-AntiPhishRule",
            "Workload": "Exchange",
            "ResultStatus": "Succeeded",
            "Parameters": [{"Name": "Identity", "Value": "Office365 AntiPhish Default"}],
        },
        id="antiphish-defense-evasion",
    ),
    pytest.param(
        "New-TransportRule",
        {
            "Operation": "New-TransportRule",
            "Workload": "Exchange",
            "ResultStatus": "Succeeded",
            "Parameters": [
                {"Name": "Name", "Value": "External Mail Sync"},
                {"Name": "RedirectMessageTo", "Value": "exfil-drop@protonmail.com"},
            ],
        },
        id="transport-persistence",
    ),
]


def _make_capped_m365_rule(overrides=None):
    import detection_rules
    return detection_rules.create_rule({
        "name": "[SCENARIO] persistence — mail transport rule",
        "source": "m365",
        "field_overrides": overrides or {"Operation": "New-TransportRule", "Workload": "Exchange"},
        "periodicity": 2,
        "max_events": 1,
        "visibility": "public",
    })


def _reset_injector_state():
    import detection_rules
    from sources import m365
    detection_rules._save_rules([])  # wipe persisted rules — test isolation
    detection_rules._injected_total.clear()
    detection_rules._last_fired.clear()
    m365._BLOB_CACHE.clear()


# ── Unit: listing caches, blob fetch serves the SAME events ──────────────────


def test_capped_event_reaches_blob_fetch_exactly_once():
    from sources import m365

    _reset_injector_state()
    _make_capped_m365_rule()

    # Listing step: generate + inject once, cache per blob.
    resp = m365.get_content_response(limit=50, base_url="https://h", tenant_id="t")
    assert resp["blobs"], "listing must return at least one blob"

    # Collector behaviour: fetch every blob and union the events.
    fetched: list[dict] = []
    for blob in resp["blobs"]:
        fetched.extend(m365.pop_blob_events(blob["contentId"]))

    transport = [e for e in fetched if e.get("Operation") == "New-TransportRule"]
    assert len(transport) == 1, (
        f"capped scenario event must reach the blob fetch exactly once, "
        f"got {len(transport)}")


def test_second_poll_respects_global_cap():
    from sources import m365

    _reset_injector_state()
    _make_capped_m365_rule()

    # First poll consumes the single-event budget.
    r1 = m365.get_content_response(limit=50, base_url="https://h", tenant_id="t")
    for blob in r1["blobs"]:
        m365.pop_blob_events(blob["contentId"])

    # Second poll must NOT emit another capped event (max_events=1 lifetime).
    r2 = m365.get_content_response(limit=50, base_url="https://h", tenant_id="t")
    fetched2: list[dict] = []
    for blob in r2["blobs"]:
        fetched2.extend(m365.pop_blob_events(blob["contentId"]))
    assert not [e for e in fetched2 if e.get("Operation") == "New-TransportRule"], (
        "cap exhausted — a second poll must not deliver another capped event")


def test_unknown_blob_id_falls_back_without_injection():
    from sources import m365

    _reset_injector_state()
    _make_capped_m365_rule()

    # An unknown/evicted blob id must NOT trigger detection injection (which
    # would double-consume the cap). It returns a plain benign batch.
    benign = m365.pop_blob_events("00000000-0000-0000-0000-000000000000")
    assert isinstance(benign, list) and benign, "fallback must return events"
    assert not [e for e in benign if e.get("Operation") == "New-TransportRule"], (
        "fallback path must never carry a capped alert event")


# ── Integration: full two-step flow through the FastAPI route ────────────────


def test_route_two_step_delivers_capped_event_once():
    from fastapi.testclient import TestClient

    import app as apigenie_app
    from sources import m365

    _reset_injector_state()
    _make_capped_m365_rule()

    client = TestClient(apigenie_app.app)
    tenant = "my-roarin-111-m365tenant"
    headers = {"Authorization": "Bearer eyJ.fake.jwt"}

    r = client.get(
        f"/api/v1.0/{tenant}/activity/feed/subscriptions/content",
        params={"contentType": "Audit.General"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    blobs = r.json()
    assert blobs, "content listing must return blobs"

    seen = 0
    for blob in blobs:
        path = urlparse(blob["contentUri"]).path
        r2 = client.get(path, headers=headers)
        assert r2.status_code == 200, r2.text
        seen += sum(1 for e in r2.json() if e.get("Operation") == "New-TransportRule")

    assert seen == 1, (
        f"the capped New-TransportRule event must be ingested exactly once via "
        f"the two-step content→audit flow, got {seen}")


@pytest.mark.parametrize("operation, overrides", _BEC_M365_PHASES)
def test_all_bec_m365_phases_reach_collector_once(operation, overrides):
    """Every capped M365 BEC phase event must reach the collector exactly once.

    Locks in the regression for all three M365 phases — consent
    (privilege-escalation), Remove-AntiPhishRule (defense-evasion) and
    New-TransportRule (persistence) — not just transport. Each phase's ACTIVE
    shipped STAR rule keys off this event; if the two-step poll drops it (the
    pre-v5.1.24 max_events double-injection bug) the alert never fires.
    """
    from fastapi.testclient import TestClient

    import app as apigenie_app

    _reset_injector_state()
    _make_capped_m365_rule(overrides)

    client = TestClient(apigenie_app.app)
    tenant = "my-roarin-111-m365tenant"
    headers = {"Authorization": "Bearer eyJ.fake.jwt"}

    r = client.get(
        f"/api/v1.0/{tenant}/activity/feed/subscriptions/content",
        params={"contentType": "Audit.General"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    blobs = r.json()
    assert blobs, "content listing must return blobs"

    # Some Operations (consent) are ALSO emitted by the M365 background noise,
    # so match on the override's unique ModifiedProperties marker when present
    # to isolate the scenario-injected event from benign background traffic.
    marker = overrides.get("ModifiedProperties")
    matches = []
    for blob in blobs:
        path = urlparse(blob["contentUri"]).path
        r2 = client.get(path, headers=headers)
        assert r2.status_code == 200, r2.text
        for e in r2.json():
            if e.get("Operation") != operation:
                continue
            if marker and marker not in str(e.get("ModifiedProperties", "")):
                continue
            matches.append(e)

    assert len(matches) == 1, (
        f"capped {operation!r} event must be ingested exactly once via the "
        f"two-step content→audit flow, got {len(matches)}")

    # The shipped rule discriminators must survive onto the delivered event.
    ev = matches[0]
    for field, value in overrides.items():
        assert ev.get(field) == value, (
            f"{operation!r}: override {field}={value!r} must be present on the "
            f"delivered event, got {ev.get(field)!r}")
