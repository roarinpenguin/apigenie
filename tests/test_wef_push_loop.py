"""Tests for the WEFEmitter push loop (v5.2).

Verifies that ``sources.windows_event_forwarding.WEFEmitter`` builds a
correct outbound POST against the WEC, respects per-binding rate /
batch-size knobs, and surfaces wire-level failures cleanly.

HTTP traffic is intercepted with ``httpx.MockTransport`` — the same
pattern used elsewhere in the suite (see tests/test_alerts_phase4.py,
tests/test_s1_assets.py). The mock captures every request so we can
assert path, headers, and body shape without standing up a real socket.

Spec: docs/ROADMAP_2026-06-12.md §"Protocol details" + §"Continuous emit
with rate control".
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import httpx
import pytest


NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
NS_WIN_EVENT = "http://schemas.microsoft.com/win/2004/08/events/event"


# ── Test helpers ───────────────────────────────────────────────────────

def _capturing_client(status: int = 202, body: bytes = b""):
    """Return ``(client, captured)`` where ``captured`` is a list every
    request is appended to. The mock answers each POST with
    ``status_code=status`` and ``body``."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(status_code=status, content=body)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return client, captured


def _binding_config(**overrides) -> dict:
    """Default binding config with mTLS off (so the loop just uses the
    mock transport unmodified) and no Basic credentials configured (so
    these wire-shape tests don't engage the auth path — covered
    separately in tests/test_wef_auth.py). The 'no auth configured'
    state is signalled by leaving both basic_username and
    basic_password_enc empty; tests that need real auth set both."""
    base = {
        "target_host": "wec.lab.example.com",
        "target_port": 5986,
        "target_path": "/wsman/SubscriptionManager/WEC",
        "auth_method": "basic",
        "basic_username": None,
        "basic_password_enc": None,
        "tls_verify": True,
        "ca_bundle_path": None,
        "rate_per_min": 60,
        "batch_size": 5,
        "jitter_pct": 0,
        "channels_enabled": [
            "Security", "System", "Directory Service", "DNS Server",
            "Windows-PowerShell-Operational",
            "Microsoft-Windows-Sysmon/Operational",
        ],
    }
    base.update(overrides)
    return base


def _emitter(http_client, **cfg_overrides):
    from sources import windows_event_forwarding as wef
    return wef.WEFEmitter(_binding_config(**cfg_overrides), http_client=http_client)


# ── Wire shape ─────────────────────────────────────────────────────────

def test_push_batch_posts_to_configured_target():
    client, captured = _capturing_client()
    emitter = _emitter(client)
    emitter.push_batch(event_count=3)

    assert len(captured) == 1
    req = captured[0]
    assert req.method == "POST"
    assert str(req.url) == (
        "https://wec.lab.example.com:5986/wsman/SubscriptionManager/WEC"
    )


def test_push_batch_uses_http_when_port_is_5985():
    client, captured = _capturing_client()
    emitter = _emitter(client, target_port=5985, target_host="wec-plain.local")
    emitter.push_batch(event_count=1)
    assert str(captured[0].url).startswith("http://wec-plain.local:5985/")


def test_push_batch_sets_soap_content_type():
    client, captured = _capturing_client()
    _emitter(client).push_batch(event_count=1)
    assert captured[0].headers["content-type"] == \
        "application/soap+xml;charset=UTF-8"


def test_push_batch_body_is_valid_soap_with_n_events():
    client, captured = _capturing_client()
    _emitter(client, batch_size=4).push_batch(event_count=4)
    body = captured[0].content.decode("utf-8")
    root = ET.fromstring(body)
    win_events = root.findall(f".//{{{NS_WIN_EVENT}}}Event")
    assert len(win_events) == 4, (
        f"Expected 4 <Event> children in the envelope, got {len(win_events)}"
    )


def test_push_batch_returns_result_dict():
    client, _ = _capturing_client(status=202)
    result = _emitter(client).push_batch(event_count=2)
    assert isinstance(result, dict)
    assert result.get("sent") == 2
    assert result.get("status_code") == 202
    assert result.get("ok") is True


def test_push_batch_marks_non_2xx_as_failure():
    client, _ = _capturing_client(status=500, body=b"internal error")
    result = _emitter(client).push_batch(event_count=1)
    assert result["ok"] is False
    assert result["status_code"] == 500


# ── Batching / rate ────────────────────────────────────────────────────

def test_explicit_events_list_takes_precedence_over_count():
    """When the caller hands in a pre-built ``events`` list (e.g. the
    Attack Scenarios historical backlog), the emitter must POST exactly
    those events, not generate fresh ones."""
    client, captured = _capturing_client()
    emitter = _emitter(client)
    custom = [
        {"event_id": 4624, "channel": "Security",
         "provider": "Microsoft-Windows-Security-Auditing",
         "computer": "DC01", "level": "Information",
         "time_created": "2026-06-13T10:00:00.000Z",
         "event_record_id": 1, "data": {"TargetUserName": "alice"}},
        {"event_id": 4625, "channel": "Security",
         "provider": "Microsoft-Windows-Security-Auditing",
         "computer": "DC01", "level": "Information",
         "time_created": "2026-06-13T10:00:01.000Z",
         "event_record_id": 2, "data": {"TargetUserName": "bob"}},
    ]
    result = emitter.push_batch(events=custom)
    assert result["sent"] == 2
    body = captured[0].content.decode("utf-8")
    assert "alice" in body and "bob" in body


def test_default_batch_size_caps_at_binding_config():
    """``event_count=100`` with ``batch_size=5`` must split into 20 POSTs."""
    client, captured = _capturing_client()
    emitter = _emitter(client, batch_size=5)
    result = emitter.push_batch(event_count=100)
    assert len(captured) == 20
    assert result["sent"] == 100


# ── Lifecycle ──────────────────────────────────────────────────────────

def test_emitter_exposes_a_stoppable_run_loop():
    """The push loop is owned by the existing scheduler — verify the
    emitter exposes a clean ``stop()`` so the scheduler can tear it down
    on binding delete without leaking the loop."""
    client, _ = _capturing_client()
    emitter = _emitter(client)
    # No assertions on internals; just contract that the method exists
    # and is idempotent.
    emitter.stop()
    emitter.stop()
