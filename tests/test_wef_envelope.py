"""Tests for ``sources.windows_event_forwarding.build_envelope`` (v5.2).

Verifies that the SOAP 1.2 envelope carrying WS-Eventing ``Events``
records embeds well-formed Windows EventLog XML and parses back through
the standard ``xml.etree`` parser without any custom shims.

The envelope shape is fixed by Microsoft's WS-Management / WS-Eventing
spec and by what real Windows Event Collector subscriptions accept. The
constants below are the canonical namespace URIs.

Spec: docs/ROADMAP_2026-06-12.md §"Protocol details".
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest


# Canonical namespace URIs — must NEVER drift; real WEC validates them.
NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
NS_ADDRESSING = "http://www.w3.org/2005/08/addressing"
NS_WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_EVENTING = "http://schemas.xmlsoap.org/ws/2004/08/eventing"
NS_WIN_EVENT = "http://schemas.microsoft.com/win/2004/08/events/event"

# Single canonical action for emitting events to a WEC subscription.
EVENTS_ACTION = "http://schemas.xmlsoap.org/ws/2004/08/eventing/Events"


def _sample_event(event_id: int = 4624,
                  channel: str = "Security",
                  computer: str = "DC01.lab.local") -> dict:
    """Minimal in-memory event the envelope builder must be able to
    serialise into Windows EventLog XML."""
    return {
        "event_id": event_id,
        "channel": channel,
        "provider": "Microsoft-Windows-Security-Auditing",
        "computer": computer,
        "level": "Information",
        "time_created": "2026-06-13T10:00:00.000Z",
        "event_record_id": 9001,
        "data": {
            "TargetUserName": "alice",
            "TargetDomainName": "LAB",
            "IpAddress": "10.0.0.5",
            "LogonType": "3",
        },
    }


def _build(events, message_id=None):
    from sources import windows_event_forwarding as wef
    return wef.build_envelope(events, message_id=message_id)


# ── Basic structure ────────────────────────────────────────────────────

def test_envelope_is_well_formed_xml():
    xml = _build([_sample_event()])
    # Must not raise. If it does, the test prints the offending payload.
    try:
        ET.fromstring(xml)
    except ET.ParseError as exc:  # pragma: no cover — diagnostic only
        pytest.fail(f"build_envelope produced malformed XML: {exc}\n---\n{xml}")


def test_envelope_root_is_soap12():
    xml = _build([_sample_event()])
    root = ET.fromstring(xml)
    assert root.tag == f"{{{NS_SOAP12}}}Envelope", (
        f"Expected SOAP 1.2 envelope, got root {root.tag!r}"
    )


def test_envelope_has_header_and_body():
    xml = _build([_sample_event()])
    root = ET.fromstring(xml)
    assert root.find(f"{{{NS_SOAP12}}}Header") is not None
    assert root.find(f"{{{NS_SOAP12}}}Body") is not None


# ── WS-Eventing action ────────────────────────────────────────────────

def test_action_is_ws_eventing_events():
    xml = _build([_sample_event()])
    root = ET.fromstring(xml)
    action = root.find(
        f"{{{NS_SOAP12}}}Header/{{{NS_ADDRESSING}}}Action"
    )
    assert action is not None, "wsa:Action missing"
    assert action.text.strip() == EVENTS_ACTION, (
        f"Expected WS-Eventing Events action, got {action.text!r}"
    )


def test_message_id_is_present_and_uuid_shaped():
    xml = _build([_sample_event()])
    root = ET.fromstring(xml)
    msgid = root.find(
        f"{{{NS_SOAP12}}}Header/{{{NS_ADDRESSING}}}MessageID"
    )
    assert msgid is not None
    text = (msgid.text or "").strip()
    assert text.startswith("uuid:") and len(text) > 10, (
        f"MessageID must start with 'uuid:' followed by a UUID, got {text!r}"
    )


def test_explicit_message_id_round_trips():
    explicit = "uuid:11111111-2222-3333-4444-555555555555"
    xml = _build([_sample_event()], message_id=explicit)
    root = ET.fromstring(xml)
    msgid = root.find(
        f"{{{NS_SOAP12}}}Header/{{{NS_ADDRESSING}}}MessageID"
    )
    assert msgid.text.strip() == explicit


# ── Body / Events ─────────────────────────────────────────────────────

def test_body_contains_one_event_element_per_input():
    events = [_sample_event(4624), _sample_event(4625), _sample_event(4688)]
    xml = _build(events)
    root = ET.fromstring(xml)
    body = root.find(f"{{{NS_SOAP12}}}Body")
    win_events = body.findall(f".//{{{NS_WIN_EVENT}}}Event")
    assert len(win_events) == len(events), (
        f"Expected {len(events)} <Event> children, found {len(win_events)}"
    )


def _local_name(tag: str) -> str:
    """Strip the ``{namespace}`` prefix from a Clark-notation tag.

    Stdlib ``xml.etree.ElementTree.QName`` does NOT expose a
    ``.localname`` attribute (only lxml does); use this helper instead.
    """
    return tag.split("}", 1)[-1] if "}" in tag else tag


def test_each_event_has_system_section_with_required_subfields():
    xml = _build([_sample_event()])
    root = ET.fromstring(xml)
    win_event = root.find(f".//{{{NS_WIN_EVENT}}}Event")
    system = win_event.find(f"{{{NS_WIN_EVENT}}}System")
    assert system is not None, "<System> missing"
    required = {"EventID", "TimeCreated", "Channel", "Computer", "Provider"}
    children = {_local_name(child.tag) for child in system}
    missing = required - children
    assert not missing, f"<System> missing required children: {missing}"


def test_event_id_matches_input():
    ev = _sample_event(event_id=4624)
    xml = _build([ev])
    root = ET.fromstring(xml)
    eid = root.find(f".//{{{NS_WIN_EVENT}}}EventID")
    assert eid is not None
    assert int(eid.text) == 4624


def test_event_data_carries_substituted_fields():
    ev = _sample_event()
    ev["data"]["TargetUserName"] = "bob"
    xml = _build([ev])
    root = ET.fromstring(xml)
    event_data = root.find(f".//{{{NS_WIN_EVENT}}}EventData")
    assert event_data is not None, "<EventData> missing"
    data_elems = event_data.findall(f"{{{NS_WIN_EVENT}}}Data")
    by_name = {d.get("Name"): (d.text or "") for d in data_elems}
    assert by_name.get("TargetUserName") == "bob"


def test_special_chars_in_data_are_escaped():
    """A literal '&' or '<' in event data must not break XML parsing."""
    ev = _sample_event()
    ev["data"]["TargetUserName"] = "<bad&user>"
    xml = _build([ev])
    root = ET.fromstring(xml)  # must not raise
    event_data = root.find(f".//{{{NS_WIN_EVENT}}}EventData")
    by_name = {d.get("Name"): (d.text or "") for d in
               event_data.findall(f"{{{NS_WIN_EVENT}}}Data")}
    assert by_name["TargetUserName"] == "<bad&user>"


# ── Content-Type / encoding (used by the push loop) ───────────────────

def test_module_declares_canonical_content_type():
    """The push loop pulls Content-Type from a module constant so the
    spec is single-sourced. Verify it matches the SOAP 1.2 contract."""
    from sources import windows_event_forwarding as wef
    assert getattr(wef, "SOAP_CONTENT_TYPE", "") == \
        "application/soap+xml;charset=UTF-8"
