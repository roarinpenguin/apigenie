"""Tests for ``class_uid`` coverage on alert templates (v5.3 Step 2, Phase 4).

S1's STAR / Custom Detection pipeline binds an alert to its Target
Asset only when the event carries a non-zero ``class_uid``. A template
shipped without one — or with one explicitly set to 0 — will land in
UAM as "Unknown Device" no matter how good the asset resolver is.

Two safeguards:

1. **Load-time lint** — ``alerts.prepare_alert`` emits a
   ``log.warning`` when the prepared alert lacks a usable
   ``class_uid``. The operator sees the issue in the container
   logs immediately after a send, instead of debugging UAM ingest
   for an hour.
2. **Build-time test** — this file scans every JSON under
   ``alert_templates/`` and fails CI if a template ships without
   ``class_uid`` or with a zero/falsy value. Catches a regression
   the moment someone adds a new template missing the field.

The test is wide-ranging on purpose: it walks the entire directory,
no allow-listing. If a future template legitimately needs
``class_uid=0`` (it shouldn't, per the binding doc) the test must
be updated explicitly — never silently skipped.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "alert_templates"


# ── Coverage scan ──────────────────────────────────────────────────


def _iter_template_files():
    """Yield every *.json file under ``alert_templates/`` as a Path."""
    if not _TEMPLATES_DIR.is_dir():
        pytest.skip(f"templates directory not found: {_TEMPLATES_DIR}")
    yield from sorted(_TEMPLATES_DIR.glob("*.json"))


def test_every_template_carries_non_zero_class_uid():
    """Walk every template and assert ``class_uid`` is present + non-
    zero. The failure list names every offender so the operator can
    fix them in one pass instead of running the test repeatedly."""
    offenders: list[tuple[str, str]] = []
    for path in _iter_template_files():
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            offenders.append((path.name, f"unreadable: {exc}"))
            continue
        if not isinstance(data, dict):
            offenders.append((path.name,
                              f"top-level must be an object, got {type(data).__name__}"))
            continue
        cu = data.get("class_uid")
        if cu is None:
            offenders.append((path.name, "missing class_uid"))
            continue
        if not isinstance(cu, int) or cu <= 0:
            offenders.append((path.name,
                              f"class_uid must be a positive int, got {cu!r}"))
    assert not offenders, (
        f"alert templates missing or with invalid class_uid: {offenders}")


# ── prepare_alert load-time warning ────────────────────────────────


def test_prepare_alert_warns_when_class_uid_missing(caplog):
    """An alert prepared from a template without ``class_uid`` (legacy
    or hand-written) must emit a single warning log line so the
    operator notices in the container logs immediately. The send
    path is NOT blocked — back-compat with templates already in the
    wild — but the warning surfaces the issue."""
    import logging
    import alerts

    bad_template = {
        # No class_uid at all — would silently bind to "Unknown Device".
        "category_uid": 2,
        "severity": "low",
        "finding_info": {"title": "x", "desc": "y"},
        "resources":   [{"type": "Device", "name": "h"}],
    }
    with caplog.at_level(logging.WARNING, logger="alerts"):
        out = alerts.prepare_alert(bad_template)
    assert out is not None, "send path must not be blocked by missing class_uid"
    msgs = [r.getMessage() for r in caplog.records
            if "class_uid" in r.getMessage().lower()]
    assert msgs, (
        "expected a WARNING mentioning class_uid; caplog records were: "
        f"{[r.getMessage() for r in caplog.records]}")


def test_prepare_alert_does_not_warn_when_class_uid_present(caplog):
    """A well-formed template (every shipped one) must NOT emit the
    warning — otherwise the operator's container logs would be
    flooded by a noisy lint every send."""
    import logging
    import alerts

    good_template = {
        "category_uid": 2,
        "class_uid": 99602001,
        "severity": "low",
        "finding_info": {"title": "x", "desc": "y"},
        "resources":   [{"type": "Device", "name": "h"}],
    }
    with caplog.at_level(logging.WARNING, logger="alerts"):
        alerts.prepare_alert(good_template)
    msgs = [r.getMessage() for r in caplog.records
            if "class_uid" in r.getMessage().lower()]
    assert not msgs, (
        f"unexpected class_uid warning emitted for a good template: {msgs}")


def test_prepare_alert_warns_on_zero_class_uid(caplog):
    """``class_uid=0`` is just as broken as missing — STAR rules
    treat it as "unclassified" and bind to Unknown Device. Lint
    must catch both."""
    import logging
    import alerts

    bad_template = {
        "class_uid": 0,
        "category_uid": 2,
        "severity": "low",
        "finding_info": {"title": "x", "desc": "y"},
        "resources":   [],
    }
    with caplog.at_level(logging.WARNING, logger="alerts"):
        alerts.prepare_alert(bad_template)
    msgs = [r.getMessage() for r in caplog.records
            if "class_uid" in r.getMessage().lower()]
    assert msgs, "zero class_uid must trigger the lint warning"
