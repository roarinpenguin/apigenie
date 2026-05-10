"""Unit tests for alert generators and S1 schema builder.

Run with:  python -m pytest tests/test_alerts.py -v
"""
import sys
import os
import time

# Ensure the project root is on sys.path so imports work from any cwd.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sources.alerts import (
    build_s1_alert,
    load_adapters,
    generate_alerts,
    list_alert_sources,
    ALERT_SOURCES,
    _severity,
)

# ── S1 schema builder tests ──────────────────────────────────────────────────

def test_build_s1_alert_required_fields():
    alert = build_s1_alert(
        finding_uid="test-uid-001",
        title="Test Alert",
        description="Test description",
        severity_raw="high",
        vendor_name="TestVendor",
        product_name="TestProduct",
    )
    assert alert["finding_info"]["uid"] == "test-uid-001"
    assert alert["finding_info"]["title"] == "Test Alert"
    assert alert["finding_info"]["desc"] == "Test description"
    assert alert["category_uid"] == 2
    assert alert["category_name"] == "Findings"
    assert alert["class_name"] == "S1 Security Alert"
    assert alert["type_name"] == "S1 Security Alert: Create"
    assert alert["severity"] == "high"
    assert alert["severity_id"] == 4
    assert alert["metadata"]["product"]["name"] == "TestProduct"
    assert alert["metadata"]["product"]["vendor_name"] == "TestVendor"
    assert alert["metadata"]["version"] == "1.1.0"


def test_build_s1_alert_timestamps():
    before = int(time.time() * 1000)
    alert = build_s1_alert(
        finding_uid="ts-test",
        title="TS",
        description="",
        severity_raw="low",
        vendor_name="V",
        product_name="P",
    )
    after = int(time.time() * 1000) + 1
    mod = alert["metadata"]["modified_time"]
    log = alert["metadata"]["logged_time"]
    assert before <= mod <= after
    # logged_time is 1–120 seconds before modified_time
    assert mod - 120_000 <= log <= mod - 1000


def test_build_s1_alert_optional_fields():
    alert = build_s1_alert(
        finding_uid="opt-test",
        title="Opt",
        description="",
        severity_raw="medium",
        vendor_name="V",
        product_name="P",
        resources=[{"uid": "r1", "name": "res1", "type": "computer"}],
        observables=[{"name": "1.2.3.4", "type": "ip"}],
        evidences=[{"process": {"name": "cmd.exe"}}],
        finding_types=["Malware", "Detection"],
        unmapped={"vendor_field": "value"},
    )
    assert len(alert["resources"]) == 1
    assert len(alert["observables"]) == 1
    assert len(alert["evidences"]) == 1
    assert alert["finding_info"]["types"] == ["Malware", "Detection"]
    assert alert["unmapped"]["vendor_field"] == "value"


# ── Severity mapping tests ───────────────────────────────────────────────────

def test_severity_string_mapping():
    assert _severity("high") == (4, "High")
    assert _severity("critical") == (5, "Critical")
    assert _severity("low") == (2, "Low")
    assert _severity("medium") == (3, "Medium")
    assert _severity("informational") == (1, "Informational")
    assert _severity("info") == (1, "Informational")


def test_severity_numeric_mapping():
    assert _severity(1)[0] == 1   # Informational
    assert _severity(3)[0] == 2   # Low
    assert _severity(5)[0] == 3   # Medium
    assert _severity(7.3)[0] == 4  # High
    assert _severity(9)[0] == 5   # Critical


def test_severity_unknown_defaults_medium():
    assert _severity("unknown") == (3, "Medium")
    assert _severity("") == (3, "Medium")


# ── Adapter registry tests ───────────────────────────────────────────────────

def test_load_adapters():
    adapters = load_adapters()
    assert len(adapters) == 11
    expected_keys = {
        "checkpoint_ngfw", "cortex_xdr",
        "microsoft_defender", "microsoft_entra_id", "mimecast", "netskope",
        "okta", "palo_alto_ngfw", "proofpoint_tap", "extrahop_revealx", "vectra_ai",
    }
    assert set(adapters.keys()) == expected_keys


def test_list_alert_sources():
    sources = list_alert_sources()
    assert len(sources) == 11
    for s in sources:
        assert "key" in s
        assert "vendor" in s
        assert "product" in s
        assert s["variant_count"] > 0
        assert len(s["variants"]) > 0


# ── Per-adapter generation tests (no profile context) ────────────────────────

_ALL_KEYS = [
    "checkpoint_ngfw", "cortex_xdr",
    "microsoft_defender", "microsoft_entra_id", "mimecast", "netskope",
    "okta", "palo_alto_ngfw", "proofpoint_tap", "extrahop_revealx", "vectra_ai",
]


def _validate_s1_alert(alert: dict, source_key: str):
    """Validate that an alert conforms to the S1 schema."""
    assert alert["category_name"] == "Findings", f"{source_key}: bad category_name"
    assert alert["class_name"] == "S1 Security Alert", f"{source_key}: bad class_name"
    assert alert["type_name"] == "S1 Security Alert: Create", f"{source_key}: bad type_name"
    assert alert["category_uid"] == 2, f"{source_key}: bad category_uid"
    assert alert["severity_id"] in (1, 2, 3, 4, 5), f"{source_key}: bad severity_id"
    assert alert["severity"] in ("informational", "low", "medium", "high", "critical"), f"{source_key}: bad severity"
    fi = alert["finding_info"]
    assert "uid" in fi and fi["uid"], f"{source_key}: missing finding_info.uid"
    assert "title" in fi and fi["title"], f"{source_key}: missing finding_info.title"
    assert "desc" in fi, f"{source_key}: missing finding_info.desc"
    meta = alert["metadata"]
    assert "product" in meta, f"{source_key}: missing metadata.product"
    assert meta["product"]["name"], f"{source_key}: empty product name"
    assert meta["product"]["vendor_name"], f"{source_key}: empty vendor name"
    assert meta["logged_time"] > 0, f"{source_key}: bad logged_time"
    assert meta["modified_time"] > 0, f"{source_key}: bad modified_time"
    assert meta["modified_time"] >= meta["logged_time"], f"{source_key}: modified < logged"


def test_generate_each_adapter_no_profile():
    """Generate 3 alerts per adapter without ProfileContext and validate schema."""
    if not ALERT_SOURCES:
        load_adapters()
    for key in _ALL_KEYS:
        alerts = generate_alerts(key, n=3)
        assert len(alerts) == 3, f"{key}: expected 3 alerts, got {len(alerts)}"
        for alert in alerts:
            _validate_s1_alert(alert, key)


def test_generate_single_alert():
    """Generating n=1 should produce exactly 1 alert."""
    if not ALERT_SOURCES:
        load_adapters()
    alerts = generate_alerts("okta", n=1)
    assert len(alerts) == 1
    _validate_s1_alert(alerts[0], "okta")


def test_generate_unknown_source_raises():
    """Unknown source key should raise ValueError."""
    if not ALERT_SOURCES:
        load_adapters()
    try:
        generate_alerts("nonexistent_source", n=1)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# ── Adapter-specific field checks ────────────────────────────────────────────

def test_microsoft_defender_fields():
    if not ALERT_SOURCES:
        load_adapters()
    alerts = generate_alerts("microsoft_defender", n=5)
    for a in alerts:
        assert "[Defender]" in a["finding_info"]["title"]
        assert "mitreTechniques" in a["unmapped"]
        assert len(a["evidences"]) > 0


def test_okta_event_types():
    if not ALERT_SOURCES:
        load_adapters()
    alerts = generate_alerts("okta", n=20)
    event_types = set()
    for a in alerts:
        et = a["unmapped"].get("eventType", "")
        event_types.add(et)
    # With 20 alerts, we should see at least 3 different event types
    assert len(event_types) >= 3, f"Only {len(event_types)} event types in 20 alerts"


def test_netskope_all_families():
    if not ALERT_SOURCES:
        load_adapters()
    alerts = generate_alerts("netskope", n=50)
    families = set()
    for a in alerts:
        families.add(a["unmapped"]["alert_type"])
    # With 50 alerts, should cover most of the 8 families
    assert len(families) >= 5, f"Only {len(families)} families in 50 alerts"


if __name__ == "__main__":
    # Run all test_ functions and report results
    import traceback
    funcs = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in funcs:
        try:
            fn()
            print(f"  ✓ {name}")
            passed += 1
        except Exception as exc:
            print(f"  ✗ {name}: {exc}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)
