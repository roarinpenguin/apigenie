"""Alert Push Phase 4.1 — pure-module tests (no UI, no router).

Covers:
* Template loader: at least one template loads, list_templates carries
  the metadata the UI needs, get_template returns a deep copy (mutating it
  doesn't poison the cache).
* prepare_alert: fresh UID injected, DYNAMIC timestamp replaced, dot-path
  overrides applied, original template untouched.
* egress_alert: hits the exact wire contract — URL, headers, gzip body
  round-trips back to the input alert.
* send_alert: count=N produces N unique UIDs, transport called N times,
  unknown template returns a structured error.

All HTTP traffic is intercepted with ``httpx.MockTransport``.
"""
from __future__ import annotations

import gzip
import json
from typing import Any

import httpx
import pytest

# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _fresh_template_cache():
    """Reset the alerts module template cache around each test.

    The cache is module-level; without this, a test that monkeypatches the
    templates dir would leak its view of the world into the next test.
    """
    import alerts
    alerts._TEMPLATE_CACHE = None
    yield
    alerts._TEMPLATE_CACHE = None


@pytest.fixture
def captured_requests() -> list[httpx.Request]:
    return []


@pytest.fixture
def mock_client(captured_requests):
    """An httpx.Client backed by a MockTransport that records every request
    and replies 202 Accepted with an empty JSON body — the same shape the
    real UAM ingest endpoint returns."""
    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(202, json={})

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as client:
        yield client


# ── Template loading ─────────────────────────────────────────────────────────

class TestTemplateLoader:
    def test_at_least_one_template_loads(self):
        import alerts
        tmpls = alerts.list_templates()
        assert len(tmpls) > 0, "no templates loaded — alert_templates dir missing?"

    def test_default_alert_template_present(self):
        import alerts
        ids = {t["id"] for t in alerts.list_templates()}
        assert "default_alert" in ids

    def test_list_templates_carries_ui_metadata(self):
        import alerts
        for entry in alerts.list_templates():
            assert "id" in entry
            assert "title" in entry
            assert "class_name" in entry
            assert "severity_id" in entry
            assert "product_name" in entry

    def test_get_template_returns_deep_copy(self):
        import alerts
        a = alerts.get_template("default_alert")
        b = alerts.get_template("default_alert")
        assert a is not b
        a["finding_info"]["title"] = "MUTATED"
        assert b["finding_info"]["title"] != "MUTATED", \
            "get_template handed out a shared reference (cache poisoning risk)"

    def test_get_template_missing_returns_none(self):
        import alerts
        assert alerts.get_template("does_not_exist") is None


# ── prepare_alert ────────────────────────────────────────────────────────────

class TestPrepareAlert:
    def test_injects_fresh_uid(self):
        import alerts
        tmpl = alerts.get_template("default_alert")
        a1 = alerts.prepare_alert(tmpl)
        a2 = alerts.prepare_alert(tmpl)
        assert a1["finding_info"]["uid"] != "placeholder_uid"
        assert a1["finding_info"]["uid"] != a2["finding_info"]["uid"], \
            "two calls must yield distinct UIDs"

    def test_replaces_dynamic_with_time_ms(self):
        import alerts
        tmpl = alerts.get_template("default_alert")
        alert = alerts.prepare_alert(tmpl, time_ms=1_700_000_000_000)
        assert alert["time"] == 1_700_000_000_000
        assert alert["metadata"]["logged_time"] == 1_700_000_000_000
        assert alert["metadata"]["modified_time"] == 1_700_000_000_000

    def test_replaces_resource_uid_placeholders(self):
        import alerts
        tmpl = alerts.get_template("default_alert")
        alert = alerts.prepare_alert(tmpl)
        for r in alert["resources"]:
            assert r["uid"] not in ("DYNAMIC_RESOURCE_UID", "placeholder_uid", "")
            assert len(r["uid"]) >= 8  # roughly a UUID

    def test_dot_path_override_sets_nested_field(self):
        import alerts
        tmpl = alerts.get_template("default_alert")
        alert = alerts.prepare_alert(tmpl, overrides={
            "finding_info.title": "Custom title",
            "severity_id": 5,
        })
        assert alert["finding_info"]["title"] == "Custom title"
        assert alert["severity_id"] == 5

    def test_empty_override_value_is_skipped(self):
        import alerts
        tmpl = alerts.get_template("default_alert")
        original_title = tmpl["finding_info"]["title"]
        alert = alerts.prepare_alert(tmpl, overrides={
            "finding_info.title": "",   # empty — should not overwrite
            "severity_id": None,        # None — should not overwrite
        })
        # Title stays at template default, severity stays at template default.
        assert alert["finding_info"]["title"] == original_title
        assert alert["severity_id"] == tmpl["severity_id"]

    def test_override_falsy_literal_still_applied(self):
        """severity_id=0 and similar must still override (only None/empty skip)."""
        import alerts
        tmpl = alerts.get_template("default_alert")
        alert = alerts.prepare_alert(tmpl, overrides={"severity_id": 0})
        assert alert["severity_id"] == 0

    def test_original_template_untouched(self):
        import alerts
        tmpl_first = alerts.get_template("default_alert")
        snapshot = json.dumps(tmpl_first, sort_keys=True)
        alerts.prepare_alert(tmpl_first, overrides={"finding_info.title": "X"})
        # The variable we passed in is mutable, but its cached source must not be.
        tmpl_second = alerts.get_template("default_alert")
        assert json.dumps(tmpl_second, sort_keys=True) == snapshot


# ── egress_alert ─────────────────────────────────────────────────────────────

class TestEgressWireContract:
    def test_post_to_v1_alerts(self, mock_client, captured_requests):
        import alerts
        tmpl = alerts.get_template("default_alert")
        prepared = alerts.prepare_alert(tmpl)
        alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            client=mock_client,
        )
        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert req.method == "POST"
        assert str(req.url) == "https://ingest.us1.sentinelone.net/v1/alerts"

    def test_trailing_slash_in_ingest_url_is_tolerated(self, mock_client, captured_requests):
        import alerts
        tmpl = alerts.get_template("default_alert")
        prepared = alerts.prepare_alert(tmpl)
        alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net/",
            service_token="svc-tok",
            account_id="acct-123",
            client=mock_client,
        )
        assert str(captured_requests[0].url) == "https://ingest.us1.sentinelone.net/v1/alerts"

    def test_headers_carry_bearer_and_s1_scope(self, mock_client, captured_requests):
        import alerts
        prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
        alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            site_id="site-9",
            client=mock_client,
        )
        h = captured_requests[0].headers
        assert h["authorization"] == "Bearer svc-tok"
        assert h["s1-scope"] == "acct-123:site-9"
        assert h["content-encoding"] == "gzip"
        assert h["content-type"] == "application/json"

    def test_s1_scope_without_site(self, mock_client, captured_requests):
        import alerts
        prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
        alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-only",
            client=mock_client,
        )
        assert captured_requests[0].headers["s1-scope"] == "acct-only"

    def test_s1_scope_with_site_and_group(self, mock_client, captured_requests):
        """Triplet S1-Scope ``account:site:group`` — Resilient-Inc-style scope.

        The S1 UAM gateway accepts this form (verified empirically against
        ingest.us1.sentinelone.net 2026-06-10) and routes the alert into the
        named group so binding to inventory can succeed when the agent lives
        there.
        """
        import alerts
        prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
        alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            site_id="site-9",
            group_id="grp-77",
            client=mock_client,
        )
        assert captured_requests[0].headers["s1-scope"] == "acct-123:site-9:grp-77"

    def test_s1_scope_orphan_group_falls_back_to_site(self, mock_client, captured_requests):
        """``group_id`` without ``site_id`` is invalid (group lives inside a
        site). build_scope ignores the orphan group and degrades to account
        scope so a misconfigured profile still ingests rather than 400ing."""
        import alerts
        prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
        alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-only",
            group_id="grp-77",   # orphan — no site_id provided
            client=mock_client,
        )
        assert captured_requests[0].headers["s1-scope"] == "acct-only"

    def test_build_scope_helper(self):
        """Unit-test build_scope directly so regressions surface even if
        egress_alert is refactored."""
        import alerts
        assert alerts.build_scope("A") == "A"
        assert alerts.build_scope("A", "S") == "A:S"
        assert alerts.build_scope("A", "S", "G") == "A:S:G"
        # Orphan group is dropped
        assert alerts.build_scope("A", None, "G") == "A"
        # Empty string treated as absent
        assert alerts.build_scope("A", "", "G") == "A"

    def test_body_is_gzipped_json_round_trip(self, mock_client, captured_requests):
        import alerts
        prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
        alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            client=mock_client,
        )
        wire_body = captured_requests[0].content
        decoded = json.loads(gzip.decompress(wire_body))
        assert decoded["finding_info"]["uid"] == prepared["finding_info"]["uid"]
        assert decoded["severity_id"] == prepared["severity_id"]


class TestEgressResultShape:
    def test_success_result(self, mock_client):
        import alerts
        prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
        result = alerts.egress_alert(
            prepared,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            client=mock_client,
        )
        assert result["success"] is True
        assert result["status"] == 202
        assert result["alert_uid"] == prepared["finding_info"]["uid"]

    def test_http_error_result(self):
        import alerts

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"detail": "bad token"})

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
            result = alerts.egress_alert(
                prepared,
                uam_ingest_url="https://ingest.us1.sentinelone.net",
                service_token="bad",
                account_id="acct-123",
                client=client,
            )
        assert result["success"] is False
        assert result["status"] == 401
        assert "bad token" in result["detail"]

    def test_connection_error_result(self):
        import alerts

        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("simulated network down")

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            prepared = alerts.prepare_alert(alerts.get_template("default_alert"))
            result = alerts.egress_alert(
                prepared,
                uam_ingest_url="https://ingest.us1.sentinelone.net",
                service_token="x",
                account_id="acct-123",
                client=client,
            )
        assert result["success"] is False
        assert result["status"] == 0
        assert "simulated network down" in result["error"]


# ── send_alert (high-level) ──────────────────────────────────────────────────

class TestSendAlert:
    def test_count_n_produces_n_unique_uids(self, mock_client, captured_requests):
        import alerts
        results = alerts.send_alert(
            "default_alert",
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            count=3,
            client=mock_client,
        )
        assert len(results) == 3
        assert len(captured_requests) == 3
        uids = {r["alert_uid"] for r in results}
        assert len(uids) == 3, "send_alert(count=3) must produce 3 distinct UIDs"
        for i, r in enumerate(results):
            assert r["success"] is True
            assert r["alert_index"] == i

    def test_unknown_template_returns_error_result(self, mock_client):
        import alerts
        results = alerts.send_alert(
            "does_not_exist_xyz",
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            client=mock_client,
        )
        assert len(results) == 1
        assert results[0]["success"] is False
        assert "not found" in results[0]["error"]

    def test_overrides_apply_to_every_alert(self, mock_client, captured_requests):
        import alerts
        alerts.send_alert(
            "default_alert",
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            count=2,
            overrides={"finding_info.title": "Phase4 override"},
            client=mock_client,
        )
        for req in captured_requests:
            payload = json.loads(gzip.decompress(req.content))
            assert payload["finding_info"]["title"] == "Phase4 override"


class TestSendCustomAlert:
    def test_round_trip_with_auto_uid(self, mock_client, captured_requests):
        import alerts
        custom: dict[str, Any] = {
            "finding_info": {"uid": "placeholder_uid", "title": "Custom"},
            "severity_id": 3,
            "time": "DYNAMIC",
            "metadata": {"product": {"name": "TestProduct"}},
            "resources": [{"name": "host-1", "uid": "DYNAMIC_RESOURCE_UID"}],
        }
        result = alerts.send_custom_alert(
            custom,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            client=mock_client,
        )
        assert result["success"] is True
        sent = json.loads(gzip.decompress(captured_requests[0].content))
        assert sent["finding_info"]["uid"] != "placeholder_uid"
        assert sent["resources"][0]["uid"] != "DYNAMIC_RESOURCE_UID"
        assert isinstance(sent["time"], int) and sent["time"] > 0

    def test_no_auto_uid_sends_verbatim(self, mock_client, captured_requests):
        import alerts
        custom = {
            "finding_info": {"uid": "literal-uid-1234", "title": "Custom"},
            "severity_id": 3,
        }
        alerts.send_custom_alert(
            custom,
            uam_ingest_url="https://ingest.us1.sentinelone.net",
            service_token="svc-tok",
            account_id="acct-123",
            auto_generate_uid=False,
            client=mock_client,
        )
        sent = json.loads(gzip.decompress(captured_requests[0].content))
        assert sent["finding_info"]["uid"] == "literal-uid-1234"
