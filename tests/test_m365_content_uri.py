"""M365 ``contentUri`` must point back to apigenie, not Microsoft.

Bug observed 2026-06-24 with a real SDL Marketplace collector
(LUA-scripted) pulling against ``apigenie-poc.roarinpenguin.com``:

* ``GET  /api/v1.0/<tenant>/activity/feed/subscriptions/list``   → 200
* ``POST /api/v1.0/<tenant>/activity/feed/subscriptions/start``  → 200
* ``GET  /api/v1.0/<tenant>/activity/feed/subscriptions/content`` → 200
  Response body:
    ``[{"contentUri": "https://manage.office.com/api/v1.0/<rand>/...", ...}]``
* Collector then does ``GET https://manage.office.com/api/v1.0/<rand>/...``
  with the fake JWT we issued                                    → **401**
  (because that hostname is the REAL Microsoft, which has never heard
  of our fake client_id/secret nor our random tenant guid).

Apigenie's logs show only the 200s; the 401 lives in the collector's
own log, which is why the symptom looked like "m365 fails with 401"
even though every apigenie endpoint was happy. The root cause is the
hardcoded ``manage.office.com`` host (and a randomly-chosen tenant
that doesn't match the one the collector used) in the ``contentUri``
field returned by :func:`sources.m365.get_content_response`.

This suite locks in the new contract:

* The function accepts (optional) ``base_url`` and ``tenant_id``
  arguments so the FastAPI route can stamp the request's own host
  and tenant onto the blob URLs.
* When supplied, ``contentUri`` uses those values verbatim, so the
  collector's follow-up GET hits apigenie's
  ``/api/v1.0/<tenant>/activity/feed/audit/<id>`` route (already
  implemented) instead of leaving apigenie's domain.
* When NOT supplied, the legacy ``manage.office.com`` shape is
  preserved — so any caller that doesn't pass the kwargs (e.g. a
  unit-test snapshot) keeps the same response.
* The integration with the FastAPI route is end-to-end: a TestClient
  request to ``/api/v1.0/<tenant>/activity/feed/subscriptions/content``
  returns blobs whose ``contentUri`` is reachable on the same
  TestClient (i.e. /audit/<id> returns 200, not 404).
"""
from __future__ import annotations

import random


# ── Unit: get_content_response respects optional kwargs ──────────────


def test_default_contentUri_keeps_legacy_manage_office_host():
    """Caller that doesn't supply base_url + tenant_id is unchanged.

    Snapshot tests and any internal usage that doesn't go through the
    HTTP route keep the old wire shape.
    """
    from sources import m365

    random.seed(7)
    resp = m365.get_content_response(limit=3)
    for blob in resp["blobs"]:
        assert blob["contentUri"].startswith("https://manage.office.com/"), (
            "default contract preserved")


def test_contentUri_uses_passed_base_url_and_tenant():
    """When the route passes base_url + tenant_id, every blob URL is
    rooted at apigenie's own host and carries the exact tenant the
    collector is asking for (NOT a random one from the internal pool)."""
    from sources import m365

    random.seed(7)
    resp = m365.get_content_response(
        limit=5,
        base_url="https://apigenie-poc.roarinpenguin.com",
        tenant_id="my-roarin-111-m365tenant",
    )
    for blob in resp["blobs"]:
        uri = blob["contentUri"]
        assert uri.startswith("https://apigenie-poc.roarinpenguin.com/"), (
            f"contentUri must point back to apigenie, got: {uri}")
        # The tenant id in the contentUri is the route's tenant id, not
        # a random pick from _TENANT_IDS — so the collector's follow-up
        # GET lands on the audit/{content_id} route for the same tenant.
        assert "/api/v1.0/my-roarin-111-m365tenant/" in uri, (
            f"contentUri must carry the route's tenant id, got: {uri}")
        # The path shape matches the audit/{content_id} route we expose:
        # /api/v1.0/<tenant>/activity/feed/audit/<id>
        assert "/activity/feed/audit/" in uri, (
            f"contentUri must use the audit/<id> route shape, got: {uri}")


def test_contentUri_strips_trailing_slash_on_base_url():
    """A caller that hands us a base_url with a trailing slash must
    NOT produce a contentUri with a double slash. Common foot-gun for
    callers that build ``f"{request.url.scheme}://{request.url.netloc}/"``.
    """
    from sources import m365

    random.seed(7)
    resp = m365.get_content_response(
        limit=1,
        base_url="https://apigenie-poc.roarinpenguin.com/",
        tenant_id="t1",
    )
    uri = resp["blobs"][0]["contentUri"]
    assert "//api/v1.0/" not in uri, f"double slash: {uri}"
    assert uri.startswith("https://apigenie-poc.roarinpenguin.com/api/v1.0/")


# ── Integration: the FastAPI route wires base_url + tenant_id through ─


def test_route_subscriptions_content_yields_self_reachable_contentUri():
    """End-to-end via the FastAPI TestClient: the route under
    ``/api/v1.0/<tenant>/activity/feed/subscriptions/content`` must
    return blobs whose ``contentUri`` resolves to a route on the same
    server. We verify the loop closes by issuing the follow-up GET on
    the URL the route just handed us and checking it returns 200.
    """
    from fastapi.testclient import TestClient

    import app as apigenie_app

    client = TestClient(apigenie_app.app)
    tenant = "my-roarin-111-m365tenant"
    # Auth: any token starting with eyJ is accepted by require_bearer_auth,
    # so a hand-crafted fake JWT is enough.
    headers = {"Authorization": "Bearer eyJ.fake.jwt"}
    r = client.get(
        f"/api/v1.0/{tenant}/activity/feed/subscriptions/content",
        params={"contentType": "Audit.General"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    blobs = r.json()
    assert blobs, "the route must return at least one content blob"
    for blob in blobs:
        uri = blob["contentUri"]
        # 1) The URL points at apigenie, not at manage.office.com.
        assert "manage.office.com" not in uri, (
            f"contentUri still pointing at Microsoft: {uri}")
        # 2) The URL is on the SAME host the collector just talked to
        #    (the TestClient default base is http://testserver). If the
        #    route picks the wrong host, the collector's follow-up GET
        #    lands somewhere it can't authenticate.
        assert "testserver" in uri, (
            f"contentUri must be self-reachable, got: {uri}")
        # 3) The tenant id matches the path parameter — apigenie's
        #    audit/{content_id} route is tenant-scoped.
        assert f"/api/v1.0/{tenant}/" in uri, (
            f"contentUri must carry the route's tenant id, got: {uri}")
        # 4) The audit blob endpoint is reachable. The collector follows
        #    the URI we hand it; if that GET 404s the customer never
        #    actually receives any events even though list/start/content
        #    all returned 200.
        from urllib.parse import urlparse
        parsed = urlparse(uri)
        r2 = client.get(parsed.path, headers=headers)
        assert r2.status_code == 200, (
            f"follow-up GET on the contentUri must succeed; "
            f"path={parsed.path} status={r2.status_code} body={r2.text[:200]}")


def test_route_honors_x_forwarded_proto_and_host():
    """In production apigenie runs behind nginx which terminates TLS
    and forwards to FastAPI over plain HTTP. Without consulting the
    X-Forwarded-* headers we'd hand the collector an ``http://...``
    contentUri even though the client originally connected on TLS —
    which either redirects, double-hops, or outright fails for
    collectors that enforce HTTPS on contentUri fetches.
    """
    from fastapi.testclient import TestClient

    import app as apigenie_app

    client = TestClient(apigenie_app.app)
    tenant = "my-roarin-111-m365tenant"
    headers = {
        "Authorization":     "Bearer eyJ.fake.jwt",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host":  "apigenie-poc.roarinpenguin.com",
    }
    r = client.get(
        f"/api/v1.0/{tenant}/activity/feed/subscriptions/content",
        params={"contentType": "Audit.General"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    blobs = r.json()
    assert blobs, "the route must return at least one content blob"
    for blob in blobs:
        uri = blob["contentUri"]
        assert uri.startswith("https://apigenie-poc.roarinpenguin.com/"), (
            f"X-Forwarded-Proto/Host must be honored; got: {uri}")
