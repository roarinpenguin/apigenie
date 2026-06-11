"""Per-source event-mix wiring tests.

Two failure modes silently break the override system, so we pin both:

1. **Catalog / template drift.** An admin's mix override is keyed on
   ``EVENT_CATALOG[i]['id']``. If a source renames a ``_LOG_TEMPLATES``
   key (or vice versa) without updating the other, the override binds to
   an event id that's no longer there — and the source silently emits its
   defaults forever. Each wired source asserts the two sets are equal.

2. **Resolver bypass.** A source can declare ``EVENT_CATALOG`` and still
   forget to thread ``event_mix.apply()`` through ``weighted_choice``.
   The empirical-distribution check at scale (2000 samples) catches that:
   if the override doesn't reach the call site, the disabled events keep
   firing and we see them in the output.
"""
from __future__ import annotations

import collections
import importlib
import random

import pytest


# ── Per-test isolation ──────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_data_root(tmp_path, monkeypatch):
    """Redirect APIGENIE_DATA_ROOT to a temp dir + reload event_mix so its
    module-level Path constants pick up the override."""
    monkeypatch.setenv("APIGENIE_DATA_ROOT", str(tmp_path))
    import event_mix as em
    importlib.reload(em)
    yield em
    import profiles
    profiles._CURRENT_USER.set(None)


# ── Catalog / template alignment ────────────────────────────────────────────


# Sources known to be wired today. As we land more, add them here so the
# coverage check stays exhaustive — a fresh wiring without a row in this
# list would still pass, but we want the safety of the explicit list.
_WIRED_SOURCES = (
    "cisco_duo",
    "okta",
    "proofpoint",
    "aws_cloudtrail",
    "aws_guardduty",
    "aws_waf",
    "azure_ad",
    "microsoft_defender",
    "m365",
    "mimecast",
)


@pytest.mark.parametrize("source", _WIRED_SOURCES)
def test_source_declares_non_empty_event_catalog(source):
    from sources import get_event_catalog

    catalog = get_event_catalog(source)
    assert catalog is not None, f"{source} must declare EVENT_CATALOG"
    assert len(catalog) >= 1
    # Every entry has the keys the merge layer + UI rely on.
    for entry in catalog:
        assert "id" in entry and entry["id"].strip()
        assert "label" in entry and entry["label"].strip()
        assert "default_weight" in entry
        assert 0.0 <= float(entry["default_weight"]) <= 1.0


@pytest.mark.parametrize("source", _WIRED_SOURCES)
def test_catalog_default_weights_sum_to_approximately_one(source):
    """Catalogue defaults sum to ≈ 1.0 per endpoint family.

    Sources that expose multiple endpoint families (e.g. cisco_duo splits
    its catalog across ``authentication`` and ``administrator``) are
    grouped by the optional ``endpoint`` field — each group must sum to
    ≈ 1.0 on its own since the resolver runs per template-dict, not over
    the whole catalogue.
    """
    from sources import get_event_catalog

    catalog = get_event_catalog(source)
    # Group by endpoint when the catalog declares one; otherwise sum the
    # whole catalogue as a single group.
    by_endpoint: dict[str, list[float]] = {}
    for entry in catalog:
        bucket = entry.get("endpoint", "_default")
        by_endpoint.setdefault(bucket, []).append(entry["default_weight"])
    for bucket, weights in by_endpoint.items():
        total = sum(weights)
        assert abs(total - 1.0) < 0.05, (
            f"{source}[{bucket}] catalog weights sum to {total:.3f}"
        )


def test_okta_catalog_ids_match_template_keys():
    from sources import okta

    cat_ids = {e["id"] for e in okta.EVENT_CATALOG}
    tpl_ids = set(okta._LOG_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"okta catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_proofpoint_catalog_ids_match_template_keys():
    from sources import proofpoint

    cat_ids = {e["id"] for e in proofpoint.EVENT_CATALOG}
    tpl_ids = set(proofpoint._LOG_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"proofpoint catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_cisco_duo_catalog_ids_match_template_keys():
    """Pilot source — also covered by test_event_mix.py but pinned here
    too so the coverage matrix is self-contained."""
    from sources import cisco_duo

    cat_ids = {e["id"] for e in cisco_duo.EVENT_CATALOG}
    tpl_ids = set(cisco_duo._AUTH_TEMPLATES.keys()) | set(cisco_duo._ADMIN_TEMPLATES.keys())
    assert cat_ids == tpl_ids


def test_aws_cloudtrail_catalog_ids_match_template_keys():
    from sources import aws_cloudtrail

    cat_ids = {e["id"] for e in aws_cloudtrail.EVENT_CATALOG}
    tpl_ids = set(aws_cloudtrail._EVENT_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"aws_cloudtrail catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_aws_guardduty_catalog_ids_match_template_keys():
    from sources import aws_guardduty

    cat_ids = {e["id"] for e in aws_guardduty.EVENT_CATALOG}
    tpl_ids = set(aws_guardduty._FINDING_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"aws_guardduty catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_aws_waf_catalog_ids_match_template_keys():
    from sources import aws_waf

    cat_ids = {e["id"] for e in aws_waf.EVENT_CATALOG}
    tpl_ids = set(aws_waf._LOG_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"aws_waf catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_azure_ad_catalog_ids_match_template_keys():
    """azure_ad spans two endpoint families like cisco_duo. The catalogue
    must cover BOTH _AUDIT_TEMPLATES and _SIGNIN_TEMPLATES key sets — a
    rename in either silently breaks overrides for that endpoint."""
    from sources import azure_ad

    cat_ids = {e["id"] for e in azure_ad.EVENT_CATALOG}
    tpl_ids = (
        set(azure_ad._AUDIT_TEMPLATES.keys())
        | set(azure_ad._SIGNIN_TEMPLATES.keys())
    )
    assert cat_ids == tpl_ids, (
        f"azure_ad catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_microsoft_defender_catalog_ids_match_template_keys():
    from sources import microsoft_defender

    cat_ids = {e["id"] for e in microsoft_defender.EVENT_CATALOG}
    tpl_ids = set(microsoft_defender._ALERT_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"microsoft_defender catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_m365_catalog_ids_match_template_keys():
    """m365 stores callables (not data dicts) as template payloads, but the
    catalog → template key contract is identical."""
    from sources import m365

    cat_ids = {e["id"] for e in m365.EVENT_CATALOG}
    tpl_ids = set(m365._EVENT_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"m365 catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_mimecast_catalog_ids_match_template_keys():
    from sources import mimecast

    cat_ids = {e["id"] for e in mimecast.EVENT_CATALOG}
    tpl_ids = set(mimecast._EVENT_TEMPLATES.keys())
    assert cat_ids == tpl_ids, (
        f"mimecast catalog/template drift: "
        f"catalog-only={cat_ids - tpl_ids}, template-only={tpl_ids - cat_ids}"
    )


def test_mimecast_mta_subset_is_subset_of_event_templates():
    """The MTA-only endpoint restricts to a subset of EVENT_CATALOG. If the
    subset references an id that isn't in the catalogue, the override system
    breaks for that endpoint."""
    from sources import mimecast

    tpl_ids = set(mimecast._EVENT_TEMPLATES.keys())
    assert set(mimecast._MTA_ONLY_IDS).issubset(tpl_ids), (
        f"_MTA_ONLY_IDS references unknown ids: "
        f"{set(mimecast._MTA_ONLY_IDS) - tpl_ids}"
    )


# ── Empirical override at scale (resolver actually wired through) ───────────


def _apply_disable_mix(em, source: str, disable_ids: list[str]) -> None:
    """Disable the given event ids on *source*. Other entries keep
    defaults."""
    em.set_mix(source, [
        {"event_id": eid, "enabled": False, "weight": 0.0}
        for eid in disable_ids
    ])


def test_okta_resolver_actually_disables_event(_isolate_data_root):
    """Disabling rate_limited should drop its API-token-create eventType
    from the empirical output at 200 samples."""
    em = _isolate_data_root
    _apply_disable_mix(em, "okta", ["rate_limited"])
    from sources import okta

    random.seed(42)
    counts = collections.Counter()
    for _ in range(200):
        log = okta._generate_log(ctx=None)
        counts[log["eventType"]] += 1
    assert counts.get("system.api_token.create", 0) == 0, dict(counts)


def test_proofpoint_resolver_actually_disables_event(_isolate_data_root):
    """Disabling polymorphic should drop phishScore-99 messages from the
    output at 200 samples. We assert on the disposition+phishScore tuple
    which is unique to the polymorphic template."""
    em = _isolate_data_root
    _apply_disable_mix(em, "proofpoint", ["polymorphic"])
    from sources import proofpoint

    random.seed(42)
    polymorphic_hits = 0
    for _ in range(200):
        msg = proofpoint._generate_message(since_seconds=3600, ctx=None)
        if msg["phishScore"] == 99 and msg["spamScore"] == 95:
            polymorphic_hits += 1
    assert polymorphic_hits == 0


def test_aws_cloudtrail_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``unauthorized_access`` should remove every AccessDenied
    errorCode from the output. That field is unique to that template."""
    em = _isolate_data_root
    _apply_disable_mix(em, "aws_cloudtrail", ["unauthorized_access"])
    from sources import aws_cloudtrail

    random.seed(42)
    denied = 0
    for _ in range(200):
        ev = aws_cloudtrail._generate_event(ctx=None)
        if ev.get("errorCode") == "AccessDenied":
            denied += 1
    assert denied == 0


def test_aws_guardduty_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``crypto_mining`` should drop CryptoCurrency findings
    from the output. The Type string is unique to that template."""
    em = _isolate_data_root
    _apply_disable_mix(em, "aws_guardduty", ["crypto_mining"])
    from sources import aws_guardduty

    random.seed(42)
    crypto = 0
    for _ in range(200):
        finding = aws_guardduty._generate_finding(ctx=None)
        if finding["Type"] == "CryptoCurrency:EC2/BitcoinTool.B!DNS":
            crypto += 1
    assert crypto == 0


def test_aws_waf_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``sql_injection_block`` should drop SQLi_BODY
    terminating-rule rows. That rule id is unique to that template."""
    em = _isolate_data_root
    _apply_disable_mix(em, "aws_waf", ["sql_injection_block"])
    from sources import aws_waf

    random.seed(42)
    sqli = 0
    for _ in range(200):
        log = aws_waf._generate_log(ctx=None)
        if log["terminatingRuleId"] == "SQLi_BODY":
            sqli += 1
    assert sqli == 0


def test_azure_ad_audit_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``impossible_travel`` should drop that activity display
    name from the directoryAudits output. The string is unique to that
    template."""
    em = _isolate_data_root
    _apply_disable_mix(em, "azure_ad", ["impossible_travel"])
    from sources import azure_ad

    random.seed(42)
    resp = azure_ad.get_audit_logs_response(limit=50)
    hits = sum(
        1 for log in resp["value"]
        if log["activityDisplayName"] == "Impossible travel detected"
    )
    assert hits == 0


def test_azure_ad_signin_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``ca_block`` should drop sign-ins with errorCode 53003.
    That code is unique to the Conditional Access block template and
    proves the resolver is threaded through the signIns code path as
    well as the directoryAudits one."""
    em = _isolate_data_root
    _apply_disable_mix(em, "azure_ad", ["ca_block"])
    from sources import azure_ad

    random.seed(42)
    resp = azure_ad.get_signin_logs_response(limit=50)
    hits = sum(
        1 for log in resp["value"]
        if log["status"].get("errorCode") == 53003
    )
    assert hits == 0


def test_microsoft_defender_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``lsass_dump`` should drop ``Suspicious LSASS Memory
    Access`` alerts. That display name is unique to the lsass template."""
    em = _isolate_data_root
    _apply_disable_mix(em, "microsoft_defender", ["lsass_dump"])
    from sources import microsoft_defender

    random.seed(42)
    resp = microsoft_defender.get_alerts_response(limit=50)
    hits = sum(
        1 for alert in resp["value"]
        if alert["properties"]["alertDisplayName"] == "Suspicious LSASS Memory Access"
    )
    assert hits == 0


def test_m365_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``oauth_consent`` should drop every event whose Operation
    starts with the OAuth consent verbs (``Consent to application.``,
    ``Add OAuth2PermissionGrant.``, etc.). Those Operations are unique to
    the _oauth_consent generator."""
    em = _isolate_data_root
    _apply_disable_mix(em, "m365", ["oauth_consent"])
    from sources import m365

    random.seed(42)
    resp = m365.get_content_response(limit=100)
    oauth_ops = (
        "Consent to application.",
        "Add OAuth2PermissionGrant.",
        "Add application.",
        "Add service principal.",
        "Update application.",
    )
    hits = sum(1 for ev in resp["events"] if ev.get("Operation") in oauth_ops)
    assert hits == 0


def test_mimecast_resolver_actually_disables_event(_isolate_data_root):
    """Disabling ``ttp_imperson`` should remove events whose subtype is
    ``ttp_imperson`` from the SIEM stream. That subtype is unique to the
    _ttp_impersonation_event generator."""
    em = _isolate_data_root
    _apply_disable_mix(em, "mimecast", ["ttp_imperson"])
    from sources import mimecast

    random.seed(42)
    events = mimecast.generate_events(count=100)
    hits = sum(1 for ev in events if ev.get("subtype") == "ttp_imperson")
    assert hits == 0


def test_mimecast_mta_only_endpoint_respects_global_disable(_isolate_data_root):
    """The MTA-only endpoint must honour a global ``receipt`` disable —
    proves the single-source-of-truth contract (the override applies
    everywhere, not just to the broad SIEM stream)."""
    em = _isolate_data_root
    _apply_disable_mix(em, "mimecast", ["receipt"])
    from sources import mimecast

    random.seed(42)
    events, _token = mimecast.generate_siem_logs_response(count=100)
    hits = sum(1 for ev in events if ev.get("subtype") == "receipt")
    assert hits == 0
