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
_WIRED_SOURCES = ("cisco_duo", "okta", "proofpoint")


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
