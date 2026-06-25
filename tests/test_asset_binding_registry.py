"""Tests for the per-source asset-binding registry (v5.3 Step 2, Phase 1).

For SentinelOne STAR / Custom Detection rules to bind their alerts
to a *real* Target Asset (and not "Unknown Device"), the matched
event must carry:

1. A unified-asset identifier in ``device.uid`` (endpoint / cloud)
   or ``user.uid`` (identity) — the value being the XDR Asset ID
   from ``datasource assets`` (or the console agent id for endpoints).
2. A ``class_uid`` that classifies the event as asset-bearing:
   - ``1007`` Process Activity → endpoint
   - ``3002`` Authentication   → identity
   - ``6003`` Web Resources    → cloud
   - ``4001`` Network Activity → network (cloud-shaped)
   - ``4002`` HTTP Activity    → network (HTTP-shaped)

The registry below is the source of truth for the push loop: it
tells the loop "for source X, stamp ``class_uid=Y`` and resolve the
asset on the ``device/user`` side". Sources marked ``kind=none``
(Snyk, Tenable, Wiz — pure governance feeds) explicitly opt out so
the push loop never tries to find an asset for them.

Contract enforced here:

* The 19 sources listed in the v5.3 plan all resolve to a non-None
  binding (either real or explicitly ``kind=none``).
* Every binding has a ``kind`` ∈ {endpoint, identity, cloud, network,
  none} and an int ``class_uid`` (0 when ``kind=none``).
* Source aliases resolve (``entra_id`` → ``azure_ad``,
  ``defender`` → ``microsoft_defender``).
* Unknown sources return ``None`` — the push loop treats that as
  "no binding configured", same as ``kind=none``.
* A source module's own module-level ``ASSET_BINDING`` constant wins
  over the registry table — lets a vendor module pin its kind/class
  in the same file as ``EVENT_CATALOG`` / ``PERSONA_PROJECTION``.
"""
from __future__ import annotations


# Canonical mapping from v5.3 plan (asset-binding-plan.md table).
# Tests below iterate this list — easier to expand than a hard-coded
# 'expected dict' that we'd have to re-edit for every new entry.
_EXPECTED: dict[str, tuple[str, int]] = {
    # identity (3002 — Authentication)
    "okta":              ("identity", 3002),
    "azure_ad":          ("identity", 3002),
    "cisco_duo":         ("identity", 3002),
    "m365":              ("identity", 3002),
    # cloud (6003 — Web Resources Activity)
    "aws_cloudtrail":    ("cloud",    6003),
    "aws_guardduty":     ("cloud",    6003),
    "aws_waf":           ("cloud",    6003),
    "azure_platform":    ("cloud",    6003),
    "gcp_audit":         ("cloud",    6003),
    # endpoint (1007 — Process Activity)
    "sentinelone":       ("endpoint", 1007),
    "microsoft_defender":("endpoint", 1007),
    # network (4001 / 4002 — Network / HTTP Activity)
    "cato":              ("network",  4001),
    "cloudflare":        ("network",  4002),
    "darktrace":         ("network",  4001),
    "mimecast":          ("network",  4002),
    "netskope":          ("network",  4002),
    "proofpoint":        ("network",  4002),
    "zscaler_zpa":       ("network",  4002),
    # governance — opt out: no asset target
    "snyk":              ("none",     0),
    "tenable":           ("none",     0),
    "wiz":               ("none",     0),
}

_VALID_KINDS = {"endpoint", "identity", "cloud", "network", "none"}


def test_every_planned_source_has_a_binding():
    """The 21 sources from the v5.3 plan must each resolve to a
    binding. A forgotten entry would silently push events with no
    class_uid and bind to 'Unknown Device' — exactly the bug Step 2
    is meant to fix."""
    import sources

    missing = []
    for src in _EXPECTED:
        if sources.get_asset_binding(src) is None:
            missing.append(src)
    assert not missing, (
        f"sources without an asset binding configured: {missing}")


def test_every_binding_has_valid_kind_and_class_uid():
    """Shape contract: ``kind`` is one of the 5 known categories and
    ``class_uid`` is a non-negative int (0 only when kind=none)."""
    import sources

    bad: list[tuple[str, dict]] = []
    for src in _EXPECTED:
        b = sources.get_asset_binding(src)
        if not isinstance(b, dict):
            bad.append((src, {"why": "not a dict", "value": b}))
            continue
        kind = b.get("kind")
        cu = b.get("class_uid")
        if kind not in _VALID_KINDS:
            bad.append((src, {"why": "invalid kind", "value": b}))
        if not isinstance(cu, int) or cu < 0:
            bad.append((src, {"why": "invalid class_uid", "value": b}))
        if kind == "none" and cu != 0:
            bad.append((src, {"why": "kind=none must imply class_uid=0",
                              "value": b}))
        if kind != "none" and cu == 0:
            bad.append((src, {"why": "non-none kind needs class_uid",
                              "value": b}))
    assert not bad, f"malformed bindings: {bad}"


def test_planned_kind_and_class_uid_match_table():
    """The registry MUST emit the exact (kind, class_uid) pair
    documented in the plan — those values are what S1 expects on
    the OCSF stream. Drift here means STAR rules won't bind."""
    import sources

    drifted: list[tuple[str, tuple, tuple]] = []
    for src, (kind, cu) in _EXPECTED.items():
        b = sources.get_asset_binding(src) or {}
        got = (b.get("kind"), b.get("class_uid"))
        if got != (kind, cu):
            drifted.append((src, (kind, cu), got))
    assert not drifted, (
        f"binding values do not match the v5.3 plan: {drifted}")


def test_aliases_resolve_to_same_binding():
    """The bindings UI uses ``entra_id`` / ``defender`` as source ids
    even though the modules are ``azure_ad`` / ``microsoft_defender``.
    Without alias resolution scenarios that bind via UI id would
    silently fall through to "no binding" → "Unknown Device"."""
    import sources

    assert sources.get_asset_binding("entra_id") == \
           sources.get_asset_binding("azure_ad")
    assert sources.get_asset_binding("defender") == \
           sources.get_asset_binding("microsoft_defender")


def test_unknown_source_returns_none():
    """Unknown / not-yet-wired source ids must return ``None``. The
    push loop treats None as 'no binding configured' and emits the
    raw event — never a stamped 0 / empty class_uid."""
    import sources

    assert sources.get_asset_binding("not-a-real-source") is None
    assert sources.get_asset_binding("") is None


def test_module_level_override_wins_over_registry(monkeypatch):
    """A source module that declares its own ``ASSET_BINDING`` const
    wins over the table — so a vendor module can keep its
    class_uid + kind co-located with its other constants.

    We mock by directly setting the attribute on an existing source.
    """
    import importlib
    import sources

    # Use okta as the canary — currently identity/3002 from the table.
    mod = importlib.import_module("sources.okta")
    sentinel = {"kind": "cloud", "class_uid": 9999, "_test": True}
    monkeypatch.setattr(mod, "ASSET_BINDING", sentinel, raising=False)

    got = sources.get_asset_binding("okta")
    assert got == sentinel, (
        "module-level ASSET_BINDING must win over the table default")
