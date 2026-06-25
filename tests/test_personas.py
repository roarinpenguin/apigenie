"""Tests for the scenario persona bundle (v5.3 Step 1, Layer 1).

The persona module is the single source of truth for the entities
involved in an attack scenario: the victim user, the victim host, the
attacker, and the malicious payload. A scenario carries one bundle for
its entire lifetime so the events emitted by every source (Okta,
Proofpoint, M365, Defender, Netskope, Azure AD, CloudTrail, Duo) all
share the same user / IP / hostname / hash — turning what used to be
"five disjoint random streams" into one correlated attack story an
analyst can actually reconstruct.

Contract:

* ``personas.generate_bundle()`` returns a fresh, fully-populated
  bundle. Every persona slot the runtime touches downstream is
  present, non-empty, and of the expected shape. No optional fields
  on the canonical slots — a half-populated bundle is a regression.
* ``personas.resolve_path(bundle, "victim_user.email")`` walks the
  nested dict by dotted path and returns the value, or ``None`` for
  paths that don't resolve. ``None`` is the explicit signal that a
  projection should fall through to the source's existing random
  default — crashing in the rule engine when a slot is missing would
  block the whole event mix.
* Validation: ``validate_bundle(bundle)`` returns a list of human-
  readable problems (empty list ⇒ OK). Used by import/export and by
  any future UI persona editor so the operator gets actionable
  feedback instead of silent corruption.
* Two consecutive calls to ``generate_bundle()`` MUST NOT return the
  same bundle — otherwise every scenario starts with the same victim
  and the demo gets boring fast.
"""
from __future__ import annotations


# ── Generation ──────────────────────────────────────────────────────


def test_generate_bundle_has_all_canonical_slots():
    """Every slot referenced by any source PERSONA_PROJECTION must
    exist in the freshly generated bundle. Missing slots silently
    skip the override in `_apply_overrides` and the bug surfaces only
    when an analyst notices an alert with `attacker.ip = None`."""
    import personas

    b = personas.generate_bundle()

    # Top-level slots
    assert set(b.keys()) >= {"victim_user", "victim_host", "attacker",
                              "malicious"}, (
        f"missing top-level persona slot, got keys: {sorted(b.keys())}")

    # victim_user: identity fields used by Okta, AAD, Defender, M365,
    # CloudTrail, Duo, Proofpoint.
    vu = b["victim_user"]
    for key in ("name", "username", "email", "upn", "object_id"):
        assert vu.get(key), f"victim_user.{key} must be populated, got {vu}"
    assert "@" in vu["email"], f"victim_user.email shape wrong: {vu['email']}"
    assert vu["upn"] == vu["email"], (
        "victim_user.upn defaults to email so Entra/M365 see a "
        "consistent principal name")

    # victim_host: device fields used by WEF, Defender, Netskope.
    vh = b["victim_host"]
    for key in ("hostname", "ip", "os", "agent_uuid"):
        assert vh.get(key), f"victim_host.{key} must be populated, got {vh}"
    # Internal IP — RFC 1918 / link-local. Public IPs belong to the attacker.
    assert (vh["ip"].startswith("10.")
            or vh["ip"].startswith("192.168.")
            or vh["ip"].startswith("172.")), (
        f"victim_host.ip should be an internal RFC1918 address, got {vh['ip']}")

    # attacker: external infrastructure fields used by Proofpoint,
    # Okta client.ip, Defender hostStates, Netskope dstip, CloudTrail
    # sourceIPAddress, AAD ipAddress.
    a = b["attacker"]
    for key in ("ip", "country", "email", "domain"):
        assert a.get(key), f"attacker.{key} must be populated, got {a}"
    # Attacker IP must NOT be in the RFC1918 ranges — that would defeat
    # the "external attacker" narrative and confuse geo-enrichment.
    assert not a["ip"].startswith(("10.", "192.168.", "172.")), (
        f"attacker.ip must look external, got {a['ip']}")
    assert "@" in a["email"]
    assert "." in a["domain"]

    # malicious: payload fingerprints used by Proofpoint hashes, WEF
    # process+cmdline, Defender fileStates, Netskope object.
    m = b["malicious"]
    for key in ("file_name", "sha256", "md5", "process"):
        assert m.get(key), f"malicious.{key} must be populated, got {m}"
    assert len(m["sha256"]) == 64, (
        f"malicious.sha256 wrong length: {len(m['sha256'])}")
    assert len(m["md5"]) == 32, (
        f"malicious.md5 wrong length: {len(m['md5'])}")


def test_generate_bundle_is_not_deterministic():
    """Two scenarios created back-to-back must roll different victims
    and attacker infrastructure. A deterministic seed would make every
    demo identical and ruin variety across runs."""
    import personas

    bundles = [personas.generate_bundle() for _ in range(5)]
    emails = {b["victim_user"]["email"] for b in bundles}
    attacker_ips = {b["attacker"]["ip"] for b in bundles}
    # At least 3/5 unique on each side — leaves room for the rare
    # collision in a small pool without making the assertion flaky.
    assert len(emails) >= 3, f"victim emails repeat too much: {emails}"
    assert len(attacker_ips) >= 3, (
        f"attacker IPs repeat too much: {attacker_ips}")


# ── Path resolution ─────────────────────────────────────────────────


def test_resolve_path_walks_dotted_paths():
    """The rule engine's _set_nested already uses dotted paths; the
    persona resolver must speak the same dialect so the projection
    table is symmetric on both sides ('actor.email' ⇔ 'victim_user.email')."""
    import personas

    b = {
        "victim_user": {"email": "jdoe@acme.test", "name": "John Doe"},
        "attacker":    {"ip": "203.0.113.7"},
    }
    assert personas.resolve_path(b, "victim_user.email") == "jdoe@acme.test"
    assert personas.resolve_path(b, "victim_user.name")  == "John Doe"
    assert personas.resolve_path(b, "attacker.ip")       == "203.0.113.7"


def test_resolve_path_returns_none_on_missing():
    """Returning None — never raising — is the contract the rule
    engine relies on. Missing slot ⇒ projection falls through to the
    source's random default ⇒ scenario keeps running."""
    import personas

    b = {"victim_user": {"email": "jdoe@acme.test"}}
    assert personas.resolve_path(b, "victim_user.missing") is None
    assert personas.resolve_path(b, "missing.slot") is None
    assert personas.resolve_path(b, "") is None
    assert personas.resolve_path(b, "victim_user.email.too.deep") is None


def test_resolve_path_handles_empty_bundle():
    """Defensive: a legacy scenario stored before this feature exists
    has no 'personas' key. The resolver must treat {} as 'nothing
    here' and the splicer downstream must skip silently."""
    import personas

    assert personas.resolve_path({}, "anything") is None
    assert personas.resolve_path({}, "victim_user.email") is None


# ── Validation ──────────────────────────────────────────────────────


def test_validate_accepts_freshly_generated_bundle():
    """Whatever generate_bundle produces must, by construction, pass
    validation. If this ever breaks, generate_bundle and the schema
    have drifted."""
    import personas

    b = personas.generate_bundle()
    problems = personas.validate_bundle(b)
    assert problems == [], f"freshly generated bundle has problems: {problems}"


def test_validate_flags_missing_top_level_slot():
    """A bundle that has been hand-edited via the (future) UI editor
    and lost a slot must produce a clear human-readable problem so
    the operator knows what to fix."""
    import personas

    b = personas.generate_bundle()
    del b["attacker"]
    problems = personas.validate_bundle(b)
    assert problems, "missing 'attacker' slot must produce a problem"
    assert any("attacker" in p for p in problems), problems


def test_validate_flags_empty_string_email():
    """Empty strings are as bad as missing keys — they propagate into
    the wire format and break the analyst's correlation. Validation
    must surface them."""
    import personas

    b = personas.generate_bundle()
    b["victim_user"]["email"] = ""
    problems = personas.validate_bundle(b)
    assert any("victim_user.email" in p for p in problems), problems


def test_validate_rejects_non_dict_bundle():
    """Defensive: a JSON import that landed a list / scalar where a
    dict was expected must be flagged, not silently coerced."""
    import personas

    assert personas.validate_bundle([]) != []     # type: ignore[arg-type]
    assert personas.validate_bundle("nope") != [] # type: ignore[arg-type]
    assert personas.validate_bundle(None) != []   # type: ignore[arg-type]
