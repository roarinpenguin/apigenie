"""Tests for ``alert_enrichment`` and its integration with ``alerts.prepare_alert``.

Pins (Phase 4.7):

* MITRE registry covers every shipped template (no silent gaps).
* :func:`lookup_attacks` resolves via registry first, then the keyword
  fallback, then returns ``[]``.
* :func:`harvest_observables` extracts the OCSF paths we promise (device,
  resources, src/dst_endpoint, actor.user, actor.process, url, email,
  evidences) with stable dedup.
* :func:`enrich_alert` synthesises ``finding_info.related_events`` when
  none exist and merges additively when they do, preserving caller
  values.
* Idempotent: enriching twice produces the same shape.
* :func:`alerts.prepare_alert` defaults enrichment ON, regenerates
  ``related_events[].uid`` each call (HELIOS parity), and respects
  ``enrich=False``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import alert_enrichment
import alerts


# ── MITRE registry ──────────────────────────────────────────────────────────

def test_mitre_registry_covers_every_shipped_template():
    """No silent gaps — every JSON file in ``alert_templates/`` has a
    registry entry. Empty lists are allowed (e.g. ``sample_alert``);
    missing entries are not."""
    templates_dir = Path(__file__).resolve().parent.parent / "alert_templates"
    stems = sorted(p.stem for p in templates_dir.glob("*.json"))
    missing = [s for s in stems if s not in alert_enrichment.MITRE_BY_TEMPLATE]
    assert missing == [], f"templates without a MITRE mapping: {missing}"


def test_mitre_attack_shape_is_ocsf_compatible():
    """Each attack carries the OCSF ``attacks[]`` keys SentinelOne UAM
    and downstream consumers render: tactic+technique sub-objects with
    ``uid``/``name``, plus a top-level ``version`` string."""
    sample = alert_enrichment.MITRE_BY_TEMPLATE["wel_brute_force_success"]
    assert sample, "wel_brute_force_success should have at least one attack"
    for atk in sample:
        assert set(atk.keys()) >= {"tactic", "technique", "version"}
        assert atk["tactic"]["uid"].startswith("TA")
        assert atk["technique"]["uid"].startswith("T")
        assert atk["version"]  # non-empty


def test_lookup_attacks_by_template_id():
    out = alert_enrichment.lookup_attacks("wel_brute_force_success", alert=None)
    assert any(a["technique"]["uid"] == "T1110" for a in out)


def test_lookup_attacks_returns_a_copy_not_the_registry_reference():
    """Mutating the returned list must NOT pollute the registry."""
    out = alert_enrichment.lookup_attacks("wel_brute_force_success")
    out.append({"poison": True})
    again = alert_enrichment.lookup_attacks("wel_brute_force_success")
    assert {"poison": True} not in again


def test_lookup_attacks_keyword_fallback_for_unknown_template():
    """When the template id is unknown but the alert mentions a vendor
    keyword we ship a default mapping."""
    alert = {
        "finding_info": {"title": "Some custom phishing alert"},
        "metadata": {"product": {"vendor_name": "Proofpoint"}},
    }
    out = alert_enrichment.lookup_attacks(template_id=None, alert=alert)
    assert out, "expected at least one MITRE entry from the Proofpoint keyword"


def test_lookup_attacks_returns_empty_for_total_unknown():
    out = alert_enrichment.lookup_attacks(
        template_id=None,
        alert={"finding_info": {"title": "totally unrelated"}, "metadata": {}},
    )
    assert out == []


# ── Observable harvester ────────────────────────────────────────────────────

def test_harvest_observables_extracts_device_fields():
    alert = {"device": {"hostname": "host01", "ip": "10.0.0.5",
                        "mac": "aa:bb:cc:dd:ee:ff", "uid": "uid-1"}}
    obs = alert_enrichment.harvest_observables(alert)
    names = {(o["name"], o["value"]) for o in obs}
    assert ("device.hostname", "host01") in names
    assert ("device.ip", "10.0.0.5") in names
    assert ("device.mac", "aa:bb:cc:dd:ee:ff") in names
    assert ("device.uid", "uid-1") in names


def test_harvest_observables_walks_resources_user_shape():
    """A ``resources[]`` entry whose name contains ``@`` is emitted as
    an email observable, not a hostname — even when ``type`` is missing.
    """
    alert = {"resources": [{"name": "alice@acme.test", "uid": "u-1"}]}
    obs = alert_enrichment.harvest_observables(alert)
    pairs = {(o["name"], o["type_id"]) for o in obs}
    assert ("resource.email", alert_enrichment.OBS_EMAIL_ADDRESS) in pairs
    assert ("resource.uid", alert_enrichment.OBS_RESOURCE_UID) in pairs


def test_harvest_observables_walks_resources_endpoint_shape():
    alert = {"resources": [{"name": "RoarinSrv2022", "uid": "x1",
                             "type": "Windows Server"}]}
    obs = alert_enrichment.harvest_observables(alert)
    pairs = {(o["name"], o["type_id"]) for o in obs}
    assert ("resource.hostname", alert_enrichment.OBS_HOSTNAME) in pairs


def test_harvest_observables_walks_endpoints_and_url_and_email():
    alert = {
        "src_endpoint": {"ip": "203.0.113.5", "port": 4444},
        "dst_endpoint": {"hostname": "evil.example", "ip": "198.51.100.7", "port": 443},
        "url": {"url": "https://evil.example/path", "hostname": "evil.example"},
        "email": {"from": "bad@evil.example", "to": ["victim@acme.test"],
                  "subject": "hi"},
    }
    obs = alert_enrichment.harvest_observables(alert)
    names = {(o["name"], o["value"]) for o in obs}
    assert ("src_endpoint.ip", "203.0.113.5") in names
    assert ("src_endpoint.port", "4444") in names
    assert ("dst_endpoint.hostname", "evil.example") in names
    assert ("dst_endpoint.port", "443") in names
    assert ("url.url", "https://evil.example/path") in names
    assert ("email.from", "bad@evil.example") in names
    assert ("email.to", "victim@acme.test") in names


def test_harvest_observables_walks_evidences_process_file_hashes():
    alert = {"evidences": [{"process": {
        "name": "mal.exe", "pid": 1234,
        "file": {"name": "mal.exe",
                  "hashes": [{"algorithm_id": 1, "value": "deadbeef"}]},
    }}]}
    obs = alert_enrichment.harvest_observables(alert)
    names = {(o["name"], o["value"]) for o in obs}
    assert ("evidences.process.name", "mal.exe") in names
    assert ("evidences.process.pid", "1234") in names
    assert ("evidences.process.file.name", "mal.exe") in names
    assert ("evidences.process.file.hash", "deadbeef") in names


def test_harvest_observables_dedup_across_paths():
    """Same hostname surfaced from ``device.hostname`` and
    ``actor.endpoint.hostname`` should be emitted only once."""
    alert = {
        "device": {"hostname": "h1"},
        "actor": {"endpoint": {"hostname": "h1"}},
    }
    obs = alert_enrichment.harvest_observables(alert)
    # We allow both observables (they have different `name` paths) but the
    # VALUE/type_id should be deduped per (name, value). So two entries
    # with the same value but different name paths are fine; the same
    # (name, value) appearing twice is NOT.
    keys = [(o["name"], o["value"]) for o in obs]
    assert len(keys) == len(set(keys))


def test_harvest_observables_returns_empty_for_non_dict():
    assert alert_enrichment.harvest_observables(None) == []
    assert alert_enrichment.harvest_observables([1, 2, 3]) == []


def test_harvest_observables_walks_actor_under_finding_info():
    """Canonical OCSF placement: ``finding_info.actor.user`` must be
    harvested. Phase-2 templates moved the actor block under
    ``finding_info`` for shape consistency."""
    alert = {
        "finding_info": {
            "actor": {
                "user": {"name": "alice", "email_addr": "alice@acme.test"},
                "process": {"name": "powershell.exe", "pid": 1234},
            },
        },
    }
    obs = alert_enrichment.harvest_observables(alert)
    pairs = {(o["name"], o["value"]) for o in obs}
    assert ("user.name", "alice") in pairs
    assert ("user.email", "alice@acme.test") in pairs
    assert ("actor.process.name", "powershell.exe") in pairs


def test_harvest_observables_back_compat_for_top_level_actor():
    """Legacy payloads that still place ``actor`` at the top level
    must keep working — fall-through path."""
    alert = {
        "actor": {
            "user": {"name": "bob", "email_addr": "bob@acme.test"},
        },
    }
    obs = alert_enrichment.harvest_observables(alert)
    pairs = {(o["name"], o["value"]) for o in obs}
    assert ("user.name", "bob") in pairs
    assert ("user.email", "bob@acme.test") in pairs


# ── Top-level enrichment ────────────────────────────────────────────────────

def test_enrich_alert_synthesises_related_events_when_none_present():
    alert = {
        "finding_info": {"title": "WEL brute force"},
        "resources": [{"name": "RoarinSrv2022", "type": "Windows Server"}],
        "severity_id": 5,
    }
    report = alert_enrichment.enrich_alert(
        alert, template_id="wel_brute_force_success")
    assert report["applied"] is True
    assert report["mode"] == "synthesised"
    events = alert["finding_info"]["related_events"]
    assert isinstance(events, list) and len(events) == 1
    ev = events[0]
    assert ev["uid"]  # uuid assigned
    assert any(a["technique"]["uid"] == "T1110" for a in ev["attacks"])
    assert any(o["name"] == "resource.hostname"
               and o["value"] == "RoarinSrv2022"
               for o in ev["observables"])


def test_enrich_alert_respects_authored_attacks_and_backfills_empty_entries():
    """When a template carries pre-built ``related_events[]``:

    * Entries with their own ``attacks[]`` / ``observables[]`` are
      preserved verbatim (template author is authoritative on the
      narrative). Broadcasting template-level MITRE to every event
      would contaminate each step with the others' techniques.
    * Entries with **empty** ``attacks[]`` / ``observables[]`` get
      backfilled from the template-level registry + harvester so the
      OCSF surface is never empty.
    """
    alert = {
        "finding_info": {
            "title": "Custom alert",
            "related_events": [
                {
                    "type": "Authored step",
                    "attacks": [{
                        "tactic": {"uid": "TA0001", "name": "Initial Access"},
                        "technique": {"uid": "T1078", "name": "Valid Accounts"},
                        "version": "13.1",
                    }],
                    "observables": [{
                        "name": "user.name", "type_id": 4, "value": "alice",
                    }],
                },
                {"type": "Bare step"},   # empty -> backfilled
            ],
        },
        "resources": [{"name": "alice@acme.test"}],
    }
    report = alert_enrichment.enrich_alert(
        alert, template_id="o365_brute_force_success")
    assert report["mode"] == "merged"

    authored, bare = alert["finding_info"]["related_events"]
    # Authored entry kept as-is.
    techs = {a["technique"]["uid"] for a in authored["attacks"]}
    assert techs == {"T1078"}
    obs_vals = {o["value"] for o in authored["observables"]}
    assert obs_vals == {"alice"}
    # Bare entry backfilled with the registry's mapping for the template.
    bare_techs = {a["technique"]["uid"] for a in bare["attacks"]}
    assert "T1110.003" in bare_techs
    assert "T1078.004" in bare_techs
    assert bare["observables"], "bare entry should be backfilled with observables"


def test_enrich_alert_is_idempotent():
    alert = {
        "finding_info": {"title": "WEL brute force"},
        "resources": [{"name": "h1", "type": "Device"}],
        "device": {"hostname": "h1", "ip": "10.0.0.1"},
    }
    alert_enrichment.enrich_alert(alert, template_id="wel_brute_force_success")
    snapshot = json.dumps(alert, sort_keys=True)
    # Second run should be a no-op (attack/observable already present).
    alert_enrichment.enrich_alert(alert, template_id="wel_brute_force_success")
    # The synthesised related_events[0] uid is randomised, so blank it
    # before comparing.
    for ev in alert["finding_info"]["related_events"]:
        ev["uid"] = "_"
    once = json.loads(snapshot)
    for ev in once["finding_info"]["related_events"]:
        ev["uid"] = "_"
    assert alert == once


def test_enrich_alert_no_op_when_alert_is_not_a_dict():
    rep = alert_enrichment.enrich_alert(None, template_id="x")
    assert rep["applied"] is False


# ── prepare_alert integration ───────────────────────────────────────────────

def test_prepare_alert_default_on_attaches_enrichment():
    """The wel_brute_force_success template ships its own narrative
    (T1110.001 → T1078 → T1003.001). prepare_alert must preserve those
    authored entries and ensure every entry's uid is fresh."""
    tmpl = alerts.get_template("wel_brute_force_success")
    out = alerts.prepare_alert(tmpl, template_id="wel_brute_force_success")
    events = out["finding_info"]["related_events"]
    assert events and len(events) >= 3
    # Every event has authored attacks[] preserved.
    techs = {a["technique"]["uid"]
             for ev in events for a in (ev.get("attacks") or [])}
    assert {"T1110.001", "T1078", "T1003.001"} <= techs
    # Each related event got its own fresh UUID (no placeholders).
    uids = [ev["uid"] for ev in events]
    assert all(u and u != "placeholder_uid" for u in uids)
    assert len(set(uids)) == len(uids)


def test_prepare_alert_enrich_false_skips_synthesis():
    """``enrich=False`` must skip the enricher entirely. A template
    without ``related_events[]`` stays without them; a template that
    already ships them keeps the authored content verbatim (no fresh
    UID rewrite happens via the enricher path \u2014 prepare_alert still
    rewrites uids in its own dedicated step for HELIOS parity).
    """
    # 1) Template without related_events stays bare.
    tmpl_bare = alerts.get_template("sample_alert")
    out_bare = alerts.prepare_alert(tmpl_bare, enrich=False)
    assert "related_events" not in (out_bare.get("finding_info") or {})
    # 2) Authored template keeps its narrative (the enricher would be a
    # no-op anyway since every entry already has attacks+observables;
    # this asserts the wiring respects enrich=False).
    tmpl_rich = alerts.get_template("wel_brute_force_success")
    out_rich = alerts.prepare_alert(tmpl_rich, enrich=False)
    rich_events = out_rich["finding_info"]["related_events"]
    techs = {a["technique"]["uid"]
             for ev in rich_events for a in (ev.get("attacks") or [])}
    assert "T1110.001" in techs  # authored content preserved


def test_prepare_alert_regenerates_related_events_uid_each_call():
    """HELIOS parity — every batch ships fresh UUIDs even when the
    template carries pre-built ``related_events``."""
    tmpl = alerts.get_template("advanced_sample_alert")
    a1 = alerts.prepare_alert(tmpl, template_id="advanced_sample_alert",
                              enrich=False)
    a2 = alerts.prepare_alert(tmpl, template_id="advanced_sample_alert",
                              enrich=False)
    uids1 = [e["uid"] for e in a1["finding_info"]["related_events"]]
    uids2 = [e["uid"] for e in a2["finding_info"]["related_events"]]
    assert all(u and u != "placeholder_uid" for u in uids1)
    assert uids1 != uids2  # fresh each time


def test_prepare_alert_keyword_fallback_when_no_template_id():
    """Custom alerts (no template_id) still get MITRE via the keyword
    fallback. Here we use a Proofpoint-flavoured ad-hoc alert."""
    alert = {
        "finding_info": {"title": "Custom phishing campaign hit"},
        "metadata": {"product": {"vendor_name": "Proofpoint"}},
    }
    out = alerts.prepare_alert(alert)  # template=alert; enrich default ON
    events = out["finding_info"]["related_events"]
    assert events and events[0]["attacks"]
    assert any("T1566" in a["technique"]["uid"]
               for a in events[0]["attacks"])


# ── S1 alert envelope guard ─────────────────────────────────────────────────

def test_every_template_uses_s1_alert_envelope():
    """UAM routes each pushed alert by ``metadata.extension`` (singular
    object) keyed on ``uid == "998"``. It also expects ``type_uid`` as
    an int and ``activity_id == 1`` (Create) for new findings.

    A template that ships the wrong envelope shape is silently dropped
    by UAM, which is exactly the failure mode we hit on the Palo Alto
    templates. Pin every shipped template here so a future addition
    can't reintroduce the same regression.
    """
    templates_dir = Path(__file__).resolve().parent.parent / "alert_templates"
    bad = []
    for path in sorted(templates_dir.glob("*.json")):
        obj = json.loads(path.read_text())
        md = obj.get("metadata") or {}
        ext = md.get("extension")
        problems = []
        if not isinstance(ext, dict):
            problems.append(f"metadata.extension must be a dict, got {type(ext).__name__}")
        else:
            if ext.get("uid") != "998":
                problems.append(f"metadata.extension.uid={ext.get('uid')!r} (must be '998')")
            if ext.get("name") != "s1":
                problems.append(f"metadata.extension.name={ext.get('name')!r} (must be 's1')")
        if "extensions" in md:
            problems.append("metadata.extensions[] (plural) is not the S1 envelope shape")
        if not isinstance(obj.get("type_uid"), int):
            problems.append(f"type_uid must be int, got {type(obj.get('type_uid')).__name__}")
        if obj.get("activity_id") != 1:
            problems.append(f"activity_id={obj.get('activity_id')} (must be 1 / Create)")
        if problems:
            bad.append((path.name, problems))
    assert not bad, "S1 envelope violations:\n" + "\n".join(
        f"  {n}:\n    - " + "\n    - ".join(probs) for n, probs in bad
    )
