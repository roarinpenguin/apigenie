"""Tests for ``wef_runner`` — async push loop driving enabled WEF bindings.

The runner is the bridge between :mod:`wef_bindings` (storage of binding
rows) and :class:`sources.windows_event_forwarding.WEFEmitter` (the
actual push wire). Per enabled binding it owns:

* a cached emitter (recreated on config change)
* a per-cycle push that calls :func:`wef_bindings.record_push_result`
  so the admin UI sees the throughput / last error.

Production usage is fully async (one supervisor task + sleeps based on
``rate_per_min``), but the deterministic surface this test file exercises
is **sync** — :meth:`WEFRunner.push_once` and :meth:`reconcile_sync` —
because pytest-asyncio is not in the test stack and integration smoke is
done out-of-band via docker compose. The async wrapper is a thin loop
around the same primitives so a green sync test transfers.

Spec: docs/ROADMAP_2026-06-12.md §"WEF push runner".
"""
from __future__ import annotations

import pytest


# ── Test doubles ──────────────────────────────────────────────────────

class FakeEmitter:
    """Stand-in for :class:`WEFEmitter` — records calls, returns a
    pre-canned result, never touches the network."""

    def __init__(self, cfg, http_client=None, binding_id=None):
        self.cfg = cfg
        self.binding_id = binding_id
        self.calls: list[dict] = []
        self.next_result: dict = {"sent": 5, "status_code": 200, "ok": True}
        self.stopped = False
        self.raise_on_push: Exception | None = None

    def push_batch(self, events=None, event_count=None):
        self.calls.append(
            {"event_count": event_count, "events_len": len(events) if events else 0},
        )
        if self.raise_on_push:
            raise self.raise_on_push
        return self.next_result

    def stop(self):
        self.stopped = True


class FailingFactoryEmitter:
    """Emitter factory that raises BindingConfigError at construction
    time — simulates a misconfigured row that should never come online."""

    def __init__(self, cfg, http_client=None, binding_id=None):
        from sources.windows_event_forwarding import BindingConfigError
        raise BindingConfigError("simulated bad cert")


# ── Fixtures ──────────────────────────────────────────────────────────

_BASIC_CFG = {
    "target_host": "wec1.lab.example.com",
    "target_port": 5986,
    "target_path": "/wsman/SubscriptionManager/WEC",
    "auth_method": "basic",
    "basic_username": "wef-svc",
    "tls_verify": True,
    "ca_bundle_path": None,
    "rate_per_min": 60,
    "batch_size": 10,
    "jitter_pct": 0,
    "channels_enabled": ["Security"],
}


def _make_binding(name: str = "B1", enabled: bool = True,
                  **cfg_overrides) -> dict:
    """Create a binding in storage and optionally enable it."""
    import wef_bindings
    cfg = {**_BASIC_CFG, **cfg_overrides}
    bnd = wef_bindings.create_binding(
        {"name": name, "config": cfg, "password": "pw"},
    )
    if enabled:
        wef_bindings.set_enabled(bnd["id"], True)
    return bnd


# ── push_once: per-binding push cycle ─────────────────────────────────

def test_push_once_with_unknown_binding_returns_error():
    import wef_runner
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    result = runner.push_once("wef-does-not-exist")
    assert result["ok"] is False
    assert "not found" in result["error"].lower()


def test_push_once_uses_emitter_factory_and_caches_instance():
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    runner.push_once(bnd["id"])
    # Same emitter instance reused — i.e. factory called exactly once.
    em = runner._emitters[bnd["id"]]
    assert isinstance(em, FakeEmitter)
    assert len(em.calls) == 2


def test_push_once_records_status_on_success():
    import wef_bindings
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    after = wef_bindings.get_binding(bnd["id"])
    assert after["status"]["sent_total"] == 5
    assert after["status"]["last_status_code"] == 200
    assert after["status"]["last_error"] is None
    assert after["status"]["last_push_at"] is not None


def test_push_once_records_error_when_emitter_raises():
    import wef_bindings
    import wef_runner

    class Boom(FakeEmitter):
        def push_batch(self, events=None, event_count=None):
            raise RuntimeError("WEC connection refused")

    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=Boom)
    runner.push_once(bnd["id"])
    after = wef_bindings.get_binding(bnd["id"])
    assert after["status"]["sent_total"] == 0
    assert "WEC connection refused" in (after["status"]["last_error"] or "")


def test_push_once_records_non_2xx_as_error():
    import wef_bindings
    import wef_runner

    class Bad(FakeEmitter):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.next_result = {"sent": 0, "status_code": 503, "ok": False}

    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=Bad)
    runner.push_once(bnd["id"])
    after = wef_bindings.get_binding(bnd["id"])
    assert after["status"]["last_status_code"] == 503
    assert after["status"]["last_error"], (
        "non-2xx response must surface as a last_error string so the UI "
        "can flag the binding"
    )


def test_push_once_handles_binding_config_error_from_factory():
    """An emitter that refuses to come online (mTLS without a cert,
    bad auth method, …) must NOT crash the runner — the failure is
    recorded as a status error and the next reconcile will try again
    once the operator fixes the config."""
    import wef_bindings
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FailingFactoryEmitter)
    result = runner.push_once(bnd["id"])
    assert result["ok"] is False
    after = wef_bindings.get_binding(bnd["id"])
    assert "simulated bad cert" in (after["status"]["last_error"] or "")


def test_push_once_passes_batch_size_to_emitter():
    import wef_runner
    bnd = _make_binding(batch_size=42)
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    em = runner._emitters[bnd["id"]]
    assert em.calls == [{"event_count": 42, "events_len": 0}]


# ── reconcile_sync: keep emitter cache in sync with the enabled set ───

def test_reconcile_drops_emitter_for_disabled_binding():
    import wef_bindings
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    em = runner._emitters[bnd["id"]]
    # Operator disables the binding.
    wef_bindings.set_enabled(bnd["id"], False)
    runner.reconcile_sync()
    assert bnd["id"] not in runner._emitters
    assert em.stopped is True, "Emitter must be .stop()'d on disable"


def test_reconcile_drops_emitter_for_deleted_binding():
    import wef_bindings
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    wef_bindings.delete_binding(bnd["id"])
    runner.reconcile_sync()
    assert bnd["id"] not in runner._emitters


def test_reconcile_recreates_emitter_when_config_changes():
    import wef_bindings
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    old_emitter = runner._emitters[bnd["id"]]
    # Operator edits target_host — config changed, restart needed.
    wef_bindings.update_binding(
        bnd["id"], {"config": {**bnd["config"], "target_host": "wec2.example.com"}},
    )
    runner.reconcile_sync()
    runner.push_once(bnd["id"])
    new_emitter = runner._emitters[bnd["id"]]
    assert new_emitter is not old_emitter, (
        "Config change must replace the cached emitter so the next push "
        "talks to the new target"
    )
    assert old_emitter.stopped is True


def test_reconcile_keeps_emitter_when_config_unchanged():
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    first = runner._emitters[bnd["id"]]
    runner.reconcile_sync()
    runner.push_once(bnd["id"])
    second = runner._emitters[bnd["id"]]
    assert first is second
    assert first.stopped is False


# ── Error isolation between bindings ──────────────────────────────────

def test_one_broken_binding_does_not_affect_others():
    """If binding A's emitter raises every push, binding B must still
    accumulate sent_total normally."""
    import wef_bindings
    import wef_runner

    a = _make_binding("A")
    b = _make_binding("B")

    created_emitters: dict[str, FakeEmitter] = {}

    def factory(cfg, http_client=None, binding_id=None):
        em = FakeEmitter(cfg, binding_id=binding_id)
        if binding_id == a["id"]:
            em.raise_on_push = RuntimeError("A is broken")
        created_emitters[binding_id] = em
        return em

    runner = wef_runner.WEFRunner(emitter_factory=factory)
    runner.push_once(a["id"])
    runner.push_once(b["id"])

    a_after = wef_bindings.get_binding(a["id"])
    b_after = wef_bindings.get_binding(b["id"])
    assert "A is broken" in (a_after["status"]["last_error"] or "")
    assert b_after["status"]["sent_total"] == 5
    assert b_after["status"]["last_error"] is None


# ── Stop hygiene ──────────────────────────────────────────────────────

def test_stop_all_releases_every_emitter():
    import wef_runner
    a = _make_binding("A")
    b = _make_binding("B")
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(a["id"])
    runner.push_once(b["id"])
    em_a = runner._emitters[a["id"]]
    em_b = runner._emitters[b["id"]]
    runner.stop_all()
    assert em_a.stopped is True
    assert em_b.stopped is True
    assert runner._emitters == {}
