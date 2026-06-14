"""Async push runner for enabled WEF bindings (v5.2 Phase B).

Bridges :mod:`wef_bindings` (storage) and
:class:`sources.windows_event_forwarding.WEFEmitter` (wire). Per
enabled binding it owns:

* a cached :class:`WEFEmitter` (recreated when the binding's config
  changes, ``stop()``-ed when the binding is disabled or deleted)
* a per-cycle ``push_batch(event_count=batch_size)`` call that pipes the
  result back to :func:`wef_bindings.record_push_result` so the admin
  UI's Activity panel renders the latest throughput / error string

Architecture
============

The runner exposes **two layered surfaces**:

1. **Sync primitives** — :meth:`push_once`, :meth:`reconcile_sync`,
   :meth:`stop_all`. Each is a deterministic single-shot operation
   safe to call from tests, from REPL smoke, or from a synchronous
   admin endpoint ("Test push" button).
2. **Async lifecycle** — :meth:`start` / :meth:`stop`. Wraps the sync
   primitives in an asyncio supervisor task that reconciles every
   ``RECONCILE_INTERVAL_S`` seconds and schedules per-binding push
   tasks throttled by each binding's ``rate_per_min`` + ``jitter_pct``.

The async layer is a thin loop around the sync primitives — once the
sync tests are green, the async wrapper inherits correctness. The
integration verification for the async layer is the docker-compose
smoke (Phase D), not unit tests.

Error isolation
===============

Every exception from an emitter (network, TLS, binding config) is
caught at the per-binding boundary, recorded via
``record_push_result(error=str(exc))``, and the loop continues. A
single broken WEC can therefore never take down the supervisor or
starve other bindings.
"""
from __future__ import annotations

import asyncio
import logging
import random
import threading
from typing import Any, Callable

import wef_bindings
from sources.windows_event_forwarding import BindingConfigError, WEFEmitter

log = logging.getLogger(__name__)


# How often the supervisor re-checks the enabled set (seconds). Short
# enough that an admin disabling a binding sees the loop quiesce within
# one tick, long enough not to thrash the JSON store under steady state.
RECONCILE_INTERVAL_S = 5.0

# Floor for the per-binding inter-batch sleep so a misconfigured
# rate_per_min=600000 doesn't busy-loop the event loop.
MIN_INTERVAL_S = 0.1


EmitterFactory = Callable[..., Any]


class WEFRunner:
    """Singleton-style orchestrator. One instance per process, owned by
    ``app.py`` startup. Tests construct their own with a fake factory
    so they never spin up real HTTP clients.
    """

    def __init__(self,
                 emitter_factory: EmitterFactory | None = None) -> None:
        self._emitter_factory: EmitterFactory = emitter_factory or WEFEmitter
        self._emitters: dict[str, Any] = {}
        # Last config seen per binding, for change detection. Stored as
        # the dict itself; reconcile compares by equality.
        self._configs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        # Async lifecycle state — None when not started.
        self._supervisor_task: asyncio.Task | None = None
        self._push_tasks: dict[str, asyncio.Task] = {}
        self._stopping = False

    # ── Sync primitives ──────────────────────────────────────────────

    def push_once(self, bid: str) -> dict[str, Any]:
        """Execute one push cycle for binding *bid* synchronously.

        Returns a result dict shaped like :meth:`WEFEmitter.push_batch`'s
        return value, plus an optional ``error`` key when the cycle
        failed before/during the push. Always records the outcome via
        :func:`wef_bindings.record_push_result` so the admin UI sees
        the latest status, regardless of success/failure.
        """
        cfg = wef_bindings.effective_config(bid)
        if cfg is None:
            # No binding row — most likely deleted between schedule and
            # execution. Nothing to record (the row is gone), just
            # surface the miss to the caller.
            return {
                "sent": 0,
                "status_code": None,
                "ok": False,
                "error": "binding not found",
            }

        try:
            emitter = self._get_or_create_emitter(bid, cfg)
        except BindingConfigError as exc:
            msg = str(exc)
            wef_bindings.record_push_result(
                bid, sent=0, status_code=None, error=msg,
            )
            return {"sent": 0, "status_code": None, "ok": False,
                    "error": msg}
        except Exception as exc:                          # pragma: no cover
            # Defensive: a custom emitter factory may raise something
            # other than BindingConfigError. Treat the same way.
            log.exception("wef_runner: emitter factory raised for %s", bid)
            msg = f"{type(exc).__name__}: {exc}"
            wef_bindings.record_push_result(
                bid, sent=0, status_code=None, error=msg,
            )
            return {"sent": 0, "status_code": None, "ok": False,
                    "error": msg}

        batch_size = int(cfg.get("batch_size") or 10)
        try:
            result = emitter.push_batch(event_count=batch_size)
        except Exception as exc:
            log.warning("wef_runner: push failed for %s: %s", bid, exc)
            msg = str(exc) or type(exc).__name__
            wef_bindings.record_push_result(
                bid, sent=0, status_code=None, error=msg,
            )
            return {"sent": 0, "status_code": None, "ok": False,
                    "error": msg}

        ok = bool(result.get("ok"))
        err = None if ok else (
            f"non-2xx status {result.get('status_code')}"
        )
        wef_bindings.record_push_result(
            bid,
            sent=int(result.get("sent") or 0),
            status_code=result.get("status_code"),
            error=err,
        )
        # Pass the runner-shaped result back (with the synthesised error
        # string) so callers don't need to derive ok-vs-error themselves.
        return {**result, "error": err}

    def reconcile_sync(self) -> None:
        """Sync reconcile cycle.

        Drops cached emitters for bindings that are no longer enabled
        or whose config has changed. Doesn't *create* emitters
        eagerly — :meth:`push_once` does that lazily on first push,
        keeping reconcile cheap and IO-free.
        """
        enabled = {b["id"]: b for b in wef_bindings.list_enabled_bindings()}

        with self._lock:
            stale_bids = [bid for bid in self._emitters if bid not in enabled]
            for bid in stale_bids:
                self._drop_emitter_locked(bid)

            for bid, bnd in enabled.items():
                cfg = bnd.get("config") or {}
                if bid in self._emitters and self._configs.get(bid) != cfg:
                    # Config drifted — drop the cached emitter; the next
                    # push_once will rebuild it against the new config.
                    self._drop_emitter_locked(bid)
                # Stash the latest config so push_once can detect
                # equality at next call too.
                if bid not in self._emitters:
                    self._configs[bid] = cfg

    def stop_all(self) -> None:
        """Tear down every cached emitter. Called by the async
        :meth:`stop` and from process shutdown hooks."""
        with self._lock:
            for bid in list(self._emitters.keys()):
                self._drop_emitter_locked(bid)
            self._configs.clear()

    # ── Internal helpers ─────────────────────────────────────────────

    def _get_or_create_emitter(self, bid: str, cfg: dict[str, Any]) -> Any:
        with self._lock:
            cached = self._emitters.get(bid)
            cached_cfg = self._configs.get(bid)
            if cached is not None and cached_cfg == cfg:
                return cached
            # Either no cached emitter or config drifted under us. Build
            # a fresh one and swap it in.
            if cached is not None:
                self._drop_emitter_locked(bid)
            emitter = self._emitter_factory(cfg, binding_id=bid)
            self._emitters[bid] = emitter
            self._configs[bid] = cfg
            return emitter

    def _drop_emitter_locked(self, bid: str) -> None:
        """Internal: drop emitter *bid* assuming caller holds the lock."""
        em = self._emitters.pop(bid, None)
        self._configs.pop(bid, None)
        if em is not None:
            try:
                em.stop()
            except Exception as exc:                       # pragma: no cover
                log.warning("wef_runner: emitter %s stop() raised: %s",
                            bid, exc)

    # ── Async lifecycle ──────────────────────────────────────────────

    async def start(self) -> None:
        """Start the async supervisor. Idempotent — calling twice is a
        no-op. Safe to invoke from ``app.py``'s startup hook even when
        no bindings exist yet; the supervisor reconciles every tick."""
        if self._supervisor_task is not None and not self._supervisor_task.done():
            return
        self._stopping = False
        self._supervisor_task = asyncio.create_task(
            self._supervise(), name="wef-runner-supervisor",
        )
        log.info("wef_runner: supervisor started")

    async def stop(self) -> None:
        """Cancel every per-binding task + the supervisor, then release
        all cached emitters. Safe to call multiple times."""
        self._stopping = True
        for task in list(self._push_tasks.values()):
            task.cancel()
        self._push_tasks.clear()
        sup = self._supervisor_task
        self._supervisor_task = None
        if sup is not None:
            sup.cancel()
            try:
                await sup
            except (asyncio.CancelledError, Exception):
                pass
        self.stop_all()
        log.info("wef_runner: supervisor stopped")

    async def _supervise(self) -> None:
        """Reconcile loop — wakes every ``RECONCILE_INTERVAL_S`` and
        syncs per-binding push tasks with the enabled set."""
        while not self._stopping:
            try:
                self.reconcile_sync()
                self._sync_push_tasks()
            except Exception:
                log.exception("wef_runner: supervisor reconcile failed")
            try:
                await asyncio.sleep(RECONCILE_INTERVAL_S)
            except asyncio.CancelledError:
                break

    def _sync_push_tasks(self) -> None:
        """Spawn / cancel per-binding asyncio tasks based on the enabled
        set. Called from the supervisor on every tick."""
        enabled_ids = {b["id"] for b in wef_bindings.list_enabled_bindings()}
        # Cancel tasks for vanished bindings.
        for bid in list(self._push_tasks.keys()):
            if bid not in enabled_ids or self._push_tasks[bid].done():
                task = self._push_tasks.pop(bid)
                if not task.done():
                    task.cancel()
        # Spawn tasks for newly-enabled bindings.
        for bid in enabled_ids:
            if bid not in self._push_tasks:
                self._push_tasks[bid] = asyncio.create_task(
                    self._run_binding(bid), name=f"wef-push-{bid}",
                )

    async def _run_binding(self, bid: str) -> None:
        """Per-binding push loop. One emitter, paced by ``rate_per_min``
        + ``jitter_pct``. Runs until cancelled."""
        try:
            while not self._stopping:
                cfg = wef_bindings.effective_config(bid) or {}
                rate = max(int(cfg.get("rate_per_min") or 60), 1)
                jitter_pct = max(0, int(cfg.get("jitter_pct") or 0))
                interval = max(60.0 / rate, MIN_INTERVAL_S)
                if jitter_pct:
                    jitter = random.uniform(
                        -jitter_pct / 100.0, jitter_pct / 100.0,
                    ) * interval
                else:
                    jitter = 0.0
                try:
                    await asyncio.sleep(max(0.0, interval + jitter))
                except asyncio.CancelledError:
                    raise
                # push_once swallows its own exceptions and records
                # status; we just call it and continue.
                self.push_once(bid)
        except asyncio.CancelledError:
            return


# ── Module-level singleton ────────────────────────────────────────────

# app.py's startup hook calls ``await get_runner().start()`` and the
# shutdown hook calls ``await get_runner().stop()``. Tests bypass this
# and construct their own ``WEFRunner`` instance directly.
_runner_singleton: WEFRunner | None = None


def get_runner() -> WEFRunner:
    """Return (creating once) the process-wide runner instance."""
    global _runner_singleton
    if _runner_singleton is None:
        _runner_singleton = WEFRunner()
    return _runner_singleton


__all__ = [
    "WEFRunner",
    "RECONCILE_INTERVAL_S",
    "MIN_INTERVAL_S",
    "get_runner",
]
