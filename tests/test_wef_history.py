"""WEF v5.2 — Phase F: per-binding & global push history ring buffer.

The pre-F status block (`last_push_at`, `last_status_code`, `last_error`,
`sent_total`) gives the operator one snapshot per binding. Phase F adds a
bounded in-memory **history** ring so the admin UI can render a
chronological "Recent activity" feed — the same UX the alert-push module
ships in `_alertHistoryEntryHtml` / `get_history("_global")`.

Storage shape mirrors `alert_push._history`:

* per-binding deque keyed by binding id, bounded to `_HISTORY_MAX`
* synthetic `"_global"` key for the cross-binding feed
* entries are plain dicts with `ts` / `ok` / `sent` / `status_code` /
  `error` / `binding_id` / `binding_name` so the global feed knows which
  binding produced each row without a second lookup

The runner's existing `push_once` is the only writer (it already records
into the persistent `wef_bindings.record_push_result` snapshot — Phase F
adds a parallel `wef_runner.record_push` call along the same paths so
*every* outcome lands in both surfaces).
"""
from __future__ import annotations

import time

import pytest


# Re-use the test doubles from the runner suite so behaviour stays
# consistent between the two files.
from test_wef_runner import FakeEmitter, FailingFactoryEmitter, _make_binding


@pytest.fixture(autouse=True)
def _clear_history():
    """Per-test reset of the in-memory ring \u2014 the runner module is a
    singleton across tests in the same process, so without this every
    `_global` assertion would inherit entries from earlier tests."""
    import wef_runner
    wef_runner.clear_history()
    yield
    wef_runner.clear_history()


# ── Ring-buffer primitives ────────────────────────────────────────────

def test_get_history_empty_by_default():
    """A fresh module exposes an empty global feed."""
    import wef_runner
    assert wef_runner.get_history() == []
    assert wef_runner.get_history("any-bid") == []


def test_record_push_appends_to_per_binding_and_global_rings():
    """A single record lands on both the binding-keyed ring and the
    synthetic _global ring so the per-binding pane and the cross-binding
    feed both see it without a second write."""
    import wef_runner
    wef_runner.record_push(
        "bid-A",
        ok=True, sent=10, status_code=200, error=None,
        binding_name="Prod WEC",
    )
    per_bid = wef_runner.get_history("bid-A")
    glob = wef_runner.get_history()  # default "_global"
    assert len(per_bid) == 1
    assert len(glob) == 1
    entry = per_bid[0]
    assert entry["binding_id"] == "bid-A"
    assert entry["binding_name"] == "Prod WEC"
    assert entry["ok"] is True
    assert entry["sent"] == 10
    assert entry["status_code"] == 200
    assert entry["error"] is None
    assert "ts" in entry  # ISO timestamp surfaced at record time


def test_get_history_is_newest_first():
    """The UI lists newest at the top \u2014 deque.appendleft semantics."""
    import wef_runner
    for i in range(3):
        wef_runner.record_push("bid-A", ok=True, sent=i, status_code=200)
        time.sleep(0.001)  # ensure monotonic timestamps for the assertion
    h = wef_runner.get_history("bid-A")
    # Newest first \u2014 the last record we wrote (sent=2) comes first.
    assert [e["sent"] for e in h] == [2, 1, 0]


def test_history_ring_is_bounded():
    """The deque caps at _HISTORY_MAX so a long-running binding can't
    blow the heap. Older entries get evicted FIFO."""
    import wef_runner
    cap = wef_runner._HISTORY_MAX
    for i in range(cap + 5):
        wef_runner.record_push("bid-A", ok=True, sent=i, status_code=200)
    h = wef_runner.get_history("bid-A", limit=cap + 10)
    assert len(h) == cap
    # The 5 oldest (sent=0..4) must have been evicted.
    sents = {e["sent"] for e in h}
    assert 0 not in sents and 4 not in sents
    # The newest 5 (sent=cap..cap+4) must be present.
    assert (cap + 4) in sents


def test_global_feed_aggregates_across_bindings():
    """`_global` carries every record regardless of which binding emitted
    it \u2014 the cross-binding "Recent activity" feed."""
    import wef_runner
    wef_runner.record_push("bid-A", ok=True, sent=1, status_code=200,
                           binding_name="A")
    wef_runner.record_push("bid-B", ok=False, sent=0, status_code=503,
                           error="WEC unreachable", binding_name="B")
    glob = wef_runner.get_history()
    assert {e["binding_id"] for e in glob} == {"bid-A", "bid-B"}
    # Newest-first: B was recorded second so it leads.
    assert glob[0]["binding_id"] == "bid-B"
    assert glob[0]["error"] == "WEC unreachable"


def test_clear_history_with_no_arg_wipes_every_ring():
    """`clear_history()` is the test-fixture knob \u2014 nukes per-binding
    deques AND the global ring."""
    import wef_runner
    wef_runner.record_push("bid-A", ok=True, sent=1, status_code=200)
    wef_runner.record_push("bid-B", ok=True, sent=1, status_code=200)
    wef_runner.clear_history()
    assert wef_runner.get_history() == []
    assert wef_runner.get_history("bid-A") == []
    assert wef_runner.get_history("bid-B") == []


def test_clear_history_per_binding_keeps_others_intact():
    """Per-binding clear drops just that binding's ring AND its matching
    rows from `_global` so the cross-binding feed stays consistent."""
    import wef_runner
    wef_runner.record_push("bid-A", ok=True, sent=1, status_code=200)
    wef_runner.record_push("bid-B", ok=True, sent=1, status_code=200)
    wef_runner.clear_history("bid-A")
    assert wef_runner.get_history("bid-A") == []
    assert len(wef_runner.get_history("bid-B")) == 1
    glob = wef_runner.get_history()
    assert {e["binding_id"] for e in glob} == {"bid-B"}


def test_get_history_respects_limit():
    """`limit` clamps the returned slice \u2014 used by the API endpoint to
    avoid shipping all 50 entries when the UI only renders 20."""
    import wef_runner
    for i in range(10):
        wef_runner.record_push("bid-A", ok=True, sent=i, status_code=200)
    assert len(wef_runner.get_history("bid-A", limit=3)) == 3
    assert len(wef_runner.get_history("bid-A", limit=0)) == 0


# ── push_once hook \u2014 the runner writes one entry per outcome ────────

def test_push_once_records_history_on_success():
    """The happy path: a 2xx push lands on both the persistent status
    block AND the new history ring."""
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once(bnd["id"])
    h = wef_runner.get_history(bnd["id"])
    assert len(h) == 1
    assert h[0]["ok"] is True
    assert h[0]["sent"] == 5  # FakeEmitter's pre-canned result
    assert h[0]["status_code"] == 200
    assert h[0]["binding_id"] == bnd["id"]
    assert h[0]["binding_name"] == bnd["name"]


def test_push_once_records_history_on_emitter_exception():
    """Wire-level failures must still record \u2014 they're the entries the
    operator most wants to see in the activity panel."""
    import wef_runner

    class Boom(FakeEmitter):
        def push_batch(self, events=None, event_count=None):
            raise RuntimeError("connection refused")

    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=Boom)
    runner.push_once(bnd["id"])
    h = wef_runner.get_history(bnd["id"])
    assert len(h) == 1
    assert h[0]["ok"] is False
    assert h[0]["sent"] == 0
    assert "connection refused" in (h[0]["error"] or "")


def test_push_once_records_history_on_binding_config_error():
    """An emitter factory that refuses to build (bad cert, missing
    creds) is also a recorded outcome \u2014 same path as the persistent
    `last_error` write."""
    import wef_runner
    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=FailingFactoryEmitter)
    runner.push_once(bnd["id"])
    h = wef_runner.get_history(bnd["id"])
    assert len(h) == 1
    assert h[0]["ok"] is False
    assert "simulated bad cert" in (h[0]["error"] or "")


def test_push_once_records_non_2xx_as_history_failure():
    """A 5xx from the WEC is recorded as a failure, mirroring how
    `record_push_result` builds the persistent last_error string."""
    import wef_runner

    class Bad(FakeEmitter):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.next_result = {"sent": 0, "status_code": 503, "ok": False}

    bnd = _make_binding()
    runner = wef_runner.WEFRunner(emitter_factory=Bad)
    runner.push_once(bnd["id"])
    h = wef_runner.get_history(bnd["id"])
    assert len(h) == 1
    assert h[0]["ok"] is False
    assert h[0]["status_code"] == 503
    assert "503" in (h[0]["error"] or "")


def test_push_once_no_history_when_binding_missing():
    """Pushing against a deleted binding returns the standard
    "not found" miss but writes NOTHING to history \u2014 the binding
    is gone, the operator has no row to attach the entry to, and the
    status block writer (`record_push_result`) skips the same path."""
    import wef_runner
    runner = wef_runner.WEFRunner(emitter_factory=FakeEmitter)
    runner.push_once("does-not-exist")
    assert wef_runner.get_history("does-not-exist") == []
    assert wef_runner.get_history() == []
