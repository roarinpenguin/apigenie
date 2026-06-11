# Event Mix — admin guide

Every simulated source under `sources/` ships with a set of event types it
can emit (an authentication success, a failure, a fraud-marked attempt, an
admin policy update, …) and a set of **default weights** that pick which
type fires on any given request. The **Event Mix** system lets an admin
re-weight those choices — or disable certain event types entirely — without
editing source code.

This guide covers:

- The mental model and where Event Mix sits next to Profiles, Bindings, and
  Detection Rules.
- The admin UI (the disclosure card on each binding).
- The REST surface that the UI consumes (useful for scripted onboarding).
- How a source opts into the system (the `EVENT_CATALOG` contract).
- RBAC: who can edit what.

---

## Where Event Mix sits

```
┌─────────────────────────────────────────────────────────────────────┐
│  Source ↔ Profile binding (existing)                                │
│  ── tells the source WHICH random data to use ──                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Event Mix (this feature)                                   │   │
│  │  ── tells the source WHICH event types to pick from ──       │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

A Log Profile decides *who* the synthetic users / machines / C2 servers
are. The Event Mix decides *what* the source talks about — success vs
failure vs fraud, admin login vs user create vs policy update, etc. Both
live on the **Source Bindings** card; the Event Mix appears as a
disclosure (collapsed by default) under the existing ratio + volume
controls.

---

## The admin UI

Every source that has opted into the system shows an `▸ Event mix (N
types)` button at the bottom of its binding card. Click to expand:

```
┌─ cisco_duo  ─────────────────────  [Save] [Unbind] ──┐
│  Profile: [my-prod-prof ▾]  ratio ▮▮▮▮▮▮▯  70%        │
│  Log volume ▮▮▮▮▯  50% (~50 logs/req)                 │
│  ─────────────────────────────────────────────────    │
│  ▾ Event mix (9 types)   [Save mix] [Reset]           │
│    9 event types · using defaults                     │
│   ☑ Authentication success     ▮▮▮▮▮▮▮▯▯▯  70%        │
│   ☑ Authentication failure     ▮▮▮▯▯▯▯▯▯▯  15%        │
│   ☐ Marked fraud by user       ▯▯▯▯▯▯▯▯▯▯   0%        │
│   ☑ Authentication error       ▮▯▯▯▯▯▯▯▯▯   5%        │
│   ☑ Administrator logged in    ▮▮▮▮▯▯▯▯▯▯  40%        │
│   ...                                                  │
│   Weights are renormalised at request time —          │
│   sliders set relative proportions.                   │
└────────────────────────────────────────────────────────┘
```

Three things to know about the UI:

1. **Sliders are relative, not absolute.** A row showing 70% doesn't mean
   "70% of requests" — it means "weight 0.70". The resolver renormalises
   so the enabled weights sum to 1.0 at runtime. If you halve every
   slider, the distribution is unchanged. This matters when you want to
   nudge one event up without redoing the maths for all the others.
2. **Disabled events never fire.** A cleared checkbox removes that event
   from the pool entirely — the source can't emit it until you re-enable
   it. If every event is disabled the resolver falls back to defaults
   (otherwise the source would silently return nothing).
3. **Save is per-source.** Each card has its own Save button. Changes are
   atomic — the resolver picks them up on the next request.

The disclosure remembers its state per page render — re-opening a section
you just collapsed is instant. **Save** automatically refreshes the
catalogue so the "custom mix active" pill updates without a manual reload.

---

## REST surface

The UI is built on five endpoints. They follow the same RBAC and
ownership semantics as `/admin/api/source-profiles/*` — admin without
acting-as writes the global mix; users (or admins acting-as a user) write
a private override that shadows the global for them only.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/api/event-mix/sources` | List source ids that have an `EVENT_CATALOG`. Used by the UI to decide whether to render the disclosure on a card. |
| GET | `/admin/api/sources/{source}/event-catalog` | Return the source's catalog enriched with each entry's effective `enabled` + `weight`. Includes `has_override` + `own` flags so the UI can colour the pill correctly. `404` if the source isn't mix-aware. |
| GET | `/admin/api/source-event-mix` | List all mixes visible to the caller. Admin → global only; user → own overlaid on global with `own: false` for inherited entries. |
| PUT | `/admin/api/source-event-mix/{source}` | Persist a mix override. Body: `{"mix": [{"event_id", "enabled", "weight"}, ...]}`. `404` if the source isn't mix-aware; `400` if the body lacks `mix`. |
| DELETE | `/admin/api/source-event-mix/{source}` | Drop the caller's mix; falls back to inherited global or to source defaults. `404` if no record. |

### Example: pin cisco_duo to 90% failures

```bash
curl -sk -b /tmp/admin.jar \
  -X PUT https://apigenie.example.com/admin/api/source-event-mix/cisco_duo \
  -H 'content-type: application/json' \
  -d '{"mix": [
    {"event_id": "auth.success", "enabled": true,  "weight": 0.10},
    {"event_id": "auth.failure", "enabled": true,  "weight": 0.90},
    {"event_id": "auth.fraud",   "enabled": false, "weight": 0.0},
    {"event_id": "auth.error",   "enabled": false, "weight": 0.0}
  ]}'
```

After this, the next 1000 requests against
`/admin/v1/logs/authentication` will land roughly 100 successes and 900
failures (±5% of empirical noise; see
`test_apply_actually_moves_the_empirical_distribution` in
`tests/test_event_mix.py`).

### Reset to defaults

```bash
curl -sk -b /tmp/admin.jar -X DELETE \
  https://apigenie.example.com/admin/api/source-event-mix/cisco_duo
```

---

## How a source opts in

A source becomes mix-aware by declaring one extra module-level constant
in `sources/<vendor>.py`:

```python
EVENT_CATALOG: list[dict[str, Any]] = [
    {"id": "auth.success",
     "label": "Authentication success",
     "endpoint": "authentication",
     "default_weight": 0.70,
     "docs_anchor": "duo.com/docs/adminapi#authentication-logs"},
    ...
]
```

Each entry needs:

- `id` — stable identifier matching the keys in the source's internal
  `_AUTH_TEMPLATES` / `_ADMIN_TEMPLATES` / etc. dicts. The resolver looks
  up overrides by this id, so renaming a key without renaming the
  catalogue entry silently disables that event.
- `label` — human-readable name shown in the UI.
- `default_weight` — float in `[0, 1]`. The defaults should reflect a
  realistic vendor distribution; admins tweak from there.
- `docs_anchor` — link to the vendor's docs for that endpoint family,
  used in the UI tooltip.

The source then threads `event_mix.apply()` through every
`weighted_choice` call:

```python
def _make_auth_log(...):
    template = weighted_choice(event_mix.apply(_AUTH_TEMPLATES, "cisco_duo"))
    ...
```

`apply()` returns the input dict unchanged when no override is configured,
so wiring a source up is **zero-cost** when no admin has touched it.

### Pilot sources

| Source | Status | Notes |
|--------|--------|-------|
| `cisco_duo` | **wired** | 9 event types across `/admin/v1/logs/authentication` and `/admin/v1/logs/administrator`. |
| Everyone else | pending | 13 other sources still hard-code their weights; subsequent commits will add `EVENT_CATALOG` per vendor (`okta`, `proofpoint`, `aws_*`, `azure_ad`, `microsoft_defender`, …). |

---

## RBAC

Event Mix uses the existing `source_bindings` entitlement category — a
user with `source_bindings:modify` automatically gets event-mix
management, matching the mental model *"I can shape what this source
sends to my collector."*

| Action | Required permission |
|--------|---------------------|
| List / view catalogue | session valid (no extra perm) |
| PUT mix | `source_bindings: create + modify` |
| DELETE mix | `source_bindings: delete + modify` |

Ownership rules mirror Source Bindings:

- **Built-in admin** (no acting-as) writes the global mix.
- **Real user** (or admin acting-as a user) writes a private override
  that only shadows the global mix for that user. Other users keep
  seeing the global.
- A user's `DELETE` removes only their own record; the global stays.

---

## Storage

| Item | Path |
|------|------|
| All mixes (global + per-user) | `$APIGENIE_DATA_ROOT/source_event_mix.json` |

File format (illustrative):

```json
{
  "cisco_duo": {
    "source": "cisco_duo",
    "owner_id": null,
    "mix": [
      {"event_id": "auth.success", "enabled": true,  "weight": 0.7},
      {"event_id": "auth.fraud",   "enabled": false, "weight": 0.0}
    ]
  },
  "cisco_duo::u::u-alice": {
    "source": "cisco_duo",
    "owner_id": "u-alice",
    "mix": [...]
  }
}
```

Keys: bare `{source}` for the global record; `{source}::u::{user_id}` for
per-user overrides. The resolver picks the right one at request time via
`get_mix(source, user_id)`.

---

## Test coverage

| Suite | File | What it covers |
|-------|------|----------------|
| Core resolver | `tests/test_event_mix.py` | Storage CRUD, per-user override shadowing, `apply()` math, empirical distribution at 2000 samples, `merge_catalog_with_mix`. |
| Admin REST | `tests/test_event_mix_admin.py` | Source registry, all five endpoints, 401/404/400 paths, persistence round-trip. |
