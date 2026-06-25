# Asset-binding improvements — plan for next session

> **Status (2026-06-26):** Phases 1–6 ✅ shipped on branch
> `fix/s1-site-scoped-tokens`. Release notes + version bump deferred
> to v5.3 release work (Step 4 of the broader plan).

Source of truth: SentinelOne ai-siem repo,
`plugins/s1-secops-skills/docs/detection-asset-binding.md` (2026-06-14).

## TL;DR of the doc

For a STAR / Custom Detection events-type rule (`queryType=events`,
`queryLang=2.0`) to bind its alert to the **real** Target Asset (and not
show "Unknown Device"), the matched event must carry:

1. An identifier in a `uid` field:
   - `device.uid` for endpoint / cloud assets
   - `user.uid` for identity assets
   - The value must be the **unified asset id** from
     `datasource assets` (the `id` column on the XDR asset record), or
     the **console agent id** for endpoints. NOT a UUID, NOT a SID,
     NOT an objectGUID.
2. A `class_uid` so the pipeline treats the event as asset-bearing.
   - 1007 (Process Activity) for endpoints
   - 3002 (Authentication) for identities
   - 6003 (Web Resources Activity) for cloud resources
   - the value only needs to be PRESENT — S1 resolves the real asset
     category from inventory, the class_uid is just the trigger

Scheduled (PowerQuery) rules don't auto-bind — they need an explicit
`data.entityMappings` array mapping result columns to entities, capped
at 3 columns.

## Status check against the current apigenie codebase

### What we have today

- `s1_assets.py::S1AssetResolver` — already discovers real assets via
  `/web/api/v2.1/xdr/assets`, returns the XDR Asset ID in the `uid`
  field of the resolver hit, filters to managed agents only, caches
  per-batch, exposes diagnostics. **This is the right primitive.**
- `alerts.py::_inject_resource_device` — already stamps the XDR Asset
  ID on `resources[].uid` for the **UAM Alert Interface** path. UAM
  binding works end-to-end (HELIOS reference, usea1-purple
  2026-06-10).

### What's missing

1. **Log push path has zero asset binding** — events go out with
   synthetic UUIDs, no `device.uid` / `user.uid` mapped to real
   inventory, often no `class_uid` either. A customer with STAR rules
   that match apigenie traffic gets "Unknown Device" alerts. Demo
   value of fixing this: very high.

2. **No per-source registry of `class_uid` and asset-kind** — needed
   so the push loop knows what to stamp (Okta events should carry
   `class_uid=3002` and bind on `user.uid`; SentinelOne native events
   `class_uid=1007` and `device.uid`; AWS CloudTrail `class_uid=6003`
   and `device.uid`).

3. **No identity asset binding** — `S1AssetResolver` only walks
   `/web/api/v2.1/xdr/assets`. To bind identity events, we'd need to
   also query `/web/api/v2.1/active-directory/accounts` (caveat: this
   endpoint returned 404 on the POC tenant during the v2.2 work, see
   `alerts.py:510-512`). Worth probing on a tenant with Identity
   deployed.

4. **No template lint for `class_uid`** — UAM Alert Interface
   templates in `data/alert_templates/` could ship without a
   `class_uid` and bind would silently fall back to "Unknown Device".
   A load-time lint + a unit test that walks every template catches
   this regression.

5. **No diagnostics for push-side binding** — the resolver has
   counters and trace already, but they're only surfaced on the alert
   send path. Push-loop usage would need to plumb them into the
   `/admin/api/push/<id>/status` response so the operator sees "12
   events stamped, 3 misses".

## Implementation plan (when resumed)

Six phases, in order:

### Phase 1 — Per-source asset-binding registry

`sources/__init__.py` gains a fallback table and a
`get_asset_binding(source: str) -> dict | None` helper. Each entry:

```python
{
    "kind":      "endpoint" | "identity" | "cloud" | "none",
    "class_uid": int,  # OCSF class (1007 / 3002 / 6003 / 4001 / ...)
}
```

Per-source defaults (proposed mapping):

| Source            | Kind     | class_uid | Notes |
|-------------------|----------|-----------|-------|
| okta              | identity | 3002 | Authentication |
| azure_ad          | identity | 3002 | Entra ID auth |
| cisco_duo         | identity | 3002 | MFA |
| m365              | identity | 3002 | Workload audit (mostly user-shaped) |
| aws_cloudtrail    | cloud    | 6003 | IAM + service events |
| aws_guardduty     | cloud    | 6003 | finding-shaped |
| aws_waf           | cloud    | 6003 | WAFv2 alerts |
| azure_platform    | cloud    | 6003 | Activity Log |
| gcp_audit         | cloud    | 6003 | Cloud Audit Logs |
| sentinelone       | endpoint | 1007 | self — Process Activity |
| microsoft_defender| endpoint | 1007 | EDR alerts |
| cato              | network  | 4001 | (kind: cloud, class 4001) |
| cloudflare        | network  | 4002 | HTTP Activity |
| darktrace         | network  | 4001 | model breaches |
| mimecast          | network  | 4002 | email/HTTP |
| netskope          | network  | 4002 | CASB/SSE |
| proofpoint        | network  | 4002 | TAP |
| zscaler_zpa       | network  | 4002 | ZPA logs |
| snyk              | none     | 0    | governance, no asset target |
| tenable           | none     | 0    | governance, no asset target |
| wiz               | none     | 0    | governance, no asset target |

(For network-shaped sources, `kind="cloud"` and we bind on
`device.uid` of the network appliance / proxy if discoverable, else
fall through to `none`.)

A source module CAN override the registry by declaring its own
module-level `ASSET_BINDING = {...}`. Lazy discovery walks
`sources/*.py` first and falls back to the table.

### Phase 2 — Extend `S1AssetResolver`

New methods (push-side picks — different shape from the alert-side
`resolve_endpoint(name_hint)` which is name-driven):

- `random_endpoint() -> dict | None` — picks a random managed agent
  from the asset list. The whole point of push binding is that we
  don't have a name to look up; we're injecting noise and want it to
  appear on SOMEONE's device.
- `random_identity() -> dict | None` — same, but queries
  `/web/api/v2.1/active-directory/accounts` (with a feature-flag
  fallback when the endpoint 404s, like it did on the POC tenant in
  v2.2 testing).

Both return the unified asset id in the `uid` slot, matching the
existing `resolve_endpoint` hit shape.

Caches the inventory list across calls within the same resolver
instance (already true for `_all_assets`). Random picks SHOULD be
biased by `lastActiveAt` to prefer recently-seen assets, so push
events bind to assets that are actually alive in the tenant.

### Phase 3 — Hook resolver into `log_pusher`

In `_load_source_module` flow at `log_pusher.py:639-693`, after
`event = mod.generate_event(ctx=ctx)`:

```python
binding = sources.get_asset_binding(source_type)
if binding and binding["kind"] != "none" and resolver is not None:
    hit = (resolver.random_identity() if binding["kind"] == "identity"
           else resolver.random_endpoint())
    if hit:
        event["class_uid"] = binding["class_uid"]
        target_field = "user" if binding["kind"] == "identity" else "device"
        event.setdefault(target_field, {})["uid"] = hit["uid"]
```

Resolver is built once per push profile (like on the alert send path)
when the operator opts in via a new profile flag `link_xdr_assets` —
mirrors the existing alert-side flag.

Diagnostic counters bumped on every stamp; surfaced in the push status
response.

### Phase 4 — Template lint for `class_uid`

`alerts.py::prepare_alert` warns (via `log.warning`) when the loaded
template carries no `class_uid` or it's 0 — this would silently bind
the alert as "Unknown Device" even with a perfect resources[].uid.

Unit test `tests/test_template_class_uid_coverage.py` walks
`data/alert_templates/` and asserts every template carries a
non-zero `class_uid`.

### Phase 5 — Diagnostics

Wire resolver counters into:
- `GET /admin/api/push/profiles/<id>/status` response (push-side)
- `GET /admin/api/asset-resolver/last-trace` (top-level diag, like
  the alert-side `resolver_status` block returned by
  `/admin/api/alerts/profiles/<id>/send`)

### Phase 6 — Docs + version bump

- RELEASE_NOTES.md → v5.3 section
- README.md → mention asset-binding on push
- pyproject.toml → 5.3.0
- USER_GUIDE / ADMIN_GUIDE → "Linking apigenie events to real assets"

## Open questions for the user (next session)

- Is `/web/api/v2.1/active-directory/accounts` reachable on the
  current S1 POC? (Was 404 during v2.2 work — may need a Phase 4
  fallback to skip identity binding cleanly.)
- Random-pick vs. round-robin: do we want each push profile to bind
  to ONE asset for the full session (more demo-realistic — "this
  laptop is under attack") or fan out across many (more noise-like)?
- Profile-level flag name: `link_xdr_assets` for symmetry with the
  alert-side, or `bind_real_assets` for clarity?

---

## Implementation outcome (2026-06-26)

Six phases delivered on branch `fix/s1-site-scoped-tokens`. **39 new
tests, 0 regressions** across the 647-test fast lane.

### Decisions on the open questions

- **Identity endpoint 404 fallback.** `S1AssetResolver.random_identity()`
  catches `httpx.HTTPStatusError` with `status_code == 404` and caches
  the result as "feature unavailable" — every subsequent call returns
  `None` without hitting the network. Push binding for identity-shaped
  sources (okta / azure_ad / m365 / cisco_duo) falls through cleanly to
  the no-op atomic path — events ship unbound, no class_uid stamped.
- **Sticky pick semantics.** `S1AssetResolver.sticky_pick(kind, ratio=0.8)`
  picks the same "primary" asset 80% of the time and a random alternate
  20% of the time. This makes a push profile look like one laptop /
  user under attack with occasional lateral-movement noise — the
  demo-realistic shape — rather than uniformly random fan-out.
- **Profile flag name.** Kept `link_xdr_assets` for symmetry with the
  alert-side flag of the same name. The UI checkbox is wired into
  the push-profile modal in `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/admin.py:1456-1468`.

### Files touched (high-signal pointers)

| Layer | File / function |
|-------|-----------------|
| Per-source registry | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/sources/__init__.py:127-215` — `ASSET_BINDING` table + `get_asset_binding()` |
| Resolver picks | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/s1_assets.py:377-627` — `random_endpoint`, `random_identity`, `sticky_pick` |
| Splice + resolver lifecycle | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/log_pusher.py:586-647` — `apply_asset_binding()` + `_build_push_resolver()` |
| Push loop integration | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/log_pusher.py:817-885` — splice call inside the loop, resolver closed in `finally:` |
| `class_uid` lint | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/alerts.py:700-716` — `log.warning` when missing/zero |
| Status diagnostics | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/log_pusher.py:947-997` — `get_status()` extended with `binding` block |
| UI — toggle | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/admin.py:1456-1468` (modal) + `:6028, 6044, 6115` (load/save) |
| UI — pill + diag strip | `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/admin.py:5850-5856` + `:6166-6188` |

### Test suites (all under `tests/`)

- `test_asset_binding_registry.py` — 4 tests for the per-source registry
- `test_s1_assets_random_picks.py` — 11 tests for `random_endpoint` /
  `random_identity` / `sticky_pick` (including the 404 identity
  fallback and the bias-toward-recent endpoint weighting)
- `test_log_pusher_asset_binding.py` — 10 tests for the splice
  (no-op cases, idempotency, identity vs device targeting)
- `test_alert_template_class_uid_coverage.py` — 4 tests (72-template
  scan + 3 lint behaviours on `prepare_alert`)
- `test_log_pusher_binding_diagnostics.py` — 4 tests for the
  `binding` block on `get_status()` + counter reset semantics

### What's deferred to v5.3 release (Step 4)

- `RELEASE_NOTES.md` v5.3 section
- `README.md` mention of asset binding on push
- `pyproject.toml` version bump 5.0.0 → 5.3.0
- `USER_GUIDE` / `ADMIN_GUIDE` operator-facing how-to ("Linking
  apigenie events to real assets")
