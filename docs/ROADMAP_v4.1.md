# ApiGenie v4.1 — Roadmap

Two features, shipping in this order:

1. **Phase 5** — Selectable event mix per source (accuracy).
2. **Phase 6** — Webhook composer (outbound HTTP with Log-Profile-templated body).

Both are additive (no breaking changes to existing profiles, bindings, sources,
or alert templates). Target branch: `feat/v4.1-webhooks-and-event-mix` off
current `feat/v4.0-alert-push`.

---

## Phase 5 — Selectable event mix per source

### Goals

- Every simulated source exposes its **real** event-type catalog (sourced
  from the vendor's official API docs), not just the subset we happen to
  emit today.
- Admin (and per-user, like profiles) can:
  - Toggle each event type on/off.
  - Adjust its weight as a percentage of the mix.
- Catalogs are anchored to the vendor's published docs so we can refresh
  when a vendor adds new event types.

### Step 5.0 — Source inventory & docs anchors

Twenty-one simulated vendors. For each: harvest the vendor's official
event catalog, diff against the current `_EVENT_TEMPLATES` in the source
file, and persist as `docs/sources/<vendor>.md` (event id, label,
default weight, gap flag).

| Source file | Vendor doc reference |
| --- | --- |
| `aws_cloudtrail.py` | CloudTrail `LookupEvents` + event source catalog |
| `aws_guardduty.py` | GuardDuty Findings type matrix |
| `aws_waf.py` | WAFv2 logging format |
| `azure_ad.py` | MS Graph audit + signin schemas |
| `cato.py` | Cato Events Feed (GraphQL) |
| `cisco_duo.py` | Duo Admin API `/admin/v1/logs/*` |
| `cloudflare.py` | Cloudflare Logpush datasets + Audit Logs |
| `darktrace.py` | Darktrace REST `/modelbreaches`, `/aianalyst/incidentevents` |
| `gcp_audit.py` | Cloud Audit Logs (activity / system / data-access) |
| `m365.py` | M365 Management Activity API + Audit Schemas |
| `microsoft_defender.py` | Defender XDR `alertsAndIncidents` schema |
| `mimecast.py` | Mimecast API 1.0 SIEM endpoints (registry already exists) |
| `netskope.py` | Netskope v2 event endpoints (alert/application/audit/...) |
| `okta.py` | System Log API event-type catalog |
| `proofpoint.py` | TAP SIEM API endpoints |
| `sentinelone.py` | S1 Mgmt API v2.1 (already broad — calibrate, don't expand) |
| `snyk.py` | Snyk Audit Logs + Issues |
| `tenable.py` | T.io API audit log + vuln events |
| `wiz.py` | Wiz GraphQL `issuesV2`, `auditLogEntries` |
| `zscaler_zpa.py` | ZPA Log Streaming Service fields catalog |

### Step 5.1 — Architecture

**A. Promote per-source catalogs to first-class metadata** in each
`sources/<vendor>.py`:

```python
EVENT_CATALOG = [
    {"id": "auth.success",
     "label": "Successful authentication",
     "default_weight": 0.70,
     "docs_anchor": "duo.com/docs/adminapi#authentication-logs",
     "category": "authentication"},
    ...
]
```

**B. Source registry interface** (`sources/__init__.py`):

```python
class SourceModule(Protocol):
    EVENT_CATALOG: list[dict]
    def generate_event(event_id: str,
                       ctx: profiles.ProfileContext | None) -> dict: ...
```

**C. New `event_mix.py` module** — mirrors `profiles.py`'s storage and
RBAC pattern exactly:

- File: `DATA_ROOT/source_event_mix.json`.
- Keys: `{source}` (global) or `{source}::u::{user_id}` (per-user
  override — same scheme as bindings).
- Value:
  ```json
  {"mix": [{"event_id": "...", "enabled": true, "weight": 0.7}, ...]}
  ```
- Public API: `get_effective_mix(source, user_id)`,
  `set_mix(source, mix, owner_id)`, `reset_mix(...)`,
  `list_mixes_for_user(...)`.

**D. Resolver shim.** Each source's `weighted_choice(_EVENT_TEMPLATES)`
becomes
`weighted_choice(event_mix.filter_and_reweight(_EVENT_TEMPLATES, "cisco_duo", current_user))`.
The filter drops disabled `event_id`s, replaces default weights with
overrides, and re-normalises so weights still sum to 1.0 after disables.

### Step 5.2 — Admin UI

New collapsible card per source in the existing Profiles tab, under the
binding row (so admins see mix + ratio + intensity together):

```
┌─ cisco_duo  ─────────────────────  [defaults] [save] ─┐
│ ☑ auth.success           ▮▮▮▮▮▮▮▯▯▯  70%              │
│ ☑ auth.failure           ▮▮▮▯▯▯▯▯▯▯  20%              │
│ ☐ auth.fraud_marked      ▯▯▯▯▯▯▯▯▯▯   0%              │
│ ☑ admin.policy_edit      ▮▯▯▯▯▯▯▯▯▯  10%              │
│  Coverage: 12 / 18 events   📄 Duo Admin API docs     │
└───────────────────────────────────────────────────────┘
```

**Endpoints** (mirror `source-profiles`):

- `GET /admin/api/sources/{source}/event-catalog`
- `GET /admin/api/source-event-mix` (all)
- `PUT /admin/api/source-event-mix/{source}` — body `{mix: [...]}`
- `DELETE /admin/api/source-event-mix/{source}` — revert to defaults

### Step 5.3 — Tests

- **Catalog:** every source declares non-empty `EVENT_CATALOG`; default
  weights sum to ≈ 1.0.
- **Resolver:** disabled events never emitted at scale (N = 10k sample);
  enabled ratios honoured within ±2%.
- **Per-user override:** user mix shadows global mix; falls back when
  absent (matches the binding model).
- **RBAC:** new capability `event_mix` (verbs: `list / edit / delete`).
  Non-owner cannot write.
- **Coverage matrix:** `tests/test_event_catalog_coverage.py` parses
  each `docs/sources/<vendor>.md` and asserts the declared list
  contains the `EVENT_CATALOG` ids — so a doc update without a code
  update fails CI.

### Stretch

- "Preview distribution" button → generate 1k events with the current
  mix, render a mini histogram in the admin pane.
- Detection-rule injection (`detection_rules.inject_detection_events`)
  gets its own weight knob (today it's force-injected).

---

## Phase 6 — Webhook composer (outbound)

### Goals

- Graphical composer for HTTP requests: URL, method, auth, headers,
  query params, body.
- Body templated with variables from Log Profiles (`{{profile.user.email}}`,
  `{{profile.machine.ip}}`, `{{profile.c2.fqdn}}`, etc.).
- Send button fires the request; full response (status, headers, body,
  effective request) rendered in a lower pane.

### Data model — `webhooks.py` (new)

JSON-per-id under `DATA_ROOT/webhooks/<id>.json`, mirroring the profile
storage idiom:

```json
{
  "id": "wh-...", "name": "Pipedream demo", "owner_id": "u-...",
  "visibility": "private",
  "url": "https://eok...m.pipedream.net/hook",
  "method": "POST",
  "auth": {"type": "none|basic|bearer|custom",
           "username": "...", "password": "...",
           "token_prefix": "Bearer", "token_value": "..."},
  "headers": [{"key": "X-Trace", "value": "{{profile.user.username}}"}],
  "query":   [{"key": "src", "value": "apigenie"}],
  "body_template": "{ \"user\": \"{{profile.user.email}}\", \"alert\": \"{{custom.title}}\" }",
  "body_format": "json|form|raw",
  "profile_id": "p-...",
  "created_at": "...", "updated_at": "..."
}
```

### Template variables

Decision deferred (regex `{{...}}` resolver vs Jinja2 sandboxed). In both
cases, the variable surface is:

| Variable | Source |
| --- | --- |
| `{{profile.user.<field>}}` | Random user from bound profile |
| `{{profile.machine.<field>}}` | Random machine |
| `{{profile.c2.<field>}}` | Random C2 server |
| `{{profile.malware.<field>}}` | Random malware sample |
| `{{profile.mail_sender.<field>}}` | Random mail sender |
| `{{custom.<key>}}` | Per-send values from the modal's "custom variables" pane |
| `{{now}}` / `{{epoch_ms}}` / `{{uuid}}` | Convenience helpers |
| `{{env.<KEY>}}` | Allowlisted env vars only |

Missing vars render as `{{?profile.user.foo}}` markers so the user sees
the gap rather than a silent empty string.

### Send pipeline

```python
def send_webhook(wh, custom_vars=None) -> SendResult:
    ctx = WebhookRenderContext(
        profile=profiles.get_profile(wh.profile_id) if wh.profile_id else None,
        custom=custom_vars or {},
    )
    url     = render(wh.url, ctx) + build_query(wh.query, ctx)
    headers = {k: render(v, ctx) for k, v in build_headers(wh, ctx).items()}
    body    = render(wh.body_template, ctx) if wh.method in ("POST", "PUT", "PATCH") else None
    if wh.body_format == "json":
        body = json.dumps(json.loads(body), separators=(",", ":"))
        headers.setdefault("Content-Type", "application/json")
    r = httpx.request(wh.method, url, headers=headers, content=body, timeout=10.0)
    return SendResult(
        status=r.status_code,
        elapsed_ms=int(r.elapsed.total_seconds() * 1000),
        response_headers=dict(r.headers),
        response_body=r.text[:64_000],
        effective_request={"url": url, "method": wh.method,
                           "headers": redact(headers), "body": body},
    )
```

### Admin UI

New top-level tab **"Webhooks"** next to Profiles and Alert Push.

- **Left rail:** list of saved webhooks (name + method badge + URL preview).
- **Center editor**, collapsible sections:
  1. URL + method dropdown.
  2. Auth — radio (none / basic / bearer / custom prefix+value); fields appear contextually.
  3. Headers — key/value rows with `+` / `×`; values support `{{vars}}` with hover preview.
  4. Query params — same shape.
  5. Body — textarea (monospace) + `Format JSON` + `Validate JSON` + line numbers.
  6. **Bound profile** dropdown + **"Insert variable"** combobox that injects `{{profile.user.email}}` into the focused field.
- **Bottom response pane** (collapsed until first send):
  - Status line with colour-coded badge (2xx green / 3xx blue / 4xx orange / 5xx red) + elapsed ms.
  - Tabs: **Response body** | **Response headers** | **Effective request** (post-render).
  - **Copy as curl** button (built from `effective_request`).

**API:**

- `GET /admin/api/webhooks` — list visible.
- `POST /admin/api/webhooks` — create.
- `GET|PUT|DELETE /admin/api/webhooks/{id}` — CRUD.
- `POST /admin/api/webhooks/{id}/send` — body `{custom_vars: {...}, override_url?: "..."}`.
- `POST /admin/api/webhooks/{id}/clone` — clone (mirrors profile clone).

### Security & guardrails

- **Egress allowlist** (env var `APIGENIE_WEBHOOK_ALLOWED_HOSTS`):
  CIDRs + domains. RFC1918, link-local, loopback, IMDS
  (`169.254.169.254`) **blocked by default** to prevent SSRF against
  neighbouring containers.
- **Per-user rate limit** on `/send`: 60/min via the existing
  rate-limit middleware.
- **Header redaction** in the "Effective request" view: `Authorization`,
  `X-Api-Key`, `Cookie`, `Proxy-Authorization` show last 4 chars only.
- **Response size cap:** 64 KB.
- **Hard timeout:** 10 s; UI surfaces it on failure.
- **Templating:** strict — see decision below.

### RBAC

New capability `webhooks` in `capabilities.py` with verbs
`list / create / edit / delete / send`. Same admin-vs-user gating as
Log Profiles. Defaults:

- Admin: all verbs.
- User: full CRUD on own; read + send on public ones.

### Tests

- Renderer: vars resolve; missing vars produce `{{?...}}` markers;
  nested JSON renders without broken quotes.
- Send: redact strips secrets; response body truncated at 64 KB;
  timeout honoured; bad JSON in `body_format=json` surfaces a clear 400.
- Egress allowlist: requests to `127.0.0.1`, `169.254.169.254`,
  `10.0.0.0/8` rejected by default; allowlist override enables them.
- RBAC: non-owner can read public webhooks but cannot edit; send
  permitted on public ones (configurable).
- API: standard CRUD round-trip; clone produces a per-user copy.

---

## Release shape

- **Branch:** `feat/v4.1-webhooks-and-event-mix` off `feat/v4.0-alert-push`.
- **Version bump:** v4.1 (both features additive).
- **Migration:** zero. Empty `source_event_mix.json` and empty
  `webhooks/` directory both default to "use catalog defaults" and
  "no webhooks yet".
- **Docs to ship:**
  - `docs/EVENT_MIX.md` — admin guide for Phase 5.
  - `docs/WEBHOOKS.md` — admin guide + security model for Phase 6.
  - `docs/sources/<vendor>.md` × 21 — Phase 5 inventory output.

## Open decisions

- **Templating engine for Phase 6** — regex `{{...}}` (zero SSTI
  surface, no loops/filters) vs Jinja2 sandboxed (more expressive,
  needs careful disable-list). Deferred until Phase 6 kickoff.
