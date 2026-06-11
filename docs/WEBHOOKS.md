# Webhooks — Outbound HTTP Request Composer

Status: **v5.0 — GA**. Implements [ROADMAP_v4.1.md](./ROADMAP_v4.1.md) Phase 6.

---

## 1. What it is

Webhooks let any signed-in user (with the `Webhooks` RBAC capability)
compose, save, and fire **templated outbound HTTP requests** from
ApiGenie. The composer is purpose-built for two recurring SecOps demos:

1. **"Light up a third-party SIEM/SOAR with a synthetic alert"** —
   build a JSON body that references a log profile, click *Send*, and
   the bound profile's users / machines / C2 servers / malware /
   mail-senders are substituted in.
2. **"Drive an arbitrary HTTPS endpoint with shaped events"** — write
   a `{{custom.<key>}}`-driven body, paste send-time variables in the
   bottom pane, and trigger from the admin panel or via REST.

Captured "effective request" + response are kept for inspection and
can be exported as a copy-pastable `curl` command for use elsewhere.

---

## 2. Where it lives

| Layer            | File                                                |
| ---------------- | --------------------------------------------------- |
| Data model       | `webhooks.py` (`create_webhook`, `update_webhook`…) |
| Template engine  | `webhooks.py::render(template, RenderContext)`      |
| Send pipeline    | `webhooks.py::send_webhook` (httpx)                 |
| REST API         | `admin.py` — `/admin/api/webhooks/*`                |
| UI tab           | `admin.py` — `pane-webhooks`                        |
| Storage          | `${APIGENIE_DATA_ROOT}/webhooks/<id>.json`          |
| RBAC category    | `accounts.Category.WEBHOOKS`                        |
| Tests            | `tests/test_webhooks.py` (23 tests)                 |

---

## 3. Variable surface

`render(template, ctx)` substitutes `{{var.path}}` markers. Missing
variables render as `{{?<original>}}` markers so authors see the gap
explicitly rather than getting a silent empty string.

| Variable                            | Resolves to                              |
| ----------------------------------- | ---------------------------------------- |
| `{{profile.user.<field>}}`          | One randomly picked user from the bound profile (same pick across the whole render pass) |
| `{{profile.machine.<field>}}`       | One randomly picked machine              |
| `{{profile.c2.<field>}}`            | One randomly picked C2 server            |
| `{{profile.malware.<field>}}`       | One randomly picked malware sample       |
| `{{profile.mail_sender.<field>}}`   | One randomly picked mail sender          |
| `{{custom.<key>}}`                  | Value supplied at send time (UI pane / `custom_vars` in REST) |
| `{{now}}`                           | ISO-8601 UTC timestamp                   |
| `{{epoch}}`                         | Unix epoch seconds                       |
| `{{epoch_ms}}`                      | Unix epoch milliseconds                  |
| `{{uuid}}`                          | Random UUID4 (stable inside one render)  |
| `{{env.<KEY>}}`                     | Allow-listed env var (see below); other keys render as the miss marker |

**Env allowlist.** Only these process env vars are exposed to the
renderer — anything else returns `{{?env.X}}` even if the variable
exists at runtime:

- `APIGENIE_DOMAIN`
- `APIGENIE_VERSION`
- `APIGENIE_DEPLOYMENT`

Extend `webhooks.ENV_ALLOWLIST` to expose more — never leak free-form
process state to a templated outbound request.

**Determinism inside one render pass.** A given `{{profile.user.*}}`
chain reuses the same picked user across all lookups, so
`{{profile.user.username}}` and `{{profile.user.email}}` describe the
*same person* in the body you send. Repeat sends pick again.

---

## 4. Security guardrails

`send_webhook` enforces:

| Guardrail                  | Behaviour                                                        |
| -------------------------- | ---------------------------------------------------------------- |
| Egress allowlist           | Refuses RFC1918 / link-local / loopback / IMDS / unique-local v6 by default. Two override sources are merged: the `APIGENIE_WEBHOOK_ALLOWED_HOSTS` env var (infra-baked, read-only at runtime) **and** the persisted **Settings → Webhook egress allowlist** card (admin-only, editable from the UI). |
| Header redaction           | `Authorization`, `X-Api-Key`, `Cookie`, `Proxy-Authorization`, `X-Auth-Token` are rendered as `<redacted:****XXXX>` in the effective-request view (last 4 chars kept for traceability). |
| Hard timeout               | 10 s.                                                            |
| Response body cap          | 64 KiB. Larger bodies are truncated and `response_truncated: true` is set. |
| Redirect follow            | Disabled.                                                        |
| JSON pre-flight            | If `body_format=json`, the *rendered* template is parsed; a JSON error returns immediately as a guard rejection instead of going out the wire. |

### 4.1 Allowlist override examples

**Option A — Settings UI** (recommended for lab operators who cloned ApiGenie):

1. Sign in to the **admin** portal (only `admin`-role sessions can edit;
   `user`-role sessions get a 401 even if they hold every `Webhooks`
   entitlement).
2. Open **Settings → Webhook egress allowlist**.
3. Type a CIDR or hostname and press <kbd>Enter</kbd> (or click **+ Add**).
4. Click **💾 Save allowlist**. The change takes effect on the next send —
   no container restart required.

Entries are persisted to `${APIGENIE_DATA_ROOT}/webhook_settings.json`
(atomic replace), and each accepted entry is canonicalised:
hostnames are lower-cased, CIDRs collapse to their network form, and
single IPs are kept as `/32` (or `/128`). Bad input (e.g. `rm -rf /`) is
rejected at save with the offending value surfaced to the UI.

**Option B — `APIGENIE_WEBHOOK_ALLOWED_HOSTS` env var** (for ops-driven
config baked into `.env` / Helm values / Kubernetes Secrets):

```bash
# Allow localhost (useful in dev / tests):
APIGENIE_WEBHOOK_ALLOWED_HOSTS="127.0.0.0/8"

# Allow a known internal collector + its IP range:
APIGENIE_WEBHOOK_ALLOWED_HOSTS="collector.internal,10.42.0.0/24"
```

The env-var entries appear in the Settings UI as **read-only blue
chips** — useful as documentation but not editable from the browser
(intentional: env-baked config is the operator's contract, not the
admin's).

**Precedence.** The two sources are **unioned**, not stacked: each
resolved address is permitted if it is **either** outside every blocked
network **or** covered by an entry from *either* source. The default
block list is never removed — adding `10.0.0.0/8` to either source just
opens that one slice.

---

## 5. REST API

All endpoints live under `/admin/api/webhooks` and require
authentication (built-in admin **or** a registered user with the
`Webhooks` capability — server-enforced through the central
`_perm_requirement` gate in `admin.py`).

| Method | Path                                  | Capability                              | Body                                                                                  |
| ------ | ------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------- |
| GET    | `/admin/api/webhooks`                 | any (visibility filters list)           | —                                                                                     |
| POST   | `/admin/api/webhooks`                 | `Webhooks: Create`                      | `{name, url, method, auth, headers, query, body_template, body_format, profile_id, visibility}` |
| GET    | `/admin/api/webhooks/{id}`            | any (must be own / public)              | —                                                                                     |
| PUT    | `/admin/api/webhooks/{id}`            | `Webhooks: Modify` (must own)           | Partial payload — any subset of the create body                                       |
| DELETE | `/admin/api/webhooks/{id}`            | `Webhooks: Delete` (must own)           | —                                                                                     |
| POST   | `/admin/api/webhooks/{id}/clone`      | `Webhooks: Create`                      | —                                                                                     |
| POST   | `/admin/api/webhooks/{id}/send`       | `Webhooks: Operate` (a.k.a. Manage) or `Modify` | `{custom_vars?: {...}, override_url?: "..."}`                                |
| GET    | `/admin/api/webhook-settings`         | **admin role only**                     | — (returns `{allowed_hosts, env_allowed_hosts, env_var_name, default_blocked}`)      |
| PUT    | `/admin/api/webhook-settings`         | **admin role only**                     | `{allowed_hosts: ["CIDR or hostname", ...]}` — full replace, validated server-side    |

### 5.1 Send result shape

```json
{
  "status": 200,
  "elapsed_ms": 142,
  "response_headers": {"content-type": "application/json"},
  "response_body":    "{\"ok\":true}",
  "response_truncated": false,
  "effective_request": {
    "url":     "https://hooks.example/incoming?src=apigenie",
    "method":  "POST",
    "headers": {"Authorization": "<redacted:****abcd>", "Content-Type": "application/json"},
    "body":    "{\"who\":\"alice@acme.test\",\"msg\":\"hello\"}"
  },
  "error": null
}
```

When a guardrail rejects the request (allowlist, JSON parse, timeout,
DNS failure), `status` is `0` and `error` carries a human-readable
reason. The REST endpoint still returns HTTP 200 in that case — the
SendResult dict is the source of truth, not the wrapping status code.

---

## 6. UI walkthrough

Sign in to the user portal → **Webhooks** tab.

1. **Left rail** lists every webhook you can see (your own +
   public ones). Click a row to load it into the editor.
2. **Editor** (right pane) is laid out in six sections:
   1. Name, visibility, description.
   2. Method + URL (both support `{{vars}}`).
   3. Auth type — `none` / `bearer` / `basic` / `custom`. The `custom`
      mode lets you set an `Authorization` prefix (`ApiKey`, `Token`,
      etc.) plus its value.
   4. Headers (add/remove rows; values support `{{vars}}`).
   5. Query parameters (same shape as headers).
   6. Bound profile + body template + body format. The variable
      chip bar inserts common variables at the cursor.
3. **Send-time variables** is a key/value pane that fills the
   `{{custom.<key>}}` namespace. Pre-filled with `title=Hello from
   ApiGenie` to make the very first send work out of the box.
4. **Save / Send / Clone / Delete** buttons live at the bottom.
   *Send* auto-saves the current draft first so the saved
   webhook always matches what went out.
5. **Last response** card (below the editor) reveals on first send,
   showing the status, elapsed time, the effective request (with
   redacted auth), and the response headers + body. The **Copy as
   curl** button writes a fully-formed `curl` invocation to the
   clipboard.

---

## 7. RBAC model

| Capability             | Verb         | What it allows                                  |
| ---------------------- | ------------ | ----------------------------------------------- |
| `Webhooks: List`       | implicit GET | See your own + public webhooks                  |
| `Webhooks: Create`     | POST         | Create new + clone                              |
| `Webhooks: Modify`     | PUT / PATCH  | Edit (must own the object)                      |
| `Webhooks: Delete`     | DELETE       | Delete (must own the object)                    |
| `Webhooks: Operate`    | POST `/send` | Fire a webhook (your own or a public one)       |

The built-in admin (env-file credentials) bypasses RBAC entirely.
Registered users (`accounts.py`) see only their own + public
webhooks, and can only edit / delete / clone webhooks they own.
A user with no `Webhooks: Create` perm gets **HTTP 403** on `POST`.

---

## 8. Testing

`tests/test_webhooks.py` covers 23 scenarios across four areas:

- **Renderer** — variable resolution, deterministic profile picks,
  missing-var markers, custom-var pane, env allowlist gating,
  singletons (`now` / `epoch` / `uuid`).
- **Storage / validation** — CRUD round-trip, validation rejects
  bad URLs / methods / body formats / header shapes, clone produces
  a private copy with the `(copy)` suffix (without double-appending).
- **Send pipeline** — loopback / IMDS rejected by default, allowlist
  unlocks loopback, JSON pre-flight fails fast on bad templates,
  authorization redacted, 64 KiB response body cap honoured.
- **REST API** — list / create / get / update / delete / clone /
  send happy paths, 404 on unknown id, 400 on invalid update,
  send wires through to the renderer + allowlist, RBAC denial
  returns 403 when the entitlement is missing.

Run the suite via `bash scripts/dev_sync_and_test.sh tests/test_webhooks.py`.

---

## 9. Notes for operators

- **Where do webhooks live on disk?** `${APIGENIE_DATA_ROOT}/webhooks/<id>.json`,
  one JSON file per webhook. Storage is straightforward enough that you can
  hand-edit / back up / version-control the directory if you want.
- **Where do failed sends live?** Currently in the API response only — there
  is no persistent send history yet. The Request Inspector picks up *inbound*
  hits only.
- **Can a webhook fire from automation?** Yes — call the
  `/admin/api/webhooks/{id}/send` endpoint with the same cookie you
  use for any other admin-API call.
- **Can a webhook be triggered by an attack scenario?** Not in v5.0.
  That's deferred to a future phase (the design hook is the
  `profile_id` binding — a scenario would set `custom_vars` at run
  time and POST `/send`).
