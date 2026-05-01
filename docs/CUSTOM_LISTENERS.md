# Custom Listeners — Design Doc

> **Status:** ✅ **implemented** — all four phases (backbone, synthetic topics, admin UI, replay engine) are complete and verified by `scripts/smoke-test.sh`. This document is preserved as the design-of-record (rationale, deferred items, env-var table) for future revisits and onboarding. See §11 for the per-phase shipped summary.

## 1. Goal

Add a **🎯 Listeners** tab to the ApiGenie admin UI that lets a user stand up an arbitrary, on-the-fly HTTP endpoint which behaves like a real SaaS log API. The intended consumer is an **Observo Site Collector (SCol)** custom Lua source: the operator writes a Lua script that polls ApiGenie, and ApiGenie serves either synthetic data from one of four telemetry topics or a user-uploaded log file replayed with a configurable time anchor.

The feature exists so that a solutions engineer can:

1. Validate a hand-rolled SCol Lua script end-to-end without standing up the real upstream platform.
2. Demo "bring your own logs" scenarios with realistic timestamps shifted to "now".
3. Stress collector behaviour under controlled rate-limit / failure injection.

## 2. Direction of data flow (read this before anything else)

**SCol is a *puller*, not a receiver.** The Lua script runs inside the Observo Dataplane (the `data-plane-collector` deployment) and issues outbound `fetch(url, …)` calls against an external HTTP API. Responses are decoded and `emit()`ed into the Vector pipeline.

Consequence: ApiGenie is the **HTTP server** the collector polls. This is the same shape the existing built-in source modules (`okta.py`, `netskope.py`, …) already implement, just hard-wired. The new feature makes that shape **user-configurable at runtime via the admin UI**.

## 3. User experience

A new admin tab **🎯 Listeners** (peer of *Sources / Requests / Flows / GeoMap / Settings*) where the user can:

1. **Define a listener** — a named HTTP endpoint exposed at `https://<domain>/listener/<id><path>` with configurable auth, codec, pagination, rate-limit and failure-injection.
2. **Pick a data source** for the listener:
   - One of four built-in **synthetic topics** (endpoint / identity / cloud / network telemetry); or
   - **Upload a log file** for replay with a configurable time anchor.
3. **Watch live collection** — a per-listener panel showing every inbound request with headers/body, hit rate, decoded auth identity, and the last N responses sent.
4. **Generate a ready-to-paste collector snippet** — a Lua script template that fetches against `https://<domain>/listener/<id><path>` plus the matching `http_cfgs.default.auth` + `decoders.default.decoding` YAML for the SCol source definition.

### UI layout

```
┌─ 🎯 Listeners ────────────────────────────────────────────────┐
│ [ + New listener ]                                            │
│                                                               │
│ ┌──── customer-edr (endpoint) ─── enabled ──── 12 hits/min ┐ │
│ │ GET https://<domain>/listener/customer-edr/v1/events    │ │
│ │ Auth: Bearer  ·  Codec: NDJSON  ·  Cursor pagination    │ │
│ │ [ Edit ] [ Snippet ] [ Live trace ▾ ] [ Disable ] [ × ] │ │
│ └──────────────────────────────────────────────────────────┘ │
│ ┌──── azure-replay (replay: 8.4 MB JSONL) ─── enabled ─── ┐ │
│ │ POST https://<domain>/listener/azure-replay/api/audit   │ │
│ │ Auth: OAuth2 CC  ·  Codec: JSON  ·  Anchor: -2 days     │ │
│ │ [ Edit ] [ Snippet ] [ Live trace ▾ ] [ Disable ] [ × ] │ │
│ └──────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

The **+ New listener** modal is a 4-step wizard:

1. Identity (name, path, method)
2. Auth (none / basic / bearer / oauth2_cc / x-api-key) — fields appear conditionally
3. Data (synthetic topic + records-per-call, *or* upload file → choose ts field + anchor)
4. Behaviour (codec, pagination, rate-limit, chaos)

The **Snippet** dialog has two tabs: "Lua script" and "Source YAML".

## 4. Data model

```python
# new module: listeners.py
@dataclass
class Listener:
    id: str                          # short slug, used in URL
    name: str                        # human label
    path: str                        # e.g. "/v1/events"  (joined under /listener/<id>)
    method: str = "GET"              # GET | POST
    auth: AuthSpec
    codec: str                       # "json" | "ndjson" | "syslog"  (v1 set — see §10)
    pagination: PaginationSpec | None
    rate_limit: RateLimitSpec | None
    chaos: ChaosSpec | None          # status-code injection
    data_source: SyntheticTopicSpec | ReplayFileSpec
    created_at: datetime
    enabled: bool = True

@dataclass
class AuthSpec:
    kind: Literal["none","basic","bearer","oauth2_cc","x_api_key"]
    # kind="basic"      → username, password
    # kind="bearer"     → token (and optional header name + prefix per Config.md)
    # kind="oauth2_cc"  → reuses ApiGenie's existing /oauth2/v1/token endpoint (see §6)
    # kind="x_api_key"  → header name, key value

@dataclass
class PaginationSpec:
    kind: Literal["cursor","since","page"]
    page_size: int = 100
    total_pages: int = 5             # generator caps after this

@dataclass
class SyntheticTopicSpec:
    topic: Literal["endpoint","identity","cloud","network"]
    rate_per_request: int = 100
    seed: int | None = None

@dataclass
class ReplayFileSpec:
    file_id: str                      # uploaded blob, stored under ./data/replays/
    format: Literal["json","jsonl","csv","syslog","cef"]
    anchor: AnchorSpec
    timestamp_field: str              # JSONPath to the ts field, or column name for CSV

@dataclass
class AnchorSpec:
    mode: Literal["now","offset","fixed"]
    # mode="offset" → seconds_ago: int
    # mode="fixed"  → datetime
    preserve_spread: bool = True      # keep relative deltas between records
```

### Persistence

| Item | Where | Notes |
|------|-------|-------|
| Listener configs | `./data/listeners/<id>.json` | one file per listener; loaded into `LISTENERS: dict[str, Listener]` at boot |
| Replay uploads | `./data/replays/<file_id>/{meta.json, blob}` | hard cap (default 100 MB) per file via `APIGENIE_REPLAY_MAX_MB` |
| **Live hits** | `./data/listeners/<id>.hits.jsonl` (append-only, line-buffered) **plus** in-memory ring of last N | persistent across restarts; capped by `APIGENIE_LISTENER_HITS_CAP` (default 200 in memory, default 5000 on disk via `APIGENIE_LISTENER_HITS_DISK_CAP` with rotation) |

> **Why persistent hits?** Per the agreed design: the user wants live trace history to survive container restarts so demos and post-mortem inspections aren't wiped by a `docker compose up -d --build`. The on-disk store is rotated (truncate-and-rewrite) when it exceeds `APIGENIE_LISTENER_HITS_DISK_CAP` lines, keeping the most recent.

> **Single-worker constraint still applies.** The in-memory ring is per-process, same as `REQUEST_TRACE`. ApiGenie is pinned to `--workers 1` already.

## 5. REST surface

All admin routes are gated by the existing admin session cookie. All listener data routes are public (auth is whatever the listener config declares).

```
# admin (cookie-gated)
GET    /admin/api/listeners                       # list configs + last-hit timestamp
POST   /admin/api/listeners                       # create
GET    /admin/api/listeners/{id}
PATCH  /admin/api/listeners/{id}                  # toggle enabled, edit fields
DELETE /admin/api/listeners/{id}
GET    /admin/api/listeners/{id}/hits             # hit history (memory ring + tail of disk file)
DELETE /admin/api/listeners/{id}/hits             # clear (memory + disk)
GET    /admin/api/listeners/{id}/snippet?lang=lua # generate the collector boilerplate

POST   /admin/api/replays                         # upload a file → returns file_id
GET    /admin/api/replays                         # list uploaded files + sizes
DELETE /admin/api/replays/{file_id}

# data-serving (public, listener auth applies)
{method}  /listener/{listener_id}{path}           # e.g. GET /listener/lx7/v1/events
```

### Dynamic routing

The data-serving routes are mounted via a single FastAPI catch-all:

```python
@router.api_route("/listener/{lid}/{rest:path}",
                  methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def _dispatch(lid: str, rest: str, request: Request):
    listener = LISTENERS.get(lid)
    if not listener or not listener.enabled:
        return JSONResponse({"error": "not_found"}, status_code=404)
    if request.method != listener.method or "/" + rest != listener.path.lstrip("/").join(...):
        return JSONResponse({"error": "method_or_path_mismatch"}, status_code=404)
    # 1. auth check  → 401 on fail
    # 2. rate-limit  → 429 if tripped
    # 3. chaos       → injected status if tripped
    # 4. delegate to synthetic generator or replay engine
    # 5. record hit (in-memory ring + append-only disk file)
```

## 6. Authentication strategies

| `AuthSpec.kind` | What ApiGenie checks | v1? |
|---|---|---|
| `none` | no header check | ✅ |
| `basic` | `Authorization: Basic …` decodes to configured `username:password` | ✅ |
| `bearer` | configurable header (default `Authorization`) + prefix (default `Bearer `) matches configured token | ✅ |
| `oauth2_cc` | `Authorization: Bearer <token>` where `<token>` came from the **existing** `POST /oauth2/v1/token` endpoint (any `client_id`/`client_secret` accepted, returns `apigenie-fake-oauth-access-token`) | ✅ — reusing the global token endpoint |
| `x_api_key` | configurable header name carries the configured key value | ✅ |
| **mTLS** | client cert verification | ❌ — **deferred, see §10** |

> **Reusing `/oauth2/v1/token`** keeps the design simple: the SCol `auth.oauth2_cc.token_url` field in the generated YAML always points at the global endpoint regardless of which listener will consume the resulting bearer. The token itself isn't listener-scoped, which is acceptable in a lab/test context. If listener-scoped tokens become necessary later, we can mint per-listener token URLs without breaking the global one.

## 7. Pagination patterns

Three shapes, mirroring what the existing source modules do:

| Kind | Request → response |
|------|---------------------|
| `cursor` | first call returns `{ "data": [...], "next_cursor": "abc" }`; subsequent call passes `?cursor=abc`; cursor exhausted after `total_pages` |
| `since` | client passes `?since=<iso8601>`; server returns records with `ts > since` from the generator |
| `page` | client passes `?page=N&page_size=…`; server returns slice; bounded by `total_pages` |

Synthetic topics generate fresh data per call. Replay sources iterate the file with cursor/page state held under `LISTENER_PAGINATION_STATE[listener_id][client_token]`.

## 8. Synthetic topic catalogues

One module per topic under `sources/synthetic/`, each exposing `generate(n: int, seed: int | None) -> list[dict]`.

| Topic | Shape | Key fields |
|---|---|---|
| **endpoint** | EDR / process telemetry | `host_id`, `user`, `process.{name,cmdline,parent}`, `file.{path,hash}`, `event.action` ∈ {process_start, file_write, network_connect, …}, `risk_score`, `mitre.technique` |
| **identity** | Auth / SSO / IAM | `actor`, `event.type` ∈ {login, mfa_challenge, group_change, role_grant, password_change}, `outcome`, `auth_method`, `client.ip`, `geo`, `mfa_factor`, `target_user` |
| **cloud** | Multi-cloud audit | `provider` ∈ {aws, azure, gcp}, `event.name` (CreateBucket, AssumeRole, RunInstance, …), `principal`, `resource.arn`, `region`, `error_code`, `request_params`, `response_elements` |
| **network** | Zeek-style + flow | `conn.uid`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `service` ∈ {dns, http, ssl, ssh}, `duration`, `bytes_in`, `bytes_out`, `dns.query`, `http.host`, `ssl.server_name` |

Generators reuse the existing `generators.py` helpers (UUID, IP, hostname, weighted choice). Distributions are weighted to be visually realistic in dashboards (e.g. ~95% benign + ~5% suspicious endpoint events).

## 9. Replay engine

```python
class Replay:
    def __init__(self, spec: ReplayFileSpec): ...
    def stream(self, anchor_now: datetime) -> Iterator[dict]:
        # 1. Parse file (json/jsonl/csv/syslog/cef) lazily — never load 100 MB into RAM.
        # 2. For each record, read the timestamp field (JSONPath / column name).
        # 3. shift = anchor_now - earliest_record_ts  (computed once on first call).
        # 4. Yield record with ts shifted; if preserve_spread=True keep relative deltas.
        # 5. Pagination state is held per (listener_id, client_token).
```

- Files stored under `./data/replays/<file_id>/{meta.json, blob}`.
- Hard cap per upload: `APIGENIE_REPLAY_MAX_MB` (default 100).
- Format auto-detected from extension + first-line sniff; user can override in the wizard.
- v1 supports: `json` (single array), `jsonl`, `csv`, `syslog` (RFC 3164 / 5424), `cef`.

## 10. Scope — what's in v1, what's deferred

### In scope for v1

- All five auth kinds **except mTLS** (see deferred list).
- Codecs: **JSON, NDJSON, syslog**.
- Synthetic topics: endpoint, identity, cloud, network.
- Replay formats: json, jsonl, csv, syslog, cef.
- Persistent hits with ring buffer + on-disk rotation.
- One path per listener (multi-step flows = multiple listeners).
- Per-listener live trace pane.
- Snippet generator (Lua + YAML).

### ❌ Deferred (must be tracked)

| Item | Reason | Tracking |
|------|--------|----------|
| **mTLS auth on listeners** | SCol `http_cfgs.default.tls.client_cert/key` is supported on the collector side; on the listener side it requires extra nginx config (client-cert verification, CA bundle) and is non-trivial in this stack. | Track in this doc + open issue when v1 ships. |
| **Codecs: GELF, protobuf, Avro, VRL** | The Observo `DeserializerConfig` enum includes these; the four common ones (JSON / NDJSON / syslog / text) cover ~all real customer scenarios. | Track in this doc; add to the wizard greyed-out with a "v2" badge. |
| **Multiple paths per single listener** | Some collectors hit several URLs in sequence (e.g. Tenable's 3-step export). v1 forces "one path per listener"; the user can stand up multiple listeners that share a topic. | Track in this doc; revisit if real customer flows need shared state across paths. |
| **Listener-scoped OAuth2 token URLs** | v1 reuses the global `/oauth2/v1/token`. | Revisit only if it becomes necessary. |

## 11. Phasing

Each phase is a self-contained, mergeable slice with a smoke-test extension and (where applicable) a screenshot driver entry.

1. **Phase 1 — backbone** ✅ shipped
   `listeners.py` data model + persistence, CRUD admin endpoints, dynamic FastAPI router for `/listener/{id}/{rest:path}`, auth dispatcher, persistent hit recorder. **No UI yet.** Verifiable with `curl`.

2. **Phase 2 — synthetic topics** ✅ shipped
   Four generator modules under `sources/synthetic/` (endpoint, identity, cloud, network) wired into the dispatcher with seedable determinism. Codecs json / ndjson / syslog. Pagination cursor / page / since.

3. **Phase 3 — admin UI** ✅ shipped
   Listeners tab, 4-step wizard, edit/delete flow, inline live-trace pane, snippet generator (Lua + Observo SCol YAML).

4. **Phase 4 — replay** ✅ shipped
   `replay.py` module with on-disk storage at `./data/replays/<file_id>/{meta.json, blob}`, lazy parsers for json (single array) / jsonl / csv / syslog (RFC 3164 + 5424) / cef, time-shift streaming with three anchor modes (`now` / `offset` / `fixed`) preserving original record spread, admin REST endpoints (`POST/GET/DELETE /admin/api/replays`, `GET /preview`), wizard step 3 synthetic↔replay toggle, file-upload modal, manage-uploads panel. Delete-while-in-use returns 409 to prevent dangling references. The dispatcher applies pagination over the lazy stream the same way it does for synthetic topics, with `total_pages` derived from `meta.line_count` rather than the listener's static spec.

## 12. New environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APIGENIE_LISTENER_HITS_CAP` | `200` | In-memory ring buffer size per listener |
| `APIGENIE_LISTENER_HITS_DISK_CAP` | `5000` | Max lines kept in `./data/listeners/<id>.hits.jsonl` before rotation |
| `APIGENIE_REPLAY_MAX_MB` | `100` | Per-file upload cap for replay sources |

These are present in `.env.example` and the README env-var table.

## 13. Open / revisit-later items

- Whether to add a "burst then quiet" rate-limit profile in addition to "every Nth request 429".
- Whether to expose listener configs over a CLI for IaC-style provisioning (lower priority than the UI).
- Whether to grant per-listener API keys for the admin CRUD endpoints (so external automation can manage listeners without a session cookie).
