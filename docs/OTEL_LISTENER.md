# OpenTelemetry Custom Listener — Design

> Push sink for OTLP/HTTP and OTLP/gRPC, both signals × all three telemetry
> types (logs, metrics, traces). Slots into the existing Custom Listener
> framework (`@/listeners.py`, `@/app.py:1333`) as a new data-source kind
> alongside `synthetic` and `replay`.

## 1. Goals & non-goals

**Goals**

- Accept OTLP exports from off-the-shelf OpenTelemetry collectors (otelcol,
  Vector with OTLP sink, Splunk OTel Collector, the OpenTelemetry SDKs).
- Support **both** transports a real OTLP receiver does:
  - **OTLP/HTTP** on `:443` (re-using nginx + `/listener/<id>/v1/{logs,metrics,traces}`),
    accepting `application/x-protobuf` *and* `application/json`.
  - **OTLP/gRPC** on `:4317` (new nginx server block, `grpc_pass` to the
    apigenie container's in-process gRPC server).
- Record every export as a hit in the same per-listener history pane as the
  pull-style listeners, with a **decoded preview** (resource attributes +
  first N record/span/data-point summaries) so an operator can confirm the
  collector is sending the right shape.
- Reply with the OTel-spec-compliant 200 / `Export*ServiceResponse` ack so
  the collector treats the export as a success and does not retry.
- Keep all the existing listener concerns working: auth, rate-limit, chaos
  injection, RBAC (`Category.LISTENERS`), ownership/visibility, hit history.

**Non-goals (for this iteration)**

- No actual storage / forwarding of OTLP data to a downstream backend. The
  hit history *is* the storage; this is a mock receiver, not a Collector
  exporter.
- No OTLP-over-HTTP/2 cleartext (`h2c`). Collectors that need plaintext gRPC
  can talk to apigenie on port `4317` inside the docker network only.
- No mTLS for gRPC. The same self-signed / Let's Encrypt cert that nginx
  serves on 443/8443 is presented on 4317.
- No partial success reporting (always returns `{}` partial_success — the
  ack the collector wants when everything was accepted).

## 2. Architecture overview

```
┌──────────────┐  https://apigenie/listener/<id>/v1/logs          ┌────────────────────┐
│ OTel exporter│ ─────────────────────────────────────────────►   │  nginx :443        │
│  (HTTP)      │ POST application/x-protobuf | application/json   │  proxy_pass 8000   │
└──────────────┘                                                  └────────────────────┘
                                                                            │
                                                                            ▼
                                                              ┌─────────────────────────┐
                                                              │  apigenie FastAPI :8000 │
                                                              │  /listener/{lid}/{path} │
                                                              │  ─ existing dispatcher  │
                                                              │  ─ NEW push_sink branch │
                                                              └─────────────────────────┘
                                                                            │
                                                                            ▼
                                                              ┌─────────────────────────┐
                                                              │ listeners_otlp.decode_  │
                                                              │ preview(body, codec)    │
                                                              └─────────────────────────┘
                                                                            │
                                                                            ▼
                                                              ┌─────────────────────────┐
                                                              │ listeners.record_hit()  │
                                                              │ + OTel-spec 200 ack     │
                                                              └─────────────────────────┘

┌──────────────┐  apigenie:4317                                   ┌────────────────────┐
│ OTel exporter│ ─────────────────────────────────────────────►   │  nginx :4317 (TLS) │
│  (gRPC)      │ Logs/Metrics/TracesService.Export                │  grpc_pass apigenie│
└──────────────┘                                                  └────────────────────┘
                                                                            │
                                                                            ▼
                                                              ┌─────────────────────────┐
                                                              │  apigenie listeners_grpc│
                                                              │  grpc.aio.Server :4317  │
                                                              │  ─ shares LISTENERS dict│
                                                              │  ─ same auth, hits, ack │
                                                              └─────────────────────────┘
```

The HTTP path re-uses the **existing dispatcher** — we just add a
`push_sink` branch in `listener_dispatch()` before the synthetic/replay
response build. The gRPC path is a **separate server** that starts in the
FastAPI `lifespan` context manager and shares the in-memory `LISTENERS`
and `LISTENER_HITS` dicts (single-process, `--workers 1` already).

## 3. Data model — `PushSinkSpec`

New dataclass in `@/listeners.py`, sibling to `SyntheticTopicSpec` and
`ReplayFileSpec`:

```python
@dataclass
class PushSinkSpec:
    protocol: Literal["otlp_http", "otlp_grpc"] = "otlp_http"
    signal:   Literal["logs", "metrics", "traces"] = "logs"
    decode_preview: bool = True
    ack_partial_success: bool = True       # always {} partial_success on 200
    max_decode_records: int = 5             # preview cap (records / spans / dp)
```

`Listener` gains an optional `push_sink: PushSinkSpec | None = None`.

**Validation** (`validate_listener_payload`):

- Exactly **one of** `synthetic` / `replay` / `push_sink` must be set
  (today it's `synthetic XOR replay`; we extend to a three-way XOR).
- If `push_sink.protocol == "otlp_http"`, `method` must be `POST`,
  `codec` must be one of the new OTLP codecs.
- If `push_sink.protocol == "otlp_grpc"`, `path` is informational only
  (gRPC routes by service name, not URL), `method` is forced to `POST`
  for UI consistency, `codec` must be `otlp_proto`.

**New codecs** (`ALLOWED_CODECS_V1` extended):

| codec        | Content-Type the dispatcher accepts |
|--------------|-------------------------------------|
| `otlp_proto` | `application/x-protobuf`            |
| `otlp_json`  | `application/json`                  |

## 4. HTTP dispatch — new `push_sink` branch

In `@/app.py` `listener_dispatch()`, **after** auth + chaos check, **before**
the call to `build_response()`:

```python
if listener.push_sink is not None:
    preview = None
    if listener.push_sink.decode_preview:
        preview = listeners_otlp.decode_preview(
            body=body_bytes,
            codec=listener.codec,
            signal=listener.push_sink.signal,
            max_records=listener.push_sink.max_decode_records,
        )
    ack_body = listeners_otlp.http_ack_body(listener.push_sink.signal)
    extra = {"x-apigenie-otlp-decoded": "1"} if preview else {}
    # Record hit with the decoded preview attached for the UI:
    return _finish(200, ack_body, "application/json", identity, extra,
                   otlp_preview=preview)
```

`_finish` is extended with an optional `otlp_preview` kwarg that gets
copied into the hit entry next to `resp_preview`.

## 5. gRPC server — `listeners_grpc.py`

New module. Public surface:

```python
def start(port: int = 4317) -> None: ...
def stop() -> None: ...
```

Internally:

- Uses `grpc.aio.server` so it cooperates with FastAPI's event loop.
- Registers three servicers (lazy-imported from `opentelemetry-proto`'s
  generated stubs):
  - `LogsServiceServicer.Export`     → routes to push_sink listeners with `signal == "logs"`
  - `MetricsServiceServicer.Export`  → routes to `signal == "metrics"`
  - `TraceServiceServicer.Export`    → routes to `signal == "traces"`
- **Listener routing** (matches real-world OTLP multi-tenancy patterns;
  Grafana Loki/Mimir/Tempo, Datadog, Splunk OTel Collector all use
  metadata-based tenancy on a single port). In priority order:
  1. gRPC metadata `x-apigenie-listener-id: <lid>` — apigenie-specific
     alias, documented explicitly.
  2. gRPC metadata `x-scope-orgid: <lid>` — the Grafana Loki / Mimir /
     Tempo multi-tenancy convention. Stock OpenTelemetry Collector
     exporters already support this through their `headers:` config
     block, so a collector configured for Loki multi-tenancy can be
     pointed at apigenie with **zero** configuration changes other than
     `endpoint`.
  3. Bearer token in `authorization` metadata, matched against any
     `push_sink` listener whose `auth.kind == "bearer"` and token matches.
  4. If exactly one push_sink listener exists for that signal, route to it
     (development convenience, logged at WARN).
  5. Otherwise: reject with `grpc.StatusCode.NOT_FOUND` and the error
     message `no_listener_matches`.

  The HTTP side currently routes purely by URL prefix
  (`/listener/<id>/v1/<signal>`), which is the cleanest mapping onto the
  existing dispatcher. For symmetry with gRPC, the HTTP dispatcher will
  *also* honour the same two metadata headers as a routing override when
  the URL is the generic `/v1/<signal>` form (future extension behind the
  same listener catch-all).
- Auth, rate-limit and chaos are re-used by calling the same helpers from
  `listeners.py` after listener resolution. gRPC has no path/method so
  those checks are skipped for the gRPC branch.
- Hit recording uses the same `record_hit()` machinery; the synthetic
  fields fill in like:
  - `method`: `"gRPC"`
  - `path`: `/<service>/Export`
  - `req_body`: a single-line summary of the decoded preview (NOT the raw
    protobuf — that would blow up the JSONL on-disk store).
- Returns the spec-required empty `Export*ServiceResponse{ partial_success: {} }`.

## 6. nginx — TLS-terminated gRPC on 4317

New `server { listen 4317 ssl; http2 on; ... grpc_pass grpc://apigenie:4317; ... }`
block in `nginx.conf.template`, modelled on the existing 8443 Pub/Sub
block (`@/nginx/nginx.conf.template:87-114`). Returns a `grpc-status:14`
error page if the upstream is down.

`docker-compose.yaml` nginx `ports:` gains `"4317:4317"`.

## 7. Wizard / admin UI

New tile in the listener wizard, alongside "Synthetic" and "Replay":

> **OTLP push sink** — accept OpenTelemetry exports from a collector.

Tile expands to:

- **Signal**: logs / metrics / traces (radio).
- **Protocol**: OTLP/HTTP (POST) / OTLP/gRPC.
- **Codec** (HTTP only): protobuf / JSON.
- **Path** (HTTP only, pre-filled): `/v1/logs|metrics|traces`. Editable for
  customised collectors.
- **Decode preview** (default on): "Decode payloads to show resource
  attributes and first 5 records in the hit pane".
- **Auth**: any of the existing auth kinds. For gRPC the bearer token
  becomes a routing hint too (see §5).

The "URL / endpoint" hint shown next to the row:

- HTTP listeners → `https://<domain>/listener/<id>/v1/<signal>`
- gRPC listeners → `<domain>:4317` + recommended metadata header
  `x-apigenie-listener-id: <id>`

## 8. Hit-pane rendering

Existing `resp_preview` rendering in `@/admin.py:3482-3498` already
handles a generic preview string. We add a **new** optional field
`otlp_preview` to the hit entry, structured as:

```json
{
  "signal": "logs",
  "resource_count": 2,
  "record_count": 17,
  "resources": [
    {"service.name": "my-app", "host.name": "ip-10-0-0-12"},
    {"service.name": "my-app", "host.name": "ip-10-0-0-13"}
  ],
  "records": [
    {"timestamp": "2026-06-11T08:00:00Z", "severity": "INFO",
     "body": "request handled", "trace_id": "abc…", "span_id": "def…"},
    ...
  ],
  "truncated": false
}
```

The hit viewer renders `otlp_preview` (when present) as a small expandable
sub-panel under the row, with a "📡 OTLP" pill instead of the byte-count
pill.

## 9. RBAC

No new capability. Push sinks are listeners. The existing
`Category.LISTENERS` permissions (create / modify / delete) gate creation,
editing and deletion. View is gated by ownership/visibility like every
other listener. Existing wiring in
`@/admin.py:340-352` is sufficient.

## 10. Security guardrails

- **Body size cap**: the decoder reads at most
  `APIGENIE_OTLP_MAX_BODY_BYTES` (default 4 MiB) of the protobuf/JSON body.
  Larger payloads are still acked 200 but no preview is generated.
- **gRPC message size**: `grpc.max_receive_message_length` set to the same
  cap so a malicious client can't OOM the apigenie process.
- **Decode is best-effort**: any protobuf parse failure becomes
  `otlp_preview = {"decode_error": "<reason>"}`; the ack is still 200 so
  the collector isn't blocked by apigenie's decode bugs.
- **No outbound traffic**: this listener kind never makes outbound
  requests. SSRF surface is zero.
- **Auth applies**: a push_sink listener with `auth.kind == "bearer"`
  rejects unauthenticated exports with 401 (HTTP) or
  `grpc.StatusCode.UNAUTHENTICATED` (gRPC).

## 11. Dependencies

Adding to `pyproject.toml` `[project] dependencies` (and the Dockerfile
`uv pip install` line):

- `opentelemetry-proto>=1.27.0` — vendored OTLP protobuf stubs (logs,
  metrics, traces, common, resource).
- `grpcio>=1.65.0` — gRPC server (already a transitive dep of
  google-cloud-pubsub but pinning explicitly is honest).

Both are pure-Python wheel installs on `python:3.13-slim`; no native
build needed beyond what `grpcio` already provides.

## 12. Tests

New file `@/tests/test_otel_listener.py`:

1. **Model**
   - `PushSinkSpec` round-trips through `to_dict()` / `from_dict()`.
   - `validate_listener_payload` rejects `push_sink` + `synthetic` together.
   - Codec validation: `otlp_proto` ↔ `application/x-protobuf`.
2. **HTTP**
   - Create push-sink listener via `/admin/api/listeners`.
   - POST a hand-crafted protobuf body to `/listener/<id>/v1/logs`,
     assert 200, ack body, hit recorded with `otlp_preview.signal == "logs"`.
   - POST the same as `application/json`, assert decoded preview.
   - Bearer auth rejection on wrong token.
3. **gRPC**
   - Start the gRPC server on an ephemeral port (helper).
   - Open a gRPC channel, build a `ExportLogsServiceRequest` with two
     resource log entries, call `Export` with metadata
     `x-apigenie-listener-id: <id>`.
   - Assert empty `partial_success`, hit recorded with `method == "gRPC"`.
4. **Routing edge cases**
   - Wrong listener id in metadata → `NOT_FOUND`.
   - No metadata, two push_sinks for `logs` → `NOT_FOUND`.
   - No metadata, exactly one push_sink for `signal` → auto-routed.
5. **Decoder**
   - Empty body → `{"decode_error":"empty_body"}`.
   - Body > cap → no preview, hit still recorded.
   - Malformed protobuf → `decode_error` set, ack still 200.

## 13. Live smoke (operator)

```bash
# 1) HTTP/protobuf
curl -sS -X POST -H 'Content-Type: application/x-protobuf' \
     --data-binary @sample-logs.pb \
     https://apigenie.roarinpenguin.com/listener/otel-logs/v1/logs

# 2) HTTP/JSON
curl -sS -X POST -H 'Content-Type: application/json' \
     -d '{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[]}]}' \
     https://apigenie.roarinpenguin.com/listener/otel-logs/v1/logs

# 3) gRPC (logs) — example using grpcurl + the proto descriptor set
grpcurl \
  -H "x-apigenie-listener-id: otel-logs" \
  -d @ \
  apigenie.roarinpenguin.com:4317 \
  opentelemetry.proto.collector.logs.v1.LogsService/Export \
  < sample-export-request.json
```

The hit history pane shows each export with the **📡 OTLP** pill and an
expandable preview of resource attributes + first 5 records.

## 14. Phasing inside this PR

Even though we ship HTTP + gRPC together, the implementation order is:

1. Data model + codecs + validation (`listeners.py`)
2. Decoder module (`listeners_otlp.py`) — pure functions, easy to test
3. HTTP dispatcher branch (`app.py`)
4. Wizard tile + hit-pane preview (`admin.py`)
5. gRPC server (`listeners_grpc.py`) + lifespan wiring
6. docker-compose port + nginx server block
7. Tests
8. Live smoke (HTTP first, then gRPC)
9. README link

The HTTP half is operable and demoable after step 4; the gRPC half lights
up after step 6. Both must be green before the feature is committable
per the six-step gate.

## 15. OTLP egress — the symmetric half

The listener side documented above accepts OTLP exports *into* apigenie.
v4.1 also ships the mirror: a way to stream the same synthetic topics
and uploaded replay files *out* of apigenie to an external OTLP
collector. The implementation extends the pre-existing Log Push
framework (`log_pusher.py`) so existing primitives — profile CRUD,
RBAC, start/stop, rate + duration, event-log ring buffer, observability
hooks — all apply unchanged.

### 15.1. New push sources

| key                  | module                              | shape                        |
|----------------------|-------------------------------------|------------------------------|
| `synthetic_endpoint` | `push_sources/synthetic_endpoint.py`| EDR / process telemetry      |
| `synthetic_identity` | `push_sources/synthetic_identity.py`| SSO / IAM events             |
| `synthetic_cloud`    | `push_sources/synthetic_cloud.py`   | AWS / Azure / GCP audit      |
| `synthetic_network`  | `push_sources/synthetic_network.py` | Zeek-style flow + protocol   |
| `replay_file`        | `push_sources/replay_file.py`       | Streams an uploaded log file |

The four synthetic adapters are trivial wrappers around the same
generators the listener uses (`sources/synthetic/*.py`), so a topic that
plays back the same way on both sides has byte-identical structure
in-process. The replay source is **stateful** — it exposes
`make_iterator(profile) -> Iterator[dict]` instead of the stateless
`generate_event(ctx)` used by the 16 vendor sources, and the push loop
(`log_pusher._push_loop`) automatically picks the right calling
convention based on which symbol the module defines. This kept the
existing modules untouched.

### 15.2. New transports

```
                   wire shape per Log Push transport
   ┌────────────────────────────────────────────────────────────┐
   │  http        → POST <path> · JSON / Syslog / CEF text body │
   │  hec         → POST <path> · Splunk envelope               │
   │  syslog      → TCP/UDP    · RFC 5424 line                  │
   │  otlp_http   → POST /v1/<signal> · application/x-protobuf  │   ←  v4.1
   │  otlp_grpc   → unary RPC  · LogsService/Export, MetricsServ│   ←  v4.1
   └────────────────────────────────────────────────────────────┘
```

Both OTLP transports live in `otlp_pusher.py`. They marshal the
*structured* push event dict (not the text-formatted body the
existing transports use) into an `ExportLogsServiceRequest` and ship
it. `log_pusher.send_event` dispatches `otlp_http` / `otlp_grpc` to
this module via a single lazy import, leaving the hot path for the
JSON / syslog / CEF transports unchanged.

### 15.3. Dict → LogRecord mapping

For each push event dict `ev`:

```
LogRecord.time_unix_nano  := int(ev.timestamp · 1e9)   if parseable
                              else current wall-clock ns
LogRecord.severity_text   := mapped from ev.severity   (info|warn|…)
LogRecord.severity_number := OTel band number per the spec
LogRecord.body            := JSON-encoded ev as string_value
LogRecord.attributes      := whitelisted scalar keys (event_type,
                              src_ip, user, hostname, …). Nested
                              dicts/lists are kept in the JSON body.
```

The Resource is built once per export from the profile name and
source_type plus the optional `APIGENIE_DOMAIN` env, so a single
collector deployment can distinguish `apigenie / paloalto` from
`apigenie / synthetic_endpoint` without parsing log bodies.

### 15.4. Routing into an apigenie push-sink

Both the HTTP and gRPC transports honour a `listener_id` field on the
destination (also accepted at the profile root as `otlp_listener_id`).
When set, the outbound request carries:

| transport  | header / metadata                                     |
|------------|-------------------------------------------------------|
| otlp_http  | `X-Apigenie-Listener-Id: <lid>` AND `X-Scope-Orgid`   |
| otlp_grpc  | `x-apigenie-listener-id: <lid>` AND `x-scope-orgid`   |

These are exactly the headers the listener-side router consumes (§5.2,
§5.3), so an in-cluster smoke can point an OTLP push profile at a
push-sink listener and the export round-trips end-to-end with no
external collector needed.

### 15.5. Wizard

The push-profile editor (`admin.py`, push wizard) gets:

* **Transport** dropdown — adds `OTLP/HTTP` and `OTLP/gRPC`.
* **Source type** dropdown — adds the 5 new sources in addition to the
  16 vendor sources.
* **Replay file** picker — visible when `source_type == replay_file`,
  reuses the existing `/admin/api/replays` endpoint.
* **OTLP export** group — visible for the two OTLP transports; carries
  the signal (logs only in v4.1) and an optional listener_id field.
* Smart defaults: OTLP/HTTP auto-sets path `/v1/logs` + port 443 +
  TLS on; OTLP/gRPC auto-sets port 4317 + TLS off (in-cluster h2c).

### 15.6. Tests

`tests/test_otel_pusher.py` (added in this PR) covers:

* Source-registry contents (5 new + 16 vendor intact)
* Profile data-model round-trip (3 new fields)
* Synthetic generators + the replay iterator's required-field validation
* OTLP request build (logs only — proto round-trip + body / attribute /
  severity / timestamp mapping)
* OTLP/HTTP transport against a stub `http.server` (path + headers +
  protobuf parse-back)
* OTLP/gRPC transport against the **real** listeners_grpc server on an
  ephemeral port — end-to-end push profile → listener hit pane
* Dispatcher-level coverage that `log_pusher.send_event` routes
  `otlp_*` transports to `otlp_pusher.send`

### 15.7. Live smoke

`scripts/smoke_otlp_egress.py` is the operator smoke. It logs in,
creates a push-sink listener + an OTLP push profile pointing at it,
runs the profile for ~3 seconds at 5 eps, asserts that decoded events
landed on the listener hit pane, and cleans both objects up.

