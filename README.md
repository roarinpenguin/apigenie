# <img src="assets/logo.png" width="60" align="center" alt="ApiGenie logo"> ApiGenie

> Self-contained, **multi-user** mock server for **19 security platform APIs** plus **Azure Event Hubs (Kafka)** and **GCP Cloud Logging (Pub/Sub)** — built for [Observo](https://observo.ai) source-configuration testing and SE / customer demos.

ApiGenie exposes realistic, dynamically-varied data through the same authentication shapes the real platforms use (Bearer, Basic, X-ApiKeys, Duo HMAC, OAuth2 client-credentials, Microsoft tenant OAuth, GraphQL, Tenable async export, Kafka SASL/PLAIN, gRPC Pub/Sub). It runs as a single Docker Compose stack — nginx, FastAPI, Kafka + Zookeeper, Pub/Sub emulator — with TLS via Let's Encrypt, a self-signed cert, or your own files.

The deployment hostname is fully parameterised: pick any domain, run `./scripts/bootstrap.sh`, and the whole stack (nginx server names, TLS certs, Kafka advertised listeners, admin UI source-config examples) is rebuilt around it.

**Multi-tenant by design.** One ApiGenie deployment can host many isolated users — each with their own log profiles, detection rules, source identifiers, SentinelOne console, avatar and recovery flow. Admins drive the platform from `/admin`; users drive their own corner from `/portal`. Same TLS port, two distinct portals, role-aware UI, owner-scoped APIs. See **[Multi-user & RBAC](#multi-user--rbac)** below for the model, and the two companion guides in [`docs/`](docs/) for hands-on labs.

**Current release: v5.1** — *Security hardening + time-shifted attack stories*. Per-user SentinelOne console URL + API token moved out of the server entirely — they now live exclusively in the operator's browser `localStorage` and ride on every request as `X-S1-Console-URL` / `X-S1-Console-Token` headers. The admin-global S1 token is **Fernet-encrypted at rest** (key from `APIGENIE_SECRET_KEY` or auto-generated `data/secret.key`). Attack scenarios gain two new dimensions: a **Mode** switch (realtime keeps today's forward-running scheduler; historical pre-stages every event with backdated timestamps so the full attack story is immediately drainable by collectors) and a **Visibility** switch (private = only the launching user's collector token sees the backlog). Every scenario now also carries an auto-generated, expandable **Setup notes** card explaining which collectors / push profiles to configure for the run to play out end-to-end. See [`RELEASE_NOTES.md`](RELEASE_NOTES.md) for the full v4.0 → v5.1 chronology and the (container-only) upgrade path.

---

## Supported sources

### HTTP sources (FastAPI)

| # | Platform | Auth method | Key endpoints |
|---|----------|-------------|---------------|
| 1 | **Okta** | Bearer / SSWS | `GET /api/v1/logs` |
| 2 | **Netskope** | Bearer | `GET /api/v2/events/data/alert`, `/audit` |
| 3 | **Microsoft Entra ID** | OAuth2 (tenant-aware) | `GET /v1.0/auditLogs/directoryAudits`, `/signIns` · `POST /{tenant}/oauth2/v2.0/token` |
| 4 | **Microsoft Defender for Cloud** | Bearer | `GET /v1.0/subscriptions/{id}/providers/Microsoft.Security/alerts` |
| 5 | **Cisco Duo** | HMAC-SHA1 | `GET /admin/v1/logs/authentication`, `/admin/v2/...`, `/admin/v1/logs/administrator` |
| 6 | **Tenable VM** | X-ApiKeys (async export) | `POST /vulns/export` → `GET /vulns/export/{uuid}/status` → `GET /vulns/export/{uuid}/chunks/{n}` · `GET /audit-log/v1/events` |
| 7 | **Proofpoint TAP** | Basic Auth | `GET /v2/siem/all`, `/v2/siem/messages/blocked` |
| 8 | **Wiz** | OAuth2 + GraphQL | `POST /oauth2/token` → `POST /graphql` |
| 9 | **Snyk** | Bearer | `GET /v1/org/{id}/issues`, `/rest/orgs/{id}/issues` (JSON:API), `/projects`, `/audit` |
| 10 | **Darktrace** | HMAC-SHA1 | `GET /modelbreaches`, `/aianalyst/incident/log`, `/status`, `/groups` |
| 11 | **Microsoft 365** | OAuth2 (tenant → JWT) | Two modes: Graph API security alerts + Management Activity API. 14 event categories. See [Microsoft 365 Configuration](#microsoft-365-configuration) |
| 12 | **Cato Networks SASE** | x-api-key header | `POST /api/v1/graphql2` — eventsFeed (Security/IPS/AV/FW, Internet Access, WAN, Audit) + auditFeed. Marker-based pagination |
| 13 | **Cloudflare** | Bearer token | `GET /client/v4/zones/{id}/logs/received` (Logpull), `/firewall/events` (WAF), `/dns_analytics/report`, `/accounts/{id}/access/logs` (Zero Trust), `/gateway/audit_logs` |
| 14 | **Zscaler ZPA** | Bearer (OAuth2) | `GET /mgmtconfig/v2/admin/customers/{id}/userActivity`, `/auditLogEntryReport`, `/connectorStatus`, `/healthStatus` |
| 15 | **SentinelOne** | ApiToken header | `GET /web/api/v2.1/threats`, `/activities`, `/agents` — full MITRE ATT&CK mapping, cursor pagination, real console response shape |
| 16 | **Mimecast Email Security** | OAuth2 client credentials | `POST /oauth/token` → `GET /siem/v1/events/cg` — 8 log types: receipt, process, delivery, AV, spam, TTP URL/Attachment/Impersonation Protect |

> **AWS sources (CloudTrail, WAF, GuardDuty)** are intentionally not exposed via HTTP. Real Observo collectors fetch them via SQS-notified S3 polling using the AWS SDK with hostnames hardcoded to `*.amazonaws.com` and SigV4 host-binding, which apigenie cannot intercept. The data generators remain at `sources/aws_cloudtrail.py`, `sources/aws_waf.py`, and `sources/aws_guardduty.py` for a planned LocalStack-based extension — see [`docs/LOCALSTACK_PLAN.md`](docs/LOCALSTACK_PLAN.md).

### Log Push sources

Actively send generated logs to external destinations (S1 DPM/Observo, S1 AI SIEM, Splunk HEC, Syslog, HTTP POST). Configure via the Admin UI **Log Push** tab.

| # | Source | Event types |
|---|--------|-------------|
| 1 | **Palo Alto Firewall (PAN-OS)** | TRAFFIC, THREAT, URL, AUTH, USERID, SYSTEM, CONFIG, HIP-MATCH, GlobalProtect, WildFire, Decryption, Correlation |
| 2 | **Fortinet FortiGate** | Traffic, UTM (AV, IPS, Web Filter, App Control), Event, Anomaly |
| 3 | **Check Point NGFW** | Accept/Drop/Reject, Blade logs (IPS, AV, App Control, URL Filtering, Anti-Bot) |
| 4 | **Cisco ASA/FTD** | Connection build/teardown, denied, threat, VPN, AAA, system (syslog format) |
| 5 | **CrowdStrike Falcon** | DetectionSummaryEvent, IncidentSummaryEvent, AuthActivityAudit, UserActivityAudit |
| 6 | **VMware Carbon Black Cloud** | Alerts, watchlist hits, process events, audit |
| 7 | **Zscaler Internet Access (ZIA)** | Web transactions, firewall, DNS, tunnel (NSS format) |
| 8 | **Imperva Cloud WAF** | Security events, bot detection, ACL violations, DDoS mitigation |
| 9 | **Barracuda Email Security** | Spam, virus, DLP, ATP sandbox, admin audit |
| 10 | **Infoblox DDI** | DNS queries, RPZ hits, DHCP events, threat intelligence |
| 11 | **Cisco Switch (IOS/NX-OS)** | Port security, STP, ACL, AAA, CDP, DHCP snooping, ARP inspection |
| 12 | **HPE Aruba Switch (AOS-CX)** | 802.1X, RADIUS, STP, LLDP, ACL, DHCP snooping, PoE, VSF |
| 13 | **SentinelOne Singularity (XDR)** | Threats, Activities, Deep Visibility (process/network/file/registry), Audit, MITRE ATT&CK mapped |
| 14 | **Corelight / Zeek NDR** | conn.log, dns.log, http.log, ssl.log, files.log, notice.log, weird.log, x509.log, smtp.log, dpd.log |
| 15 | **CyberArk EPM / PAM** | Credential checkout/checkin, privileged sessions, policy violations, password changes, safe operations, admin audit |
| 16 | **Stamus Networks SSP (Suricata)** | IDS/IPS alerts, flow, DNS, HTTP, TLS, fileinfo, anomaly, stats (Suricata EVE JSON) |

### Streaming sources

| Platform | Transport | Endpoints |
|----------|-----------|-----------|
| **Azure Platform (Event Hubs)** | Kafka SASL/PLAIN | `apigenie.roarinpenguin.com:9093` (SASL_SSL) · `:9094` (SASL_PLAINTEXT) · `:9092` (PLAINTEXT, legacy) — topic `azure-platform-logs` |
| **GCP Cloud Logging (Pub/Sub)** | gRPC | `apigenie.roarinpenguin.com:8443` (TLS, recommended) · `:8085` (plaintext, emulator-aware SDKs only) — project `obs-test`, topic `audit-logs`, subscription `audit-logs-sub` |

A background publisher pushes 5 randomly-generated events into both streams every 10 seconds. Kafka events include **Entra ID / Azure AD user activity events** with user principal names, app sign-ins, device details, and risk levels.

---

## Architecture

```
                     Internet
                        │
        ┌───────────────┼─────────────────────────────┐
        │ 80/443        │ 8443             │ 9092/3/4 │ 8085
        ▼               ▼                  ▼          ▼
┌────────────────────────────────────────┐  ┌──────────────────┐
│            apigenie-nginx              │  │   apigenie-kafka │
│  Let's Encrypt TLS (HTTP + gRPC)       │  │   ZK + 4 listeners│
│  • 443  → apigenie:8000 (FastAPI)      │  │   PLAINTEXT       │
│  • 4317 → apigenie:4317 (OTLP/gRPC)    │  │   SASL_SSL        │
│  • 8443 → pubsub-emulator:8085 (gRPC)  │  │   (and more)      │
└────────────────┬───────────────────────┘  │   SASL_PLAINTEXT  │
                 │                          │   internal        │
                 ▼                          └──────────────────┘
       ┌──────────────────┐
       │     apigenie     │     ┌──────────────────┐
       │     FastAPI      │ →   │ pubsub-emulator  │
       │  + admin UI      │     │  gRPC :8085      │
       │  + 2 publishers  │     └──────────────────┘
       └──────────────────┘
```

All containers join the `apigenie-net` Docker network. Two one-shot init services (`kafka-cert-init`, `pubsub-emulator-seed`) prepare TLS material and create the topic/subscription before the broker and emulator start serving.

---

## Multi-user & RBAC

ApiGenie is a **multi-tenant** mock platform: one deployment, many isolated users. The same TLS port (`443`) exposes two distinct UIs — `/admin` for operators and `/portal` for end-users — and two distinct authentication models. Read this section once before configuring users; the rest of the README assumes it.

### Two portals, one stack

| Portal | Path | Who logs in | What they can do |
|--------|------|-------------|------------------|
| **Admin** | `/admin` | The built-in admin account (env-set password) | Everything — system settings, S1 console, entitlements, user CRUD, investigations, intrusions, container logs, request-log download, plus all user-portal capabilities |
| **User** | `/portal` | Any registered user (SQLite-backed account) — and admins can sign in here too, to operate as themselves or as a target user via the "Viewing as" switcher | Their own log profiles, detection rules, custom listeners, source identifiers, log-push profiles, avatar, account settings (Phase 3.5 — email, password, **personal SentinelOne console URL + API token**) |

Both portals share the same cookie (`ag_session`, `HttpOnly`, 24 h TTL). The user portal cannot see admin-only categories; the `_portal_role_guard` HTTP middleware in [`app.py`](app.py) rejects any user-portal session reaching an admin-only prefix at the HTTP layer.

### Authentication: source-data vs control-plane

ApiGenie speaks **two completely different APIs on the same port** — confusing them is the #1 source of "why does my request 401?" tickets:

| API surface | Examples | How you authenticate |
|-------------|----------|----------------------|
| **Source-data endpoints** (the whole point of ApiGenie — generate logs for a pipeline) | `/api/v1/logs`, `/web/api/v2.1/threats`, `/siem/v1/events/cg`, `/v1.0/auditLogs/directoryAudits`, … | The header the real vendor expects: `Authorization: SSWS …`, `Authorization: ApiToken …`, `Authorization: Bearer …`, `X-ApiKeys: …`, HTTP Basic, etc. The credential value identifies the *caller* — either a reserved demo token (public profile) or a **per-user identifier** the user registered in the portal. |
| **Control-plane** (`/admin/api/*` and `/portal/api/*`) | `/admin/api/me`, `/admin/api/rbac/users`, `/admin/api/detection-rules`, `/admin/api/s1/test`, … | The `ag_session` cookie issued by `POST /admin/login` or `POST /portal/login`. **Per-user SentinelOne override (v5.1):** additionally send `X-S1-Console-URL` and `X-S1-Console-Token` headers; values stored client-side in `localStorage`. |

The source-data token authenticates the *caller* for log-shaping (which profile / detection rules to inject). The session cookie authenticates the *operator* for control-plane changes. They never overlap.

### Entitlements + permissions

Every registered user has an **entitlement** — a named bundle of `{category: [permissions]}` assignments — plus a flat `is_admin` bit. Five categories × five permissions:

- Categories: **Log Profiles · Detection Rules · Log Push Profiles · Custom Listeners · Source Bindings**
- Permissions per category: **View · Create · Modify · Delete · Manage**

Admins implicitly hold every permission. Permission enforcement is **server-side** for every write endpoint (UI hiding is best-effort UX); see `_portal_role_guard` and `permission_error` in [`app.py`](app.py) and `accounts.has_permission` / `accounts.get_permissions` in [`accounts.py`](accounts.py).

Admin-only categories are not in entitlements at all: **Intrusions · Investigations & Bans · Container Logs · Observability · System Settings · Entitlement / User management**.

### Per-user identifier matching (pull sources)

Each pull source stays a **single shared endpoint** (e.g. `GET /api/v1/logs`). The credential the collector presents (Bearer token, tenant id, API key, …) is matched against per-user identifiers the user registered in the portal under **Source Identifiers**. The first match wins:

```
collector → Authorization: SSWS alice-okta-personal-001
              │
              ▼
  ApiGenie  → match "SSWS alice-okta-personal-001" against `identifiers` table
              → resolves to user_id=alice
              → applies Alice's profile binding, log volume intensity, custom fields,
                detection-rule injections, custom entity blending
              → response is shaped for Alice
```

No match? Falls back to the public profile binding (reserved demo tokens like `apigenie-valid-token-001` always hit the public profile).

### Per-user SentinelOne console (v5.1 — browser-only)

Every registered user can configure their **own** S1 console URL + API token via the portal **My Account** tab. As of v5.1 the credentials are stored **only in the browser** (`localStorage` keys `apigenie.s1.console_url` and `apigenie.s1.api_token`) and forwarded on every authenticated request as the headers `X-S1-Console-URL` and `X-S1-Console-Token`. A global `fetch` wrapper installed at admin shell load handles the header injection transparently. Server-side, `s1_detection_library._resolved_settings()` reads them from a request-scoped `ContextVar` set by the middleware in [`app.py`](app.py), then falls back to the admin-global console (Fernet-encrypted at rest) when no headers are present. **The server never persists a per-user S1 token.** Two SEs / customers / analysts sharing the same ApiGenie deployment can each point at their own S1 console without coordination, and a leaked SQLite file carries zero real tokens.

### RBAC quickstart (~5 minutes)

```bash
# 0. Make sure the stack is up and you can log into /admin
curl -sk -c /tmp/admin.jar -X POST \
  -d "username=admin&password=<admin-pw>" \
  https://<your-domain>/admin/login

# 1. Create an entitlement that grants full access to log profiles + detection rules
curl -sk -b /tmp/admin.jar -X POST -H "Content-Type: application/json" \
  -d '{"name":"SOC Analyst","description":"Full LP+DR control",
       "permissions":{"log_profiles":["view","create","modify","delete","manage"],
                      "detection_rules":["view","create","modify","delete","manage"],
                      "source_bindings":["view","create","modify"]}}' \
  https://<your-domain>/admin/api/rbac/entitlements

ENT_ID=$(curl -sk -b /tmp/admin.jar \
  https://<your-domain>/admin/api/rbac/entitlements | jq -r '.[] | select(.name=="SOC Analyst") | .id')

# 2. Create Alice WITHOUT a password — get back a one-time handoff link instead
curl -sk -b /tmp/admin.jar -X POST -H "Content-Type: application/json" \
  -d "{\"username\":\"alice\",\"email\":\"alice@team.io\",\"entitlement_id\":\"$ENT_ID\"}" \
  https://<your-domain>/admin/api/rbac/users
# → { "user": {...}, "setup_link": "/portal/set-password?token=..." }

# 3. Share that setup_link with Alice (chat, ticket, sticky note — no SMTP needed).
#    Alice opens it, sets her password, and lands on /portal/login.

# 4. Alice signs in and immediately gets her own slice of ApiGenie: My Account, Source
#    Identifiers, her log profiles, her detection rules, her S1 console.
```

For the full guided lab — including avatars, recovery links, acting-as switching, per-user S1 verification and cross-user isolation tests — see [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) Section 0 and [`docs/ADMIN_GUIDE.md`](docs/ADMIN_GUIDE.md) Section 0.

### Phase summary & regression tests

The RBAC story landed in four phases. All 91 tests pass under `pytest`:

| Phase | What | Tests |
|-------|------|-------|
| **P1** | Identity & RBAC core: SQLite accounts, entitlements, permission model, two-portal auth, admin user-CRUD, retirement of the legacy investigation password gate | `tests/test_rbac_phase2.py` (Phase 1 fundamentals are exercised by every later test) |
| **P2** | Data ownership: `owner_id` + `visibility` on profiles / rules / push / listeners / bindings, per-user isolation, public publishing, per-source identifier matching, source-detail placeholders in the user portal | `tests/test_rbac_phase2.py`, `tests/test_rbac_phase2_5_detection.py` |
| **P3** | Polish: per-user avatars (Pillow circle), admin-handoff confirm / recovery links (no SMTP), Log-Push detection-rule injection scoping | `tests/test_rbac_phase3_avatars.py`, `tests/test_rbac_phase3_recovery.py`, `tests/test_rbac_phase3_log_push.py` |
| **P3.5** | Self-service: email, password (verifies current), per-user SentinelOne console URL + API token. New caller-context middleware automatically scopes every `/admin/api/s1/*` call to the resolved user | `tests/test_rbac_phase35_self_service.py`, `tests/test_rbac_phase35_endpoints.py` |

Run the whole suite inside the container:

```bash
docker exec apigenie pip install --quiet pytest pytest-asyncio   # one-time
docker exec apigenie python -m pytest tests/ -v
```

For the full design rationale see [`docs/MULTI_USER_LOG_PROFILING.md`](docs/MULTI_USER_LOG_PROFILING.md).

---

## Deployment

### Prerequisites

- Docker + Docker Compose v2 on a host with a public DNS name resolving to it (or just use `localhost` for a lab)
- `python3` and `openssl` on the host (used only by `scripts/bootstrap.sh`; not needed at runtime)
- Inbound firewall (e.g. UFW on Ubuntu) allowing the ports listed below

That's it. Cert issuance, renewal, and the entire lifecycle live inside the stack — no host-side certbot, no cron jobs, no `/etc/letsencrypt`.

### Firewall

```bash
sudo ufw allow 80/tcp        # HTTP → HTTPS redirect (and Let's Encrypt HTTP-01)
sudo ufw allow 443/tcp       # Main HTTPS API + admin UI
sudo ufw allow 8443/tcp      # Pub/Sub gRPC over TLS
sudo ufw allow 8085/tcp      # Pub/Sub gRPC plaintext (optional)
sudo ufw allow 9092/tcp      # Kafka PLAINTEXT (legacy)
sudo ufw allow 9093/tcp      # Kafka SASL_SSL (Event Hubs)
sudo ufw allow 9094/tcp      # Kafka SASL_PLAINTEXT
```

### Deploy (first time)

```bash
git clone https://github.com/roarinpenguin/apigenie.git
cd apigenie
./scripts/bootstrap.sh                # interactive: domain, admin pwd, TLS mode
docker compose up -d --build
```

The bootstrap script writes a `.env` file and populates `./certs/<domain>/` with either:
- a **self-signed** 825-day cert (lab default — browsers warn, collectors need TLS verify off),
- a **Let's Encrypt** cert via certbot HTTP-01 on port 80 (production), or
- **provided** files you place yourself.

For Let's Encrypt mode, bootstrap puts `COMPOSE_PROFILES=letsencrypt` in your `.env` so plain `docker compose up -d` includes the **`apigenie-certbot`** sidecar. That container:

1. On first start, issues a real Let's Encrypt cert via HTTP-01 on port 80 (~10 s after nginx is up).
2. Wakes up every 12 h and runs `certbot renew --keep-until-expiring` (no-op until within 30 days of expiry).
3. After every renewal, copies the new cert into `./certs/<domain>/`, sends nginx `SIGHUP` for a zero-downtime reload, and restarts kafka so the SASL_SSL listener picks up the new cert.

Watch it with `docker logs -f apigenie-certbot`.

### Verify

```bash
curl -sk https://${APIGENIE_DOMAIN}/health
# {"status":"ok","service":"apigenie"}

docker logs apigenie-kafka-cert-init   # wrote /secrets/kafka-combined.pem
docker logs apigenie-pubsub-seed       # topic + subscription created
docker compose ps                      # all containers up
```

### Update

```bash
docker compose down
git pull
docker compose up -d --build
```

`.env` and `./certs/` are gitignored and persist across pulls. If a future commit adds a new env var, copy the new line over from `.env.example` manually — or just re-run `./scripts/bootstrap.sh` (it loads existing values as prompt defaults; press enter to keep them).

### Migrating from a pre-portable deployment

If you're upgrading from an earlier apigenie that mounted `/etc/letsencrypt:ro` into nginx, do this once:

```bash
docker compose down
git pull
./scripts/bootstrap.sh                            # detects existing cert, offers to import
# OR, if you already have .env:
./scripts/migrate-certs.sh apigenie.example.com   # explicit import
docker compose up -d --build
```

The imported cert lets nginx boot. The in-stack certbot manager re-issues it once (one-time duplicate, well under the rate limit) and from then on owns the renewal lifecycle. You can then disable the host-side certbot.

### Change the domain later

Edit `APIGENIE_DOMAIN` in `.env`, then:

```bash
# Self-signed lab: regenerate the cert
./scripts/gen-self-signed.sh <new-domain>
# Let's Encrypt: nothing to do — apigenie-certbot will issue on next cycle
docker compose up -d              # nginx re-renders its config from the template
docker compose restart kafka-cert-init kafka   # rewrite advertised listeners + SASL JAAS
```

---

## Authentication credentials

Use these when configuring sources in Observo (or any HTTP client):

| Auth type | Header | Value |
|-----------|--------|-------|
| Bearer token | `Authorization: Bearer <token>` | `apigenie-valid-token-001` … `003` |
| Basic Auth | `Authorization: Basic <b64>` | `apigenie-principal-001` / `apigenie-secret-001` |
| X-ApiKeys (Tenable) | `X-ApiKeys` | `accessKey=apigenie-ak-001;secretKey=apigenie-sk-001` |
| Cisco Duo | HMAC-SHA1 (signature mocked) | any Authorization value accepted |
| OAuth2 client_credentials | `POST /oauth2/v1/token` | returns valid Bearer token |
| Microsoft tenant OAuth | `POST /{tenant}/oauth2/v2.0/token` | tenant id can be UUID or named |

### Error simulation

Substitute the Bearer token to trigger specific HTTP errors:

| Token | Response |
|-------|----------|
| `apigenie-error-401` | 401 Unauthorized |
| `apigenie-error-403` | 403 Forbidden |
| `apigenie-error-404` | 404 Not Found |
| `apigenie-error-429` | 429 Rate Limited |
| `apigenie-error-500` | 500 Internal Server Error |

---

## Portals — `/admin` and `/portal`

ApiGenie ships two UIs on the same TLS port. They share assets (sidebar, dashboard chrome, toast system, …) but differ in visibility, navigation and the API surface they can drive. See [Multi-user & RBAC](#multi-user--rbac) above for the model; this section covers the surfaces and where to find things.

### Admin portal — `/admin`

Login: `admin` / *(password set during `bootstrap.sh`)*. The admin password is stored as a PBKDF2-HMAC-SHA256 hash (600k iterations) in either the `ADMIN_PASSWORD_HASH` env var or, after the first in-app change, the override file at `./data/admin_pass`. The plaintext `ADMIN_PASSWORD` env var only acts as a first-boot fallback when no hash is present.

The admin sidebar is grouped into four sections:

| Section | Items |
|---------|-------|
| **Monitor** | Observability *(admin)* · Requests *(both portals)* |
| **Troubleshooting** | Intrusions · Investigations · Container Logs *(all admin-only)* |
| **Configuration & Reference** | Listeners · Log Profiles & Detection Rules · Log Push · Source Identifiers · Source Details · **My Account** *(Phase 3.5; both portals)* |
| **System** | System Settings *(admin-only)* |

The **System Settings** tab exposes the resolved domain, Kafka advertised host, TLS mode, where the active admin password is coming from, the live TLS cert metadata, a one-click **Renew certificate** button that prints the exact host-side command for your TLS mode, a **Change admin password** form, a **Change user-portal password** form (for the legacy shared user-portal password, kept as a back-door), and the global **SentinelOne console** settings.

Beyond System Settings, the admin tabs cover:

| Tab | What it shows |
|-----|---------------|
| **Requests** | Live trace of every inbound HTTP request, grouped by source. Shows request headers, body, **response size and preview**. Includes Pub/Sub and Kafka heartbeats, plus a **Bus Subscribers** panel showing Kafka consumer groups and Pub/Sub subscription status with lag and member counts |
| **Observability** | Four sub-tabs: **Flows** (Sankey: source IPs → log sources), **GeoMap** (world map with IP bubbles), **Usage** (stacked area chart, 1h–1y range, SQLite-backed), and **System** (real-time host CPU/RAM/disk + per-container resource monitoring via Docker API) |
| **Intrusions** | Threat detection for unrecognised paths (scanners, bots, attackers). Categorizes attempts (credential_theft, wordpress_scan, rce_attempt, php_scan, etc.), shows top offenders with one-click banning, and supports **acknowledgement** of known-good paths with multi-condition suppression (path, IP, category, prefix — AND logic). Acknowledged paths are persisted and silently counted |
| **Listeners** | Custom HTTP endpoints for collector testing — three kinds: **synthetic data** (endpoint / identity / cloud / network), **replay** of uploaded log files (json / jsonl / csv / syslog / cef), or **OTLP push sink** that accepts OpenTelemetry exports over OTLP/HTTP (port 443) and OTLP/gRPC (port 4317) from any collector (OpenTelemetry Collector, Splunk OTel Collector, Vector, OTel SDKs). Design: [`docs/CUSTOM_LISTENERS.md`](docs/CUSTOM_LISTENERS.md), [`docs/OTEL_LISTENER.md`](docs/OTEL_LISTENER.md) |
| **Container Logs** | Tail logs of any container via `docker logs --follow` |
| **Investigations** | IP lookup (WHOIS, rDNS, GeoIP), request history, anomaly detection, and IP banning. Request log files downloadable as JSONL. *(The earlier investigation-password gate was removed in Phase 1 — Investigations is now plain admin-only.)* |
| **Log Profiles & Detection Rules** | Entity pools (users, machines, C2 servers, malware, mail senders) bound to sources with signal-to-noise ratio. **Per-source log volume control** (1–100%) scales how many logs each API response contains. **Detection Rules** inject SIEM-triggering log patterns at configurable periodicity. Owner-scoped — admin sees everything, can publish public; users only see their own + public. See [Log Profiles](#log-profiles) and [Detection Rules](#detection-rules) below |
| **Log Push** | Actively send generated logs to external destinations. Push profiles also inherit owner-scoped detection-rule injection (Phase 3). 10 source types, 3 formats, 3 transports. See [Log Push](#log-push) below |
| **Source Identifiers** | Register the credential value a collector presents (Bearer token, tenant id, API key, …) and bind it to a source. ApiGenie uses identifier matching to resolve per-user log shaping on every pull request. Built-in demo tokens are reserved and rejected here |
| **Source Details** | Reference cards per platform with copy-pasteable endpoints, auth values, and `curl` / `kcat` examples. **User portal sees placeholders** instead of the shared demo tokens (Phase 2 substitution layer) |
| **My Account** *(Phase 3.5)* | Self-service email, password change (verifies current), and **personal SentinelOne console URL + API token**. When set, every `/admin/api/s1/*` call from this session uses *your* console. Disabled and inert for the built-in admin |

### User portal — `/portal`

Login: any registered user (`POST /portal/login`) or — for back-door admin access without the admin portal's broader surface — the built-in admin credentials (creates an `is_admin=true` session marked `role=user`, which is what powers the "Viewing as" switcher).

The user portal shows the **Configuration & Reference** section only: **Listeners · Log Profiles & Detection Rules · Log Push · Source Identifiers · Source Details · My Account**. Plus the **Requests** tab. Everything else (Observability, Intrusions, Investigations, Container Logs, System Settings, Entitlements, User CRUD) is hidden client-side and blocked server-side via `_portal_role_guard`.

Admin signed into `/portal` gets the **"Viewing as" user-switcher** in the topbar: pick a target user, and every owner-scoped read & write happens in that user's namespace (their bindings, identifiers, profiles, rules, S1 console). Useful for support and reproduction without password sharing. The acting-as state lives on the in-memory session record and clears on logout.

### GeoMap data source

The GeoMap tab uses a hybrid resolver:

1. If `./data/geoip/GeoLite2-City.mmdb` is present → offline lookup via the bundled file (fast, no rate limit).
2. Otherwise → on-demand calls to `ip-api.com/json/<ip>` (free, 45 req/min, requires outbound HTTPS).

To enable offline lookups, get a free MaxMind license key at <https://www.maxmind.com/en/geolite2/signup> and either run the bootstrap (it will prompt for the key and download the DB) or refresh manually:

```bash
echo 'MAXMIND_LICENSE_KEY=your_key_here' >> .env
./scripts/refresh-geoip.sh         # writes ./data/geoip/GeoLite2-City.mmdb
docker compose restart apigenie
```

MaxMind ships weekly updates; re-running the script (or scheduling it via cron) keeps the DB current.

### Useful control-plane endpoints

Both `/admin/api/*` and `/portal/api/*` are gated by the `ag_session` cookie (see [Authentication: source-data vs control-plane](#authentication-source-data-vs-control-plane)). Path **prefixes** marked admin-only return 403 for user-role sessions (`ADMIN_ONLY_API_PREFIXES` in [`admin.py`](admin.py)); everything else is shared and owner-scoped.

**Identity, auth & RBAC**

| Path | Purpose | Admin-only |
|------|---------|------------|
| `/admin/login` · `/admin/logout` | Admin portal login form / session destroy | — |
| `/portal/login` · `/portal/logout` | User portal login form / session destroy | — |
| `/portal/set-password?token=…` | One-shot handoff page where new users / password-recovery flows land | — |
| `/admin/api/me` | Current session identity + effective permissions + has_avatar flag | no |
| `/admin/api/me/account` | Self-service profile snapshot (email, is_builtin_admin) — **Phase 3.5** | no |
| `/admin/api/me/email` | `PUT` to change your own email — **Phase 3.5** | no |
| `/admin/api/me/password` | `PUT` to change your own password (verifies current) — **Phase 3.5** | no |
| ~~`/admin/api/me/s1-console`~~ | **Removed in v5.1.** Per-user S1 console is now stored in browser `localStorage` and sent on each request via `X-S1-Console-URL` / `X-S1-Console-Token` headers. | n/a |
| `/admin/api/act-as` | `GET`/`POST`/`DELETE` the admin "Viewing as" switcher | implicit (is_admin) |
| `/admin/api/users/me/avatar` | `POST` (multipart) / `DELETE` your own avatar — **Phase 3** | no |
| `/admin/api/users/{uid}/avatar` | `GET` any user's avatar (PNG) | no |
| `/admin/api/rbac/meta` | Category / permission / identifier-kind vocabulary | yes |
| `/admin/api/rbac/entitlements` | `GET`/`POST` entitlements; `PUT`/`DELETE` on `/{eid}` | yes |
| `/admin/api/rbac/users` | `GET`/`POST` users; `PUT`/`DELETE` on `/{uid}` | yes |
| `/admin/api/rbac/users/{uid}/password` | `POST` to admin-reset a user's password (no current-pw challenge) | yes |
| `/admin/api/rbac/users/{uid}/reset-link` | `POST` to mint a one-shot `/portal/set-password?token=…` link | yes |
| `/admin/api/identifiers` | List / register per-user source identifiers | no (owner-scoped) |
| `/admin/api/change-password` | Legacy form-encoded admin password change | yes |
| `/admin/api/change-user-password` | Set the legacy shared user-portal password | yes |

**Telemetry config (owner-scoped — admin sees everything, users see their own + public)**

| Path | Purpose | Admin-only |
|------|---------|------------|
| `/admin/api/profiles` · `/admin/api/profiles/{id}` · `/admin/api/profiles/{id}/preview` | Log Profiles CRUD + entity-pool preview | no |
| `/admin/api/source-profiles[/{source}]` | Bind/unbind a profile to a source with blend ratio | no |
| `/admin/api/source-intensity[/{source}]` | Per-source log volume (1–100%) | no |
| `/admin/api/detection-rules[/{id}]` | Detection Rules CRUD | no |
| `/admin/api/listeners[/{id}]` | Custom HTTP listeners CRUD | no |
| `/admin/api/push/source-types` | Catalogue of Log-Push source types | no |
| `/admin/api/push/profiles[/{id}]` | Log-Push profiles CRUD | no |
| `/admin/api/push/profiles/{id}/start` · `/stop` · `/status` · `/events` · `/tls` | Runtime control + observability | no |

**S1 Detection Library**

| Path | Purpose | Notes |
|------|---------|-------|
| `/admin/api/s1/settings` | `GET`/`POST` the **admin-global** console settings (token Fernet-encrypted at rest since v5.1) | per-user override sent as `X-S1-Console-URL` / `X-S1-Console-Token` headers (v5.1) |
| `/admin/api/s1/test` | Connection check (uses *resolved* settings — global or per-user) | — |
| `/admin/api/s1/data-sources` | Discoverable data-source list | — |
| `/admin/api/s1/rules[/for-phase]` · `/admin/api/s1/custom-rules` | Query the catalog & custom rules | — |
| `/admin/api/s1/rules/{id}/{enable,disable,import-preview}` · `/admin/api/s1/rules/import` | Enable/disable on S1; preview + import to local detection rules | — |

**Admin-only diagnostic / observability surfaces**

| Path | Purpose |
|------|---------|
| `/admin/gcp-sa.json` | Fresh in-memory RSA-2048 GCP service-account JSON for collectors that need a credentials file. `token_uri` points back at our fake OAuth endpoint so the collector never reaches real Google. |
| `/admin/api/requests/{source}` | JSON request trace for a source (drives the dashboard) |
| `/admin/api/flows[?ip=…]` | Sankey feed (IP × source) |
| `/admin/api/geo` | GeoMap feed (per-IP totals + lat/lon) |
| `/admin/api/usage?range=…` | Usage-over-Time (`1h 6h 24h 7d 30d 90d 1y`) |
| `/admin/api/logs/{container}` | SSE stream of container logs |
| `/admin/api/investigate/{ip}` | IP investigation context (WHOIS, GeoIP, request history) |
| `/admin/api/bans` | List / create IP bans |
| `/admin/api/request-logs/stats` · `/admin/api/request-logs/{file}` | Request-log metadata + JSONL download |
| `/admin/api/intrusions[/log\|/acknowledge]` | Intrusion stats, log, suppress |
| `/admin/api/sysmon[/latest]` | Host CPU/memory/disk + container stats |
| `/admin/api/bus-status` | Kafka consumer groups + Pub/Sub subscription status |

---

## Tenable async export flow

Tenable uses a 3-step stateful export API — implemented fully in-memory with TTL eviction:

```
POST  /vulns/export                          → { "export_uuid": "..." }
GET   /vulns/export/{uuid}/status            → { "status": "FINISHED", "chunks_available": [1,2,3] }
GET   /vulns/export/{uuid}/chunks/{chunk_id} → [ { vuln }, ... ]
```

Same pattern for `/assets/export`. Exports are cached for 1 hour then auto-evicted.

`GET /audit-log/v1/events` returns Tenable platform audit events with `f=` filter and `next=` cursor support.

`GET /api/v1/refresh-access-token` returns a Bearer token for collectors that exchange X-ApiKeys for a temporary token.

---

## GCP Pub/Sub — emulator-aware vs production-shape clients

The emulator is plaintext gRPC on port `8085`. There are two ways to connect:

### Option A — emulator-aware (preferred, simplest)

The collector honours `PUBSUB_EMULATOR_HOST=apigenie.roarinpenguin.com:8085` and bypasses authentication entirely. No SA JSON, no TLS.

### Option B — production-shape (for Observo and similar collectors)

The collector treats the emulator like real GCP: TLS, SA JSON, OAuth2 JWT exchange. We support this end-to-end:

- **Pub/Sub endpoint:** `apigenie.roarinpenguin.com:8443` — nginx terminates TLS using Let's Encrypt and forwards plaintext gRPC to the emulator
- **Service account:** download from `https://apigenie.roarinpenguin.com/admin/gcp-sa.json` and upload as the GCP credentials file
- **OAuth2 token endpoint:** `https://apigenie.roarinpenguin.com/oauth2/token` (already baked into the SA JSON's `token_uri` field) — accepts any JWT assertion, returns a synthetic access token

Configure the Observo GCP source:

| Field | Value |
|-------|-------|
| Pub/Sub Endpoint | `apigenie.roarinpenguin.com:8443` |
| Project ID | `obs-test` |
| Subscription | `audit-logs-sub` |
| Credentials | upload `/admin/gcp-sa.json` |

---

## Azure Event Hubs (Kafka)

Three external listeners cover every Observo / Event Hubs configuration:

| Listener | Port | Auth | When to use |
|----------|------|------|-------------|
| `EXTERNAL` | 9092 | none | Plain Kafka clients, no SASL |
| `SASLSSL` | 9093 | SASL_SSL + PLAIN | **Real Event Hubs shape — recommended for Observo** |
| `SASLPLAIN` | 9094 | SASL_PLAINTEXT + PLAIN | Same auth as 9093, no TLS — lab override when the collector cannot validate the cert |

SASL/PLAIN credentials accepted on 9093 and 9094:

| Username | Password |
|----------|----------|
| `admin` | `apigenie-eh-admin-2026` |
| `$ConnectionString` | `Endpoint=sb://apigenie.roarinpenguin.com/;SharedAccessKeyName=mock;SharedAccessKey=apigenie-eh-mock-2026;EntityPath=azure-platform-logs` |

Configure the Observo Azure Platform source:

| Field | Value |
|-------|-------|
| Event Hubs Namespace Endpoint | `apigenie.roarinpenguin.com:9093` |
| Event Hub Name | `azure-platform-logs` |
| Consumer Group | anything (e.g. `observo-az`) |
| SASL Mechanism | `PLAIN` |
| Connection String | (the password above) |

Verify from the host:

```bash
kcat -b apigenie.roarinpenguin.com:9094 -t azure-platform-logs -C \
  -X security.protocol=SASL_PLAINTEXT -X sasl.mechanism=PLAIN \
  -X sasl.username='$ConnectionString' \
  -X sasl.password='Endpoint=sb://apigenie.roarinpenguin.com/;SharedAccessKeyName=mock;SharedAccessKey=apigenie-eh-mock-2026;EntityPath=azure-platform-logs'
```

---

## Project structure

```
apigenie/
├── app.py                    # FastAPI app + role-guard middleware + per-request caller-context binding
├── admin.py                  # Both portals (/admin & /portal), dashboard HTML, all control-plane APIs
├── accounts.py               # RBAC: users, entitlements, identifiers, recovery tokens — SQLite (apigenie.db)
├── avatars.py                # Per-user 250×250 circular PNG store (Pillow) — Phase 3
├── s1_detection_library.py   # S1 console settings + _resolved_settings (per-user override) — Phase 3.5
├── auth.py                   # Bearer / Basic / X-ApiKeys / Duo HMAC dependency injectors + identifier matching
├── profiles.py               # Log Profiles: CRUD, Star Wars padding, ProfileContext, per-source intensity, caller ContextVar
├── detection_rules.py        # Detection Rules: CRUD, field override injection, count/time-based periodicity, owner scoping
├── log_pusher.py             # Log Push framework: transports, formatters, scheduling, CRUD, observability, caller-aware injection
├── listeners.py              # Custom HTTP listeners (Phase 2 owner-scoped)
├── intrusions.py             # Intrusion tracking: path classification, per-IP aggregation, acknowledgement
├── sysmon.py                 # System resource monitor: CPU, memory, disk, Docker container stats
├── bus_monitor.py            # Kafka consumer-group + Pub/Sub subscription status poller
├── bans.py                   # IP ban management (persistent JSON)
├── telemetry.py              # Persistent usage telemetry: SQLite, minute-granularity, 1-year retention
├── trace.py                  # Request-tracing middleware → REQUEST_TRACE deque + AGG (client_ip × source) LRU
├── geoip.py                  # Hybrid GeoIP resolver: MaxMind .mmdb if present, else ip-api.com
├── state.py                  # Thread-safe Tenable export cache (TTL eviction)
├── generators.py             # Random-data helpers (UUID, IP, hostname, weighted choice)
├── tests/                    # 91 pytest tests (RBAC Phases 1–3.5) with isolated tmp storage
│   ├── conftest.py           # Redirects all storage paths to tmp BEFORE any project import
│   ├── test_rbac_phase2.py · test_rbac_phase2_5_detection.py
│   ├── test_rbac_phase3_{avatars,recovery,log_push}.py
│   └── test_rbac_phase35_{self_service,endpoints}.py
├── nginx/
│   └── nginx.conf            # 443 HTTPS + 8443 gRPC TLS proxy
├── html/
│   └── index.html            # Public landing page
├── sources/                  # One module per pull platform (data generators, profile-aware)
│   ├── okta.py · netskope.py · azure_ad.py · m365.py · microsoft_defender.py · cisco_duo.py
│   ├── gcp_audit.py · tenable.py · proofpoint.py
│   ├── wiz.py · snyk.py · darktrace.py · sentinelone.py · mimecast.py
│   ├── cato.py · cloudflare.py · zscaler_zpa.py
│   ├── aws_cloudtrail.py · aws_waf.py · aws_guardduty.py    # generators only (no HTTP routes — see LocalStack plan)
│   └── synthetic/            # Synthetic topics for custom listeners (also profile-aware)
├── push_sources/             # Push log generators (one module per vendor)
│   ├── paloalto.py · fortigate.py · checkpoint.py · cisco_asa.py
│   ├── crowdstrike.py · carbonblack.py · zscaler.py
│   ├── imperva.py · barracuda.py · infoblox.py
│   ├── cisco_switch.py · aruba_switch.py · corelight.py · cyberark.py · stamus.py · sentinelone.py
├── publishers/
│   ├── kafka_publisher.py    # Background thread → Kafka topic azure-platform-logs
│   └── pubsub_publisher.py   # Background thread → Pub/Sub topic audit-logs
├── docs/
│   ├── USER_GUIDE.md         # Hands-on lab (single-user + RBAC exercises)
│   ├── ADMIN_GUIDE.md        # Admin lab (entitlements, viewing-as, audit, …) + API reference
│   ├── MULTI_USER_LOG_PROFILING.md   # RBAC design rationale (Phases 1–3.5)
│   ├── AWS_DEPLOYMENT.md     # Zero-to-hero AWS deployment guide
│   ├── CUSTOM_LISTENERS.md · LOCALSTACK_PLAN.md · …
├── scripts/
│   ├── bootstrap.sh          # Interactive first-run: domain, admin pwd, TLS mode, optional MaxMind key
│   ├── gen-self-signed.sh    # Generate a self-signed cert for ./certs/<domain>/
│   ├── migrate-certs.sh      # Move existing Let's Encrypt material into ./certs/<domain>/
│   ├── refresh-geoip.sh      # Download/update GeoLite2-City.mmdb (cron-safe, atomic)
│   ├── hash_password.py      # PBKDF2-SHA256 hasher used by bootstrap to set ADMIN_PASSWORD_HASH
│   ├── seed-fake-traffic.sh  # Generate X-Forwarded-For-spoofed traffic for Flows/GeoMap demos
│   ├── smoke-test.sh         # Regression suite (functional + admin endpoints)
│   ├── check_dashboard_js.py # Parse-check the rendered dashboard JS (catch admin.py JS bugs early)
│   └── admin-screenshot.py   # Headless-Chrome driver: screenshot /admin tabs + dump console
├── terraform/                # Parametrised AWS deployment (EC2 + EIP + SG + IAM + cert-bot bootstrap)
├── docker-compose.yaml       # nginx, apigenie, zookeeper, kafka-cert-init, kafka, pubsub-emulator, pubsub-emulator-seed, certbot
├── Dockerfile                # python:3.13-slim + uv + docker-cli + Pillow + pytest (for admin log streaming + avatar processing + in-container tests)
├── pyproject.toml
└── assets/
    └── logo.png
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Uvicorn / app log level |
| `PUBLISHERS_ENABLED` | `true` | Enable background Kafka + Pub/Sub publishers |
| `APIGENIE_DOMAIN` | `apigenie.example.com` | Public hostname — drives nginx server names, cert paths, Kafka advertised listener |
| `APIGENIE_TLS_MODE` | `self-signed` | One of `self-signed`, `letsencrypt`, `existing` (set by bootstrap) |
| `APIGENIE_TLS_EMAIL` |  | Contact email for Let's Encrypt registration (only when `APIGENIE_TLS_MODE=letsencrypt`) |
| `APIGENIE_KAFKA_ADVERTISED_HOST` | = `APIGENIE_DOMAIN` | Override the Kafka SASL_SSL advertised host if it differs from the API hostname |
| `ADMIN_USERNAME` | `admin` | Admin portal login |
| `ADMIN_PASSWORD` | `apigenie` | First-boot fallback admin password (only used if no hash is set) |
| `ADMIN_PASSWORD_HASH` |  | PBKDF2-HMAC-SHA256 hash (600k iterations); takes precedence over `ADMIN_PASSWORD` |
| `ADMIN_PASSWORD_FILE` | `/var/lib/apigenie/admin_pass` | On-disk override location for the admin hash (written by `POST /admin/api/change-password`). Wins over the env var when present. |
| `USER_PORTAL_USERNAME` | `user` | Legacy shared user-portal username (back-door — kept for upgrade paths; real users live in the SQLite accounts table) |
| `USER_PORTAL_PASSWORD` |  | Legacy shared user-portal password — defaults to the admin password when empty |
| `USER_PORTAL_PASSWORD_HASH` |  | Hash equivalent for `USER_PORTAL_PASSWORD` |
| `USER_PASSWORD_FILE` | `/var/lib/apigenie/user_pass` | On-disk override for the legacy shared user-portal hash |
| `APIGENIE_DATA_ROOT` | `/var/lib/apigenie` | Root of JSON state for `profiles`, `detection_rules`, `log_pusher`, `s1_detection_library`, `attack_scenarios` |
| `APIGENIE_DATA_DIR` | `/var/lib/apigenie` | Root of the SQLite accounts DB, avatar store, custom listeners and replay uploads (`accounts`, `avatars`, `listeners`, `replay`) |
| `APIGENIE_DATA` | `/var/lib/apigenie` | Root of `bans.json`, `acknowledged_paths.json`, `request-logs/`, and (as fallback) `telemetry.db` |
| `APIGENIE_DB` | `${APIGENIE_DATA_DIR}/apigenie.db` | SQLite file backing accounts, entitlements, identifiers, recovery tokens |
| `MAXMIND_LICENSE_KEY` |  | Free MaxMind key — when set, bootstrap downloads `GeoLite2-City.mmdb` for offline GeoMap lookups |
| `APIGENIE_AGG_CAP` | `5000` | Max distinct (client_ip, source) pairs the Flows/GeoMap aggregator retains (LRU eviction) |
| `APIGENIE_LISTENER_HITS_CAP` | `200` | Per-listener in-memory ring buffer for the live trace pane *(custom Listeners feature)* |
| `APIGENIE_LISTENER_HITS_DISK_CAP` | `5000` | Per-listener on-disk hit log line cap before rotation *(custom Listeners feature)* |
| `APIGENIE_REPLAY_MAX_MB` | `100` | Hard cap (MB) on a single replay-mode log file upload *(custom Listeners feature)* |
| `SYSMON_INTERVAL` | `30` | Seconds between system resource samples |
| `SYSMON_MAX_SAMPLES` | `2880` | Max samples retained in memory (~24h at 30s intervals) |
| `PUBSUB_EMULATOR_HOST` | `pubsub-emulator:8085` | Pub/Sub emulator (in-Docker) |
| `GCP_PROJECT_ID` | `obs-test` | Pub/Sub project |
| `PUBSUB_TOPIC_ID` | `audit-logs` | Pub/Sub topic |
| `PUBSUB_SUBSCRIPTION_ID` | `audit-logs-sub` | Pub/Sub subscription created by seed job |
| `PUBSUB_PUBLISH_INTERVAL` | `10` | Seconds between Pub/Sub batches |
| `PUBSUB_BATCH_SIZE` | `5` | Messages per Pub/Sub batch |
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:29092` | In-Docker Kafka listener used by the publisher |
| `KAFKA_TOPIC` | `azure-platform-logs` | Kafka topic |
| `KAFKA_PUBLISH_INTERVAL` | `10` | Seconds between Kafka batches |
| `KAFKA_BATCH_SIZE` | `5` | Messages per Kafka batch |

---

## Log Profiles

Log Profiles let you define **reusable entity pools** that are blended into generated logs across any combination of sources — producing correlatable telemetry where the same user, machine, or C2 IP appears in Okta, Defender, Darktrace, and custom listeners simultaneously.

### Entity types

| Entity | Max per profile | Blended into |
|--------|----------------|--------------|
| **Users** | 10 | Okta (actor), Azure AD (audit/signin), Cisco Duo (email), GCP Audit (principal), AWS CloudTrail (IAM), Snyk (audit), listener identity/cloud/endpoint |
| **Machines** | 10 | Defender (compromised entity), Tenable (asset), Darktrace (device), GuardDuty (instance), Wiz (cloud entity), listener endpoint/network |
| **C2 Servers** | 5 | Defender (remote IP), Darktrace (dest IP), GuardDuty (remote IP), WAF (blocked client IP), Netskope (C2), listener endpoint/network |
| **Malware** | 10 | Proofpoint (threat name), Netskope (malware name) |
| **Mail Senders** | 5 | Proofpoint (sender address, subject, attachment) |

### How it works

1. **Create a profile** via the Admin UI *Log Profiles* tab or `POST /admin/api/profiles` — define as few or many entities as you want.
2. **Star Wars padding** — entity lists shorter than the limit are automatically filled with themed characters (Mandalorian, Rebels, Andor, etc.) so the pool is always full.
3. **Bind to sources** — assign a profile to one or more sources with a signal-to-noise **ratio** (0–100%). At 80%, roughly 80% of generated events use profile entities and 20% use random noise.
4. **Log volume control** — set per-source **intensity** (1–100%) to scale how many log entries each API response contains. At 100% a source returns the full batch (e.g. 100 Okta logs); at 25%, ~25 logs per request. Useful for balancing ingestion load across many pipelines.
5. **Deterministic seeding** — the same profile + source combination always produces the same entity sequence (useful for reproducible demos).

---

## Detection Rules

Detection Rules let you inject specific log patterns into the normal event flow to **trigger SIEM detection rules** during demos and testing. Unlike profiles (which control *who* appears in logs), detection rules control *what happens* — overriding specific field values to match alert signatures.

### Creating a rule

Via the Admin UI *Log Profiles* tab → *Detection Rules* section, or `POST /admin/api/detection-rules`:

| Field | Description |
|-------|-------------|
| **Name** | Human-readable label (e.g. "Brute force login") |
| **Source** | Which source this rule applies to (e.g. `okta`, `azure_platform`, `gcp_audit`) |
| **Field overrides** | Key-value pairs using dot notation for nested fields (e.g. `outcome.result` → `FAILURE`) |
| **Periodicity** | How often to inject (see below) |
| **Enabled** | Toggle on/off without deleting |

### Periodicity modes

| Value | Mode | Behaviour |
|-------|------|-----------|
| **1–100** | Count-based | Inject 1 detection event per N normal logs. E.g. `5` = 1 in every 5 logs |
| **>100** | Time-based | Inject 1 detection event every N seconds. E.g. `300` = once every 5 minutes |

### Coverage

Detection rules apply to **all 14 HTTP sources** plus the **Kafka publisher** (source key `azure_platform`) and **Pub/Sub publisher** (source key `gcp_audit`). Injected events carry a `_detection_rule` field with the rule name for easy identification.

### Example

A rule for Okta brute-force detection:

```json
{
  "name": "Brute force login",
  "source": "okta",
  "periodicity": 5,
  "field_overrides": {
    "eventType": "user.session.start",
    "outcome.result": "FAILURE",
    "severity": "WARN",
    "displayMessage": "Authentication failed - invalid credentials"
  }
}
```

With periodicity 5 and a batch of 50 Okta logs, this injects ~10 failed-login events — enough to trigger a brute-force detection rule in your SIEM.

---

## Event Mix

**New in v5.0.** Every simulated source publishes an **event catalog** — the set of event types it can emit (an authentication success, a failure, a fraud-marked attempt, a policy update, an Entra ID risky sign-in, …) along with a **default weight** per type. The **Event Mix** admin surface lets an operator re-weight those choices — or disable specific event types entirely — without editing source code.

Think of it as a third reshape layer that sits *between* the binding (which pool of entities the source draws from) and Detection Rules (which fields a specific rule overrides):

```
Profile binding ──→ which entities exist          (users, hosts, IPs, …)
Event Mix      ──→ which event_ids are picked     (and at what proportion)
Detection Rules ──→ which fields are overridden    (when a rule periodically fires)
```

### Where to use it

- **Bindings page** (`/admin/source-bindings`): every mix-aware source card exposes an **Event mix (N types)** disclosure. Open it, drag the sliders, toggle types on/off, **Save** persists. **Reset** drops your override back to the source's hard-coded defaults.
- **Acting-as**: an admin acting as a real user writes a private override that only shadows that user's mix. The built-in admin (no acting-as) writes the global mix.

### Rollout

**21 / 21** mix-aware sources in v5.0:

`cisco_duo` · `okta` · `proofpoint` · `aws_cloudtrail` · `aws_guardduty` · `aws_waf` · `azure_ad` (alias `entra_id`) · `microsoft_defender` (alias `defender`) · `m365` · `mimecast` · `cato` · `darktrace` · `gcp_audit` · `netskope` · `sentinelone` · `cloudflare` · `snyk` · `tenable` · `wiz` · `zscaler_zpa` · `azure_platform` (Event Hubs / Kafka).

Two bindings UI ids are aliases for the Python module filenames (`entra_id → azure_ad`, `defender → microsoft_defender`). The alias system canonicalises ids at every storage boundary so a save against the Entra ID card persists under `azure_ad` and the source-side resolver sees it.

### RBAC

Event Mix reuses the **`source_bindings`** entitlement category — anyone with `source_bindings:modify` automatically gets event-mix management ("I can shape what this source sends to my collector"). No new entitlement to wire.

### Full guide

The mental model, the REST surface (`/admin/api/event-mix/sources`, `/admin/api/sources/{src}/event-catalog`, `/admin/api/source-event-mix/{src}` PUT/DELETE), and the `EVENT_CATALOG` contract for adding a new mix-aware source all live in [`docs/EVENT_MIX.md`](docs/EVENT_MIX.md).

---

## Webhooks

**New in v5.0.** Webhooks let any signed-in user (with the `Webhooks` RBAC capability) compose, save, and fire **templated outbound HTTP requests** directly from ApiGenie — purpose-built for two recurring SecOps demos:

1. **Light up a third-party SIEM/SOAR with a synthetic alert** — build a JSON body that references a log profile, click *Send*, and the bound profile's users / machines / C2 servers / malware / mail-senders are substituted at send-time.
2. **Drive an arbitrary HTTPS endpoint with shaped events** — write a `{{custom.<key>}}`-driven body, paste send-time variables in the bottom pane, and trigger from the admin panel or via REST.

Full reference: [`docs/WEBHOOKS.md`](docs/WEBHOOKS.md).

---

## Attack Scenarios

**Phase 2 + 3 land in v5.0.** The Attack Scenario Builder simulates **multi-source, multi-phase attack campaigns** mapped to the MITRE ATT&CK kill chain. Each scenario is a sequence of phases that generate specific log events across different sources, timed to create a realistic attack progression.

- **Phase 2 — Custom scenario builder + import/export.** Operators can compose new scenarios in the admin UI (add phases, pick sources, set fan-out and timing) and export / re-import them as JSON. The shipped scenario library doubles as starter templates.
- **Phase 3.1 — Per-scenario event log.** Every event the scenario emitted (with its `attack.id` + `phase.id`) shows up in a dedicated event log panel scoped to that scenario run.
- **Phase 3.2 — Cross-source `attack.id` search + reveal nav.** Search by an `attack.id` anywhere and the UI jumps to the originating scenario / phase, with deep-links into the source's hit pane.
- **Phase 3.3 — Exportable attack timeline.** A chronological timeline export (JSON) that joins every emitted event with its phase metadata, ready to drop into a post-mortem deck or a SIEM hunt.

Full guide: [`docs/ATTACK_SCENARIOS.md`](docs/ATTACK_SCENARIOS.md).

---

## Log Push

Log Push actively **sends** generated logs from ApiGenie to external destinations — the reverse of the pull model used by the HTTP sources. This is how real firewalls, EDRs, and email gateways deliver telemetry.

### Source types

| # | Source | Event Types | Typical Transport |
|---|--------|-------------|-------------------|
| 1 | **Palo Alto (PAN-OS)** | Traffic, Threat, URL, WildFire, GlobalProtect, System, Config, Auth, HIP, Decryption, Tunnel, UserID | Syslog, HEC |
| 2 | **Fortinet FortiGate** | Traffic, UTM (virus, IPS, webfilter, appctrl), Event (system, VPN), Anomaly | Syslog, HEC |
| 3 | **Check Point NGFW** | Firewall, IPS, Anti-Bot, Anti-Virus, URL Filtering, Application Control | Syslog, CEF |
| 4 | **Cisco ASA / FTD** | Connection built/teardown, denied, threat detection, VPN, AAA, system (ASA- msg IDs) | Syslog |
| 5 | **CrowdStrike Falcon** | DetectionSummary, IncidentSummary, AuditEvent (MITRE ATT&CK mapped) | HTTP, HEC |
| 6 | **Carbon Black Cloud** | CB_ANALYTICS alerts, WATCHLIST hits, process events, network connections | HTTP, HEC |
| 7 | **Zscaler ZIA** | Web transactions, firewall, DNS, tunnel (NSS format) | HTTP, HEC |
| 8 | **Imperva Cloud WAF** | WAF events, bot detection, ACL violations, DDoS | HTTP, HEC |
| 9 | **Barracuda Email Gateway** | Email filtering (spam, virus, DLP), ATP sandbox, admin audit | Syslog, HEC |
| 10 | **Infoblox DDI** | DNS queries, RPZ hits, DHCP, threat intelligence (C2, DGA, tunneling) | Syslog |

### Formats

| Format | Description |
|--------|-------------|
| **JSON** | Structured JSON, one event per line |
| **Syslog** | RFC5424 compliant with structured data |
| **CEF** | Common Event Format (ArcSight compatible) |

### Transports

| Transport | Protocol | Delivery confirmation |
|-----------|----------|----------------------|
| **HTTP POST** | HTTP/HTTPS with Bearer/Basic auth | Yes (HTTP status code) |
| **Splunk HEC** | HTTP with `Splunk <token>` auth | Yes (HTTP status code) |
| **Syslog TCP** | TCP with optional TLS | Yes (TCP ACK) |
| **Syslog UDP** | UDP (fire-and-forget) | No |

### Features

- **Rate control**: 1–1000 events per second
- **Duration**: seconds, minutes, hours, days, or weeks
- **TLS**: per-profile certificate upload or system default
- **Password protection**: optional per-profile
- **Log Profile integration**: blends profile entities into generated events
- **Detection Rules**: injects SIEM-triggering patterns at configured periodicity
- **Observability**: push events appear in Request Inspector, Usage charts, and Flows/GeoMap
- **Event log**: last 100 events per profile with delivery confirmation (protocol, bytes, status)
- **Start/Stop**: runtime control via UI or API

### Storage

Everything ApiGenie persists lives under one Docker volume (`./data` on host, `/var/lib/apigenie` in the container). Mount it as a named volume for production so container recreation keeps state.

| Item | Path | Owner |
|------|------|-------|
| **Accounts, entitlements, identifiers, recovery tokens** *(RBAC core)* | `./data/apigenie.db` (SQLite, WAL) | `accounts.py` |
| **Per-user avatars** *(Phase 3)* | `./data/avatars/<uid>.png` (250×250 RGBA) | `avatars.py` |
| **Admin / legacy user-portal password hashes** | `./data/admin_pass` · `./data/user_pass` | `admin.py` |
| **Global S1 console settings** | `./data/s1_settings.json` | `s1_detection_library.py` (per-user override lives inside `apigenie.db` users row) |
| Log Profiles | `./data/profiles/<uuid>.json` | `profiles.py` |
| Source↔profile bindings | `./data/source_profiles.json` | `profiles.py` |
| Per-source intensity | `./data/source_intensity.json` | `profiles.py` |
| Detection rules | `./data/detection_rules.json` | `detection_rules.py` |
| Custom listeners | `./data/listeners/<id>.json` | `listeners.py` |
| Replay uploads (listener replay mode) | `./data/replays/<uuid>.{json,jsonl,csv,…}` | `replay.py` |
| Log-Push profiles | `./data/push_profiles.json` | `log_pusher.py` |
| Log-Push TLS certificates | `./data/push_certs/*.pem` | `log_pusher.py` |
| Acknowledged intrusion paths | `./data/acknowledged_paths.json` | `intrusions.py` |
| IP ban list | `./data/bans.json` | `bans.py` |
| Usage telemetry | `./data/telemetry.db` (SQLite) | `telemetry.py` |
| Daily request logs | `./data/request-logs/YYYY-MM-DD.jsonl` | `request_log.py` |

Backups: a `tar` of the whole `./data/` directory captures everything above. The volume is fully portable across hosts — no host-side state lives outside it.

---

## Microsoft 365 Configuration

M365 uses the same OAuth2 tenant-aware token flow as Entra ID, but returns a **JWT with Microsoft role claims** (`SecurityEvents.Read.All`, `ActivityFeed.Read`, `AuditLog.Read.All`, etc.). The collector decodes the JWT and checks these roles before proceeding.

### Authentication

| Field | Value |
|-------|-------|
| **Client ID** | `apigenie-client` (any value accepted) |
| **Client Secret** | `apigenie-secret` (any value accepted) |
| **Token URL** | `https://{host}/{tenant-id}/oauth2/v2.0/token` |
| **Scope** | `https://manage.office.com/.default` |
| **Token type** | JWT with `roles` array (RS256 header, fake signature) |

The token endpoint returns a JWT containing:
```json
{
  "roles": ["ActivityFeed.Read", "ActivityFeed.ReadDlp", "SecurityEvents.Read.All",
            "ServiceHealth.Read.All", "User.Read.All", "Directory.Read.All",
            "Mail.Read", "AuditLog.Read.All"],
  "scp": "ActivityFeed.Read ActivityFeed.ReadDlp SecurityEvents.Read.All ...",
  "aud": "https://manage.office.com",
  "iss": "https://sts.windows.net/{tenant-id}/"
}
```

### Two collection modes

**Mode 1 — Graph API Security Alerts** (`INGEST_SECURITY_ALERTS=true`):

| Endpoint | Description |
|----------|-------------|
| `GET /v1.0/security/alerts_v2` | Security alerts (supports `$top`, `$filter`, `$orderby`, `$skiptoken`) |

**Mode 2 — Management Activity API** (`INGEST_SECURITY_ALERTS=false`):

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1.0/{tenant}/activity/feed/subscriptions/list` | List active content type subscriptions |
| `POST /api/v1.0/{tenant}/activity/feed/subscriptions/start?contentType=...` | Start a subscription |
| `GET /api/v1.0/{tenant}/activity/feed/subscriptions/content?contentType=...` | Get content blob URIs |
| `GET /api/v1.0/{tenant}/activity/feed/audit/{content_id}` | Fetch events from a content blob |

Supported content types: `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`, `DLP.All`

### 14 event categories

| # | Category | Weight | Key operations |
|---|----------|--------|----------------|
| 1 | Mailbox audit | 16% | MailItemsAccessed, Send, HardDelete, SendAs |
| 2 | Email threat protection | 10% | SafeLinks, ZAP, malware verdicts |
| 3 | DLP violations | 5% | DlpRuleMatch, sensitive info detection |
| 4 | eDiscovery / Compliance | 4% | SearchExported, HoldApplied, CaseCreated |
| 5 | Admin operations | 7% | Set-Mailbox, TransportRule, RoleGroupMember |
| 6 | SharePoint / OneDrive | 16% | FileDownloaded, FileShared, AnonymousLinkCreated |
| 7 | Teams | 9% | MemberAdded, AppInstalled, GuestAccessEnabled |
| 8 | OAuth consent grants | 5% | Consent to application, OAuth2PermissionGrant |
| 9 | Inbox rules / forwarding | 5% | New-InboxRule, ForwardingSmtpAddress |
| 10 | Power Platform | 3% | CreateFlow, CreateConnection, ShareApp |
| 11 | PIM | 4% | Activate eligible role, Add member to role |
| 12 | Audit log search | 3% | SearchExported, SearchPurged |
| 13 | Quarantine actions | 3% | QuarantineRelease, QuarantineDelete |
| 14 | User login / logout | 10% | UserLoggedIn, UserLoginFailed, MailboxLogin |

### Collector configuration (Observo)

For collectors using a **Lua script** (like the Observo M365 source), the data plane base URLs are hardcoded in the script. To point them to ApiGenie, change:

```lua
-- Graph API (security alerts mode)
local base_url = "https://apigenie.roarinpenguin.com"

-- Management API (audit logs mode)
local mgmt_base_url = "https://apigenie.roarinpenguin.com"
```

### Quick test

```bash
# 1. Get JWT token
TOKEN=$(curl -s -X POST "https://apigenie.roarinpenguin.com/my-tenant/oauth2/v2.0/token" \\
  -d "grant_type=client_credentials&client_id=apigenie-client&client_secret=apigenie-secret&scope=https://manage.office.com/.default" \\
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2a. Graph API security alerts
curl -s -H "Authorization: Bearer $TOKEN" \\
  "https://apigenie.roarinpenguin.com/v1.0/security/alerts_v2?\$top=5"

# 2b. Management API audit content
curl -s -H "Authorization: Bearer $TOKEN" \\
  "https://apigenie.roarinpenguin.com/api/v1.0/my-tenant/activity/feed/subscriptions/content?contentType=Audit.General"
```

---

## Investigations (admin-only)

The 🔍 **Investigations** tab (IP lookup, WHOIS, banning) used to be guarded by a *second* password independent of the admin login. **That gate was retired in Phase 1** — Investigations is now plain admin-only, enforced server-side by `ADMIN_ONLY_API_PREFIXES` in [`admin.py`](admin.py).

The `APIGENIE_INVESTIGATE_PASSWORD` env var and `./data/investigate_pass` file are still tolerated for forward-compatibility, but they no longer control access. If you are upgrading from a pre-RBAC build, you can delete both safely.

---

## Persistent telemetry

The **Usage-over-Time** chart in the Observability tab is backed by a persistent SQLite database (`./data/telemetry.db`). Every API request increments a per-minute, per-source counter. Data is retained for **~1 year** and automatically pruned. The chart supports time ranges from 1 hour to 1 year with adaptive bucket sizes (1 min → 1 day).

---

## Data realism

Each request generates fresh, randomized log entries using weighted probability templates:

- **Okta**: 70% normal logins · 10% MFA failures · 5% suspicious activity · 5% account lockouts
- **Tenable**: 40% critical Log4Shell · 35% high Apache vulns · 20% medium SMB · 5% low/informational
- **Wiz**: 40% toxic combinations · 20% critical RCE · 15% open security groups · 10% exposed secrets
- All other sources follow similar weighted distributions anchored to `now()` timestamps

When a [Log Profile](#log-profiles) is bound to a source, profile entities are blended at the configured ratio while preserving these weighted templates — the *event shapes* stay realistic, only the *actors/targets* become correlatable across platforms.

---

## License

MIT
