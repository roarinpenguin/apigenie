# <img src="assets/logo.png" width="60" align="center" alt="ApiGenie logo"> ApiGenie

> Standalone HTTP mock server for **14 security platform APIs** — built for [Observo](https://observo.ai) Site telemetry collector source-configuration testing.

ApiGenie exposes realistic, dynamically-varied API endpoints that mimic the authentication methods and log formats of real security platforms. It runs as a single FastAPI container that slots into the existing **test-genius** Docker stack, sharing its nginx (SSL on 443), Kafka, and Pub/Sub emulator.

Live at **[https://apigenie.roarinpenguin.com](https://apigenie.roarinpenguin.com)**

---

## Supported platforms

| # | Platform | Auth method | Key endpoints |
|---|----------|-------------|---------------|
| 1 | **Okta** | Bearer (SSWS) | `GET /api/v1/logs` |
| 2 | **Netskope** | Bearer | `GET /api/v2/events/data/alert`, `/audit` |
| 3 | **Microsoft Entra ID** | Bearer | `GET /v1.0/auditLogs/directoryAudits`, `/signIns` |
| 4 | **Microsoft Defender for Cloud** | Bearer | `GET /v1.0/subscriptions/{id}/providers/Microsoft.Security/alerts` |
| 5 | **Cisco Duo** | HMAC-SHA1 | `GET /admin/v1/logs/authentication`, `/admin/v2/logs/authentication`, `/admin/v1/logs/administrator` |
| 6 | **GCP Audit Logs** | Bearer + Pub/Sub gRPC | `POST /v2/entries:list` + emulator on `:8085` |
| 7 | **Tenable VM** | X-ApiKeys | `POST /vulns/export` → `GET /vulns/export/{uuid}/status` → `GET /vulns/export/{uuid}/chunks/{n}` |
| 8 | **Proofpoint TAP** | Basic Auth | `GET /v2/siem/all`, `/v2/siem/messages/blocked` |
| 9 | **AWS CloudTrail** | Bearer | `GET /v1/cloudtrail/events` |
| 10 | **AWS WAF** | Bearer | `GET /v1/waf/logs` |
| 11 | **AWS GuardDuty** | Bearer | `GET /v1/guardduty/findings` |
| 12 | **Wiz** | Bearer | `POST /graphql` (GraphQL) |
| 13 | **Snyk** | Bearer | `GET /v1/org/{id}/issues`, `/projects`, `/audit` |
| 14 | **Darktrace** | HMAC | `GET /modelbreaches`, `/aianalyst/incident/log`, `/status` |

---

## Architecture

```
Internet
    │  HTTPS :443
    ▼
┌─────────────────────────────────────────────────┐
│          test-genius-nginx-1 (nginx:latest)      │
│   SSL termination · Let's Encrypt certs          │
│   Static HTML at /                               │
│                                                  │
│  location /api/v1/logs          → apigenie:8000  │
│  location /api/v2/              → apigenie:8000  │
│  location /v1.0/auditLogs/      → apigenie:8000  │
│  location /vulns/               → apigenie:8000  │
│  location /graphql              → apigenie:8000  │
│  ... (all 14 source paths)      → apigenie:8000  │
│  location / (catch-all)         → api:5050       │  ← test-genius
└─────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
  ┌─────────────┐              ┌──────────────────┐
  │   apigenie  │              │  test-genius-api  │
  │  FastAPI    │              │  Gunicorn :5050   │
  │   :8000     │              └──────────────────┘
  └─────────────┘
         │
    ┌────┴─────────────────────────┐
    │    test-genius_backend net   │
    │  kafka:19092  pubsub:8085    │
    └──────────────────────────────┘
```

All containers share the `test-genius_backend` Docker network. ApiGenie's publishers push events to the existing Kafka and Pub/Sub emulator containers.

---

## Deployment

### Prerequisites

The **test-genius** stack must be running first (provides nginx, Kafka, Pub/Sub emulator):

```bash
# On apigenie.roarinpenguin.com
cd ~/test-genius
docker compose --profile app --profile imaas-pubsub up -d
```

### 1. Clone and build apigenie

```bash
cd ~
git clone https://github.com/roarinpenguin/apigenie.git
cd apigenie/apigenie
docker build -t apigenie .
```

### 2. Start the apigenie container

```bash
docker compose up -d
```

The container joins `test-genius_backend` automatically and is reachable as `apigenie:8000` from within the network.

### 3. Update nginx to route apigenie paths

```bash
# Replace test-genius nginx config with the one from this repo
cp ~/apigenie/apigenie/nginx/nginx.conf ~/test-genius/nginx/nginx.conf

# Reload nginx without downtime
docker exec test-genius-nginx-1 nginx -s reload
```

That's it — all 14 source APIs are now live on `https://apigenie.roarinpenguin.com`.

---

## Authentication credentials

Use these when configuring sources in Observo (or any HTTP client):

| Auth type | Header | Value |
|-----------|--------|-------|
| Bearer token | `Authorization: Bearer <token>` | `apigenie-valid-token-001` … `003` |
| Basic Auth | `Authorization: Basic <b64>` | `apigenie-principal-001` / `apigenie-secret-001` |
| X-ApiKeys (Tenable) | `X-ApiKeys` | `accessKey=VALIDACCESSKEY001&secretKey=VALIDSECRETKEY001` |
| Cisco Duo | `Authorization: Basic <b64>` | ikey = `DIXXXXXXXXXXXXXXXXXX` |

A mock OAuth2 token endpoint is available at `POST /oauth2/v1/token` — returns a valid Bearer token automatically.

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

## Tenable async export flow

Tenable uses a 3-step stateful export API — implemented fully in-memory with TTL eviction:

```
POST  /vulns/export                          → { "export_uuid": "..." }
GET   /vulns/export/{uuid}/status            → { "status": "FINISHED", "chunks_available": [1,2,3] }
GET   /vulns/export/{uuid}/chunks/{chunk_id} → [ { vuln }, ... ]
```

Same pattern for `/assets/export`. Exports are cached for 1 hour then auto-evicted.

---

## GCP Pub/Sub

The Pub/Sub emulator runs on port `8085` (gRPC), started by the test-genius stack. On startup, ApiGenie's background publisher:

1. Creates topic `audit-logs` in project `obs-test` if it doesn't exist
2. Publishes 5 GCP audit log events every 10 seconds

Configure your Observo GCP Audit Logs source:
- **Emulator host**: `apigenie.roarinpenguin.com:8085`
- **Project ID**: `obs-test`
- **Subscription**: `audit-logs-sub`

---

## Azure Event Hubs (Kafka)

Kafka runs on port `9092` (test-genius stack). ApiGenie's background publisher produces 5 Azure Platform activity log events to topic `azure-platform-logs` every 10 seconds.

Configure your Observo Azure source:
- **Bootstrap server**: `apigenie.roarinpenguin.com:9092`
- **Topic**: `azure-platform-logs`

---

## Project structure

```
apigenie/
├── app.py                    # FastAPI app — all 14 source routes
├── auth.py                   # Bearer / Basic / X-ApiKeys / Duo HMAC auth
├── generators.py             # Shared random data helpers
├── state.py                  # Thread-safe Tenable export cache
├── nginx/
│   └── nginx.conf            # Drop-in replacement for test-genius nginx config
├── sources/                  # One file per platform
│   ├── okta.py
│   ├── netskope.py
│   ├── azure_ad.py
│   ├── microsoft_defender.py
│   ├── cisco_duo.py
│   ├── gcp_audit.py
│   ├── tenable.py
│   ├── proofpoint.py
│   ├── aws_cloudtrail.py
│   ├── aws_waf.py
│   ├── aws_guardduty.py
│   ├── wiz.py
│   ├── snyk.py
│   └── darktrace.py
├── publishers/
│   ├── kafka_publisher.py    # Background thread → Kafka (azure-platform-logs)
│   └── pubsub_publisher.py   # Background thread → Pub/Sub (audit-logs)
├── Dockerfile                # python:3.13-slim
├── docker-compose.yaml       # Single apigenie service, joins test-genius_backend
├── pyproject.toml
└── .env.example
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Uvicorn log level |
| `PUBLISHERS_ENABLED` | `true` | Enable background Kafka + Pub/Sub publishers |
| `PUBSUB_EMULATOR_HOST` | `pubsub-emulator:8085` | Pub/Sub emulator (test-genius container) |
| `GCP_PROJECT_ID` | `obs-test` | GCP project for Pub/Sub |
| `PUBSUB_TOPIC_ID` | `audit-logs` | Pub/Sub topic name |
| `PUBSUB_PUBLISH_INTERVAL` | `10` | Seconds between Pub/Sub batches |
| `PUBSUB_BATCH_SIZE` | `5` | Messages per Pub/Sub batch |
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:19092` | Kafka internal listener (test-genius container) |
| `KAFKA_TOPIC` | `azure-platform-logs` | Kafka topic for Azure Platform logs |
| `KAFKA_PUBLISH_INTERVAL` | `10` | Seconds between Kafka batches |
| `KAFKA_BATCH_SIZE` | `5` | Messages per Kafka batch |

---

## Data realism

Each request generates fresh, randomized log entries using weighted probability templates:

- **Okta**: 70% normal logins · 10% MFA failures · 5% suspicious activity · 5% account lockouts
- **Tenable**: 40% critical Log4Shell · 35% high Apache vulns · 20% medium SMB · 5% low/informational
- **GuardDuty**: 35% C2 activity · 20% crypto mining · 15% SSH brute force · 10% data exfiltration
- **Wiz**: 40% toxic combinations · 20% critical RCE · 15% open security groups · 10% exposed secrets
- All other sources follow similar weighted distributions anchored to `now()` timestamps

---

## License

MIT
