# <img src="assets/logo.png" width="60" align="center" alt="ApiGenie logo"> ApiGenie

> Standalone HTTP mock server for **14 security platform APIs** — built for [Observo](https://observo.ai) Site telemetry collector source-configuration testing.

ApiGenie exposes realistic, dynamically-varied API endpoints that mimic the authentication methods and log formats of real security platforms. No Kafka consumer, no LLM pipeline, no database — just a lean FastAPI app you can `docker compose up` anywhere.

---

## Supported platforms

| # | Platform | Auth method | Key endpoints |
|---|----------|-------------|---------------|
| 1 | **Okta** | Bearer (SSWS) | `GET /api/v1/logs` |
| 2 | **Netskope** | Bearer | `GET /api/v2/events/data/alert`, `/audit` |
| 3 | **Microsoft Entra ID** | Bearer | `GET /v1.0/auditLogs/directoryAudits`, `/signIns` |
| 4 | **Microsoft Defender for Cloud** | Bearer | `GET /v1.0/subscriptions/{id}/providers/Microsoft.Security/alerts` |
| 5 | **Cisco Duo** | HMAC-SHA1 | `GET /admin/v1/logs/authentication`, `/admin/v2/logs/authentication`, `/administrator` |
| 6 | **GCP Audit Logs** | Bearer + Pub/Sub gRPC | `POST /v2/entries:list` + emulator on `:8085` |
| 7 | **Tenable VM** | X-ApiKeys | `POST /vulns/export` → `GET /vulns/export/{uuid}/status` → `GET /vulns/export/{uuid}/chunks/{n}` |
| 8 | **Proofpoint TAP** | Basic Auth | `GET /v2/siem/all`, `/messages/blocked` |
| 9 | **AWS CloudTrail** | Bearer | `GET /v1/cloudtrail/events` |
| 10 | **AWS WAF** | Bearer | `GET /v1/waf/logs` |
| 11 | **AWS GuardDuty** | Bearer | `GET /v1/guardduty/findings` |
| 12 | **Wiz** | Bearer | `POST /graphql` (GraphQL) |
| 13 | **Snyk** | Bearer | `GET /v1/org/{id}/issues`, `/projects`, `/audit` |
| 14 | **Darktrace** | HMAC | `GET /modelbreaches`, `/aianalyst/incident/log`, `/status` |

---

## Quick start

```bash
# Clone
git clone https://github.com/roarinpenguin/apigenie.git
cd apigenie

# Copy env config
cp .env.example .env

# Start everything (API server + Kafka + Pub/Sub emulator)
docker compose up --build
```

The API server listens on **`:8000`**, the Pub/Sub emulator on **`:8085`**, and Kafka on **`:9092`**.

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

Substitute the token with one of these to trigger specific HTTP error responses:

| Token | Response |
|-------|----------|
| `apigenie-error-401` | 401 Unauthorized |
| `apigenie-error-403` | 403 Forbidden |
| `apigenie-error-404` | 404 Not Found |
| `apigenie-error-429` | 429 Rate Limited |
| `apigenie-error-500` | 500 Internal Server Error |

---

## Tenable async export flow

Tenable uses a 3-step stateful export API. ApiGenie implements it fully in-memory:

```
POST  /vulns/export                          → { "export_uuid": "..." }
GET   /vulns/export/{uuid}/status            → { "status": "FINISHED", "chunks_available": [1,2,3] }
GET   /vulns/export/{uuid}/chunks/{chunk_id} → [ { vuln }, ... ]
```

Same pattern for `/assets/export`. Exports are cached for 1 hour then auto-evicted.

---

## GCP Pub/Sub

The `pubsub-emulator` container runs on port `8085` (gRPC). On startup, ApiGenie's background publisher:

1. Creates topic `audit-logs` in project `apigenie-project` if it doesn't exist
2. Publishes 5 GCP audit log events every 10 seconds

Configure your Observo GCP Audit Logs source to use:
- **Emulator host**: `<your-host>:8085`
- **Project ID**: `apigenie-project`
- **Subscription**: `audit-logs-sub`

---

## Azure Event Hubs (Kafka)

Kafka runs on port `9092` and is advertised externally as `apigenie.roarinpenguin.com:9092`. The background publisher produces 5 Azure Platform activity log events to topic `azure-platform-logs` every 10 seconds.

Configure your Observo Azure source to use:
- **Bootstrap server**: `apigenie.roarinpenguin.com:9092`
- **Topic**: `azure-platform-logs`

> **Local testing**: set `PUBLIC_HOSTNAME=localhost` in `.env` to advertise `localhost:9092` instead.

---

## Project structure

```
apigenie/
├── app.py                    # FastAPI app — all 14 source routes
├── auth.py                   # Bearer / Basic / X-ApiKeys / Duo HMAC auth
├── generators.py             # Shared random data helpers
├── state.py                  # Thread-safe Tenable export cache
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
│   ├── kafka_publisher.py    # Background → Azure Event Hubs
│   └── pubsub_publisher.py   # Background → GCP Pub/Sub
├── Dockerfile                # python:3.13-slim (public only)
├── docker-compose.yaml
├── pyproject.toml
└── .env.example
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Uvicorn log level |
| `PUBLISHERS_ENABLED` | `true` | Enable background Kafka + Pub/Sub publishers |
| `PUBSUB_EMULATOR_HOST` | `pubsub-emulator:8085` | Pub/Sub emulator address |
| `GCP_PROJECT_ID` | `apigenie-project` | GCP project for Pub/Sub |
| `PUBSUB_TOPIC_ID` | `audit-logs` | Pub/Sub topic name |
| `PUBSUB_PUBLISH_INTERVAL` | `10` | Seconds between Pub/Sub batches |
| `PUBSUB_BATCH_SIZE` | `5` | Messages per Pub/Sub batch |
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Kafka broker (internal Docker address) |
| `KAFKA_TOPIC` | `azure-platform-logs` | Kafka topic name |
| `KAFKA_PUBLISH_INTERVAL` | `10` | Seconds between Kafka batches |
| `KAFKA_BATCH_SIZE` | `5` | Messages per Kafka batch |
| `PUBLIC_HOSTNAME` | `apigenie.roarinpenguin.com` | Public hostname for Kafka advertised listener |

---

## Data realism

Each request generates fresh, randomized log entries using weighted probability templates:

- **Okta**: 70% normal session starts, 10% MFA failures, 5% suspicious activity, 5% account lockouts
- **Tenable**: 40% critical Log4Shell CVE-2021-44228, 35% high Apache vulns, 20% medium SMB misconfig
- **GuardDuty**: 35% C2 activity, 20% crypto mining, 15% SSH brute force, 10% data exfiltration
- **Wiz**: 40% toxic combinations, 20% critical RCE vulns, 15% open security groups, 10% exposed secrets
- ...and so on for all 14 sources

Timestamps are always anchored to `now()` so log freshness checks pass automatically.

---

## Requirements

- Docker + Docker Compose (no local Python needed)
- Public internet access to pull images from Docker Hub and `gcr.io`
- Port `8000`, `8085`, `9092` open on the host

---

## License

MIT
