# LocalStack integration plan — full AWS source coverage for ApiGenie

> Status: **DESIGN** · Owner: ApiGenie maintainers · Target: extend ApiGenie so the three AWS sources currently missing (CloudTrail, WAF, GuardDuty) work end-to-end with Observo's real production-shaped collectors.

---

## 1. Why LocalStack

The three AWS log products are **not delivered as HTTP-pull APIs** in the real world:

| Service | Real production path |
|---------|----------------------|
| **CloudTrail** | Trail → S3 bucket (`s3://<bucket>/AWSLogs/<acct>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/...json.gz`) |
| **WAF** | Web ACL → Kinesis Firehose → S3 (gzip JSONL) |
| **GuardDuty** | Findings → EventBridge → SNS → **SQS** *(or)* findings export → S3 + SQS notifications |

Observo's collectors use the **AWS SDK** to do `ListObjectsV2`/`GetObject` on S3 and `ReceiveMessage`/`DeleteMessage` on SQS, with:

- Hostnames **hardcoded** to `*.amazonaws.com` (overridable via `endpoint_url` in most SDKs)
- **SigV4 signing** that binds the signature to the host header
- Optional **path-style** vs virtual-hosted-style addressing

ApiGenie's FastAPI cannot serve those wire shapes. **LocalStack** speaks the AWS Query/JSON protocols natively for S3, SQS, SNS, EventBridge, Firehose, IAM and dozens more — with fully working SigV4. It is the canonical drop-in for "AWS in a box".

The work below adds LocalStack as a sibling service in `docker-compose.yaml`, wires the existing `sources/aws_*.py` data generators into a one-shot **seeder job** that pre-populates buckets and queues, and documents the Observo source configuration for each.

---

## 2. Scope (what this delivers)

| Source | Transport added | Observo source type expected |
|--------|-----------------|------------------------------|
| AWS CloudTrail | S3 (`apigenie-cloudtrail` bucket, real path layout, gzip JSON) | "AWS S3" or "AWS CloudTrail (S3)" |
| AWS WAF | S3 (`apigenie-waf-logs` bucket, Firehose-shaped folder layout, gzip JSONL) | "AWS S3" or "AWS WAF (S3)" |
| AWS GuardDuty | SQS notifications (`apigenie-gd-findings` queue) carrying SNS-wrapped events whose payload is the finding (option A) **or** an S3 pointer (option B) | "AWS GuardDuty (SQS)" |

Out of scope (deliberate): IAM Identity Center, RDS audit, VPC Flow Logs, Lambda Insights — the same pattern would extend to them but is not part of the current Observo coverage matrix.

---

## 3. Architecture

```
              Internet (Observo collector egress IPs)
                              │
                              ▼
                   apigenie.roarinpenguin.com
                              │
                  ┌───────────┼─────────────────────────────────┐
                  │ 443/HTTPS │ 8443/gRPC-TLS │ 9093/Kafka      │ 4566/HTTPS  ← NEW
                  ▼           ▼               ▼                 ▼
              [ apigenie ] [ pubsub ]    [ kafka ]       [ localstack ]
                  │             ▲              ▲                  ▲
                  │             │              │                  │
                  ▼             │              │                  │
            FastAPI mocks       │              │           ┌──────┴──────┐
            (11 sources)        │              │           │             │
                                │              │           ▼             ▼
                                │              │      S3 buckets    SQS queues
                                │              │      (CloudTrail,  (GuardDuty
                                │              │       WAF logs)     findings)
                                │              │           ▲
                                │              │           │
                          [ pubsub-publisher ] [ kafka-publisher ]   ← existing
                                                                     +
                                                            [ aws-seeder ]   ← NEW
                                                          (one-shot, then loop)
```

`localstack` joins the existing `apigenie-net` Docker network. nginx publishes a single new HTTPS port — **`4566`** — with a `Host:`-routed proxy block that forwards to `localstack:4566`. We keep using the same Let's Encrypt cert; LocalStack itself stays plaintext inside the Docker network.

---

## 4. Service topology

### 4.1 New `localstack` service (sketch)

```yaml
localstack:
  image: localstack/localstack:3.7
  container_name: apigenie-localstack
  restart: unless-stopped
  environment:
    SERVICES: s3,sqs,sns,iam,sts
    DEBUG: 0
    PERSISTENCE: 1                       # survive restarts
    LOCALSTACK_AUTH_TOKEN: ""            # community edition
    DISABLE_CORS_CHECKS: 1
    AWS_DEFAULT_REGION: us-east-1
    HOSTNAME_EXTERNAL: apigenie.roarinpenguin.com
  volumes:
    - localstack-data:/var/lib/localstack
  networks:
    - apigenie-net
```

### 4.2 nginx — new TLS-fronted endpoint on `:4566`

Add to `nginx/nginx.conf`:

```nginx
server {
    listen 4566 ssl;
    http2 on;
    server_name apigenie.roarinpenguin.com;

    ssl_certificate     /etc/letsencrypt/live/apigenie.roarinpenguin.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/apigenie.roarinpenguin.com/privkey.pem;

    client_max_body_size 100m;          # large multipart S3 uploads

    location / {
        proxy_pass http://localstack:4566;
        proxy_http_version 1.1;
        proxy_set_header Host             $host;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_request_buffering off;    # streaming uploads
        proxy_buffering        off;
    }
}
```

Open `4566/tcp` on the host firewall. **Single port** for all AWS services because LocalStack multiplexes them on 4566.

### 4.3 New `aws-seeder` one-shot + loop service

```yaml
aws-seeder:
  build: ./seeders/aws
  container_name: apigenie-aws-seeder
  restart: unless-stopped
  depends_on:
    localstack:
      condition: service_healthy
  environment:
    AWS_ENDPOINT_URL: http://localstack:4566
    AWS_ACCESS_KEY_ID: apigenie
    AWS_SECRET_ACCESS_KEY: apigenie
    AWS_DEFAULT_REGION: us-east-1
    SEED_INTERVAL: "30"               # seconds between batches
    SEED_BATCH_SIZE: "20"
  networks:
    - apigenie-net
```

The seeder image is a tiny Python container (`python:3.13-slim` + `boto3`) running:

1. **On first boot**: `mb s3://apigenie-cloudtrail`, `mb s3://apigenie-waf-logs`, `create-queue apigenie-gd-findings`.
2. **Every `SEED_INTERVAL` seconds**:
   - Generate `SEED_BATCH_SIZE` events using the existing `sources/aws_cloudtrail.py`, `sources/aws_waf.py`, `sources/aws_guardduty.py` generators.
   - **CloudTrail**: gzip JSON `{"Records": [...]}`, key
     `AWSLogs/000000000000/CloudTrail/us-east-1/<yyyy>/<mm>/<dd>/000000000000_CloudTrail_us-east-1_<yyyymmddThhmmZ>_<rand8>.json.gz`.
   - **WAF**: gzip JSONL (one event per line), key
     `AWSLogs/000000000000/WAFLogs/us-east-1/apigenie-acl/<yyyy>/<mm>/<dd>/<HH>/<MM>/000000000000_waflogs_us-east-1_apigenie-acl_<yyyymmddThhMMZ>_<rand8>.log.gz`.
   - **GuardDuty**: each finding becomes an SNS-wrapped JSON message → `send-message` to the SQS queue. Optional fan-out: also write the raw finding to `s3://apigenie-cloudtrail/guardduty/<yyyy>/<mm>/<dd>/<id>.json` and put an S3-event-shaped pointer on the queue (mirrors AWS's "findings export" path).

This reuses the existing data generators verbatim — no duplication.

### 4.4 Admin UI integration

Add three new source cards to `admin.py`'s `SOURCE_CONFIG` describing **how to point Observo at LocalStack**, not at AWS:

| Field | CloudTrail / WAF | GuardDuty (SQS) |
|-------|------------------|-----------------|
| AWS endpoint URL | `https://apigenie.roarinpenguin.com:4566` | same |
| AWS access key id | `apigenie` | same |
| AWS secret access key | `apigenie` | same |
| Region | `us-east-1` | same |
| Bucket | `apigenie-cloudtrail` / `apigenie-waf-logs` | (n/a) |
| Queue URL | (n/a) | `https://apigenie.roarinpenguin.com:4566/000000000000/apigenie-gd-findings` |
| Force path style | **enabled** | n/a |
| Verify TLS | enabled (Let's Encrypt cert) | enabled |

Add the corresponding cards to the `/admin` request inspector so live AWS calls show up just like the FastAPI sources today (LocalStack already logs every API call; the seeder publishes a heartbeat row to `REQUEST_TRACE` per cycle).

---

## 5. Implementation phases

### Phase 0 — Feasibility check (gating, ~1 hour)

**Do not start phase 1 until this passes.** LocalStack only helps if Observo's collector can be *told* to use a custom AWS endpoint. The whole plan rests on Observo's source catalogue exposing a **generic, endpoint-overridable** AWS source — not a vendor-specific template that hardcodes `*.amazonaws.com`.

What to confirm in the Observo source-template catalogue:

1. **A generic "AWS S3" source** with one of these fields exposed in the UI:
   - `endpoint_url` / `Custom endpoint` / `S3 endpoint`
   - `force_path_style` / `Use path-style addressing` (toggle)
   - access-key + secret-key inputs (not just IAM role ARN)

2. **A generic "AWS SQS" source** with:
   - `endpoint_url` / `Custom endpoint` / `Queue URL` (where the queue URL hostname can be `apigenie.roarinpenguin.com:4566`, not `sqs.<region>.amazonaws.com`)
   - access-key + secret-key inputs

3. *(Optional, nice-to-have)* path-style URL addressing toggle exposed at source-config level rather than only in advanced/librdkafka-style overrides.

**If both #1 and #2 exist with the override fields → proceed to phase 1.**

**If they don't exist:**
- LocalStack faces the **same wall** our FastAPI mock did — the SDK composes hardcoded `*.amazonaws.com` URLs and we have no way to receive the traffic.
- Possible workarounds (each is a separate project, not part of this plan):
  - **DNS hijacking** inside Observo's collector network — point `*.amazonaws.com` at `apigenie.roarinpenguin.com` via `/etc/hosts`, CoreDNS rewrite, or Route 53 Resolver. Requires collaboration with Observo's infra team and changes their collector deployment.
  - **Mock SigV4 + wildcard cert** — re-issue our TLS cert with a `*.amazonaws.com` SAN (impossible from a public CA — that's reserved for AWS — would require a private CA installed on the collector).
  - **Run Observo's collector on a host you control** — set local DNS, install your own CA, point all AWS calls at LocalStack. Practical only for self-hosted collectors, not SaaS.

Document the result of phase 0 in this file (status table at the top) before committing further engineering effort.

### Implementation phases (assumes phase 0 passed)

| Phase | Deliverable | Effort |
|-------|-------------|--------|
| **1. Stack wiring** | `localstack` service + nginx `:4566` listener + firewall + DNS sanity test from a remote host (`aws --endpoint-url=https://apigenie.roarinpenguin.com:4566 s3 ls`) | 0.5 day |
| **2. Seeder MVP — CloudTrail** | `seeders/aws/Dockerfile` + `seed_cloudtrail.py`; pre-creates bucket and writes one realistic gzip JSON per cycle. Verify with `aws s3 cp` + `aws s3 ls` and an Observo "AWS CloudTrail (S3)" source. | 0.5 day |
| **3. Seeder — WAF** | `seed_waf.py`. Largely a copy of CloudTrail with the WAF path layout and JSONL framing. | 0.25 day |
| **4. Seeder — GuardDuty** | `seed_guardduty.py`: SNS-wrapped messages on SQS. Decide A (inline finding) vs B (S3 pointer); start with A. | 0.5 day |
| **5. Admin UI integration** | Three new source cards in `admin.py`; per-cycle heartbeats in `REQUEST_TRACE` so the existing Requests tab works. | 0.25 day |
| **6. Docs** | Update `README.md` to add three rows back to the source table (with a "via LocalStack" badge), refresh the firewall list, link this plan as historical context. | 0.25 day |
| **7. Optional polish** | Persist LocalStack data across restarts (`PERSISTENCE=1` already set); add a `cleanup` flag to drop and re-seed; expose `:4566/_localstack/health` through nginx for the admin UI. | 0.5 day |

**Total: ~2.5 engineer-days** for full coverage of all three AWS sources.

---

## 6. Risks and open questions

1. **TLS cert hostname binding for SDKs**. Most AWS SDKs validate that the cert SAN matches the endpoint hostname. Our Let's Encrypt cert is for `apigenie.roarinpenguin.com`, which Observo will use as its `endpoint_url` host — should work without SNI hacks. To verify before committing the work: spin up LocalStack locally, point a real `boto3` client at `https://apigenie.roarinpenguin.com:4566`, and confirm `s3.list_buckets()` succeeds.

2. **Path-style vs virtual-hosted-style S3**. Real S3 supports both, but `<bucket>.<endpoint>` virtual-hosted addressing requires a **wildcard** TLS cert (`*.apigenie.roarinpenguin.com`). LocalStack accepts path-style on `:4566/<bucket>/<key>` directly, so we standardise on that and document `force_path_style=true` in Observo. **Decision: path-style only.**

3. **SQS queue URL hostname**. LocalStack defaults to advertising queues at `http://localstack:4566/000000000000/<queue>`. We override with `HOSTNAME_EXTERNAL=apigenie.roarinpenguin.com` so the queue URL surfaced by `CreateQueue` and `GetQueueUrl` matches what Observo can resolve from the public internet.

4. **Authentication realism**. LocalStack accepts any credential pair by default. We standardise on `apigenie / apigenie` for the access key + secret. This is **not** a security boundary — apigenie is a public lab.

5. **Volume of data**. The seeder loops every 30 s × 20 events × 3 services × infinity. At ~1 KB per event compressed, that's ~70 KB/min, ~100 MB/day. The persisted `localstack-data` volume should be bounded; add a janitor cron in the seeder that deletes objects older than 7 days and purges the SQS DLQ.

6. **AWS SDK version compatibility**. LocalStack 3.x supports current AWS SDK behaviour. Pin the LocalStack image tag to avoid surprise upgrades breaking SigV4 details that some collectors depend on. Re-test on every upgrade.

7. **Demo blast radius vs main stack**. LocalStack adds ~250 MB RAM and ~5 % CPU on a t3.small. Acceptable for the existing 1 vCPU / 2 GB EC2 host running ApiGenie. If the host needs to be resized, do it before phase 1.

8. **Observo source-template availability**. Confirmed: Observo ships generic "AWS S3" and "AWS SQS" source templates that accept `endpoint_url`. If the Observo "AWS GuardDuty" template hardcodes the GuardDuty API endpoint without an override, we'll need to keep the SQS-fed flow rather than the direct-API flow — same end result for pipeline data, just slightly less "real" labelling.

---

## 7. Acceptance criteria

- [ ] `aws --endpoint-url=https://apigenie.roarinpenguin.com:4566 s3 ls` from a remote host returns `apigenie-cloudtrail` and `apigenie-waf-logs`.
- [ ] `aws --endpoint-url=https://apigenie.roarinpenguin.com:4566 sqs list-queues` lists `apigenie-gd-findings`.
- [ ] After 1 minute of seeder uptime, both buckets contain at least one object under the expected real-AWS path layout, and the SQS queue has `ApproximateNumberOfMessages > 0`.
- [ ] An Observo "AWS S3 / CloudTrail" source pointed at `apigenie.roarinpenguin.com:4566` with the bucket `apigenie-cloudtrail` shows events flowing in the pipeline.
- [ ] Same for WAF (bucket `apigenie-waf-logs`) and GuardDuty (queue `apigenie-gd-findings`).
- [ ] All three new sources appear in the admin UI source-config tab with correct endpoint, creds, and a curl/aws-cli example.
- [ ] `docker compose up -d --build` starts cleanly on a fresh host with no manual seed steps.

---

## 8. Out of scope (and why)

- **CloudWatch Logs / Metrics**: Observo doesn't currently consume from CloudWatch in the demo coverage; LocalStack supports it but defer until requested.
- **Direct GuardDuty API** (`/detector/{id}/findings/get`): no real customer uses this — production is always SQS or S3 export. We ship SQS only.
- **Real Kinesis Firehose path for WAF**: LocalStack supports Firehose, but adding a Firehose stream that writes to the same S3 bucket is theatre — the consumer still polls S3. We skip the Firehose and write directly to S3.
- **Cross-account bucket policies / ACLs**: real-life IAM scenarios. The demo always uses one synthetic account `000000000000`.
