# ApiGenie — Capacity Planning Report

**Date:** 2026-05-13  
**Instance:** AWS EC2 (eu-central-1)  
**Status:** Production  

---

## 1. Current Production Infrastructure

| Resource | Value | Notes |
|----------|-------|-------|
| CPU | 2 vCPU (Intel Xeon Platinum 8259CL @ 2.50 GHz) | Likely t3.large or m5.large |
| RAM | 7.8 GB | 5.8 GB available after OS |
| Disk | 30 GB NVMe (EBS) | 14 GB used (46%) |
| OS | Amazon Linux 2 | Docker 25.0.14 |
| Load avg | 0.44 (22% of 2 cores) | Measured at idle |
| TCP connections | 2 established | Near idle, no active pipelines |
| Request rate | ~38 req/min | Mostly intrusion probes |

---

## 2. Container Resource Breakdown (Idle)

Measured with **zero active S1 pipelines** connected.

| Container | CPU % | RAM (MB) | Role |
|-----------|-------|----------|------|
| **apigenie-kafka** | **64.5%** | **706** | **Azure Event Hubs emulation — THE BOTTLENECK** |
| apigenie-pubsub | 0.5% | 339 | GCP Pub/Sub emulation |
| apigenie-zookeeper | 0.1% | 114 | Kafka coordination |
| apigenie (app) | 0.2% | 90 | FastAPI mock server (1 uvicorn worker) |
| apigenie-nginx | 0.08% | 5 | TLS termination + reverse proxy |
| apigenie-certbot | 0% | 7 | Let's Encrypt certificate renewal |
| **TOTAL** | **65.4%** | **1,261** | |

### Root Cause of Kafka CPU Waste

The JVM heap is configured as `-Xmx1G -Xms1G` with G1GC `InitiatingHeapOccupancyPercent=35`.

- Actual heap usage: **734 MB** (72% of 1 GB)
- GC triggers at: **35% occupancy** (350 MB)
- Result: GC runs **constantly**, consuming an entire CPU core doing nothing useful

---

## 3. Per-Pipeline Resource Cost

Each S1 source pipeline (e.g. Okta, Check Point, Netskope connector) consumes:

| Resource | Per Pipeline | Notes |
|----------|-------------|-------|
| HTTP requests | ~10 req/min | Auth + data poll every 30–60s |
| Kafka consumer | 1 persistent TCP + SASL | For Event Hub / Observo sources |
| Kafka memory | 5–15 MB | Consumer session buffers |
| App CPU | < 0.01% | Pre-generated mock responses |
| Network I/O | ~50 KB/min | JSON payloads, small alerts |

---

## 4. Bottleneck Analysis — Limiting Factors

Ranked by which resource saturates first as pipeline count increases:

| # | Bottleneck | Current Usage | Hard Limit | Max Pipelines Before Saturation |
|---|-----------|---------------|------------|--------------------------------|
| **1** | **CPU (Kafka GC)** | **64% of 2 cores** | **~100% usable** | **10–15** |
| 2 | Uvicorn (1 worker) | Single-thread async | ~500 req/s | ~50 |
| 3 | RAM | 1.7 GB / 7.8 GB | ~6 GB usable | 80–100 |
| 4 | Disk | 14 GB / 30 GB | 16 GB free | 60–80 |
| 5 | Network / TCP | 24 open sockets | 65K kernel limit | Not a concern |

> **CPU is the hard wall.** With no changes, the machine can sustain **10–15 pipelines** before Kafka GC saturates both cores and requests start timing out.

---

## 5. Scaling Scenarios

Each tier is cumulative (includes all changes from previous tiers).

| Scenario | Changes | Est. Pipelines | Monthly Cost Delta |
|----------|---------|---------------|-------------------|
| **Current (baseline)** | No changes | **10–15** | $0 |
| **Tier 1 — Quick wins** | Kafka heap → 2G, Uvicorn → 2 workers | **30–40** | **$0 (config only)** |
| **Tier 2 — Storage** | Tier 1 + EBS disk → 100 GB | **50–60** | +$5/mo |
| **Tier 3 — Compute** | Tier 2 + EC2 → 4 vCPU m5.xlarge (16 GB RAM) | **80–100** | +$70/mo |
| **Tier 4 — Headroom** | Tier 3 + Kafka KRaft mode + 4 uvicorn workers | **100+** | +$70/mo (same) |

### Recommendation

> **Start with Tier 1** (zero cost, config-only changes). This alone **triples capacity** from 10–15 to 30–40 pipelines. Upgrade to Tier 3 only when approaching 40 active pipelines.

---

## 6. Implementation Details

### Tier 1 — Kafka Heap (docker-compose.yaml)

```yaml
KAFKA_HEAP_OPTS: "-Xmx2G -Xms2G"
```

**Impact:** CPU drops from ~64% to ~5–10%. Frees a full core.

### Tier 1 — Uvicorn Workers (Dockerfile or docker-compose.yaml)

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2
```

**Impact:** Parallel request handling. Doubles HTTP throughput.

### Tier 2 — EBS Volume Resize

```bash
# From AWS Console or CLI
aws ec2 modify-volume --volume-id vol-XXX --size 100

# Then on the instance
sudo growpart /dev/nvme0n1 1
sudo xfs_growfs /
```

**Impact:** Kafka log retention + room for growth.

### Tier 3 — EC2 Instance Upgrade

```
Stop instance → Change instance type to m5.xlarge → Start
```

**Provides:** 4 vCPU, 16 GB RAM. Elastic IP preserved. No data loss.

### Tier 4 — Kafka KRaft Mode

Replace Zookeeper with KRaft (built-in consensus). Saves 114 MB RAM, removes one container, simplifies stack. Requires Kafka config rewrite — moderate effort.

---

## 7. Risk Summary

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Kafka OOM at 100 pipelines (1G heap) | High | Service outage | Tier 1: increase heap to 2G |
| Disk full from Kafka logs | Medium | Log loss, broker crash | Tier 2: expand to 100 GB |
| CPU saturation at 40+ pipelines | Medium | Slow responses, timeouts | Tier 3: upgrade to 4 vCPU |
| Single uvicorn worker bottleneck | Low | Queued requests under burst | Tier 1: add workers |
| Network saturation | Very low | N/A at expected volumes | No action needed |

---

## 8. Monitoring

The ApiGenie admin UI (**Observability → System** tab) provides real-time monitoring of:

- Host CPU, RAM, and disk usage over time
- Per-container RAM and CPU consumption
- Request throughput per source

**Alert thresholds to watch:**
- CPU sustained > 80% → consider Tier 3
- RAM > 6 GB → consider Tier 3
- Disk > 80% → Tier 2 (expand EBS)
- Kafka container CPU > 30% after Tier 1 → investigate consumer count

---

*ApiGenie Capacity Report — Confidential — RoarinPenguin*
