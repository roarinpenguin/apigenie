# ApiGenie — User Guide

> Get started fast: deploy, configure sources, test with curl, push logs, create detection rules.

---

## 1. Deploy

```bash
git clone <repo-url> && cd apigenie
./scripts/bootstrap.sh              # generates TLS certs, configures domain
docker compose up -d --build         # starts all containers
```

Verify:

```bash
curl -sk https://localhost/health
# {"status":"ok","service":"apigenie"}
```

Open the Admin UI: `https://<your-domain>/admin`
Default credentials: `admin` / `apigenie`

> ![SCREENSHOT: Admin login page](screenshots/login.png)

---

## 2. Source Details — View Configuration

Navigate to **Source Details** in the left menu. Click any source chip to see:

- **Auth type** and credentials
- **Endpoints** (method, path, description)
- **Ready-to-use curl command**

> ![SCREENSHOT: Source Details — SentinelOne selected](screenshots/source-details-sentinelone.png)

---

## 3. Test Pull Sources with curl

### SentinelOne

```bash
# Threats (MITRE-mapped, full agent info)
curl -sk -H "Authorization: ApiToken apigenie-valid-token-001" \
  "https://localhost/web/api/v2.1/threats?limit=5"

# Activities (agent lifecycle, scans, STAR rules)
curl -sk -H "Authorization: ApiToken apigenie-valid-token-001" \
  "https://localhost/web/api/v2.1/activities?limit=5"

# Agent inventory
curl -sk -H "Authorization: ApiToken apigenie-valid-token-001" \
  "https://localhost/web/api/v2.1/agents?limit=5"
```

### Okta

```bash
curl -sk -H "Authorization: SSWS apigenie-valid-token-001" \
  "https://localhost/api/v1/logs?limit=5"
```

### Cloudflare

```bash
curl -sk -H "Authorization: Bearer apigenie-valid-token-001" \
  "https://localhost/client/v4/zones/zone_abc123/logs/received?count=5"
```

### Cato Networks (GraphQL)

```bash
curl -sk -X POST "https://localhost/api/v1/graphql2" \
  -H "x-api-key: any-key" -H "Content-Type: application/json" \
  -d '{"query":"{ eventsFeed(accountIDs:[12345]) { marker fetchedCount accounts { records { event_type time } } } }"}'
```

### Zscaler ZPA

```bash
curl -sk -H "Authorization: Bearer apigenie-valid-token-001" \
  "https://localhost/mgmtconfig/v2/admin/customers/12345/userActivity?pagesize=5"
```

### Microsoft Entra ID

```bash
curl -sk -H "Authorization: Bearer apigenie-valid-token-001" \
  "https://localhost/v1.0/auditLogs/directoryAudits"
```

### Wiz (GraphQL)

```bash
curl -sk -H "Authorization: Bearer apigenie-valid-token-001" \
  -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ issues { nodes { id severity } } }"}' \
  "https://localhost/graphql"
```

### Darktrace

```bash
curl -sk "https://localhost/modelbreaches?limit=5"
```

### Snyk

```bash
curl -sk -H "Authorization: token apigenie-valid-token-001" \
  "https://localhost/v1/org/test-org/audit"
```

### Proofpoint TAP

```bash
curl -sk -u "apigenie-principal-001:apigenie-secret-001" \
  "https://localhost/v2/siem/all"
```

### Tenable (async export)

```bash
# Start export
curl -sk -H "X-ApiKeys: accessKey=apigenie-access-001;secretKey=apigenie-secret-001" \
  -X POST "https://localhost/vulns/export" \
  -H "Content-Type: application/json" -d '{"filters":{}}'

# Check status (use uuid from response)
curl -sk -H "X-ApiKeys: accessKey=apigenie-access-001;secretKey=apigenie-secret-001" \
  "https://localhost/vulns/export/<uuid>/status"

# Download chunk
curl -sk -H "X-ApiKeys: accessKey=apigenie-access-001;secretKey=apigenie-secret-001" \
  "https://localhost/vulns/export/<uuid>/chunks/0"
```

---

## 4. Quick Reference — Auth per Source

| Source              | Auth header                              | Token value                                      |
| ------------------- | ---------------------------------------- | ------------------------------------------------ |
| Okta                | `Authorization: SSWS <token>`            | `apigenie-valid-token-001`                       |
| Netskope            | `Netskope-Api-Token: <token>`            | `apigenie-valid-token-001`                       |
| Entra ID / Defender | `Authorization: Bearer <token>`          | `apigenie-valid-token-001`                       |
| Cisco Duo           | HMAC-SHA1 (mock accepts any)             | any                                              |
| Tenable             | `X-ApiKeys: accessKey=...;secretKey=...` | `apigenie-access-001` / `apigenie-secret-001`    |
| Proofpoint          | HTTP Basic                               | `apigenie-principal-001` / `apigenie-secret-001` |
| Wiz                 | `Authorization: Bearer <token>`          | `apigenie-valid-token-001`                       |
| Snyk                | `Authorization: token <token>`           | `apigenie-valid-token-001`                       |
| Darktrace           | HMAC (mock accepts any)                  | any                                              |
| M365                | OAuth2 → JWT                             | any client_id/secret                             |
| Cato                | `x-api-key: <key>`                       | any                                              |
| Cloudflare          | `Authorization: Bearer <token>`          | `apigenie-valid-token-001`                       |
| Zscaler ZPA         | `Authorization: Bearer <token>`          | `apigenie-valid-token-001`                       |
| SentinelOne         | `Authorization: ApiToken <token>`        | `apigenie-valid-token-001`                       |

---

## 5. Log Push — Send Logs to External Destinations

### Step 1: Open Log Push tab

Navigate to **Log Push** in the left menu.

> ![SCREENSHOT: Log Push tab — empty state](screenshots/log-push-empty.png)
> 

### Step 2: Create a push profile

Click **+ New profile** and fill in:

| Field           | Description                   | Example                        |
| --------------- | ----------------------------- | ------------------------------ |
| **Name**        | Profile identifier            | `paloalto-to-s1-siem`          |
| **Source**      | Log source type               | Palo Alto PAN-OS               |
| **Format**      | JSON, Syslog, or CEF          | JSON                           |
| **Transport**   | HEC, Syslog, or HTTP POST     | HEC                            |
| **HEC Flavour** | Splunk / S1 AI SIEM / Observo | S1 AI SIEM                     |
| **Host**        | Destination hostname          | `ingest.usea1.sentinelone.net` |
| **Port**        | Destination port              | `443`                          |
| **Path**        | HEC endpoint path             | `/services/collector/raw`      |
| **Token**       | Auth token                    | `<your-api-token>`             |
| **Account ID**  | S1 account ID (S1 SIEM only)  | `2149421019176225082`          |
| **Duration**    | How long to push (seconds)    | `300`                          |
| **Rate (EPS)**  | Events per second             | `10`                           |
| **TLS**         | Enable HTTPS                  | ✓                              |

### Step 3: Start pushing

Click **Start** on the profile card. Logs stream in real-time.

> ![SCREENSHOT: Log Push profile running](screenshots/log-push-running.png)
> 

### Available sources for push

All 16 push sources are listed in the Source dropdown. Each generates realistic, weighted events matching the real vendor log format.

---

## 6. Log Profiles — Entity Blending

### What are profiles?

Profiles define **entity pools** — realistic users, machines, C2 servers, malware samples, and mail senders. When assigned to a source, profile entities are blended into generated logs.

### Step 1: Create a profile

Go to **Log Profiles & Detection Rules** → expand **▸ Log Profiles** → click **+ New profile**.

Define entity pools:

| Pool             | Example entries                                                              |
| ---------------- | ---------------------------------------------------------------------------- |
| **Users**        | `jsmith` (username), `CORP\jsmith` (domain), `jsmith@contoso.com` (email)    |
| **Machines**     | `DESKTOP-HQ01` (workstation), `192.168.1.100` (IP), `Windows 11` (OS)        |
| **C2 servers**   | `evil.com` (FQDN), `198.51.100.1` (IP), `4444` (port)                        |
| **Malware**      | `payload.exe` (filename), `mimikatz` (family), `cmd.exe /c whoami` (cmdline) |
| **Mail senders** | `phisher@evil.com` (from), `Urgent Invoice` (subject)                        |

### Step 2: Bind to sources

Expand **▸ Source ↔ Profile bindings**. For each source:

- Select the profile
- Set **signal-to-noise ratio** (how often profile entities appear vs random)
- Set **log volume** (1–100% of max output per API call)

> ![SCREENSHOT: Source bindings with sliders](screenshots/profile-bindings.png)
> 

---

## 7. Request Inspector

The **Requests** tab shows all incoming API requests in real-time:

- Method, path, query parameters
- Source auto-detection
- Response status code
- Timing

> ![SCREENSHOT: Request Inspector with SentinelOne requests](screenshots/request-inspector.png)
> 

---

## 8. Observability

The **Observability** tab provides:

- **Sankey diagram** — request flow by source
- **Geographic map** — client IP distribution
- **Usage chart** — requests over time
- **System metrics** — CPU and container stats

> ![SCREENSHOT: Observability dashboard](screenshots/observability.png)
> 
