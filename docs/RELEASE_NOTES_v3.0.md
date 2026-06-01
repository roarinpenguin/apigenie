# ApiGenie v3.0 — Release Notes

**Release date:** June 2026

---

## Overview

ApiGenie v3.0 is a major release that transforms the platform from a pull-only mock API server into a **full-spectrum security telemetry generator** — covering pull sources, push (active log shipping), and live integration with the SentinelOne Detection Library for rule-driven log injection.

### What's new at a glance

| Area | v2.x | v3.0 |
|------|------|------|
| Pull sources (HTTP/GraphQL) | 11 | **18** (+7) |
| Push sources (active log shipping) | 0 | **16** |
| Transport protocols | — | HEC, Syslog, HTTP POST |
| HEC flavours | — | Splunk, S1 AI SIEM, Observo |
| Log Profiles & entity blending | Basic | Full (users, machines, C2, malware, mail) |
| Detection Rules | — | Local + S1 Detection Library import |
| S1 console integration | — | Browse, import, enable/disable rules |
| Admin UI sections | 5 | **10** |

---

## 1. Log Push Sources (16 sources)

ApiGenie can now **actively send generated logs** to external destinations — SIEM, data lake, or pipeline — instead of waiting for collectors to pull.

### Supported sources

| # | Source | Event types |
|---|--------|-------------|
| 1 | Palo Alto PAN-OS | TRAFFIC, THREAT, URL, AUTH, USERID, SYSTEM, CONFIG, HIP-MATCH, GlobalProtect, WildFire, Decryption, Correlation |
| 2 | Fortinet FortiGate | Traffic, UTM (AV, IPS, Web Filter, App Control), Event, Anomaly |
| 3 | Check Point NGFW | Accept/Drop/Reject, Blade logs (IPS, AV, App Control, URL Filtering, Anti-Bot) |
| 4 | Cisco ASA/FTD | Connection build/teardown, denied, threat, VPN, AAA, system (syslog) |
| 5 | CrowdStrike Falcon | DetectionSummaryEvent, IncidentSummaryEvent, AuthActivityAudit, UserActivityAudit |
| 6 | VMware Carbon Black | Alerts, watchlist hits, process events, audit |
| 7 | Zscaler ZIA | Web transactions, firewall, DNS, tunnel (NSS format) |
| 8 | Imperva Cloud WAF | Security events, bot detection, ACL violations, DDoS mitigation |
| 9 | Barracuda Email Security | Spam, virus, DLP, ATP sandbox, admin audit |
| 10 | Infoblox DDI | DNS queries, RPZ hits, DHCP events, threat intelligence |
| 11 | Cisco Switch (IOS/NX-OS) | Port security, STP, ACL, AAA, CDP, DHCP snooping, ARP inspection |
| 12 | HPE Aruba Switch (AOS-CX) | 802.1X, RADIUS, STP, LLDP, ACL, DHCP snooping, PoE, VSF |
| 13 | SentinelOne XDR | Threats, Activities, Deep Visibility (process/network/file/registry), Audit |
| 14 | Corelight / Zeek NDR | conn, dns, http, ssl, files, notice, weird, x509, smtp, dpd (10 log types) |
| 15 | CyberArk EPM / PAM | Credential checkout/checkin, privileged sessions, policy violations |
| 16 | Stamus Networks SSP | IDS/IPS alerts, flow, DNS, HTTP, TLS, fileinfo, anomaly, stats (EVE JSON) |

### Transport options

- **HEC (HTTP Event Collector)** — three flavours auto-detected:
  - **Splunk HEC** — `Authorization: Splunk <token>`
  - **S1 AI SIEM** — `Authorization: Bearer <api-token>`, `S1-Scope: account=<id>`
  - **Observo / S1 DPM** — `Authorization: Bearer <jwt>`, HTTP/2 TLS
- **Syslog** — RFC 5424 over TCP/UDP, configurable facility/severity
- **HTTP POST** — JSON payload to any endpoint

### Push profile configuration

Each push profile specifies: source type, log format (JSON / Syslog / CEF), transport, destination host:port, duration, rate (EPS), and optional TLS. Profiles are managed in the Admin UI **Log Push** tab.

---

## 2. New Pull Sources (+7)

Seven new HTTP/GraphQL pull sources bring the total to **18 emulated security APIs**.

| # | Source | Auth | Endpoints |
|---|--------|------|-----------|
| 12 | Cato Networks SASE | x-api-key | `POST /api/v1/graphql2` — eventsFeed + auditFeed, marker pagination |
| 13 | Cloudflare | Bearer | Logpull, WAF events, DNS analytics, Zero Trust Access, Gateway audit |
| 14 | Zscaler ZPA | Bearer (OAuth2) | User activity, audit log, connector status, health |
| 15 | SentinelOne | ApiToken | `/web/api/v2.1/threats`, `/activities`, `/agents` — cursor pagination, MITRE ATT&CK |

Plus M365 was enhanced in v2.5.

### SentinelOne pull source highlights

- Response shapes **match the real Management Console API v2.1** — verified against a live console
- `agentDetectionInfo` and `agentRealtimeInfo` nested objects with 25+ fields each
- `threatInfo` with full classification, mitigation status, SHA256, command lines, storyline
- MITRE ATT&CK tactic/technique mapping with links
- Cursor-based pagination with `nextCursor`
- 62-field agent inventory (CPU, memory, OS, network interfaces, scan status, tags)

---

## 3. Detection Rules & S1 Integration

### Local detection rules

Detection rules inject **specific field patterns** into normal generated logs at a configurable periodicity. This lets you verify that your SIEM rules trigger correctly.

Each rule specifies:
- **Source** — which log source to inject into
- **Field overrides** — key-value pairs that replace fields in normal logs
- **Periodicity** — `1 in N logs` or `every N seconds`
- **Enabled/disabled** toggle

### S1 Detection Library integration

The Admin UI includes a **slide-out drawer** that connects to your live SentinelOne console and lets you:

1. **Browse** the full S1 Detection Library (2000+ catalog rules + custom rules)
2. **Filter** by source, MITRE tactic, detection logic visibility, and free-text search
3. **View** full rule details: severity, description, MITRE techniques, s1ql query (no truncation)
4. **Import** rules into ApiGenie with auto-mapped field overrides:
   - S1 native PowerQuery fields (`endpoint.os`, `event.type`, `registry.keyPath`, `src.process.cmdline`, etc.) → mapped as native
   - `unmapped.*` fields → prefix stripped to get original vendor field
   - OCSF fields → reverse-mapped per source via lookup table
   - `contains`, `matches`, `in()` operators → all parsed, not just `=`/`==`
5. **Enable/disable** rules directly on the S1 console via API

### S1 console settings

Configured in System Settings: Console URL + API token, with connection test.

---

## 4. Admin UI Enhancements

### New tabs and features

- **Log Profiles & Detection Rules** (renamed, collapsible sections):
  - Log Profiles — define entity pools (users, machines, C2, malware, mail senders)
  - Source ↔ Profile bindings — assign profiles to sources, tune signal-to-noise ratio and log volume
  - Detection Rules — manage local rules, browse S1 library drawer
- **Log Push** — configure and run push profiles
- **System Settings** — S1 console URL/token, connection test

### UI improvements

- All three sections in Log Profiles & Detection Rules are **collapsible** (collapsed by default)
- Detection rule list uses a **two-row layout** — name/source/period on top, description wrapped below
- S1 drawer: **480px wide**, full query display (no truncation), logic visibility filter
- Nav label: "Log Profiles & Detection Rules" with aligned two-line layout

---

## 5. HEC Transport Fixes

- **HTTP/2 compatibility** — switched from `urllib.request` to `http.client` for TLS connections (required by Observo endpoints)
- **Auth scheme auto-detection** — distinguishes Splunk HEC, S1 AI SIEM, and Observo/DPM based on endpoint hostname and stored profile
- **S1-Scope header** — automatically injected for S1 AI SIEM endpoints
- **Host field sanitisation** — strips `https://` scheme from host before opening connections

---

## Breaking changes

None. All v2.x pull sources, streaming sources, and admin UI features continue to work unchanged.

---

## Upgrade path

```bash
git pull
docker compose up -d --build
```

No database migrations. Detection rules and push profiles are stored as JSON files in `$APIGENIE_DATA_ROOT/` (default: `/data/`).
