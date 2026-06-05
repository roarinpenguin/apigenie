# ApiGenie — Release Notes

---

## v4.0 — *The Multi-User Edition*

> *Released June 2026.* The biggest release since v1.0. ApiGenie is no longer a single-tenant mock server: one deployment now hosts arbitrarily many isolated users, each with their own log profiles, detection rules, source identifiers, SentinelOne console, avatar, and recovery flow — driven from a brand-new `/portal` UI that lives side-by-side with the existing `/admin`.
>
> If you are upgrading from v3.x: read the **[Breaking changes & migration](#breaking-changes--migration-v30--v40)** section before `docker compose up -d --build`. Most installs need *zero* manual steps, but two env vars and one persistent volume path moved.

### At a glance

- **Two portals on the same TLS port.** `/admin` for operators, `/portal` for end-users. Same `ag_session` cookie, two distinct surfaces, role-aware sidebars, server-side enforcement at the HTTP middleware layer.
- **Full RBAC.** Entitlements (named bundles of `{category: [permissions]}`) × five categories × five permissions, with admin implicitly holding every permission. Permission checks are server-side on every write endpoint — not just UI hiding.
- **Per-user identifier matching.** Each pull source stays a single shared endpoint (`/api/v1/logs`, `/web/api/v2.1/threats`, …). The credential the collector presents (Bearer token, tenant id, API key, …) is matched against per-user identifiers; the first match wins, and log shaping becomes that user's profile, intensity, detection rules, and entity blending. No match → public profile fallback. Reserved demo tokens are guarded against accidental registration.
- **Per-user SentinelOne console** *(Phase 3.5)*. Every user can set their own S1 URL + API token in **My Account**. Every `/admin/api/s1/*` call from that session — or from an admin acting-as them — automatically routes through *their* tenant. Two SEs sharing one ApiGenie can finally point at their own consoles without coordination.
- **Self-service account settings** *(Phase 3.5)*. `GET /admin/api/me/account`, `PUT /admin/api/me/email`, `PUT /admin/api/me/password` (verifies current), `GET/PUT/DELETE /admin/api/me/s1-console` (token is write-only — never returned).
- **Avatars** *(Phase 3)*. Drop in a PNG / JPEG; Pillow center-crops to a 250×250 circular RGBA portrait. Topbar, switcher, sidebars all light up.
- **Password handoff & recovery** *(Phase 3)*. Admin creates a user without a password, gets a one-shot `/portal/set-password?token=…` link to share over any channel. Same machinery powers admin-issued recovery links. No SMTP required.
- **"Viewing as" switcher.** Admin signed into `/portal` can pick a target user; every owner-scoped read & write happens in that user's namespace. Support-friendly, password-sharing-free.
- **91 regression tests.** Every RBAC guarantee — identifier matching, owner scoping, S1 resolution order, avatar processing, recovery-token lifecycle, self-service semantics, acting-as edge cases — is locked in by `pytest` and ships with the repo.
- **One-page landing redesigned.** The public `/` page now opens a small menu instead of a single Admin button: **User Portal** ("Telemetry config & monitoring") and **Admin** ("Infrastructure & security").
- **New pull source — Mimecast Email Security.** OAuth2 client_credentials → SIEM API 2.0 (`/siem/v1/events/cg`), 8 log types: receipt, process, delivery, AV, spam, TTP URL/Attachment/Impersonation Protect. Plus the 1.0 endpoints aligned to the collector's `ENDPOINT_REGISTRY`.
- **AWS deployment** is now first-class: parametrised Terraform (`terraform/` — EC2 + EIP + SG + IAM + cert-bot bootstrap) and a zero-to-hero `docs/AWS_DEPLOYMENT.md` guide.

### What's new in detail

#### Multi-user & RBAC (Phases 1 – 3.5)

The full design lives in [`docs/MULTI_USER_LOG_PROFILING.md`](docs/MULTI_USER_LOG_PROFILING.md) and [`docs/RBAC_MODEL.md`](docs/RBAC_MODEL.md). Phased landings:

| Phase | What landed | Where it lives |
|-------|-------------|----------------|
| **P1 — Identity & RBAC core** | SQLite-backed `accounts.users`, `accounts.entitlements`, `accounts.identifiers`, `accounts.recovery_tokens`. Two-portal auth (`/admin/login`, `/portal/login`). Admin user CRUD (`/admin/api/rbac/*`). Server-side permission model. `_portal_role_guard` HTTP middleware rejects user-portal sessions reaching admin-only paths. Investigation password gate retired. | `accounts.py`, `app.py`, `admin.py` |
| **P2 — Data ownership** | `owner_id` + `visibility` (`private`/`public`) on Log Profiles, Detection Rules, Log Push Profiles, Custom Listeners, Source↔Profile Bindings. Admin sees everything; users see their own + public. Per-user identifier matching on every pull request (`auth.identify_caller`). Reserved-credentials guard. User portal substitutes placeholders into Source Details cards so demo tokens never leak. | `profiles.py`, `detection_rules.py`, `log_pusher.py`, `listeners.py`, `auth.py`, `admin.py` |
| **P2.5 — Detection-rule injection scoping** | Detection rules respect the resolved caller (owner-or-public). Per-source rules don't bleed across users. | `detection_rules.py`, `tests/test_rbac_phase2_5_detection.py` |
| **P3 — Polish** | Per-user avatars (Pillow 250×250 circular PNG, max 5 MB input, atomic on-disk store keyed by uid). One-shot admin handoff links + recovery-token lifecycle (`POST /admin/api/rbac/users/{uid}/reset-link`). Log-Push detection-rule injection is now caller-aware via a `ContextVar`. | `avatars.py`, `accounts.py`, `log_pusher.py` |
| **P3.5 — Self-service** | `GET /admin/api/me/account` · `PUT /admin/api/me/email` · `PUT /admin/api/me/password` (verifies current) · `GET/PUT/DELETE /admin/api/me/s1-console`. New per-request caller-context middleware so every `/admin/api/s1/*` call resolves the right console without route-level threading. Acting-as honoured for email/S1; *intentionally not* honoured for password (so admins can't silently rewrite a target's password through self-service). | `accounts.py`, `s1_detection_library.py`, `app.py`, `admin.py` |

The five RBAC categories (Log Profiles · Detection Rules · Log Push · Custom Listeners · Source Bindings) each support five permissions (View · Create · Modify · Delete · Manage). Six categories remain admin-only and are not in entitlements at all: Intrusions · Investigations & Bans · Container Logs · Observability · System Settings · Entitlement / User management.

#### New & improved sources

- **Mimecast Email Security** (pull) — OAuth2 `client_credentials` → JWT, SIEM API 2.0 batch fetch at `/siem/v1/events/cg`. 8 log types with realistic per-type weightings: `receipt`, `process`, `delivery`, `av`, `spam`, `ttp-url`, `ttp-attachment`, `ttp-impersonation`. Also exposes the matching 1.0 endpoint shapes the collector's `ENDPOINT_REGISTRY` expects.
- **Microsoft 365** — multi-domain audit logs and tightened source-trace patterns so M365 / Entra ID / Defender for Cloud don't bleed into each other's request inspector groupings.

#### Hardening, infra & dev-loop

- **AWS deployment**. `terraform/` is now parametrised (EC2 instance type, AMI, EIP, security group, IAM role, optional Route53 record, `bootstrap.sh` runs on first boot to issue Let's Encrypt). `terraform.tfvars.example` lays out every knob. Full walkthrough in [`docs/AWS_DEPLOYMENT.md`](docs/AWS_DEPLOYMENT.md).
- **91-test regression suite**. `tests/` ships with the repo and runs inside the container (`docker exec apigenie python -m pytest tests/ -v`). `tests/conftest.py` redirects every storage path to a fresh tmp dir *before* importing project modules, so the suite is hermetic. Coverage map:
  - `tests/test_rbac_phase2.py` — accounts, entitlements, identifiers, reserved-creds, masking, viewing-as.
  - `tests/test_rbac_phase2_5_detection.py` — per-user detection injection (pull).
  - `tests/test_rbac_phase3_log_push.py` — per-user detection injection (Log Push).
  - `tests/test_rbac_phase3_avatars.py` — Pillow pipeline, store, endpoints.
  - `tests/test_rbac_phase3_recovery.py` — recovery-token lifecycle.
  - `tests/test_rbac_phase35_self_service.py` — email / password / per-user S1 helpers.
  - `tests/test_rbac_phase35_endpoints.py` — `/admin/api/me/*` + caller-context middleware.
- **Dashboard JS parse-check.** `scripts/check_dashboard_js.py` boots `admin.py` against a tmp data root, renders the dashboard HTML, extracts the inline JS and parses it with `acorn` (when available) or `node --check` — turns silent template-literal bugs into a hard failure during CI.
- **Dockerfile.** Adds Pillow (for avatars) and `pytest` + `pytest-asyncio` (so the test suite runs against the actual container).

#### Documentation overhaul

The README, both lab guides, and the design doc were rewritten end-to-end for the multi-user world. New top-level resources:

- [`README.md`](README.md) — new **Multi-user & RBAC** section with the RBAC quickstart, refactored Portals section covering both UIs, completely rewritten endpoint catalogue (Identity & RBAC / Telemetry config / S1 / Diagnostics), per-row admin-only flag, refreshed env-var + storage tables.
- [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — Section 0 (single-user lab) + 11 RBAC exercises ending with **Exercise 11 — Account Settings** (Phase 3.5).
- [`docs/ADMIN_GUIDE.md`](docs/ADMIN_GUIDE.md) — Section 0 (admin RBAC lab) + Exercises A – I, with **Exercise I — Audit per-user S1 console overrides**. The §11 API reference documents the source-data vs control-plane split, the `/admin/api/me/*` family with acting-as semantics, and the global vs per-user S1 resolution order.
- [`docs/MULTI_USER_LOG_PROFILING.md`](docs/MULTI_USER_LOG_PROFILING.md) — full Phase 1 – 3.5 design rationale.
- [`docs/RBAC_MODEL.md`](docs/RBAC_MODEL.md) — categories × permissions reference card.
- [`docs/RBAC_USER_PROFILES.md`](docs/RBAC_USER_PROFILES.md) — owner-scoping rules per resource family.
- [`docs/AWS_DEPLOYMENT.md`](docs/AWS_DEPLOYMENT.md) — Terraform walkthrough.

### Breaking changes & migration (v3.0 → v4.0)

The upgrade story is "down, pull, up": container-level state lives in one Docker volume and the schema bootstraps itself on first start. But three things shifted in ways that may surprise long-running deployments:

1. **Investigation-password gate removed.** The 🔍 Investigations tab was previously protected by a second password (`APIGENIE_INVESTIGATE_PASSWORD`, `./data/investigate_pass`). It is now plain admin-only. The env var and file are still tolerated — you can delete them at your leisure — but they no longer control access. If your runbooks reference that password, simplify them.
2. **Two new SQLite files in the data volume.**
   - `./data/apigenie.db` — accounts, entitlements, identifiers, recovery tokens, per-user S1 settings.
   - `./data/avatars/<uid>.png` — one PNG per user that has uploaded an avatar.
   Make sure your `./data` host directory is a **named Docker volume** (it is by default in the shipped `docker-compose.yaml`). A bind mount that doesn't persist across `docker compose down` will lose every user — same trap as `./data/profiles/` in v3.
3. **Per-user log shaping requires identifier registration.** In v3.x, every collector that hit `/api/v1/logs?…` saw the public profile binding. In v4.0, that still happens for the reserved demo tokens (`apigenie-valid-token-001` …) and any unknown credential — but a user that wants their *own* shaping has to register the credential value under **User Portal → Source Identifiers** (or `POST /admin/api/identifiers`). Existing demos using only the reserved tokens are unaffected.

There are also four **non-breaking but worth knowing** items:

- The Admin UI sidebar grew a **My Account** entry (Phase 3.5). The built-in admin sees a stub there — admin password changes still happen in **System Settings → Change admin password** because the built-in admin has no DB row.
- `ADMIN_PASSWORD_FILE` (default `/var/lib/apigenie/admin_pass`) is now consulted ahead of `ADMIN_PASSWORD_HASH`. Behaviour matches v3 — the file is only written when an admin actively changes the password through the UI — but the env var is now documented as a debugging knob, not the primary path.
- The data-root env-var triplet (`APIGENIE_DATA_ROOT` / `APIGENIE_DATA_DIR` / `APIGENIE_DATA`) is unchanged from v3, but the README's env table now spells out which module reads which. Tests rely on this; production usually doesn't have to touch it.
- The public landing page (`/`) shows a **dropdown** instead of a single "Admin" button. Bookmarks to `/admin/login` and `/portal/login` continue to work.

### Upgrade procedure

```bash
docker compose down
git pull           # pulls v4.0
docker compose up -d --build
# That's it. The accounts DB is created automatically the first time
# the container boots; the admin password remains whatever it was.

# Optional: confirm everything is green
docker exec apigenie pip install --quiet pytest pytest-asyncio
docker exec apigenie python -m pytest tests/ -v
# → 91 passed
```

If anything looks wrong post-upgrade, the **first** diagnostic is `GET /admin/api/me` while signed into both portals — it returns the resolved identity, role, effective permissions, and `has_avatar` flag, and is the cheapest possible "is the session what I think it is?" check.

### What's next

- **Hyperautomation / SOAR integration.** Letting workflows mutate ApiGenie state (publish a profile, mint a recovery link, rotate a per-user S1 token) over a single signed webhook.
- **Bulk user import** (CSV / SCIM-lite) for SE workshops with 50+ attendees.
- **Per-user log push destinations** so each user can pipe their own generated logs into their own collector without exposing global push profiles.

If you have an opinion on any of those — or a use case the current model doesn't cover — open an issue and tag it `v4.x`.

---

## v3.0 — *SentinelOne edition* — *April 2026*

- **SentinelOne pull source** (`/web/api/v2.1/threats`, `/activities`, `/agents`) — full MITRE ATT&CK mapping, cursor pagination, real console response shape.
- **6 new pull sources**: Cato Networks SASE, Cloudflare, Zscaler ZPA, Corelight/Zeek, CyberArk EPM/PAM, Stamus Networks SSP.
- **SentinelOne Singularity push source** + **Attack Scenario Builder** (multi-event correlated attacks, ATT&CK-anchored).
- **Cisco / HPE Aruba switch push sources** (port security, STP, 802.1X, RADIUS, VSF, PoE).
- **S1 Detection Library integration** (`/admin/api/s1/*`) — query catalog + custom rules, preview-import to local detection rules, enable/disable on S1 from ApiGenie. *(In v4.0 this becomes per-user-aware.)*
- **HEC transport fix** — `http.client` rewrite, scheme stripping, auth-header auto-detection.

## v2.x — *Detection & Push* — *February – March 2026*

- **Detection Rules** — count-based (1 in N) and time-based (every N s) injection of SIEM-triggering log patterns into the normal event flow. Works across all 14 HTTP sources + Kafka + Pub/Sub publishers.
- **Log Push framework** — 10 vendor generators (Palo Alto, FortiGate, Check Point, Cisco ASA, CrowdStrike, Carbon Black, Zscaler, Imperva, Barracuda, Infoblox), 3 formats (JSON / Syslog RFC5424 / CEF), 3 transports (HTTP / Splunk HEC / Syslog TCP-or-UDP). Start/stop control, last-100 event log with delivery confirmation, per-profile TLS.
- **Microsoft 365 pull source** — 14 event categories (Mailbox, ATP, DLP, eDiscovery, Admin, SPO/OneDrive, Teams, OAuth, Inbox rules, Power Platform, PIM, Audit search, Quarantine, Login). Two modes: Graph `alerts_v2` and Management Activity API.
- **Per-source log volume control** (1 – 100 %) so different consumers can be load-balanced on the same deployment.
- **Architecture hub-and-spoke diagram** on the public landing.
- **SASL/OAUTHBEARER** support for the Azure Event Hubs Kafka listener.

## v1.x — *Foundations*

- Self-contained mock server for 14 security platform APIs (Okta, Netskope, Entra ID, Defender for Cloud, Cisco Duo, Tenable, Proofpoint, Wiz, Snyk, Darktrace, plus AWS generators).
- Azure Event Hubs (Kafka SASL/SSL + SASL/PLAINTEXT) and GCP Cloud Logging (Pub/Sub emulator over TLS) streaming sources with background publishers.
- One-shot `./scripts/bootstrap.sh`: domain, admin password, TLS mode (self-signed / Let's Encrypt / existing), all in a single Docker Compose stack.
- Admin UI with Request Inspector, Observability (Flows / GeoMap / Usage / System), Intrusions, Investigations, Container Logs, Listeners, Log Profiles, Source Details, System Settings.
- Persistent telemetry (`telemetry.db`, 1-year retention, adaptive bucketing 1 min → 1 day).
- In-stack certbot sidecar with zero-downtime nginx reload + Kafka restart on renewal.

---

*Versions before v3.0 were tagged informally inside the SE team; v4.0 is the first release with a published release-notes document. Future versions will append above this line.*
