# ApiGenie — User Guide

> Get started fast: deploy, configure sources, test with curl, push logs, create detection rules.
>
> **New testers — start with [Section 0](#0-testers-lab--multi-user--rbac-exercises).** Sections 1–8 are reference material you can dip into as the exercises demand.

---

## 0. Tester's Lab — Multi-User & RBAC Exercises

This is a hands-on lab. Each exercise has a **Goal**, the exact **Steps** to perform, and a **Pass criteria** you can tick off. Run them in order: every exercise depends on the state left by the previous one.

You will need two browsers (or one normal + one Incognito window) so the admin and the regular user can stay signed in simultaneously without sharing cookies. Throughout this lab the URL prefix is `https://<your-domain>` — substitute `localhost` if you are running the dev stack on your laptop.

> **There is only one port — 443.** Both the **source-data API** (`/api/v1/logs`, `/web/api/v2.1/threats`, …) and the **control-plane API** (`/admin/api/*`, `/portal/api/*`) are served over the same HTTPS port. They use **different credentials**:
>
> - Source endpoints → the source-specific header (`Authorization: SSWS …`, `Authorization: ApiToken …`, `Authorization: Bearer …`, `X-ApiKeys: …`, etc.) — no cookie required.
> - Control-plane endpoints → the `ag_session` HTTP cookie, obtained by `POST /portal/login` (regular user) or `POST /admin/login` (admin) with form fields `username` + `password`. The cookie is `HttpOnly`, `SameSite=Lax`, 24 h TTL.
>
> The exercises below mostly use the browser, which manages the cookie for you. If you want to script with curl, see `docs/ADMIN_GUIDE.md` § 11.1 for the copy-pasteable login recipe.

> **Lab world.** You will impersonate three personas:
>
> | Persona | Username | Role | Browser |
> |---------|----------|------|---------|
> | The administrator | `admin` (built-in) | full power | Browser A — `/admin` |
> | Alice — SOC analyst | `alice` (to be created) | scoped permissions | Browser B — `/portal` |
> | Bob — pipeline engineer | `bob` (to be created) | scoped permissions | Browser B again, after Alice signs out |

### Exercise 1 — Sign in as the built-in admin

**Goal.** Confirm the platform is up and you have admin access.

**Steps.**

1. **Browser A** → open `https://<your-domain>/admin`.
2. Sign in with `admin` / `<the password you set during bootstrap>` (default `apigenie` if you skipped the prompt).
3. Look at the top-right corner of the page.

**Pass criteria.**

- You land on the **Request Inspector** dashboard.
- The top-right does **not** show an avatar circle (the built-in admin has no avatar — by design, avatars belong to registered accounts).
- The left nav shows the **Users** entry (only visible to admins).

> ![SCREENSHOT: Admin dashboard top-bar — no avatar, "Users" in nav](screenshots/admin-topbar.png)

---

### Exercise 2 — Create an Entitlement

**Goal.** Define the permission template you will hand to Alice. This is the foundation of every user-level capability check.

**Steps.**

1. In Browser A go to **Users → Entitlements** tab.
2. Click **+ New Entitlement**.
3. Fill in:
   - **Name:** `SOC Analyst`
   - **Description:** `Read most things, push some logs, manage own detection rules.`
4. In the permission grid grant:
   - **Sources** → `read`
   - **Log Profiles** → `read`
   - **Detection Rules** → `read`, `write`
   - **Log Push** → `read`, `write`
   - Leave everything else unchecked.
5. **Save**.

**Pass criteria.**

- The new entitlement appears in the table with the count of granted perms.
- Edit it → unchecked categories are still untouched.

> **Why this matters.** Entitlements are reusable: ten "SOC Analyst" users will all reference this row, and editing it changes their effective rights atomically.

---

### Exercise 3 — Create Alice using a handoff link (no SMTP)

**Goal.** Onboard a user without sending any email. The admin generates a one-time link and shares it through whatever side channel (chat, ticket, sticky note).

**Steps.**

1. Browser A → **Users → Users** tab → **+ New User**.
2. Fill in:
   - **Username:** `alice`
   - **Email:** `alice@example.com` (purely cosmetic — never delivered)
   - **Entitlement:** `SOC Analyst` (created in Exercise 2)
   - **Password:** **leave blank** — this is the trigger for the handoff link.
3. **Save**.
4. A modal appears titled **"Share this one-time set-password link with the user"**. Copy the URL.

**Pass criteria.**

- The link is of the form `/portal/set-password?token=…` and the token is long and random.
- Alice now appears in the user list with the badge **"Pending password"**.

> **Security note.** The token is single-use and expires in 7 days. If the tester (Alice) doesn't claim it in time, the admin can reissue from the user's row → **Send reset link**.

---

### Exercise 4 — Alice claims the link and sets her password

**Goal.** Walk through the user-facing onboarding.

**Steps.**

1. **Browser B** (Incognito window) → paste the link from Exercise 3.
2. You should see a "Set a password for **alice**" form.
3. Choose a password ≥ 8 characters, confirm, **Submit**.
4. The page shows "Password set successfully." Click **Continue to sign in →**.
5. Sign in as `alice` / `<your-password>`.

**Pass criteria.**

- Alice lands on `https://<your-domain>/portal/`.
- Top-right shows a circular avatar with the initial **A** on a purple gradient (the initials fallback).
- Left nav for Alice contains only the sections allowed by the **SOC Analyst** entitlement — there is **no Users entry**.
- Try to re-use the same token (paste the URL into a new tab). It should render "This link is invalid or has expired."

> **Pass criteria you can also test from the CLI** (the underlying behaviour is covered by automated tests in `tests/test_rbac_phase3_recovery.py`).

---

### Exercise 5 — Upload Alice's avatar

**Goal.** Verify the Phase 3 avatar pipeline end-to-end (upload → Pillow circle render → topbar display).

**Steps.**

1. As Alice (Browser B), click the purple **A** circle in the top-right.
2. A file picker opens — select any JPEG or PNG portrait you have lying around. Bigger than 250 px is fine; non-square is fine; rotated phone photos with EXIF are fine.
3. Wait for the **"Avatar updated"** toast.

**Pass criteria.**

- The circle now shows your chosen image, cropped to a centred square, scaled to 250 px, with corners clipped to a perfect circle.
- A small **×** badge appears at the top-right of the avatar — click it to remove and confirm the initials fallback returns.
- Re-upload, then hard-refresh the page (Cmd-Shift-R / Ctrl-F5). The avatar persists — it is stored under `$APIGENIE_DATA_ROOT/avatars/<uid>.png`.

> **Negative tests to try.**
>
> - Upload a > 5 MB file → you get a **"too large"** error toast and the avatar is unchanged.
> - Upload a `.txt` file → backend returns 400 "Cannot decode image" — the toast surfaces it.

---

### Exercise 6 — Register a credential identifier for Alice

**Goal.** Make every API request that carries Alice's API token resolve to Alice. This is the **identifier** mechanism that powers per-user log shaping and detection scoping.

**Steps.**

1. Still in Browser B, as Alice → **Source Details** in the left nav.
2. Pick **Okta** in the source chips.
3. Look for the **"Your credentials for this source"** card. Click **+ Add identifier**.
4. Fill in:
   - **Kind:** `bearer_token` (the only choice Okta offers)
   - **Value:** `alice-okta-personal-001`  (a string you can remember — but **not** one of the reserved demo tokens such as `apigenie-valid-token-001`)
5. **Save**.

**Pass criteria.**

- The identifier appears under Alice's identifiers list.
- If you try to add the **same** value a second time you get **"That identifier value is already in use."** (globally unique).
- If you try to register one of the well-known demo tokens (e.g. `apigenie-valid-token-001`) the admin/portal blocks it as a **reserved** credential — those belong to the shared "public" profile.

> **Why globally unique?** A token must identify exactly one user; ambiguity would risk one user's traffic being attributed to another.

---

### Exercise 7 — Verify per-user shaping on a pull source

**Goal.** Two requests, same source, **different tokens** → different log content. This is the heart of the multi-user feature.

**Setup (one-time, as admin in Browser A).**

1. Go to **Log Profiles & Detection Rules → Log Profiles** and create two trivial profiles:
   - `Public Profile` — user pool `[ "publicuser01" ]`, machine pool `[ "PUBLIC-HOST" ]`.
2. As Alice (Browser B) create:
   - `Alice's Profile` — user pool `[ "alice.smith" ]`, machine pool `[ "ALICE-LAPTOP" ]`. (Make it **private** if the UI offers the toggle.)
3. As admin: bind `okta` to `Public Profile` at 100% ratio.
4. As Alice: under **Source ↔ Profile bindings**, bind `okta` to `Alice's Profile` at 100% ratio.

**Run.**

```bash
# Public token → public-shaped logs
curl -sk -H "Authorization: SSWS apigenie-valid-token-001" \
  "https://<your-domain>/api/v1/logs?limit=5" | jq '.[] | .actor.alternateId'

# Alice's token → Alice-shaped logs
curl -sk -H "Authorization: SSWS alice-okta-personal-001" \
  "https://<your-domain>/api/v1/logs?limit=5" | jq '.[] | .actor.alternateId'
```

**Pass criteria.**

- The first call returns log lines mentioning `publicuser01` / `PUBLIC-HOST`.
- The second call returns log lines mentioning `alice.smith` / `ALICE-LAPTOP`.
- Repeat with a token nobody owns (`bogus-token-zzz`): you fall back to the **Public Profile** — anonymous / unknown callers see only the public binding.

---

### Exercise 8 — Private detection rules scoped to the caller

**Goal.** Confirm that a private detection rule fires **only** for its owner.

**Steps.**

1. As Alice (Browser B) → **Log Profiles & Detection Rules → Detection Rules → + New Rule**:
   - **Name:** `Alice — LSASS access`
   - **Source:** `sentinelone`
   - **Periodicity:** `2` (one in every two events)
   - **Visibility:** `private`
   - **Field overrides:** `event.type` = `Process Access`, `tgt.process.name` = `lsass.exe`
2. Save.
3. As admin (Browser A) create a public rule on the **same** source:
   - **Name:** `Public — netsh firewall disable`
   - **Source:** `sentinelone`, **Periodicity:** `2`, **Visibility:** `public`
   - **Field overrides:** `event.type` = `Command Script`, `src.process.cmdline` = `netsh advfirewall set allprofiles state off`
4. As Alice, register a `bearer_token` identifier for SentinelOne (value e.g. `alice-s1-token-001`).

**Run.**

```bash
# As Alice — should see BOTH rules fire in the response stream
curl -sk -H "Authorization: ApiToken alice-s1-token-001" \
  "https://<your-domain>/web/api/v2.1/threats?limit=20" | jq '.data[] | .threatInfo.threatName' | sort -u

# As an anonymous public caller — should ONLY see "Public — netsh ..." fire
curl -sk -H "Authorization: ApiToken apigenie-valid-token-001" \
  "https://<your-domain>/web/api/v2.1/threats?limit=20" | jq '.data[] | .threatInfo.threatName' | sort -u
```

**Pass criteria.**

- Alice's response contains traces of **both** rules.
- The public-token response contains traces of **only** the public rule. Alice's private rule must **never** appear.
- The behavioural guarantee is locked in by `tests/test_rbac_phase2_5_detection.py`.

---

### Exercise 9 — Push profile inherits its owner's rules

**Goal.** Verify that when Alice runs a Log Push profile, **her** private detection rules show up in the pushed batch.

**Steps.**

1. As Alice → **Log Push → + New Profile**:
   - **Name:** `alice-okta-to-debug`
   - **Source:** `okta`
   - **Format:** `JSON`
   - **Transport:** `HTTP POST` to `http://localhost:9999/dump` (any unused port — it does not need to receive)
   - **Duration:** `30s`
   - **Rate:** `5 eps`
2. **Start**.
3. Open the profile card → **Live event log**.

**Pass criteria.**

- Among the pushed events you can spot at least one tagged with `_detection_rule: "Alice — LSASS access"` or whatever private rule applies to `okta` (create one on `okta` first if you only had a SentinelOne one).
- As admin, create a `okta` push profile owned by no user (admin-created → `owner_id` null). Start it: you should see **only** public/admin rules, never Alice's. This is the negative case that proves scoping works.

> **Implementation pointer.** The push worker pins its caller-context to the profile's owner via `log_pusher._set_caller_for_loop` — see `tests/test_rbac_phase3_log_push.py` for the unit/integration coverage.

---

### Exercise 10 — Password recovery handoff

**Goal.** Reset Alice's password without SMTP.

**Steps.**

1. As admin (Browser A) → **Users → Users** → open Alice's row → **Send reset link**.
2. Copy the link from the dialog.
3. In Browser B, sign Alice out, then paste the recovery URL.
4. Set a new password, sign back in.
5. Try her old password (it should be rejected) — then the new one (it should work).

**Pass criteria.**

- Old credentials → "Invalid credentials."
- New credentials → success.
- The reset link cannot be reused (paste it a second time → "invalid or has expired").
- The full lifecycle (issue / peek / one-shot / TTL / wrong-kind) is regression-tested in `tests/test_rbac_phase3_recovery.py`.

---

### Exercise 11 — Self-service account settings (Phase 3.5)

**Goal.** Walk through every field a user can manage on their own account: email address, password, and — most importantly — **their own SentinelOne console URL + API token**. When set, ApiGenie will use *your* S1 console (not the global one configured by the admin) for every detection-rule import, browse and enrich operation performed in your session.

**Where to find it.** Sign in as Alice (Browser B), then click **👤 My Account** in the sidebar (bottom of the Configuration & Reference section).

**Steps — UI.**

1. **Email.** Type a new email into the *Email address* card and click **Save email**. The bottom message turns green: *"Email updated."*. Bad input (`not-an-email`) is rejected client-side then server-side with a 400.
2. **Password.** Fill *Current password* and *New password* (min 8 chars) in the *Change password* card. Click **Change password**. Then sign out and sign back in with the new password to prove it stuck.
3. **My SentinelOne console (v5.1 — browser-only storage).** Paste your tenant URL (e.g. `https://yourtenant.sentinelone.net`) and your API token into the *My SentinelOne console* card and click **Save in this browser**. The values are written **only to `localStorage`** on this browser (keys `apigenie.s1.console_url` and `apigenie.s1.api_token`) — they never reach the server filesystem. A global `fetch` wrapper installed at admin shell load injects them on every authenticated XHR as the headers `X-S1-Console-URL` and `X-S1-Console-Token`. Click **Clear from this browser** to wipe the localStorage entries and fall back to the admin-global console; signing out alone does **not** wipe them (so you can keep your credentials across sessions on the same browser).

**Steps — curl (per-user S1 override is header-only since v5.1).**

```bash
# Capture Alice's session cookie
curl -sk -c /tmp/alice.cookie -X POST -d 'username=alice&password=<alice-pw>' \
  https://<your-domain>/portal/login

# View her account snapshot
curl -sk -b /tmp/alice.cookie https://<your-domain>/admin/api/me/account | jq

# Change email
curl -sk -b /tmp/alice.cookie -X PUT -H 'Content-Type: application/json' \
  -d '{"email":"alice.new@team.io"}' \
  https://<your-domain>/admin/api/me/email | jq

# Change password
curl -sk -b /tmp/alice.cookie -X PUT -H 'Content-Type: application/json' \
  -d '{"current":"<old>","new":"<new-min-8>"}' \
  https://<your-domain>/admin/api/me/password | jq

# v5.1 — there is NO server-side per-user S1 endpoint anymore. The browser
# stores the URL + token and forwards them on every call as headers. To
# reproduce the override from a script, send the two headers explicitly
# on each S1 call:
curl -sk -b /tmp/alice.cookie \
  -H 'X-S1-Console-URL: https://alice.sentinelone.net' \
  -H 'X-S1-Console-Token: <alice-token>' \
  https://<your-domain>/admin/api/s1/test | jq
```

The deprecated `PUT/GET/DELETE /admin/api/me/s1-console` endpoints from v5.0 now return `404 / 405`. Tests in `tests/test_rbac_phase35_endpoints.py` assert they stay removed.

**Pass criteria.**

- Email and password round-trip and persist across logout / login.
- After clicking **Save in this browser**, opening DevTools → *Application* → *Local Storage* shows `apigenie.s1.console_url` and `apigenie.s1.api_token` with the values you entered.
- The Network tab on any `/admin/api/s1/*` request shows `X-S1-Console-URL` and `X-S1-Console-Token` request headers.
- A `/admin/api/s1/*` call sent from a *different* browser that does **not** have those `localStorage` keys falls back to the admin-global console (visible in the response source).
- Clicking **Clear from this browser** removes the two `localStorage` keys; the next `/admin/api/s1/*` call no longer carries the headers.
- The built-in admin account does not use this card — it edits the admin-global console + Fernet-encrypted token from **System Settings** (Admin Guide).

**Why it matters.** Different SEs / customers / analysts can now point ApiGenie's S1 integration at **their own** tenants while sharing the same ApiGenie deployment — *without ever writing a token to the server filesystem*. v5.1 moves the entire credential lifecycle into the operator's browser, which makes the platform safe to deploy in shared / multi-tenant contexts where a leaked SQLite file used to be a real-token exposure. Admins who use the "Viewing as" switcher (Exercise 14) will see the *target* user's profile and ownership, but the S1 override displayed in their browser is still the admin's own `localStorage` — there is no cross-user S1 sharing by design.

---

### Bonus exercises (do these if you have time)

- **Exercise 12 — Cross-user isolation.** Create Bob the same way you created Alice. Give him his own SentinelOne identifier, a private detection rule, a private log profile. Then sign in as Alice and try to view Bob's rule via the API: `GET /admin/api/detection-rules` (as Alice). Verify Bob's rule is **not** in the response. The visibility filter is implemented in `admin._can_see_obj` and exercised by `tests/test_rbac_phase2.py`.

- **Exercise 13 — Reserved credentials guard.** As Alice try to add an identifier with value `apigenie-valid-token-001`. The form should reject it explaining that it is one of the reserved demo credentials used by the shared public profile. Repeat for `apigenie-ak-001`, `apigenie-sk-001`, `apigenie-principal-001`, `apigenie-secret-001`.

- **Exercise 14 — Source masking in the user portal.** As Alice open **Source Details**. The ready-to-use curl block should display **your** identifier values (`alice-okta-personal-001`) — not the shared `apigenie-valid-token-001` placeholders. This is the Phase 2.3 substitution layer; covered by `tests/test_rbac_phase2.py::TestUserPortalMasking`.

- **Exercise 15 — Admin "Viewing as" Alice.** As admin (Browser A) open the top-right user-switcher and pick `alice`. The page reloads with an amber banner **"Viewing as alice"**. Everything you see is now restricted to what Alice would see; admin power buttons are hidden. Click **Stop viewing as** to return.

---

## Where the lab evidence lives

If a test ever stops behaving as described above, the corresponding regression test will fail. Use this map to jump to the source of truth:

| Capability | Tests |
|------------|-------|
| Entitlements, users, identifier registration / matching | `tests/test_rbac_phase2.py` |
| Reserved credentials, user-portal masking, "Viewing as" | `tests/test_rbac_phase2.py` |
| Per-user detection rule injection (pull) | `tests/test_rbac_phase2_5_detection.py` |
| Per-user detection rule injection (Log Push) | `tests/test_rbac_phase3_log_push.py` |
| Avatars (Pillow circle, store, endpoints) | `tests/test_rbac_phase3_avatars.py` |
| Password handoff / recovery tokens | `tests/test_rbac_phase3_recovery.py` |
| Self-service email / password / per-user S1 (helpers) | `tests/test_rbac_phase35_self_service.py` |
| Self-service `/admin/api/me/*` endpoints + caller-context middleware | `tests/test_rbac_phase35_endpoints.py` |

Run the whole suite at any time:

```bash
docker exec apigenie pip install --quiet pytest pytest-asyncio   # one-time
docker exec apigenie python -m pytest tests/ -v
```

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

### Mimecast (OAuth2 → SIEM events)

```bash
# Step 1: Get OAuth token
TOKEN=$(curl -sk -X POST "https://localhost/oauth/token" \
  -d "grant_type=client_credentials&client_id=my-app&client_secret=my-secret" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Step 2: Fetch SIEM events (8 log types: receipt, process, delivery, AV, spam, TTP URL/Attach/Impersonation)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost/siem/v1/events/cg?limit=20"

# Batch endpoint (larger page size)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost/siem/v1/batch/events/cg?limit=100"
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
| Mimecast            | OAuth2 → `Authorization: Bearer <token>` | any client_id/secret → `POST /oauth/token`       |

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
