# Attack Scenario Builder — Design Document

**Status:** Plan (pending validation)  
**Date:** 2026-05-26

---

## Concept

The Attack Scenario Builder allows users to simulate **multi-source, multi-phase attack campaigns** mapped to the MITRE ATT&CK Kill Chain. Each scenario is a sequence of phases that generate specific log events across different sources, timed to create a realistic attack progression.

### Key principles

1. **Zero impact on existing features** — scenarios ride on top of the existing Detection Rules injection mechanism
2. **Log Profiles honored** — attack events use profile entities (users, machines, C2, malware) for consistency
3. **100% realistic logs** — events use the same generators as normal logs, just with specific field overrides
4. **Traceable** — every attack event carries `attack.id` and `phase.id` fields for correlation
5. **Time-aware** — the attack unfolds over a configurable duration, with phases distributed chronologically

---

## Architecture

### How it wires into existing code

```
                         ┌─────────────────────┐
                         │   attack_scenarios   │
                         │   .py (new module)   │
                         └──────────┬──────────┘
                                    │
                   creates temporary detection rules
                   with attack.id + phase.id overrides
                                    │
                         ┌──────────▼──────────┐
                         │  detection_rules.py │ (existing)
                         │  inject_detection   │
                         │  _events()          │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              sources/*.py    push_sources/   publishers/
              (HTTP pull)     (log push)      (Kafka/PubSub)
```

**The scenario engine does NOT modify any source generator.** Instead, it:
1. Creates time-limited detection rules for each phase
2. Each rule targets a specific source with field overrides that produce attack-relevant events
3. Rules are tagged with `attack.id` and `phase.id`
4. The existing `inject_detection_events()` picks them up naturally
5. When the scenario ends, the temporary rules are cleaned up

### Data model

```json
{
  "id": "scenario-uuid",
  "name": "BEC via Phishing (MITRE: T1566 → T1078 → T1114 → T1048)",
  "template": "bec_phishing",       // null if custom
  "status": "running",              // stopped | running | completed
  "duration": {"value": 4, "unit": "hours"},
  "started_at": "2026-05-26T10:00:00Z",
  "attack_id": "att-20260526-4827",
  "profile_id": "uuid-of-log-profile",
  "phases": [
    {
      "phase_id": "initial-access",
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1566.001",
      "name": "Phishing email delivered",
      "source": "proofpoint",
      "time_offset_pct": 0,          // 0% into the duration = start
      "duration_pct": 10,            // lasts 10% of total duration
      "field_overrides": { ... },
      "periodicity": 5
    },
    {
      "phase_id": "credential-access",
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1078",
      "name": "Compromised account login",
      "source": "okta",
      "time_offset_pct": 10,
      "duration_pct": 15,
      "field_overrides": { ... },
      "periodicity": 8
    }
  ]
}
```

### attack.id format

`att-{YYYYMMDD}-{4 random digits}` — e.g. `att-20260526-4827`

### phase.id values (MITRE ATT&CK Tactics)

| phase.id | MITRE Tactic |
|----------|-------------|
| `reconnaissance` | Reconnaissance |
| `initial-access` | Initial Access |
| `execution` | Execution |
| `persistence` | Persistence |
| `privilege-escalation` | Privilege Escalation |
| `defense-evasion` | Defense Evasion |
| `credential-access` | Credential Access |
| `discovery` | Discovery |
| `lateral-movement` | Lateral Movement |
| `collection` | Collection |
| `command-and-control` | Command and Control |
| `exfiltration` | Exfiltration |
| `impact` | Impact |

---

## 5 Ready-Made Scenarios

### Scenario 1: Business Email Compromise (BEC)

**Story:** Attacker sends phishing email → victim clicks → credentials stolen → mailbox rules created → data exfiltrated via email forwarding.

| Phase | MITRE | Source | Key events |
|-------|-------|--------|------------|
| 1. Phishing delivery | T1566.001 Initial Access | **Proofpoint** | Malicious email delivered, SafeLinks clicked |
| 2. Credential harvest | T1078 Credential Access | **Okta** | Login from unusual location, MFA bypass |
| 3. Mailbox access | T1114.002 Collection | **M365** | MailItemsAccessed from new IP, SearchQueryInitiated |
| 4. Inbox rule created | T1564.008 Persistence | **M365** | New-InboxRule forwarding to external address |
| 5. Data exfiltration | T1048.003 Exfiltration | **M365** | SendAs from compromised mailbox, mass email forward |

**Sources used:** Proofpoint, Okta, M365

---

### Scenario 2: Ransomware via Lateral Movement

**Story:** Initial compromise via vulnerability → lateral movement with stolen credentials → discovery → ransomware deployment.

| Phase | MITRE | Source | Key events |
|-------|-------|--------|------------|
| 1. Exploitation | T1190 Initial Access | **Palo Alto** (push) | Threat/vulnerability alert, inbound exploit |
| 2. C2 callback | T1071 Command & Control | **Palo Alto** (push) | Outbound connection to C2 IP, DNS tunneling |
| 3. Credential dump | T1003 Credential Access | **CrowdStrike** (push) | Mimikatz detection, LSASS access |
| 4. Lateral movement | T1021.002 Lateral Movement | **CrowdStrike** (push) | PsExec/WMI remote execution across hosts |
| 5. Discovery | T1018 Discovery | **Entra ID** | Unusual directory enumeration, group listing |
| 6. Ransomware deploy | T1486 Impact | **CrowdStrike** (push) | Ransomware behavior detected, file encryption |

**Sources used:** Palo Alto (push), CrowdStrike (push), Entra ID

---

### Scenario 3: Cloud Account Takeover

**Story:** Stolen OAuth token → illicit app consent → cloud data access → privilege escalation → persistent access.

| Phase | MITRE | Source | Key events |
|-------|-------|--------|------------|
| 1. Token theft | T1528 Credential Access | **Okta** | Suspicious login, impossible travel |
| 2. OAuth consent | T1098.003 Persistence | **M365** | Consent to application with Mail.ReadWrite |
| 3. Cloud discovery | T1538 Discovery | **M365** | SharePoint enumeration, Teams member listing |
| 4. Privilege escalation | T1078.004 Privilege Escalation | **M365** | PIM role activation (Global Admin) |
| 5. Data theft | T1530 Collection | **M365** | Mass file download from SharePoint/OneDrive |
| 6. Persistence | T1136.003 Persistence | **Entra ID** | New service principal created, federated trust |

**Sources used:** Okta, M365, Entra ID

---

### Scenario 4: Supply Chain DNS Poisoning + Data Exfiltration

**Story:** DNS-based attack → compromised internal resolution → data exfiltrated via DNS tunneling → firewall detects anomaly.

| Phase | MITRE | Source | Key events |
|-------|-------|--------|------------|
| 1. DNS manipulation | T1584.002 Initial Access | **Infoblox** (push) | RPZ hit, suspicious DNS query to DGA domain |
| 2. C2 over DNS | T1071.004 Command & Control | **Infoblox** (push) | DNS tunneling detected, high-entropy TXT queries |
| 3. Internal recon | T1046 Discovery | **FortiGate** (push) | Port scan detected, anomaly traffic alert |
| 4. Firewall evasion | T1572 Defense Evasion | **FortiGate** (push) | Encrypted traffic to unknown destination, appctrl bypass |
| 5. Data exfiltration | T1048.001 Exfiltration | **Zscaler** (push) | DLP violation, large upload to cloud storage |
| 6. Cleanup | T1070.004 Defense Evasion | **M365** | Audit log search/purge by compromised admin |

**Sources used:** Infoblox (push), FortiGate (push), Zscaler (push), M365

---

### Scenario 5: Insider Threat — Disgruntled Employee

**Story:** Employee accesses sensitive data → email exfiltration → VPN from unusual location → evidence tampering.

| Phase | MITRE | Source | Key events |
|-------|-------|--------|------------|
| 1. Excessive access | T1530 Collection | **M365** | Mass SharePoint file downloads, sensitive folder access |
| 2. Email exfiltration | T1048.003 Exfiltration | **M365** | Forward rule to personal email, large attachments |
| 3. DLP trigger | T1567 Exfiltration | **Netskope** | Cloud upload with sensitive data, DLP policy match |
| 4. Off-hours VPN | T1133 Persistence | **Cisco Duo** | VPN login at 3am from foreign IP, MFA approved |
| 5. Evidence tampering | T1070 Defense Evasion | **M365** | Audit log search, quarantine release, inbox rule deleted |
| 6. Account anomaly | T1078 Credential Access | **Okta** | Impossible travel, session from new device |

**Sources used:** M365, Netskope, Cisco Duo, Okta

---

## Implementation Plan

### New files

| File | Purpose |
|------|---------|
| `attack_scenarios.py` | Core engine: scenario CRUD, phase scheduling, temporary rule management |
| `attack_scenarios_library.py` | 5 built-in scenario templates with all field overrides |

### Modified files (minimal, additive only)

| File | Change |
|------|--------|
| `admin.py` | New sidebar item "⚔ Attack Scenarios" + tab with scenario cards, MITRE timeline visualization, start/stop controls, template selector |
| `admin.py` | API endpoints: `/admin/api/scenarios`, `/admin/api/scenarios/{id}/start`, `/admin/api/scenarios/{id}/stop` |
| `detection_rules.py` | No changes needed — scenarios create standard rules with extra fields |

### How it works at runtime

1. **User selects a scenario** (template or custom) and sets duration (e.g. 4 hours)
2. **Engine generates `attack.id`** — e.g. `att-20260526-4827`
3. **For each phase**, engine calculates the time window based on `time_offset_pct` and `duration_pct`
4. **Engine creates temporary detection rules** for each phase with:
   - `source` = the phase's target source
   - `field_overrides` = phase-specific fields + `attack.id` + `phase.id`
   - `periodicity` = phase's configured value
   - `enabled` = toggled on/off based on the current time vs phase window
5. **A background scheduler thread** manages phase transitions:
   - Enables rules when their phase window starts
   - Disables rules when their phase window ends
   - Updates scenario status (running → completed)
6. **Existing `inject_detection_events()`** picks up the active rules naturally — zero changes to generators
7. **When scenario completes or is stopped**, all temporary rules are deleted

### UI: MITRE Kill Chain Timeline

```
┌──────────────────────────────────────────────────────────────────┐
│  ⚔ BEC via Phishing    att-20260526-4827    ● Running (2h/4h)   │
│                                                                  │
│  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐                  │
│  │T1566│→ │T1078│→ │T1114│→ │T1564│→ │T1048│                  │
│  │ ██  │  │ ██  │  │ ▓▓  │  │ ░░  │  │ ░░  │                  │
│  │Init │  │Cred │  │Coll │  │Pers │  │Exfil│                  │
│  │Acces│  │Acces│  │ ectn│  │ ist │  │ trtn│                  │
│  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘                  │
│     │        │        │        │        │                        │
│  Proofpoint  Okta    M365     M365     M365                     │
│  ██=active  ▓▓=next  ░░=pending                                 │
│                                                    [Stop] [Edit]│
└──────────────────────────────────────────────────────────────────┘
```

### Phase progression over time

For a 4-hour BEC scenario:

| Time | Phase | Source | Duration |
|------|-------|--------|----------|
| 0:00–0:24 | Initial Access (phishing) | Proofpoint | 10% = 24 min |
| 0:24–0:60 | Credential Access (login) | Okta | 15% = 36 min |
| 1:00–1:48 | Collection (mailbox) | M365 | 20% = 48 min |
| 1:48–2:36 | Persistence (inbox rule) | M365 | 20% = 48 min |
| 2:36–4:00 | Exfiltration (forward) | M365 | 35% = 84 min |

### Field overrides per phase (example: BEC Scenario)

**Phase 1 — Phishing (Proofpoint):**
```json
{
  "attack.id": "att-20260526-4827",
  "phase.id": "initial-access",
  "threats": [{"threatType": "url", "classification": "phish"}],
  "quarantineFolder": "",
  "subject": "Urgent: Invoice Payment Required"
}
```

**Phase 2 — Credential Access (Okta):**
```json
{
  "attack.id": "att-20260526-4827",
  "phase.id": "credential-access",
  "eventType": "user.session.start",
  "outcome.result": "SUCCESS",
  "client.geographicalContext.country": "RU",
  "securityContext.isTor": true
}
```

---

## Implementation Phases

### Phase 1 — Core engine + 5 templates
1. `attack_scenarios.py` — CRUD, scheduler, temporary rule management
2. `attack_scenarios_library.py` — 5 built-in scenario definitions
3. API endpoints in `admin.py`
4. UI tab with scenario list, template selector, start/stop, MITRE timeline

### Phase 2 — Custom scenario builder
1. UI for creating custom scenarios (add phases, pick sources, set overrides)
2. Import/export scenarios as JSON

### Phase 3 — Reporting
1. Post-scenario report: which events were injected, when, into which source
2. Event log with attack.id correlation

---

## Non-goals (explicitly out of scope)

- **No changes to source generators** — scenarios use detection rules exclusively
- **No changes to detection_rules.py** — temporary rules are standard rules with extra fields
- **No changes to profiles.py** — scenarios bind to existing profiles
- **No changes to log_pusher.py** — push sources pick up detection rules naturally
- **No new ports or services** — purely in-process

---

## Decisions (confirmed 2026-05-26)

1. **Concurrent scenarios?** — Deferred to Phase 2 (multi-user). Single scenario for Phase 1. Architecture supports it (unique `attack.id` per scenario, separate threads).
2. **Scenario pause/resume?** — **Yes.** Pause freezes the scheduler and records elapsed time. Resume recalculates remaining phase windows from where it left off. All temporary rules disabled on pause, re-enabled on resume.
3. **Retroactive timestamps?** — **Real-time generation is primary**, but timestamps must be backdated to match the configured duration. If a scenario is set to "1 week", logs generated today will carry timestamps spanning the past 7 days. The `time_offset_pct` determines how far back each phase's timestamps go. The injection adds a `_scenario_timestamp` override that the source generator uses for the event timestamp.
4. **Auto-start/stop push profiles?** — **Yes.** When a phase targets a push source (e.g. `paloalto`), the scheduler auto-starts the matching push profile when the phase begins and auto-stops it when the phase (or scenario) ends. If no push profile exists for that source, the phase is skipped with a warning.

## Orchestration approach

**Just-in-time rule creation** (confirmed): rules are created when a phase starts and deleted when it ends. This keeps the detection rules list clean and avoids dormant rules.

**Scheduler**: single background thread per scenario, polling every ~5 seconds. Creates/deletes temporary detection rules as phases transition. Rules tagged with `_scenario_id` for cleanup.

---

## Detailed Implementation Plan

### Prerequisites

- Add 1-2 more push sources as needed for scenario coverage (e.g. Sophos, SonicWall, or others requested)

### Phase 1 — Core engine + 5 templates

| # | Task | File(s) | Effort | Dependencies |
|---|------|---------|--------|-------------|
| 1.1 | Create `attack_scenarios.py` — data model, CRUD, storage (`/var/lib/apigenie/attack_scenarios.json`) | `attack_scenarios.py` (new) | Medium | None |
| 1.2 | Scenario scheduler — background thread, phase timing, just-in-time rule creation/deletion, pause/resume | `attack_scenarios.py` | High | 1.1 |
| 1.3 | Push profile auto-start/stop — find matching push profile for source, start on phase begin, stop on phase/scenario end | `attack_scenarios.py` + `log_pusher.py` (read-only) | Low | 1.2 |
| 1.4 | Timestamp backdating — calculate phase timestamps relative to scenario duration, inject as `_scenario_timestamp` override | `attack_scenarios.py` | Medium | 1.2 |
| 1.5 | Create `attack_scenarios_library.py` — 5 built-in scenario templates with complete field overrides for every phase | `attack_scenarios_library.py` (new) | High | 1.1 |
| 1.6 | API endpoints — CRUD + start/stop/pause/resume/status | `admin.py` | Medium | 1.1, 1.2 |
| 1.7 | UI tab — scenario list, template selector, duration config, start/stop/pause buttons | `admin.py` | Medium | 1.6 |
| 1.8 | UI MITRE timeline — kill chain visualization with phase progression, source labels, active/pending/completed states | `admin.py` | High | 1.7 |
| 1.9 | Smoke test — verify no regressions on all existing sources | All | Low | 1.8 |
| 1.10 | README update | `README.md` | Low | 1.9 |

**Estimated total: ~3-4 sessions**

### Phase 2 — Multi-scenario + custom builder

| # | Task | Effort |
|---|------|--------|
| 2.1 | Concurrent scenario support (multiple threads, unique attack.id isolation) | Medium |
| 2.2 | Custom scenario builder UI (add/remove phases, pick sources, set overrides) | High |
| 2.3 | Import/export scenarios as JSON | Low |

### Phase 3 — Reporting + correlation

| # | Task | Effort |
|---|------|--------|
| 3.1 | Post-scenario report: which events were injected, when, which source, event counts per phase | Medium |
| 3.2 | attack.id search in Request Inspector — filter events by attack.id across all sources | Medium |
| 3.3 | Exportable attack timeline (JSON/PDF) for demo handoff | Low |

---

## API Endpoints (Phase 1)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/api/scenarios/templates` | List 5 built-in scenario templates |
| GET | `/admin/api/scenarios` | List all scenarios (running + completed) |
| POST | `/admin/api/scenarios` | Create a scenario from template or custom |
| GET | `/admin/api/scenarios/{id}` | Get scenario details + phase status |
| DELETE | `/admin/api/scenarios/{id}` | Delete a scenario (stops if running) |
| POST | `/admin/api/scenarios/{id}/start` | Start the scenario |
| POST | `/admin/api/scenarios/{id}/stop` | Stop the scenario (cleanup rules) |
| POST | `/admin/api/scenarios/{id}/pause` | Pause (freeze scheduler, disable rules) |
| POST | `/admin/api/scenarios/{id}/resume` | Resume from where it paused |

## API Endpoints (Phase 2 — custom builder, shipped in v5.0)

| Method | Path | Purpose |
|--------|------|---------|
| PUT | `/admin/api/scenarios/{id}` | Update a scenario (name, duration, phases). Refused with 409 while running/paused. |
| GET | `/admin/api/scenarios/{id}/export` | Download the scenario as portable JSON (runtime fields stripped). |
| POST | `/admin/api/scenarios/import` | Validate + create a new scenario from JSON (round-trip with `/export`). |

All three reuse `attack_scenarios.validate_scenario_payload()`, which returns a list of human-readable errors. The REST layer surfaces them as `{"error": "validation failed", "errors": [...]}` with HTTP 400 so the UI can list every problem at once instead of forcing a fix-and-retry loop.

---

## Phase 2 — Custom scenario builder (shipped)

Phase 2 makes scenarios fully user-authorable. The 5 built-in templates from Phase 1 stay, but now they're seeds for editing rather than fixed campaigns.

### What the UI does

The **Attack Scenarios** tab gained two new controls:

| Control | Behaviour |
|---------|-----------|
| `↑ Import` (top-right) | Opens a file picker for a `*.scenario.json` file, validates it via `POST /admin/api/scenarios/import`, and adds it to the list. |
| `+ New Scenario` (top-right) | Opens the builder modal in **create mode**. Template dropdown now has an "Empty (build from scratch)" option above the 5 built-ins. |
| `Edit` (per-card, when stopped/completed) | Opens the same modal in **edit mode**: template selector hidden, Save button visible instead of Create & Start. PUTs the scenario on save. |
| `↓ Export` (per-card, always) | Downloads the current scenario as JSON via the browser. Safe to call mid-run — the export endpoint strips runtime fields. |

### The phase editor

Inside the modal, the read-only phase preview from v1 is replaced with an editable list. Each phase row exposes:

- **Phase name** and **Source** — free-text, both required.
- **MITRE tactic** — dropdown over the 13 enterprise tactics (`Reconnaissance` through `Impact`).
- **MITRE technique** — free-text (`T1566.001`, `T1078`, …).
- **Phase ID slug** — optional; the server assigns `phase-<index>` when blank.
- **`time_offset_pct`** + **`duration_pct`** — when the phase starts and how long it runs, as percentages of the scenario duration. Their sum must be ≤ 100; the validator rejects anything that would end after the scenario does.
- **`periodicity`** — how often the temporary detection rule fires, in seconds.
- **`field_overrides`** — a JSON object pasted inline (e.g. `{"severity": "Critical"}`). The UI parses it on save and surfaces JSON errors per phase.

Phases can be added (`+ Add Phase`), removed (`×`), or reordered (`↑` / `↓`). The in-flight DOM state is synced back into the JS phase array before every re-render, so reordering doesn't drop unsaved edits.

### Validation

`attack_scenarios.validate_scenario_payload()` checks:

1. `name` is a non-empty string.
2. `duration.value > 0`, `duration.unit ∈ {seconds, minutes, hours, days, weeks}`.
3. `phases` is a non-empty array.
4. For each phase: `name`, `source`, `mitre_tactic`, `mitre_technique` are non-empty strings.
5. `time_offset_pct` and `duration_pct` are numbers in `[0, 100]` and their sum is `≤ 100`.
6. `periodicity > 0`.
7. `field_overrides` is an object (or missing).

It collects **every** problem before returning — the UI lists them all so users fix the scenario in one pass.

### Export / import JSON format

`GET /admin/api/scenarios/{id}/export` returns:

```json
{
  "_apigenie_schema": "attack_scenario/v1",
  "name": "Business Email Compromise (BEC)",
  "description": "",
  "duration": {"value": 4, "unit": "hours"},
  "profile_id": null,
  "phases": [
    {
      "phase_id": "initial-access",
      "name": "Phishing email delivered",
      "source": "proofpoint",
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1566.001",
      "time_offset_pct": 0,
      "duration_pct": 10,
      "periodicity": 3,
      "field_overrides": {
        "subject": "Urgent: Review Shared Document",
        "phishScore": 95
      }
    }
  ]
}
```

**Stripped on export** (regenerated at scenario create / start): `id`, `attack_id`, `status`, `events_injected`, `started_at`, `paused_at`, `elapsed_seconds`, `error`, `created`, `template`, plus per-phase `status` and `events_count`.

**Import** (`POST /admin/api/scenarios/import`) accepts the same shape, drops the `_apigenie_schema` marker, runs the validator, and persists it as a brand-new scenario with a fresh `id` + `attack_id`. Round-trip is lossless for everything the builder can edit.

### Why "stopped only" for PUT

The scheduler holds a `_calculate_phase_windows()` snapshot when it starts. Mutating phases mid-run would either be ignored (silently wrong) or require tearing down + recreating detection rules with the new windows (complex, racy). Phase 2 takes the simpler stance: editing a running scenario returns HTTP 409 with `{"error": "cannot edit a running or paused scenario — stop it first"}`. Stop → Edit → Start is two extra clicks but never produces a half-mutated run.

### What's still in Phase 3

The original plan (line 369 above) holds: per-scenario event log, `attack.id` search in the Request Inspector, and exportable attack timelines remain for Phase 3.

---

## Phase 3.1 — Per-scenario event log (shipped)

The first slice of Phase 3 lights up the "what just happened?" view. Every time the scenario engine's temporary detection rule fires an event into a source, the engine captures a slim record of it into a per-scenario ring buffer.

### REST endpoint

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/api/scenarios/{id}/events` | Return the per-scenario event log. Query params: `limit` (1-1000, default 200), `phase_id`, `source`. Empty buffer is HTTP 200 with `count=0`; unknown scenario id is 404. |

### How it captures

`detection_rules.inject_detection_events()` is the single chokepoint where every detection rule fires. It now checks each rule for a `_scenario_id` (set by the scenario scheduler) and, if present, calls `attack_scenarios._record_event_safe(...)` for each injected event. Plain user-defined rules carry no `_scenario_id` and skip the hook entirely — the per-scenario log only ever sees scenario-driven events.

The recorder swallows every exception so a logging-side bug can never break event injection. `_record_event_safe` wraps `record_event()` and downgrades errors to `log.warning`.

### What's stored

Each entry is intentionally slim:

```json
{
  "ts": "2026-05-26T14:32:01+00:00",
  "scenario_id": "scn-...",
  "phase_id": "initial-access",
  "attack_id": "att-20260526-0001",
  "source": "proofpoint",
  "preview": {
    "type": "phish",
    "subject": "Urgent: Review Shared Document",
    "_detection_rule": "[SCENARIO] Phishing email delivered"
  }
}
```

The full event still flows to the configured sinks via the normal HTTP / push pipelines. The buffer only keeps a small preview (whitelisted keys in `attack_scenarios._EVENT_PREVIEW_KEYS`) so it's cheap enough to keep 500 entries per scenario in memory without bloat.

### Retention

- **Cap:** `_MAX_SCENARIO_EVENT_LOG = 500` events per scenario, newest-first. Older events are evicted automatically by `collections.deque(maxlen=…)`.
- **Lifetime:** in-memory only. A container restart wipes the log — which matches the engine, since temporary scenario rules don't survive restarts either.
- **Cleanup:** `delete_scenario()` calls `clear_events()` so a re-created scenario with a new id starts with a clean slate. The persisted `events_injected` counter on the scenario object stays incremented on `record_event` so the card UI shows a meaningful total even after a restart wipes the live buffer.

### UI surface

Each scenario card gets an **Events (N)** button next to **Export**. Clicking it expands an inline log table beneath the MITRE timeline showing timestamp, phase id, source, and the top three preview fields per event. The 8-second card auto-refresh repopulates expanded panels so a running scenario streams new events without losing scroll position.

### What's still pending in Phase 3

| # | Task | Status |
|---|------|--------|
| 3.1 | Per-scenario event log + REST + card UI | **Shipped (v5.0)** |
| 3.2 | `attack.id` search in Request Inspector — filter events by attack.id across all sources | **Shipped (v5.0)** |
| 3.3 | Exportable attack timeline (JSON / PDF) for demo handoff | Pending |

---

## Phase 3.2 — Cross-source attack.id search (shipped)

Phase 3.1 answered _"what events did this scenario fire?"_. Phase 3.2 answers the inverse: _"every HTTP call that delivered an event tagged with this attack.id, across every source."_ That's the lens an analyst uses to correlate a multi-source campaign — phish lands on Proofpoint, lateral movement shows up on Okta, ransomware encryption appears on SentinelOne, all wearing the same `attack.id`.

### REST endpoint

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/api/requests/by-attack/{attack_id}` | Scan every per-source request trace buffer for entries whose request body or response preview contains `attack_id`. Returns merged, newest-first results with the `source` field injected onto each row. Query param: `limit` (1-1000, default 200). |

Response shape:

```json
{
  "attack_id": "att-20260526-4242",
  "count": 12,
  "results": [
    {
      "ts": "2026-05-26T14:32:01+00:00",
      "source": "proofpoint",
      "method": "GET",
      "path": "/v2/siem/all",
      "status": 200,
      "duration_ms": 7,
      "client": "10.0.0.42",
      "req_headers": {"...": "..."},
      "req_body": "",
      "resp_size": 2841,
      "resp_preview": "{\"events\":[{\"attack.id\":\"att-20260526-4242\",..."
    },
    ...
  ]
}
```

### How it scans

`trace.find_by_attack(attack_id, limit=200)` is a plain in-memory scan over `REQUEST_TRACE`:

- For each per-source ring buffer (`REQUEST_TRACE[source]`), iterate every entry.
- Hay = `resp_preview` (first 500 chars of the response) + `req_body` (first 2000 chars of the request).
- Needle = the raw `attack_id` string. attack.ids have the form `att-YYYYMMDD-NNNN` — distinctive enough that a substring match is faster than parsing every JSON payload.
- A matched entry is **copied** before adding the `source` key, so the per-source view's data is never mutated.
- Results are merged, sorted by `ts` newest-first, then truncated to `limit`.

The scan is O(sources × 100). With ~25 sources and 100 entries each, that's at most 2,500 substring checks — sub-millisecond on any modern CPU.

### What it does NOT see

- **Push-source events** — events that ApiGenie pushes _out_ to a sink (Log Push profiles, OTLP egress) bypass `TraceMiddleware` entirely (they're outbound, not inbound). The per-scenario event log (Phase 3.1) catches those, so the Events panel on each scenario card is the source of truth for push-only scenarios.
- **Old events past the 100-entry per-source window** — `REQUEST_TRACE[source]` is a `deque(maxlen=100)`. A high-volume source can roll old hits out of the buffer before you search.

The UI calls these limitations out inline when the result set is empty: _"No requests in the trace buffer contain `att-…`. The buffer keeps the last 100 calls per source; push-source events do not flow through here."_

### UI surface

Two entry points:

1. **Scenario card** — the `attack.id` pill on each running / completed scenario card is now a clickable affordance (dotted underline, pointer cursor). Click it → jumps to the Request Inspector with the cross-source filter pre-applied. One click from "this scenario" to "every request this scenario produced".

2. **Request Inspector** — a new filter row below the Source chips: an `attack.id` text input, an **Apply** button, and a **✕ Clear** button. When the filter is active, the Recent calls table pivots to cross-source mode: an extra **Source** column appears, each row tags the originating source as a chip, and every match of the `attack.id` in the response body is highlighted in `<mark>` so you can verify the hit at a glance.

Clicking a Source chip while the filter is active automatically clears the filter (so the chip selection feels responsive instead of silently ignored).

### Backend module touched

- `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/trace.py:35` — `find_by_attack()` helper
- `@/Users/marco.rottigni/Library/CloudStorage/GoogleDrive-marco.rottigni@sentinelone.com/My Drive/Solutions Architect SecOps/GitHub Projects/apigenie/admin.py` — `GET /admin/api/requests/by-attack/{attack_id}` endpoint + Requests pane filter UI + scenario-card pill onclick

### What's still pending in Phase 3

| # | Task | Status |
|---|------|--------|
| 3.3 | Exportable attack timeline — `GET /admin/api/scenarios/{id}/timeline` returning a chronologically ordered JSON list of phases + events for demo handoff | Pending |

## Storage

| Item | Path |
|------|------|
| Scenario definitions | `./data/attack_scenarios.json` |
| Scenario run history | `./data/attack_scenario_runs.json` |
