# Alert Push — Binding & Enrichment

ApiGenie's Alert Push feature ports HELIOS / `jarvis_coding`'s alert
sender to a per-user, RBAC-aware FastAPI surface. This document captures
the two recipes that make the feature work end-to-end against a real
SentinelOne tenant: **asset binding** (Phase 4.6) and **MITRE +
observables enrichment** (Phase 4.7).

It is the canonical reference. If something here disagrees with the
code, the code wins and this file must be updated.

---

## TL;DR — what makes an Alert Push alert "land bound and rich"

| # | What | Where in code |
|---|------|---------------|
| 1 | `resources[0].uid` = **XDR Asset ID** (26-char alphanumeric, from `/web/api/v2.1/xdr/assets`) | `s1_assets.S1AssetResolver.resolve_endpoint`, `alerts._inject_resource_device` |
| 2 | `S1-Scope` header clamped to `<account>` or `<account>:<site>` — **never** include the group id | `alerts.build_scope` |
| 3 | Payload gzipped + `Content-Encoding: gzip` + `S1-Trace-Id: apigenie-alert-push` | `alerts.egress_alert` |
| 4 | `finding_info.related_events[].uid` regenerated every call (HELIOS parity) | `alerts.prepare_alert` |
| 5 | MITRE `attacks[]` + harvested `observables[]` attached at prepare time | `alert_enrichment.enrich_alert` |
| 6 | **No** `device` block synthesised in v2, **no** `s1_metadata`, **no** `s1_detection_metadata` | `alerts._resolve_assets` |

---

## Phase 4.6 — Asset binding (the XDR Asset ID recipe)

### What we tried that didn't work

We spent a long time chasing the wrong identifiers. None of the
following bind an Alert Push alert to a real S1 asset tile:

- The numeric agent id from `/web/api/v2.1/agents` (`id` field).
- The hex UUID from `/web/api/v2.1/agents` (`uuid` field) — even when
  threaded into both `device.uid` and `resources[].uid`.
- Decorating the payload with `s1_metadata` / `s1_detection_metadata`
  blocks claiming sub-account scope.
- Sending with `S1-Scope: account:site:group` and the group declared
  inside the body too. The gateway responds 202 but the downstream
  ingest processor silently drops these.

UAM does add `s1_metadata` / `s1_detection_metadata` to the bound alert
reference payload **after** ingest, as routing annotations. They are
not inputs UAM evaluates on the way in.

### What does work

```
GET https://<console>/web/api/v2.1/xdr/assets?accountIds=<acct>[&siteIds=<site>]
Authorization: ApiToken <api-token>
```

Each response item carries:

```json
{
  "id": "3d3dp5xbcauhh5hhqa3so46e6y",   // ← THIS is the binding key
  "name": "RoarinSrv2022",               //    XDR Asset ID, 26-char alphanumeric
  "category": "Server",
  "osType": "WINDOWS",
  "agent": { "uuid": "57c2f3d4…", "id": "234098…", "version": "…" }
}
```

The 26-char `id` is the value UAM correlates against to bind an
ingested alert to the existing asset tile. Place it in
`resources[0].uid` of the Alert Push payload, send with `S1-Scope`
clamped to account-or-account:site, and within ~10s the alert appears
in UAM with `assets[].agentUuid` populated, the correct asset name,
and the right OS-type/category icon.

`s1_assets.py` paginates `/xdr/assets`, caches by `(account, site)`,
and matches names in memory with a case-insensitive fuzzy prefix /
substring rule. `alerts._inject_resource_device` writes the XDR Asset
ID into `resources[].uid` on every resolver hit.

### Reference test

Live-verified on `usea1-purple` 2026-06-10:

```
resolver: RoarinSrv2022 -> 3d3dp5xbcauhh5hhqa3so46e6y
send:      status=202
poll:      [20s] FOUND ✓ BOUND
           asset.agentUuid = 57c2f3d40cdc4484b216c319aa9eb3c2
           asset.category  = Server
           asset.osType    = WINDOWS
```

---

## Phase 4.7 — MITRE attacks + observables enrichment

### Why this exists

The HELIOS / `jarvis_coding` templates ApiGenie inherited carry only
`finding_info.title` + `finding_info.desc`. They do **not** declare
MITRE ATT&CK mappings or OCSF `observables[]`. HELIOS doesn't enrich
at send-time either — its scenario scripts only rewrite the title /
description per alert. So both implementations historically ship
sparse alerts to UAM.

`alert_enrichment.py` closes that gap deterministically and additively.

### What gets added

After `prepare_alert` resolves the resolver (when configured) it runs
`alert_enrichment.enrich_alert(alert, template_id=…)` which:

1. **Looks up MITRE attacks for the template** in `MITRE_BY_TEMPLATE`
   (a static registry covering all 71 shipped templates, plus a
   keyword fallback `MITRE_BY_KEYWORD` for ad-hoc / custom alerts).
   Each attack is a real OCSF `attacks[]` entry:

   ```json
   {
     "tactic":    { "uid": "TA0006", "name": "Credential Access" },
     "technique": { "uid": "T1110",  "name": "Brute Force" },
     "version":   "13.1"
   }
   ```

2. **Harvests OCSF observables** from the alert tree, deduped by
   `(name, value)`. Coverage:

   - `device.{hostname, ip, mac, uid}` → 1 / 2 / 3 / 10
   - `resources[]` — User shape (email) → 5, endpoint shape → 1
   - `src_endpoint.*` / `dst_endpoint.*` → 1 / 2 / 29 (port)
   - `actor.user.*` → 4 / 5 / 10
   - `actor.process.*` (name, pid, cmd_line, file{name,hashes}) → 9 / 29 / 7 / 8
   - `url.{url,hostname,path}` → 6 / 1 / 6
   - `email.{from,to,subject}` → 5 / 5 / 29
   - `evidences[].{process,file,user}` — recursive

3. **Materialises `finding_info.related_events[]`**:
   - When the template ships none, a single summary entry is
     synthesised with the attacks + observables embedded.
   - When the template already carries entries (e.g.
     `advanced_sample_alert.json`), the enricher **adds** the
     non-duplicate attacks (matched by `technique.uid`) and
     observables (matched by `(name, value)`) into each existing
     entry. Caller-supplied values are never overwritten.
   - Every entry receives a fresh `uid` UUID (HELIOS parity — without
     this every batch ships sibling events with `"placeholder_uid"`
     and UAM silently de-dupes them).

### Opt-out

- Per profile: `enrich_observables: false` in the Alert Push profile
  (UI checkbox under "🧬 Enrich with MITRE attacks & observables").
- Per custom send: `"enrich_observables": false` in the body of
  `POST /admin/api/alerts/send-custom`.
- Globally: env var `APIGENIE_ALERT_ENRICH=0` on the apigenie container.
- Per call from Python: `alerts.prepare_alert(template, enrich=False)`.

### Live verification

`/tmp/verify_enrichment.py` sends an enriched alert end-to-end and
pulls UAM's bound `rawData` to confirm the enrichment survived
ingest:

```
prepared:    MITRE TA0006/T1110, TA0001/T1078
             OBS  resource.hostname=RoarinSrv2022
                  resource.uid=3d3dp5xbcauhh5hhqa3so46e6y
poll[20s]:   ✓ BOUND  agentUuid=57c2f3d4…
rawData:     related_events landed = 1
             attacks=2, observables=2  (all preserved)
```

---

## Header contract (egress)

`alerts.egress_alert` always sends:

```
POST {uam_ingest_url}/v1/alerts
Authorization: Bearer {uam_service_token}
S1-Scope: {account_id}[:{site_id}]              # never include group
Content-Encoding: gzip
Content-Type: application/json
S1-Trace-Id: apigenie-alert-push
<gzip-compressed OCSF Finding JSON>
```

Returns `{"success": True, "status": 2xx, "alert_uid": ...}` on the
2xx path; never raises.

---

## Where each piece lives

| File | Responsibility |
|------|---------------|
| `s1_assets.py` | Per-batch XDR Asset ID resolver (`S1AssetResolver`). Paginates `/xdr/assets`, caches, matches names in-memory. |
| `alerts.py` | Template loading, `prepare_alert`, `egress_alert`, `send_alert`, `send_custom_alert`, scope builder, asset injection. |
| `alert_enrichment.py` | MITRE registry, keyword fallback, observable harvester, `enrich_alert`. |
| `alert_push.py` | Profile CRUD, persistence, public serialiser, `enrich_observables` flag. |
| `admin.py` | Routes `POST /admin/api/alerts/profiles/{id}/send` and `POST /admin/api/alerts/send-custom`. Builds resolver from per-user S1 creds, threads the enrich flag, captures `resolver` + `enrich` diagnostics in the response. |

---

## Shared entity canvas (Star Wars padding pool)

Both the **Log Profiles** (`profiles.py` → `_SW_USERS`, `_SW_MACHINES`,
`_SW_C2`, `_SW_MALWARE`, `_SW_MAIL_SENDERS`) and the **enriched alert
templates** draw from the same Star Wars cast so generated logs and
alerts share context. This is the groundwork for plausible
multi-source attack scenarios where, for example, the same
`cassian@rebel-int.net` on `ferrix-ws` is the actor in both an O365
sign-in log and a SentinelOne EDR alert ten seconds later.

Canonical entities used by the enriched templates:

| Role | Value | Source |
|---|---|---|
| Primary victim | `cassian` / `cassian@rebel-int.net` / `REBELLION` | `_SW_USERS[4]` |
| Secondary victim | `hera` / `hera@phoenix-sqd.net` / `PHOENIX` | `_SW_USERS[3]` |
| Victim workstation | `ferrix-ws` (Windows, `10.77.5.10`) | `_SW_USERS[4].primary_workstation` |
| Domain controller | `lothal-dc` (Windows server, `10.77.20.9`) | `_SW_MACHINES[8]` |
| Attacker IP | `198.51.100.42` (TEST-NET-2, RFC 5737) | — |
| C2 host | `imperial-relay.darkside.net` (`185.220.101.42:443`) | `_SW_C2[0]` |
| Primary malware | `order66.exe` (sha256 `a1b2c3…a1b2`) | `_SW_MALWARE[0]` |
| Attacker email | `emperor@galactic-empire.gov`, subject "New Imperial Decree" | `_SW_MAIL_SENDERS[0]` |
| Secondary attacker email | `tarkin@deathstar.mil`, subject "Project Stardust Update" | `_SW_MAIL_SENDERS[1]` |

---

## Multi-event narrative templates (Phase 2)

17 templates ship a full OCSF Finding shape with multi-step
`finding_info.related_events[]`, each entry carrying its own MITRE
ATT&CK technique and observables. The enricher's merge rule respects
these authored events (per-event MITRE is preserved; only entries
that ship empty `attacks[]` / `observables[]` are backfilled from the
template-level registry).

| Template | Story | MITRE chain |
|---|---|---|
| `wel_brute_force_success` | 5x failed → success → mimikatz dump | T1110.001 → T1078 → T1003.001 |
| `wel_hidden_scheduled_task` | Task created → SD hidden → fires order66.exe | T1053.005 → T1564 → T1059.003 |
| `wel_ad_global_admin_group` | Group created → user added → nested into Domain Admins | T1136.002 → T1098 → T1098.007 |
| `sharepoint_data_exfil_alert` | Anomalous sign-in → bulk download → RDP recon → cloud egress | T1078.004 → T1530 → T1018 → T1567.002 |
| `default_alert` | File write → process exec → C2 beacon | T1027 → T1204.002 → T1071.001 |
| `advanced_sample_alert` | Email → user-click → process → C2 | T1566.001 → T1204.002 → T1059.001 → T1071.001 |
| `sample_alert` | (smoke-test only — no narrative) | — |
| `proofpoint_phishing_link_clicked` | Delivery → TAP late reclassification → user click | T1566.002 → T1056.003 → T1204.001 |
| `proofpoint_attachment_delivered` | Delivery → sandbox detonation → Emotet verdict | T1566.001 → T1027.010 |
| `proofpoint_email_alert` | Delivery → user click (TAP blocked) | T1566 → T1204.001 |
| `proofpoint_impostor_unblocked` | Impostor detected → admin allowlist override | T1566.003 → T1562.006 |
| `proofpoint_large_attachments` | Anomalous volume → DLP sensitive-content hit | T1048.003 → T1213 |
| `proofpoint_outbound_phishing` | Internal sender bulk-mails → phishing URL | T1534 → T1056.003 |
| `proofpoint_phishing_unblocked` | Quarantine → admin release & deliver | T1566.001 → T1562.006 |
| `proofpoint_source_code_attachments` | Outbound zip with .py/.ts/.go → external exfil | T1213 → T1567 |
| `palo_alto_ramnit_c2` | PAN-OS spyware sig → DGA-resolved C2 → RAR payload pull | T1071.001 → T1568.002 → T1105 |
| `palo_alto_bladabindi_backdoor` | Outbound request → inbound MSIL PE → NJRat implant predicted | T1071.001 → T1105 → T1219 |

The 56 O365 templates retain their slim shape; the dynamic enricher
attaches a single summary `related_events[0]` with the registry's
MITRE mapping + harvested observables. Promote individual O365
templates to multi-event narratives when a specific story arc adds
value (e.g. a BEC chain).

Branding: all templates now use ApiGenie metadata (`metadata.product.name`)
and the "HELIOS - " prefix has been stripped from every title /
description. HELIOS remains acknowledged in code comments and this
doc as the reverse-engineering source for the binding recipe.

---

## Tests

```
tests/test_s1_assets.py                  # resolver
tests/test_alerts_phase4_6_resolver.py   # injection shape
tests/test_alerts_phase4_6_send.py       # send path with resolver
tests/test_alerts_phase4_3_send.py       # send path baseline
tests/test_alert_enrichment.py           # MITRE + observables (21 cases)
```

Run inside the container:

```
docker exec apigenie python -m pytest tests/ -q
# expect: 300 passed, 1 skipped
```
