# How to make HELIOS-pushed alerts bind to a real S1 agent

**Audience**: HELIOS / `jarvis_coding` developer hitting the "alert lands in UAM
but `asset.agentUuid` is `null` and Purple AI / DV correlation never fires"
problem.

**TL;DR**: UAM doesn't read `device.*` — only `resources[]`. Use the resource
of `type: "Device"` (or similar) with `name` matching an S1 agent on the
tenant. Don't send `scopeGroupId`. That's it.

---

## 1. What S1 actually does on ingest

When you `POST /web/api/v2.1/cloud-detection/alerts`, the alert-service
runs this rough pipeline per alert:

1. **Scope** — pick the alert's account/site/group from your
   `scopeAccountId` + `assets[].agentUuid` (if provided) or from the
   resolved resource's home scope.
2. **Bind** — for each entry in `resources[]`, try to find an S1
   asset (agent, user, etc.) whose canonical name matches `resources[i].name`.
   If found, rewrite `resources[i].uid` to the asset's resource UID
   (base32 lowercase of the UUID, e.g. `cwawrqvoujui77izl3essdinhe`).
3. **Populate `asset`** — if the bind succeeded, the top-level `asset`
   block on the resulting UAM alert gets `agentUuid`, `hostname`,
   `osType`, `siteId`, `groupId` from the matched agent.

Step 2 is where most HELIOS pushes silently fail. Three traps:

### Trap A — sending `device.hostname` instead of `resources[]`

The alert-service does **not** look at `device.*`. We can see this in
the source: the resolver only iterates `resources[]`. A perfectly valid
OCSF alert with `device.hostname = "WIN-DC-01"` will land — but with
`asset.agentUuid = null`. UAM is happy (OCSF parses), but Purple AI
can't correlate it with EDR data because there's no agent linkage.

**Fix**: every alert MUST carry `resources[]` with at least one entry,
whose `name` matches a real agent on the destination tenant.

```json
"resources": [
  {
    "uid": "<any-uuid-or-placeholder>",
    "name": "WIN-DC-01",
    "type": "Windows Server"
  }
]
```

The `uid` you send is irrelevant — S1 rewrites it. The `name` is the
binding key.

### Trap B — sending a group scope header

If you push with `scopeGroupId=<id>` (or the per-batch
`assets[].siteId` / `assets[].groupId` pre-bind), the alert-service
silently **drops the alert** when the scope target doesn't have a
matching asset. No error, no 4xx — just an "accepted" status code and
the alert never shows in UAM.

**Fix**: don't send `scopeGroupId`. Use **account-level scope only**
(`scopeAccountId=<account-id>`). S1 will then walk all sites/groups in
the account to find the named asset.

```python
# WRONG — silent drop if WIN-DC-01 isn't directly under groupId 9876:
POST /web/api/v2.1/cloud-detection/alerts?scopeAccountId=123&scopeGroupId=9876

# RIGHT — account-wide search:
POST /web/api/v2.1/cloud-detection/alerts?scopeAccountId=123
```

### Trap C — name fuzziness

S1's name match is **exact, case-insensitive**, against the agent's
`computerName` (Windows) or `hostName` (Linux/macOS). Spaces,
underscores, FQDN-vs-shortname mismatches all break the bind.

**Verification**: hit `/web/api/v2.1/agents?computerName__contains=WIN-DC`
on the tenant first, copy the exact `computerName` field, and use that
as your `resources[0].name`.

You can also bind by **user** (`type: "User"`, `name: "Jane Smith"` or
`name: "jane@corp.test"`) but the matching is fuzzier and S1 resolves
the user to their primary agent. Device binding is more reliable.

---

## 2. The verification recipe

Once you `POST` the alert and get a `202 Accepted`, poll the UAM
GraphQL endpoint to confirm the bind:

```graphql
query {
  alerts(siteIds: ["<your-site-id>"], filter: {externalId: "<your-external-id>"}) {
    edges {
      node {
        result {
          asset {
            name
            agentUuid     # <-- this is the bind proof
            osType
          }
        }
      }
    }
  }
}
```

- `agentUuid` is **non-null** → the bind worked. Purple AI will
  correlate this alert with EDR telemetry from that agent.
- `agentUuid` is **null** → the alert landed but `resources[0].name`
  didn't match. Fix the name, re-send.

UAM ingest is async — give it 20–30 seconds. We've seen binds complete
in 10s on `usea1-purple` consistently.

---

## 3. Minimum viable alert that binds

This is the smallest OCSF Finding shape that reliably binds:

```json
{
  "class_uid": 99602001,
  "class_name": "S1 Security Alert",
  "category_uid": 2,
  "category_name": "Findings",
  "type_uid": "9960200101",
  "type_name": "S1 Security Alert: Create",
  "activity_id": 1,
  "severity_id": 3,
  "state_id": 1,
  "time": 1725373112000,
  "finding_info": {
    "uid": "<your-external-id>",
    "title": "Test alert",
    "desc": "Smoke test for binding"
  },
  "metadata": {
    "version": "1.1.0",
    "product": {"name": "MyTool", "vendor_name": "MyVendor"},
    "logged_time": 1725373112000
  },
  "resources": [
    {"uid": "irrelevant", "name": "WIN-DC-01", "type": "Windows Server"}
  ]
}
```

Send that with `scopeAccountId` only, poll UAM, see `agentUuid` populated.
That's the contract.

---

## 4. What ApiGenie added on top

For our integration we needed alerts to bind PLUS carry rich
OCSF surface (MITRE attacks, observables, multi-event narratives) so
Purple AI's auto-investigation has signal to chew on. Two pieces of
machinery, both standalone:

### 4.1 `S1AssetResolver` — `s1_assets.py`

Per-batch in-memory resolver: paginates `/xdr/assets` once, builds a
lowercase-name → resource_uid lookup, then for every alert in the
batch it tries `resources[*].name` against the index and rewrites
`resources[i].uid` to the resolved UID **before** egress.

Why: S1's own ingest-time binding is name-match too, but doing it
client-side lets us:
- Log a diagnostic trace per alert (`hits / misses / not_attempted`),
  so when a customer says "alert isn't binding" we know if it's a
  name mismatch (resolver-miss) vs. an S1 scope problem.
- Pre-populate the `uid` so downstream `egress_alert` can include
  the agent in any tenant-scoped structure if needed.

If you want to skip this: send `resources[*].name` matching the agent
exactly and S1 will rebind on its side. The resolver is a UX
diagnostic, not strictly required for the bind.

### 4.2 `alert_enrichment.enrich_alert` — `alert_enrichment.py`

After binding is sorted, we noticed `asset.agentUuid` was populated
but `rawData.finding_info.related_events[]` was empty — meaning the
UAM ATT&CK panel showed "no techniques" even when our template's
title was literally "Successful Brute Force Attack".

Root cause: HELIOS templates ship `finding_info` with `title` + `desc`
but nothing inside `related_events[]`. UAM uses `related_events[].attacks[]`
as its MITRE source.

Fix: a registry-backed enricher. For each known template stem
(`wel_brute_force_success`, `proofpoint_phishing_link_clicked`,
`palo_alto_ramnit_c2`, ...) we have an authoritative MITRE mapping.
At `prepare_alert` time we either:
- **Synthesise** a single `related_events[0]` with the MITRE chain
  + observables harvested from the alert body (resource names,
  device IPs, user emails, URLs, file hashes) — used when the
  template ships nothing.
- **Merge** into existing `related_events[]` — preserving authored
  per-event MITRE (template author is authoritative on the
  narrative), backfilling empty entries from the registry.

We also regenerate `finding_info.related_events[].uid` every batch.
HELIOS does this implicitly because the alert-service uses these
UIDs for dedup on the S1 side — re-using them across batches causes
the alert-service to silently swallow the second push.

---

## 5. If your HELIOS pushes still don't bind after applying §1

In order:

1. Confirm you're sending `resources[]` (not `device.*`). Print the
   payload right before the `requests.post`.
2. Confirm `resources[0].name` is the agent's **exact** computerName
   from `GET /web/api/v2.1/agents`.
3. Drop `scopeGroupId` from the URL — keep only `scopeAccountId`.
4. Wait 30s, then poll UAM by your `externalId`. If `agentUuid` is
   null, name didn't match.
5. Regenerate `finding_info.related_events[].uid` per batch. If
   you're re-using UIDs across pushes, S1 dedups silently.

If all 5 are right and you still see `agentUuid: null`, share:
- the exact `resources[]` block you sent
- the URL of the POST including all query params
- the agent's exact name from `/agents` lookup

…and one of those three will be the culprit.

---

## 6. Cross-reference

ApiGenie's full binding + enrichment flow is documented in
`docs/ALERT_PUSH.md`. The relevant Python entry points:

| Function | File | Job |
|---|---|---|
| `S1AssetResolver.resolve_batch` | `s1_assets.py` | Name → resource_uid lookup |
| `prepare_alert` | `alerts.py` | Deep-copy template + UID rewrite + enrich |
| `enrich_alert` | `alert_enrichment.py` | Inject MITRE + observables |
| `egress_alert` | `alerts.py` | Strip non-OCSF fields, attach resolver results |
| `send_alert` | `alerts.py` | POST to `/cloud-detection/alerts` |

All five are exercised end-to-end by `tests/test_alerts_phase4_6_*.py`
(48 cases) and `tests/test_alert_enrichment.py` (21 cases).
