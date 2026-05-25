# Multi-User Log Profiling — Design Document

**Status:** Design  
**Date:** 2026-05-15  

---

## Problem Statement

ApiGenie currently applies a single log profile per source — every caller hitting `/api/v1/logs` (Okta) gets the same entity pool and detection rules. When multiple pipelines consume the same source simultaneously (e.g. a demo pipeline and a test pipeline), there is no way to differentiate what each one receives.

The goal is to let administrators define **caller-specific profile bindings** so that different pipelines consuming the same source can receive different log profiles, detection rules, and intensity settings.

---

## Concepts

### Caller Context

Every request carries implicit identity signals:

| Signal | Available in | Example |
|--------|-------------|---------|
| **Source IP** | HTTP, Kafka (via bus_monitor) | `10.0.5.42`, `192.168.1.100` |
| **User-Agent** | HTTP only | `observo-collector/2.1.0` |
| **HTTP headers** | HTTP only | `X-Pipeline-Id: demo-eu-west` |
| **Kafka consumer group** | Kafka only | `observo-prod`, `observo-demo` |
| **Pub/Sub subscription** | Pub/Sub only | `audit-logs-sub-demo` |

These signals form a **CallerContext** — a lightweight dict extracted from the inbound request or bus monitor data.

### Conditional Binding

A conditional binding extends the existing source↔profile binding with a set of match conditions. Each condition is a `field → substring` match. Multiple conditions use AND logic (all must match).

```
Source: okta
├── Binding A (no conditions)     → Profile "Starfleet" @ 80% ratio
├── Binding B (ip contains 10.0.5) → Profile "Red Team"  @ 100% ratio
└── Binding C (user_agent contains observo-demo) → Profile "Demo Corp" @ 60% ratio
```

When a request comes in:
1. Evaluate all bindings for that source
2. Pick the **most specific match** (most conditions satisfied)
3. If no conditional binding matches, fall back to the unconditional one
4. If nothing matches, no profile is applied (current behavior)

---

## Data Model

### Binding (extended)

```json
{
  "okta": {
    "profile_id": "uuid-starfleet",
    "ratio": 80,
    "intensity": 50,
    "conditions": null
  },
  "okta::cond::abc123": {
    "profile_id": "uuid-redteam",
    "ratio": 100,
    "intensity": 75,
    "conditions": {
      "source_ip_contains": "10.0.5",
      "user_agent_contains": "observo-prod"
    }
  },
  "okta::cond::def456": {
    "profile_id": "uuid-democorp",
    "ratio": 60,
    "intensity": 30,
    "conditions": {
      "header:X-Pipeline-Id": "demo-eu"
    }
  }
}
```

**Key format:** `{source}::cond::{short_id}` for conditional bindings. The base `{source}` key remains the default (unconditional) binding for backward compatibility.

### CallerContext

```python
@dataclass
class CallerContext:
    source_ip: str = ""
    user_agent: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    consumer_group: str = ""    # Kafka only
    subscription: str = ""      # Pub/Sub only
```

### Condition Matching

```python
CONDITION_EXTRACTORS = {
    "source_ip_contains":       lambda ctx, val: val in ctx.source_ip,
    "user_agent_contains":      lambda ctx, val: val in ctx.user_agent,
    "consumer_group_contains":  lambda ctx, val: val in ctx.consumer_group,
    "subscription_contains":    lambda ctx, val: val in ctx.subscription,
    "header:<name>":            lambda ctx, val: val in ctx.headers.get("<name>", ""),
}
```

All conditions in a binding must match (AND logic). A binding with more matching conditions is considered more specific and takes precedence.

---

## Affected Components

### 1. profiles.py — Core Changes

**New function signature:**

```python
def get_context(source: str, caller: CallerContext | None = None) -> ProfileContext | None:
```

When `caller` is provided:
1. Load all bindings for `source` (including `{source}::cond::*` keys)
2. Evaluate conditions against `caller`
3. Return the most specific matching binding's profile
4. Fall back to the unconditional binding

When `caller` is `None` (backward compatible): current behavior, use the unconditional binding.

**New functions:**

```python
def bind_source_conditional(source: str, profile_id: str, conditions: dict, ...) -> dict
def unbind_source_conditional(source: str, condition_id: str) -> bool
def list_conditional_bindings(source: str) -> list[dict]
```

### 2. Source Generators — Request Passthrough

Each source generator needs to receive and forward the caller context. Two approaches:

**Option A — Thread-local context (minimal changes):**

```python
# In trace.py middleware, before calling the route:
_caller_context_var.set(CallerContext(
    source_ip=client_ip,
    user_agent=request.headers.get("user-agent", ""),
    headers=dict(request.headers),
))

# In source generators:
ctx = profiles.get_context("okta")  # reads from thread-local
```

This avoids changing every generator's function signature. The middleware sets the context, and `get_context` reads it transparently.

**Option B — Explicit parameter (more explicit, more changes):**

```python
# Every generator call passes the context
def get_logs_response(since, limit, caller: CallerContext):
    ctx = profiles.get_context("okta", caller)
```

**Recommendation:** Option A (thread-local) for HTTP sources. Much less code churn.

### 3. Kafka / Pub/Sub — Separate Topics

For streaming sources, the challenge is that the publisher doesn't know who's consuming. Two strategies:

**Strategy 1 — Topic-per-pipeline (recommended for Kafka):**

```
azure-platform-logs           → default profile
azure-platform-logs-demo      → "Demo Corp" profile  
azure-platform-logs-redteam   → "Red Team" profile
```

The publisher writes different-flavored events to each topic. The Observo collector subscribes to the appropriate topic.

Implementation:
- New env var or config: `KAFKA_CONDITIONAL_TOPICS` mapping topic → profile binding
- Publisher loop iterates over all configured topics
- Minimal Kafka overhead (same broker, just more topics)

**Strategy 2 — Consumer-group tracking (complex, deferred):**

The bus_monitor already tracks consumer group IPs. In theory, we could:
1. Detect which consumer groups are active
2. Match them against conditional bindings
3. Produce tailored messages per consumer group

This requires significant architectural changes (per-consumer message targeting) and is deferred.

### 4. Admin UI

Extend the bindings card in Log Profiles:

```
┌─────────────────────────────────────────────────────────┐
│ Okta                                    [Unbind] [Save] │
│ Profile: [Starfleet ▾]  Ratio: [━━━━] 80%              │
│ Log volume: [━━━━] 50% (~50 logs/req)                   │
│                                                         │
│ ▸ Conditional bindings (2)                              │
│   ┌─────────────────────────────────────────────────┐   │
│   │ Profile: Red Team @ 100%                        │   │
│   │ Conditions: source_ip contains "10.0.5"         │   │
│   │             user_agent contains "observo-prod"  │   │
│   │                                    [Edit] [Del] │   │
│   └─────────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────────┐   │
│   │ Profile: Demo Corp @ 60%                        │   │
│   │ Conditions: header:X-Pipeline-Id contains "demo"│   │
│   │                                    [Edit] [Del] │   │
│   └─────────────────────────────────────────────────┘   │
│   [+ Add conditional binding]                           │
└─────────────────────────────────────────────────────────┘
```

### 5. Detection Rules

Detection rules should also support conditional activation. The same `conditions` block can be added to detection rules:

```json
{
  "name": "Brute force login",
  "source": "okta",
  "periodicity": 5,
  "field_overrides": { ... },
  "conditions": {
    "source_ip_contains": "10.0.5"
  }
}
```

This way, detection-triggered logs only appear for specific pipelines.

---

## API Changes

### New Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/api/source-profiles/{source}/conditions` | List conditional bindings for a source |
| POST | `/admin/api/source-profiles/{source}/conditions` | Add a conditional binding |
| PUT | `/admin/api/source-profiles/{source}/conditions/{id}` | Update a conditional binding |
| DELETE | `/admin/api/source-profiles/{source}/conditions/{id}` | Remove a conditional binding |

### Modified Endpoints

| Endpoint | Change |
|----------|--------|
| `GET /admin/api/source-profiles` | Response includes conditional bindings per source |
| `PUT /admin/api/detection-rules/{id}` | Accepts optional `conditions` block |

---

## Evaluation Priority

When multiple bindings match, specificity determines which wins:

```
1. Conditional binding with most matched conditions → highest priority
2. Conditional binding with fewer conditions → lower priority
3. Unconditional binding → fallback
4. No binding → no profile (noise only)
```

Tie-breaking: if two bindings have the same number of conditions and both match, the one created first wins.

---

## Implementation Phases

### Phase 1 — Foundation (HTTP sources only)

1. Add `CallerContext` dataclass
2. Set caller context in trace middleware (thread-local)
3. Extend `get_context()` to accept and evaluate conditions
4. Conditional binding CRUD in `profiles.py`
5. API endpoints
6. UI: expandable conditional bindings in the profiles card

**Effort:** Medium. Core logic is ~100 lines. UI is the largest part.

### Phase 2 — Kafka Topic Routing

1. Config for conditional Kafka topics
2. Publisher writes to multiple topics with different profiles
3. Admin UI for topic↔profile mapping

**Effort:** Low-medium. Publisher changes are small.

### Phase 3 — Detection Rule Conditions

1. Add optional `conditions` to detection rules
2. Evaluate conditions in `inject_detection_events`
3. UI: conditions editor in detection rule modal

**Effort:** Low. Reuses Phase 1 matching logic.

### Phase 4 — Pub/Sub Subscription Routing (optional)

1. Multiple subscriptions with different profiles
2. Publisher fans out to multiple topics/subscriptions

**Effort:** Low. Same pattern as Kafka.

---

## Backward Compatibility

- Existing bindings (no conditions) continue to work unchanged
- `get_context("okta")` without a CallerContext returns the unconditional binding
- No migration needed — conditions are additive
- The `conditions` field defaults to `null` in existing data

---

## Open Questions

1. **Maximum conditional bindings per source?** Suggest 10 to avoid performance issues in the matching loop.
2. **Regex support in conditions?** Start with substring match (`contains`). Add regex later if needed.
3. **Negation?** e.g. "NOT from IP 10.0.5" — useful but adds complexity. Defer to Phase 2.
4. **Cascading?** Should a conditional binding inherit the base binding's ratio/intensity if not explicitly set? Suggest yes — merge with base, override only what's specified.
5. **Audit trail?** Log which binding was activated for each request? Could be valuable for debugging but adds overhead.
