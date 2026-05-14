# Azure Event Hubs — SASL/PLAIN vs SASL/OAUTHBEARER

ApiGenie supports both SASL mechanisms that Azure Event Hubs offers for Kafka protocol access. This document compares the two and explains when to use each.

---

## At a Glance

| | SASL/PLAIN (SAS) | SASL/OAUTHBEARER (Entra ID) |
|---|---|---|
| **Azure name** | Shared Access Signature (SAS) | OAuth 2.0 / Microsoft Entra ID |
| **SASL mechanism** | `PLAIN` | `OAUTHBEARER` |
| **Security protocol** | `SASL_SSL` | `SASL_SSL` |
| **Port (ApiGenie)** | 9093 (TLS) · 9094 (no TLS) | 9093 (TLS) · 9094 (no TLS) |
| **Credential type** | Static connection string | OAuth2 client credentials (JWT) |
| **Token rotation** | Manual (regenerate SAS key) | Automatic (token refresh every ~1h) |
| **Azure RBAC** | No (namespace-level access) | Yes (fine-grained role assignments) |
| **Complexity** | Low — single connection string | Medium — requires app registration + token endpoint |
| **Production recommendation** | Quick start / dev | **Recommended by Microsoft for production** |

---

## Authentication Flow

### SASL/PLAIN (SAS Connection String)

```
Client                          Kafka Broker (ApiGenie :9093)
  │                                      │
  │─── TLS handshake ───────────────────▶│
  │◀── TLS established ─────────────────│
  │                                      │
  │─── SASL/PLAIN ──────────────────────▶│
  │    username: $ConnectionString        │
  │    password: Endpoint=sb://...        │
  │◀── SASL OK ─────────────────────────│
  │                                      │
  │─── Consume / Produce ───────────────▶│
```

The client sends the SAS connection string as a username/password pair. The broker validates it against a static allowlist. No external calls.

### SASL/OAUTHBEARER (Entra ID OAuth)

```
Client                Token Endpoint (ApiGenie HTTPS)     Kafka Broker (:9093)
  │                              │                               │
  │─── POST /oauth2/v2.0/token ▶│                               │
  │    client_id + secret        │                               │
  │    scope: *.servicebus.*     │                               │
  │◀── { access_token: JWT } ───│                               │
  │                                                              │
  │─── TLS handshake ───────────────────────────────────────────▶│
  │◀── TLS established ────────────────────────────────────────│
  │                                                              │
  │─── SASL/OAUTHBEARER ───────────────────────────────────────▶│
  │    token: eyJhbGci...                                        │
  │◀── SASL OK ────────────────────────────────────────────────│
  │                                                              │
  │─── Consume / Produce ──────────────────────────────────────▶│
  │                                                              │
  │    ... ~55 min later (automatic refresh) ...                 │
  │─── POST /oauth2/v2.0/token ▶│                               │
  │◀── { access_token: new JWT }│                               │
  │─── SASL re-auth ──────────────────────────────────────────▶│
```

The client first obtains a JWT from the token endpoint, then uses it as the OAUTHBEARER token in the Kafka SASL handshake. librdkafka handles token refresh automatically before expiry.

---

## Observo Collector Configuration

### SASL/PLAIN

**General Settings**

| Field | Value |
|-------|-------|
| Event Hubs Namespace Endpoint | `apigenie.roarinpenguin.com:9093` |
| Consumer Group | `observo-az` |
| Event Hub Names | `azure-platform-logs` |

**SASL Authentication**

| Field | Value |
|-------|-------|
| SASL Enabled | ✅ |
| SASL Mechanism | `PLAIN` |
| Connection String | `Endpoint=sb://apigenie.roarinpenguin.com/;SharedAccessKeyName=mock;SharedAccessKey=apigenie-eh-mock-2026;EntityPath=azure-platform-logs` |

No advanced settings needed.

---

### SASL/OAUTHBEARER

**General Settings**

| Field | Value |
|-------|-------|
| Event Hubs Namespace Endpoint | `apigenie.roarinpenguin.com:9093` |
| Consumer Group | `observo-oauth` |
| Event Hub Names | `azure-platform-logs` |

**SASL Authentication**

| Field | Value |
|-------|-------|
| SASL Enabled | ✅ |
| SASL Mechanism | `OAUTHBEARER` |
| Connection String | *(empty)* |
| SASL Username | *(empty)* |

**Advanced Settings (Librdkafka Options)**

| Key | Value |
|-----|-------|
| `sasl.oauthbearer.client.id` | `apigenie-client` |
| `sasl.oauthbearer.client.secret` | `apigenie-secret` |
| `sasl.oauthbearer.method` | `oidc` |
| `sasl.oauthbearer.scope` | `https://apigenie.roarinpenguin.com.servicebus.windows.net/.default` |
| `sasl.oauthbearer.token.endpoint.url` | `https://apigenie.roarinpenguin.com/mock-tenant/oauth2/v2.0/token` |
| `security.protocol` | `sasl_ssl` |

---

## When to Use Which

| Scenario | Recommended |
|----------|-------------|
| Quick local testing | PLAIN — simplest, one connection string |
| Demo with realistic Azure shape | OAUTHBEARER — mirrors real Entra ID flow |
| Testing collector OIDC implementation | OAUTHBEARER — exercises the full token lifecycle |
| Verifying SAS key rotation handling | PLAIN — test with different connection strings |
| Production Azure Event Hubs | OAUTHBEARER — Microsoft's recommendation |
| Multiple consumers with different roles | OAUTHBEARER — each gets its own client credentials |

---

## ApiGenie Implementation Details

### PLAIN Mechanism

- Kafka validates credentials against a static JAAS config
- Two users accepted: `admin` and `$ConnectionString`
- No external HTTP calls — pure broker-side validation

### OAUTHBEARER Mechanism

- Kafka uses the built-in **unsecured JWT validator** (`OAuthBearerUnsecuredValidatorCallbackHandler`)
- Accepts any JWT with `{"alg":"none"}` header, a `sub` claim, and a non-expired `exp`
- The token endpoint at `/{tenant_id}/oauth2/v2.0/token` detects Event Hubs scope (`.servicebus.windows.net`) and returns an unsecured JWT instead of the standard opaque token
- Both mechanisms coexist on the **same ports** (9093/9094) — the client chooses which to use during the SASL handshake

### Token Endpoint Behavior

```
POST /{tenant_id}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=apigenie-client
&client_secret=apigenie-secret
&scope=https://YOUR_NAMESPACE.servicebus.windows.net/.default
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhcGlnZW5pZS1rYWZrYS1jbGllbnQiLCJpYXQiOjE3MTU2...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

The `access_token` is an unsecured JWT:
- Header: `{"alg":"none"}`
- Payload: `{"sub":"apigenie-kafka-client","iat":...,"exp":...,"scope":"..."}`
- Signature: empty

---

## Verification Commands

### Test PLAIN with kcat

```bash
kcat -b apigenie.roarinpenguin.com:9093 -t azure-platform-logs -C \
  -X security.protocol=SASL_SSL \
  -X sasl.mechanism=PLAIN \
  -X sasl.username='$ConnectionString' \
  -X sasl.password='Endpoint=sb://apigenie.roarinpenguin.com/;SharedAccessKeyName=mock;SharedAccessKey=apigenie-eh-mock-2026;EntityPath=azure-platform-logs'
```

### Test OAUTHBEARER with kcat

```bash
# First, get a token
TOKEN=$(curl -sk -X POST \
  'https://apigenie.roarinpenguin.com/mock-tenant/oauth2/v2.0/token' \
  -d 'grant_type=client_credentials&client_id=apigenie-client&client_secret=apigenie-secret&scope=https://apigenie.servicebus.windows.net/.default' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Then consume with OAUTHBEARER
kcat -b apigenie.roarinpenguin.com:9093 -t azure-platform-logs -C \
  -X security.protocol=SASL_SSL \
  -X sasl.mechanism=OAUTHBEARER \
  -X sasl.oauthbearer.method=oidc \
  -X sasl.oauthbearer.client.id=apigenie-client \
  -X sasl.oauthbearer.client.secret=apigenie-secret \
  -X sasl.oauthbearer.scope=https://apigenie.servicebus.windows.net/.default \
  -X sasl.oauthbearer.token.endpoint.url=https://apigenie.roarinpenguin.com/mock-tenant/oauth2/v2.0/token
```

---

## Security Notes

- ApiGenie's OAUTHBEARER implementation uses **unsecured JWTs** (`alg: "none"`) — this is intentional for a mock/test environment
- In real Azure Event Hubs, tokens are signed RS256 JWTs issued by Microsoft Entra ID and validated against JWKS
- The `client_id` and `client_secret` values are not validated — any values are accepted
- Both PLAIN and OAUTHBEARER require `SASL_SSL` (TLS) in production; the `SASL_PLAINTEXT` listener on port 9094 is for lab use only
