# Credential Schemas — @aumos/agent-did

This package ships three JSON Schema definitions for W3C Verifiable Credentials.
All schemas target draft 2020-12 and are published under:

```
https://schemas.aumos.dev/vc/<schema-name>/v1
```

Schema files live in `src/credentials/schemas/` and are included in the npm
distribution under `src/credentials/schemas/`.

---

## AgentIdentity

**Schema ID:** `https://schemas.aumos.dev/vc/agent-identity/v1`
**File:** `src/credentials/schemas/agent-identity.json`

Attests that the subject DID belongs to an AI agent. Issued by an operator to
establish the agent's baseline identity.

### credentialSubject fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | DID string | Yes | The DID of the AI agent being attested |
| `agentName` | string (1–256 chars) | Yes | Human-readable display name |
| `agentVersion` | string (1–64 chars) | Yes | Software version string; semver recommended |
| `agentType` | string (1–64 chars) | Yes | Operator-assigned type tag |
| `registeredAt` | ISO-8601 date-time | Yes | Timestamp of first registration |

`additionalProperties` is `false` — no extra fields are permitted.

### Example credential subject

```json
{
  "id": "did:key:z6Mk...",
  "agentName": "Research Agent",
  "agentVersion": "1.0.0",
  "agentType": "assistant",
  "registeredAt": "2026-02-26T10:00:00.000Z"
}
```

### Issuing with the manager

```typescript
const vc = await manager.issueAgentCredential({
  issuerDID: operatorDID,
  agentDID: agentDID,
  credentialType: "AgentIdentity",
  claims: {
    credentialType: "AgentIdentity",
    agentName: "Research Agent",
    agentVersion: "1.0.0",
    agentType: "assistant",
    registeredAt: new Date().toISOString(),
  },
});
```

### Design notes

- `agentType` is an opaque string — this schema does not restrict valid values.
  Operators define their own taxonomy.
- The credential does not contain any trust level, score, or behavioural metric.
  It is a factual attestation of identity only.

---

## AgentCapability

**Schema ID:** `https://schemas.aumos.dev/vc/agent-capability/v1`
**File:** `src/credentials/schemas/agent-capability.json`

Attests that the subject AI agent is authorised to exercise a named capability.
Issued by an operator or service to grant permission.

### credentialSubject fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | DID string | Yes | The DID of the agent being granted the capability |
| `capability` | string matching `^[a-z0-9]+(\.[a-z0-9]+)*$` | Yes | Dot-namespaced capability name |
| `description` | string (1–1024 chars) | Yes | Human-readable description of what is granted |
| `resourceScope` | array of URI strings (max 64) | No | Resource URIs the capability applies to |

`capability` must use lowercase dot-namespaced notation. Examples:
- `file.read`
- `api.call`
- `api.call.openai`
- `database.query`

`resourceScope` is absent when the capability is resource-agnostic (applies to all
instances of the resource type). When present, it restricts the grant to specific
resource URIs.

### Example credential subject

```json
{
  "id": "did:key:z6Mk...",
  "capability": "api.call.openai",
  "description": "Authorised to make requests to the OpenAI API on behalf of the operator",
  "resourceScope": ["https://api.openai.com/v1/chat/completions"]
}
```

### Issuing with the manager

```typescript
const vc = await manager.issueAgentCredential({
  issuerDID: operatorDID,
  agentDID: agentDID,
  credentialType: "AgentCapability",
  claims: {
    credentialType: "AgentCapability",
    capability: "api.call.openai",
    description: "Authorised to call the OpenAI completions endpoint",
    resourceScope: ["https://api.openai.com/v1/chat/completions"],
  },
  expirySeconds: 3600, // 1 hour
});
```

### Design notes

- One VC per capability is the recommended pattern. Bundling multiple capabilities
  into one VC makes targeted revocation harder.
- Capability VCs should be short-lived when granting access to external APIs.
  Use `expirySeconds` accordingly.
- The `resourceScope` array uses URI format, which includes `urn:`, `https://`,
  and other URI schemes — allowing both HTTP APIs and arbitrary named resources.

---

## AgentDelegation

**Schema ID:** `https://schemas.aumos.dev/vc/agent-delegation/v1`
**File:** `src/credentials/schemas/agent-delegation.json`

Attests that the subject AI agent is authorised to act on behalf of an owner DID.
Used for delegation chains where an agent acts as a proxy for a human or organisation.

### credentialSubject fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | DID string | Yes | The DID of the agent receiving the delegation |
| `ownerDID` | DID string | Yes | DID of the human or organisation granting the delegation |
| `delegationScope` | string (1–256 chars) | Yes | Scope of the delegation |
| `delegatedCapabilities` | array of strings (max 64) | No | Specific capability names this delegation covers |

`delegationScope` is a free-form string. Conventions:
- `"read-only"` — agent may only read, not write
- `"admin"` — full access within the owner's permissions
- `"scoped:invoice.create"` — narrowly scoped to a named operation

When `delegatedCapabilities` is absent, the `delegationScope` applies broadly.
When present, it lists the specific capability names (matching `AgentCapability`
credential `capability` fields) that the delegation covers.

### Example credential subject

```json
{
  "id": "did:key:z6Mk...",
  "ownerDID": "did:web:acme.example.com",
  "delegationScope": "scoped:invoice.create",
  "delegatedCapabilities": ["api.call.erp", "file.write"]
}
```

### Issuing with the manager

```typescript
const vc = await manager.issueAgentCredential({
  issuerDID: ownerDID,        // owner issues the delegation
  agentDID: agentDID,         // agent receives it
  credentialType: "AgentDelegation",
  claims: {
    credentialType: "AgentDelegation",
    ownerDID: ownerDID,
    delegationScope: "scoped:invoice.create",
    delegatedCapabilities: ["api.call.erp", "file.write"],
  },
  expirySeconds: 86400, // 24 hours
});
```

### Design notes

- The issuer DID of an `AgentDelegation` credential is typically the owner DID,
  not the agent's DID. The owner signs the credential to prove consent.
- Delegation credentials should be short-lived. The recommended default is 24 hours.
  For sensitive scopes, prefer shorter expiry.
- Multi-hop delegation (agent A delegates to agent B) can be expressed as a chain
  of `AgentDelegation` VCs. Relying parties must verify each link in the chain.
- This schema does not encode trust levels, scores, or behavioural conditions.
  Delegation is a static grant, not a dynamic trust relationship.

---

## Common Schema Properties

All three schemas share these top-level fields (per the W3C VC Data Model):

| Field | Notes |
|-------|-------|
| `@context` | Must include `"https://www.w3.org/2018/credentials/v1"` |
| `type` | Array containing `"VerifiableCredential"` and the credential type |
| `id` | URI (auto-generated as `urn:uuid:<uuid>` by `CredentialIssuer`) |
| `issuer` | DID string or object with `id` field |
| `issuanceDate` | ISO-8601 date-time |
| `expirationDate` | ISO-8601 date-time (optional) |
| `credentialSubject` | Type-specific fields documented above |

When using JWT proof format (the only format supported in this version), the
`proof` field is absent from the JSON-LD body. The proof is the JWT signature
in the compact serialisation envelope.
