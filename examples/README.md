# Examples — @aumos/agent-did

These runnable TypeScript examples demonstrate the core capabilities of the framework.

## Prerequisites

```bash
npm install
npm run build
```

## Running the examples

Each example is a self-contained TypeScript script. Run with ts-node or tsx:

```bash
npx tsx examples/basic-agent-did.ts
npx tsx examples/verify-agent-credential.ts
npx tsx examples/delegation-chain.ts
```

## What each example shows

### basic-agent-did.ts

The starting point. Shows:

1. Creating a `did:key` agent identity (Ed25519 key pair generated automatically).
2. Issuing an `AgentIdentity` credential (self-attested for demonstration).
3. Issuing an `AgentCapability` credential for a specific API scope.
4. Running credential verification and inspecting the decoded claims.

### verify-agent-credential.ts

Focuses on the verification flow. Shows:

1. Issuing a credential from a separate operator identity to an agent.
2. Verifying the credential — happy path.
3. Tampered JWT — signature verification failure.
4. Deactivated issuer — credential issuance rejection.

### delegation-chain.ts

Demonstrates the owner-to-agent delegation pattern. Shows:

1. Creating an `owner` identity (represents a human principal).
2. Creating an `agent` identity.
3. Issuing an `AgentDelegation` credential — owner grants the agent authority.
4. Building a signed Verifiable Presentation containing both identity and delegation VCs.
5. Verifying the delegation credential and reading the `delegatedCapabilities`.

## Schema locations

The three VC JSON schemas are in `src/credentials/schemas/`:

| Schema file             | Credential type    |
|-------------------------|--------------------|
| `agent-identity.json`   | `AgentIdentity`    |
| `agent-capability.json` | `AgentCapability`  |
| `agent-delegation.json` | `AgentDelegation`  |
