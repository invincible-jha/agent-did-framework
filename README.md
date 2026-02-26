# @aumos/agent-did

W3C Decentralized Identifiers and Verifiable Credentials for AI agent trust attestation.

Part of the [AumOS](https://github.com/aumos-ai) open-source governance protocol suite.

## Overview

`@aumos/agent-did` gives AI agents cryptographically verifiable identities. An agent
gets a DID, can receive Verifiable Credentials attesting its capabilities or delegation
rights, and can present those credentials to any relying party that can resolve the DID.

All credentials are standard W3C VCs with JWT proofs — no proprietary format, no
vendor lock-in.

## Install

```sh
npm install @aumos/agent-did
```

Node.js 18 or higher is required.

## Quick Start

```typescript
import { AgentDIDManager } from "@aumos/agent-did";

// 1. Create a manager (defaults: in-memory store, did:key + did:web resolvers)
const manager = new AgentDIDManager();

// 2. Create a DID for your agent
const identity = await manager.createAgentDID({
  method: "did:key",
  agentAlias: "research-agent-v1",
});

console.log(identity.did);
// did:key:z6Mk...

// 3. Issue a Verifiable Credential
const vc = await manager.issueAgentCredential({
  issuerDID: identity.did,
  agentDID: identity.did,
  credentialType: "AgentIdentity",
  claims: {
    credentialType: "AgentIdentity",
    agentName: "Research Agent",
    agentVersion: "1.0.0",
    agentType: "assistant",
    registeredAt: new Date().toISOString(),
  },
});

console.log(vc.jwt);
// eyJhbGci...

// 4. Verify the credential
const result = await manager.verifyCredential(vc);

console.log(result.valid);   // true
console.log(result.claims);  // { credentialType: "AgentIdentity", agentName: "Research Agent", ... }
```

## DID Methods

| Method | When to use |
|--------|-------------|
| `did:key` | Development, testing, self-sovereign agents, no infrastructure needed |
| `did:web` | Production agents with a stable HTTPS domain to host the DID document |
| `did:ethr` | Agents anchored to an Ethereum address; resolution requires an RPC endpoint |

See [docs/did-methods.md](docs/did-methods.md) for detailed guidance.

## Credential Types

Three generic credential types are included:

- **AgentIdentity** — asserts that a DID belongs to an AI agent (name, version, type)
- **AgentCapability** — asserts that an agent is authorised to exercise a named capability
- **AgentDelegation** — asserts that an agent may act on behalf of an owner DID

All three use JWT proof format (EdDSA / Ed25519). See [docs/credential-schemas.md](docs/credential-schemas.md).

## Architecture

See [docs/architecture.md](docs/architecture.md) for a full component walkthrough.

## Examples

Working examples live in [`examples/`](examples/README.md):

- `examples/basic-agent-did.ts` — create a DID and issue an AgentIdentity VC
- `examples/verify-agent-credential.ts` — verify a JWT credential end-to-end
- `examples/delegation-chain.ts` — multi-hop delegation with AgentDelegation VCs

## API Reference

The primary entry point is `AgentDIDManager`. All exported types are documented
with TSDoc in `src/`.

```typescript
import {
  AgentDIDManager,
  AgentDIDIdentity,
  CredentialIssuer,
  CredentialVerifier,
  PresentationBuilder,
  InMemoryDIDStore,
  InMemoryCredentialStore,
  KeyDIDProvider,
  WebDIDProvider,
  EthrDIDProvider,
  UniversalResolver,
} from "@aumos/agent-did";
```

## Fire Line

This package implements open, generic W3C DID and VC primitives. It does not contain
AumOS-proprietary trust scoring, behavioural analysis, or adaptive budget allocation.
See [FIRE_LINE.md](FIRE_LINE.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Business Source License 1.1. See [LICENSE](LICENSE).

Copyright (c) 2026 MuVeraAI Corporation
