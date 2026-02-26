# Veramo Integration — @aumos/agent-did

## Why Not Depend on Veramo Directly?

[Veramo](https://veramo.io/) is a mature, pluggable agent framework for W3C DIDs
and Verifiable Credentials. `@aumos/agent-did` uses the same underlying W3C
specifications and shares conceptual vocabulary with Veramo, but does not import
the Veramo agent runtime as a dependency.

The reason is bundle size and deployment flexibility. Veramo's full plugin system
and agent runtime are designed for server-side use with database-backed stores and
a rich plugin ecosystem. `@aumos/agent-did` targets scenarios where a smaller,
tree-shakeable package is preferred — edge runtimes, serverless functions, or
client-side code where pulling in a large agent framework is impractical.

## Shared Concepts and Vocabulary

| Veramo concept | Equivalent in @aumos/agent-did |
|---------------|-------------------------------|
| `IDIDManager` | `DIDStore` interface |
| `IDataStore` | `CredentialStore` interface |
| `IKeyManager` | private key field on `DIDRecord` |
| `IResolver` | `UniversalResolver` + `DIDMethodResolver` |
| `ICredentialPlugin` | `CredentialIssuer` + `CredentialVerifier` |
| `IPresentationExchange` | `PresentationBuilder` |
| `did-provider-key` | `KeyDIDProvider` |
| `did-provider-web` | `WebDIDProvider` |
| `did-resolver` | `did-resolver` (shared npm package) |

The `did-resolver` npm package is the one shared runtime dependency between
Veramo and this library. Its `DIDDocument`, `ParsedDID`, `Resolvable`, and
`DIDResolutionResult` types are used throughout `@aumos/agent-did`'s resolver
layer, which means Veramo resolver plugins can be adapted for use here with
minimal glue code.

## Using Veramo Resolver Plugins with UniversalResolver

Any Veramo-compatible resolver plugin that satisfies the `getResolver()` pattern
can be wrapped to work with `UniversalResolver`. The adapter needs to implement
the `DIDMethodResolver` interface:

```typescript
import type { DIDMethodResolver } from "@aumos/agent-did";
import type { DIDResolutionResult, ParsedDID, Resolvable } from "did-resolver";

/**
 * Wrap a Veramo-style resolver map entry for use with UniversalResolver.
 */
function wrapVeramoResolver(
  method: string,
  resolveFn: (
    did: string,
    parsed: ParsedDID,
    resolver: Resolvable
  ) => Promise<DIDResolutionResult>
): DIDMethodResolver {
  return {
    method,
    resolve: resolveFn,
  };
}

// Example: wrapping a hypothetical custom Veramo plugin
import { getResolver as getCustomResolver } from "did-resolver-custom";

const customResolverMap = getCustomResolver({ /* options */ });

const wrappedResolvers = Object.entries(customResolverMap).map(
  ([method, resolveFn]) => wrapVeramoResolver(method, resolveFn)
);

const manager = new AgentDIDManager({
  config: {
    additionalResolvers: wrappedResolvers,
  },
});
```

## Using This Package Inside a Veramo Agent

If your application already uses a Veramo agent and you want to use
`@aumos/agent-did` credential types alongside it:

1. Issue credentials with `AgentDIDManager.issueAgentCredential`. The output
   is a compact JWT string — the same format Veramo produces.
2. Store the JWT in your Veramo data store by calling
   `agent.dataStoreSaveVerifiableCredential({ verifiableCredential })` with
   the decoded payload.
3. Verify with either `AgentDIDManager.verifyCredential` or Veramo's
   `agent.verifyCredential` — both perform standard JWT/EdDSA verification
   against the issuer's DID document.

The JSON Schema credential types (`AgentIdentity`, `AgentCapability`,
`AgentDelegation`) are plain W3C VC types. Veramo will treat them as standard
credentials without any special plugin.

## Key Management Differences

Veramo has a full `IKeyManager` subsystem with pluggable KMS backends (local,
AWS KMS, HSM). `@aumos/agent-did` stores raw private key bytes in the `DIDStore`.
For production deployments that need HSM or KMS-backed key management, the
recommended approach is:

1. Implement a custom `DIDStore` that stores key references (not raw bytes).
2. Override the signing path by subclassing or wrapping `CredentialIssuer`.
3. Use the injected `FrameworkConfig.didStore` to provide your custom store to
   `AgentDIDManager`.

This design mirrors Veramo's plugin model: the interfaces define the contract,
and the concrete implementations are swappable.

## Credential Format Compatibility

`@aumos/agent-did` produces standard JWT-encoded VCs per the
[W3C VC Data Model](https://www.w3.org/TR/vc-data-model/). The JWT payload
structure is:

```json
{
  "iss": "<issuer DID>",
  "sub": "<subject DID>",
  "jti": "<credential URI>",
  "iat": 1234567890,
  "exp": 1234654290,
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "AgentIdentity"],
    "id": "urn:uuid:...",
    "issuer": "<issuer DID>",
    "issuanceDate": "2026-02-26T10:00:00.000Z",
    "credentialSubject": { ... }
  }
}
```

This matches the Veramo JWT credential format exactly. A credential issued by
`@aumos/agent-did` can be verified by a Veramo agent, and vice versa, as long
as both can resolve the issuer's DID.
