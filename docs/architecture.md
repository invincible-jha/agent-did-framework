# Architecture — @aumos/agent-did

## Overview

`@aumos/agent-did` is a layered library with a thin facade (`AgentDIDManager`) that
wires together four independent components: DID providers, a credential layer, a
presentation layer, and a storage layer. All dependencies flow inward — higher-level
components depend on interfaces, not concrete implementations.

```
┌────────────────────────────────────────────────────────────┐
│                      AgentDIDManager                       │
│                (primary public facade)                     │
└──────────┬─────────────┬──────────────┬────────────────────┘
           │             │              │
           ▼             ▼              ▼
  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐
  │  DID Layer  │  │  Credential  │  │  Storage Layer    │
  │             │  │  Layer       │  │                   │
  │ - did:key   │  │ - Issuer     │  │ - DIDStore        │
  │ - did:web   │  │ - Verifier   │  │ - CredentialStore │
  │ - did:ethr  │  │ - Presentation│  │                   │
  │ - Resolver  │  │   Builder    │  │ (interface only)  │
  └─────────────┘  └──────────────┘  └───────────────────┘
```

## Component Descriptions

### AgentDIDManager (`src/agent/manager.ts`)

The single entry point for application code. Instantiated with optional
configuration and store overrides. Owns no state directly — all persistence is
delegated to the injected stores.

Responsibilities:
- Create agent DID identities (`createAgentDID`)
- Resolve DID strings to documents (`resolveAgentDID`)
- Deactivate locally-managed DIDs (`deactivateAgentDID`)
- Issue Verifiable Credentials (`issueAgentCredential`)
- Verify Verifiable Credentials (`verifyCredential`)
- Build Verifiable Presentations (`buildPresentation`)
- Expose store accessors (`getAgentIdentity`, `listAgentIdentities`)

### DID Providers (`src/did/`)

Each DID method is implemented as an independent class that satisfies the
`DIDMethodResolver` interface:

```typescript
interface DIDMethodResolver {
  readonly method: string;
  resolve(did: string, parsed: ParsedDID, resolver: Resolvable): Promise<DIDResolutionResult>;
}
```

**KeyDIDProvider** (`did/key.ts`)
- Generates Ed25519 key pairs using `@noble/ed25519`
- Encodes the public key as a multibase+multicodec string (prefix `0xed01`)
- Resolution is entirely local — no network calls
- The encoded DID string contains all information needed to reconstruct the document

**WebDIDProvider** (`did/web.ts`)
- Derives an HTTPS URL from the DID method-specific identifier per the did:web spec
- Fetches `/.well-known/did.json` (no path) or `/<path>/did.json` (with path)
- Validates the response document's `id` matches the requested DID
- Configurable timeout and pluggable fetch for testing

**EthrDIDProvider** (`did/ethr.ts`)
- Maps an Ethereum address to a DID: `did:ethr:0x<address>`
- Resolves the controller by calling `identityOwner(address)` on the ERC-1056
  `EthereumDIDRegistry` contract via `eth_call` JSON-RPC
- Multi-network: chainId encoded in DID (`did:ethr:<chainId>:<address>`) selects
  the matching RPC endpoint
- Read-only — no on-chain writes

**UniversalResolver** (`did/resolver.ts`)
- Routes resolution to the correct provider by DID method prefix
- Optional TTL-based cache keyed by DID string
- Supports registration of additional custom providers at construction time

### Credential Layer (`src/credentials/`)

**CredentialIssuer** (`credentials/issuer.ts`)
- Retrieves the issuer's private key from the local `DIDStore`
- Constructs a W3C VC payload (JSON-LD `@context`, `type`, `credentialSubject`)
- Signs with `jose`'s `SignJWT` using the Ed25519 private key imported via Web Crypto
- Persists the issued credential record to `CredentialStore`
- Returns a `VerifiableCredential` value object containing the compact JWT

**CredentialVerifier** (`credentials/verifier.ts`)
- Resolves the issuer DID to obtain the verification key from the DID document
- Verifies the JWT signature using `jose`'s `jwtVerify`
- Checks the `exp` claim against the current time
- Validates the decoded `credentialSubject` against the appropriate JSON Schema
- Returns a `VerificationResult` with `valid`, `issuer`, `expiry`, `claims`, and `failureReason`

**PresentationBuilder** (`credentials/presentation.ts`)
- Retrieves the holder's private key from the local `DIDStore`
- Wraps one or more credential JWTs in a W3C VP payload
- Signs the VP envelope with the holder's Ed25519 key
- Returns a `VerifiablePresentation` value object

### Storage Layer (`src/storage/`)

Two interfaces define the persistence contract:

```typescript
interface DIDStore {
  create(record: DIDRecord): Promise<void>;
  get(did: string): Promise<DIDRecord | undefined>;
  update(did: string, patch: Partial<DIDRecord>): Promise<void>;
  list(): Promise<readonly DIDRecord[]>;
  delete(did: string): Promise<void>;
}

interface CredentialStore {
  create(record: CredentialRecord): Promise<void>;
  get(id: string): Promise<CredentialRecord | undefined>;
  list(filter?: { issuerDID?: string; subjectDID?: string }): Promise<readonly CredentialRecord[]>;
  revoke(id: string): Promise<void>;
}
```

**InMemoryDIDStore** and **InMemoryCredentialStore** ship with the package for
development and testing. Production deployments should provide custom implementations
backed by a database or key vault.

### Configuration (`src/config.ts`)

`FrameworkConfig` is the single configuration object passed to `AgentDIDManager`.
It covers:

- `credential.proofAlgorithm` — signing algorithm (currently `"EdDSA"` only)
- `credential.defaultExpirySeconds` — default VC lifetime (default: 86400 = 24 hours)
- `resolver.cacheTtlMs` — DID document cache TTL (default: 300000 = 5 minutes)
- `resolver.httpTimeoutMs` — HTTP fetch timeout for did:web and did:ethr (default: 5000)
- `resolver.ethereumNetworks` — list of chain configurations for did:ethr
- `didStore` — pluggable DID store
- `credentialStore` — pluggable credential store
- `additionalResolvers` — custom DID method resolvers

## Data Flow: Issue a Credential

```
AgentDIDManager.issueAgentCredential(opts)
  -> CredentialIssuer.issue(opts)
      -> DIDStore.get(opts.issuerDID)          // retrieve issuer private key
      -> buildVCPayload(...)                   // construct W3C VC JSON-LD
      -> importEd25519PrivateKey(privateKey)   // Web Crypto import
      -> SignJWT(...).sign(cryptoKey)          // jose JWT signing
      -> CredentialStore.create(record)        // persist
      -> return VerifiableCredential
```

## Data Flow: Verify a Credential

```
AgentDIDManager.verifyCredential(vc)
  -> CredentialVerifier.verify(vc)
      -> UniversalResolver.resolve(vc.issuerDID)  // fetch DID document
      -> extractPublicKey(didDocument)             // locate verification method
      -> jwtVerify(vc.jwt, publicKey)              // jose signature check
      -> checkExpiry(payload.exp)                  // time check
      -> validateSchema(payload.vc)                // JSON Schema check
      -> return VerificationResult
```

## Dependency Graph

```
@noble/ed25519   - Ed25519 key generation and signing primitives
@noble/hashes    - SHA-512 for noble/ed25519
jose             - JWT signing and verification (Web Crypto API)
multiformats     - base58btc codec for did:key multibase encoding
varint           - multicodec varint encoding
did-resolver     - DID document types and ParsedDID utilities
```

No Veramo agent runtime is imported. The package uses the same underlying concepts
as Veramo (DID resolution, VC issuance, VP building) but implements them directly
against the lower-level primitives to keep the bundle small.
