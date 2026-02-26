# DID Methods — @aumos/agent-did

This package supports three DID methods. This document explains each one and
provides guidance on when to choose each.

## did:key

**Spec:** https://w3c-ccg.github.io/did-method-key/

### How it works

A `did:key` DID encodes the public key directly in the DID string using
multibase + multicodec encoding. No external server, registry, or database
is involved. Resolution is pure computation: the DID document is reconstructed
from the public key embedded in the DID string.

Example DID:
```
did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
```

The `z` prefix signals base58btc encoding. The `z6Mk` prefix after decoding
corresponds to the Ed25519 multicodec prefix `0xed01`.

### Creating a did:key identity

```typescript
const manager = new AgentDIDManager();

const identity = await manager.createAgentDID({
  method: "did:key",
  agentAlias: "my-agent",
});
// identity.did = "did:key:z6Mk..."
```

A fresh Ed25519 key pair is generated automatically. The private key is stored
in the local `DIDStore`. The public key is encoded in the DID string.

### When to use did:key

- Development and testing (zero infrastructure required)
- Short-lived ephemeral agents
- Self-sovereign agent identities where no domain or blockchain is available
- When the relying party controls its own resolver and does not need to fetch
  the document from an external URL

### Limitations

- The DID cannot be updated or rotated (it is permanently bound to one key)
- There is no standard mechanism for the DID to be deactivated externally
- Long DID strings may be inconvenient in some UI or logging contexts

---

## did:web

**Spec:** https://w3c-ccg.github.io/did-method-web/

### How it works

A `did:web` DID maps to an HTTPS URL where the DID document is hosted. The
mapping rule is:

| DID | URL |
|-----|-----|
| `did:web:example.com` | `https://example.com/.well-known/did.json` |
| `did:web:example.com:agents:my-agent` | `https://example.com/agents/my-agent/did.json` |

Colons in the method-specific identifier (after the domain) are decoded as
path separators. The resolver fetches the URL, validates the `Content-Type`,
and checks that the returned document's `id` matches the requested DID.

### Creating a did:web identity

```typescript
const identity = await manager.createAgentDID({
  method: "did:web",
  agentAlias: "prod-assistant",
  webDomain: "example.com:agents:prod-assistant",
});
// identity.did = "did:web:example.com:agents:prod-assistant"
```

The manager generates a local Ed25519 key pair and stores a placeholder document.
You must publish the DID document at the corresponding HTTPS URL before the DID
can be resolved by external parties.

A minimal did:web document to publish:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:example.com:agents:prod-assistant",
  "verificationMethod": [
    {
      "id": "did:web:example.com:agents:prod-assistant#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com:agents:prod-assistant",
      "publicKeyBase58": "<base58-encoded public key>"
    }
  ],
  "authentication": ["did:web:example.com:agents:prod-assistant#key-1"],
  "assertionMethod": ["did:web:example.com:agents:prod-assistant#key-1"]
}
```

### When to use did:web

- Production agents operated by an organisation that controls a domain
- Agents that need human-readable, stable identifiers tied to a brand domain
- Deployments where the DID document needs to be updated (rotate keys, add
  service endpoints) without changing the DID string
- Interoperability with systems that expect an HTTPS-resolvable DID

### Limitations

- Requires control of an HTTPS domain with a valid TLS certificate
- Resolution depends on the domain being reachable — a network outage or
  domain transfer can break resolution
- The DID is as trustworthy as the domain's PKI (certificate authority trust)

---

## did:ethr

**Spec:** https://github.com/decentralized-identity/ethr-did-resolver

### How it works

A `did:ethr` DID is an Ethereum address expressed as a DID:

```
did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a
```

With an explicit chain ID prefix:
```
did:ethr:1:0xb9c5714089478a327f09197987f16f9e5d936e8a    (mainnet)
did:ethr:11155111:0xb9c5714089478a327f09197987f16f9e5d936e8a (Sepolia)
```

Resolution calls the `identityOwner(address)` function on the
[ERC-1056 EthereumDIDRegistry](https://github.com/uport-project/ethr-did-registry)
contract via `eth_call`. The registry stores delegated controllers and
attribute-based verification methods. The resolver builds a DID document
from the controller address and any on-chain attributes.

### Creating a did:ethr identity

```typescript
const manager = new AgentDIDManager({
  config: {
    resolver: {
      ethereumNetworks: [
        {
          chainId: 11155111,
          name: "sepolia",
          rpcUrl: "https://rpc.sepolia.example.com",
        },
      ],
    },
  },
});

const identity = await manager.createAgentDID({
  method: "did:ethr",
  agentAlias: "blockchain-agent",
  ethrAddress: "0xb9c5714089478a327f09197987f16f9e5d936e8a",
});
```

The Ethereum address must be provided by the caller. Key management (signing
transactions, managing the private key for the address) is handled outside
this library.

### When to use did:ethr

- Agents that need to be anchored to an on-chain identity or asset
- Deployments where key rotation must be publicly auditable without changing
  the DID string (use the ERC-1056 registry's `changeOwner` function)
- Scenarios requiring multi-sig or smart contract ownership of the DID
- Interoperability with Ethereum-native trust frameworks

### Limitations

- Resolution requires a running JSON-RPC endpoint for the relevant chain
- RPC endpoint availability introduces a liveness dependency
- Only the `identityOwner` lookup is implemented in this package's provider.
  Full ERC-1056 event log replay (for custom verification methods and
  service endpoints) requires a more complete integration
- `did:ethr` issuers cannot sign credentials with this library's `CredentialIssuer`
  because the Ethereum private key is not held locally. Use `did:key` or `did:web`
  as the issuer DID

---

## Decision Summary

```
Do you need zero infrastructure?          -> did:key
Do you have an HTTPS domain?             -> did:web
Do you have an Ethereum address?         -> did:ethr
Are you issuing credentials?             -> did:key or did:web (must hold private key locally)
Do you need externally updatable keys?   -> did:web or did:ethr
Is this for dev/test only?               -> did:key
```
