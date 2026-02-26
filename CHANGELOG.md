# Changelog

All notable changes to `@aumos/agent-did` will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 0.1.0 - Unreleased

### Added

- `AgentDIDManager` facade: create, resolve, and deactivate agent DIDs; issue and
  verify Verifiable Credentials; build Verifiable Presentations.
- `did:key` provider: self-contained Ed25519 key-pair generation and local resolution
  (no external network calls required).
- `did:web` provider: HTTPS-based DID document resolution with configurable timeout
  and pluggable fetch implementation.
- `did:ethr` provider (optional): Ethereum-address-backed DIDs resolved via
  ERC-1056 `identityOwner` registry lookup over JSON-RPC.
- `CredentialIssuer`: issues W3C Verifiable Credentials as EdDSA JWT proofs.
- `CredentialVerifier`: verifies JWT credential signatures, expiry, and schema
  conformance.
- `PresentationBuilder`: assembles signed Verifiable Presentations from one or more
  credentials.
- Three generic JSON Schema credential schemas: `AgentIdentity`, `AgentCapability`,
  `AgentDelegation`.
- `InMemoryDIDStore` and `InMemoryCredentialStore`: zero-dependency storage backends
  suitable for testing and single-process deployments.
- `UniversalResolver`: pluggable multi-method DID resolver with optional TTL cache.
- `FrameworkConfig` with `buildDefaultCredentialConfig` and `buildDefaultResolverConfig`
  factory helpers.
- `scripts/fire-line-audit.sh`: CI guard that rejects commits containing any
  AumOS-proprietary identifier.
