# Fire Line — @aumos/agent-did

This document defines the boundary between what this package is and what it
deliberately excludes. All contributors and AI assistants must read this before
touching the source code.

## What Is IN Scope

The package implements open, generic W3C primitives:

| Feature | Details |
|---------|---------|
| **did:key** | Self-contained Ed25519 DID generation and local resolution |
| **did:web** | HTTPS-hosted DID document resolution |
| **did:ethr** | Ethereum-address-backed DID resolution via ERC-1056 (read-only) |
| **VC issuance** | W3C Verifiable Credentials with EdDSA JWT proof format |
| **VC verification** | JWT signature, expiry, and JSON Schema conformance checks |
| **3 generic schemas** | `AgentIdentity`, `AgentCapability`, `AgentDelegation` |
| **In-memory storage** | `InMemoryDIDStore`, `InMemoryCredentialStore` for testing/dev |
| **Pluggable storage** | `DIDStore` and `CredentialStore` interfaces for custom backends |
| **Verifiable Presentations** | VP assembly from one or more VCs |

## What Is EXCLUDED

The following are AumOS proprietary features and must never appear in this
open-source package:

| Excluded Feature | Reason |
|------------------|--------|
| ZK proofs (any variety) | Not part of v1 scope; complex IP surface |
| Trust-level fields in VC schemas | Core AumOS IP — trust is not expressed in credentials |
| ERC-8004 or any on-chain smart contract writes | Out of scope |
| On-chain reputation systems | Out of scope |
| AumOS-proprietary schemas | Internal only |
| Adaptive trust progression | AumOS proprietary (auto-promote based on behaviour) |
| Behavioural scoring or trust score computation | AumOS proprietary |
| Cross-protocol orchestration (GOVERNANCE_PIPELINE) | AumOS proprietary |
| Three-tier attention filters | AumOS proprietary |
| Anomaly detection or counterfactual generation | AumOS proprietary |
| Latency targets or threshold values | Internal tuning parameters |

## Forbidden Identifiers

The following identifiers must never appear anywhere in `src/` or `examples/`:

```
progressLevel
promoteLevel
computeTrustScore
behavioralScore
adaptiveBudget
optimizeBudget
predictSpending
detectAnomaly
generateCounterfactual
PersonalWorldModel
MissionAlignment
SocialTrust
CognitiveLoop
AttentionFilter
GOVERNANCE_PIPELINE
```

The CI guard `scripts/fire-line-audit.sh` enforces this list automatically.
Any PR that introduces a forbidden identifier will fail the audit.

## Dependency Constraint

Veramo and its related DID/VC toolchain packages (`@veramo/*`) are permitted as
**peer dependencies only** — they must not be added as direct runtime dependencies.
This package re-implements the specific resolution and signing primitives it needs
using `did-resolver`, `jose`, and `@noble/*` to avoid pulling the full Veramo
agent runtime into downstream bundles.

## Manual Trust Changes Only

If any storage adapter or helper function in this package needs to model trust,
the only permitted pattern is: the owner explicitly sets a trust level. Automatic
promotion, decay, or inference from behaviour is forbidden.

## Static Budget Allocation Only

If any part of this package handles resource budgets, allocation must be static
(a fixed number set by configuration). Adaptive, ML-based, or heuristic budget
adjustment is forbidden.
