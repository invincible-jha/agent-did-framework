# Claude Instructions — @aumos/agent-did

## Package Identity

- npm package: `@aumos/agent-did`
- License: BSL 1.1 (Business Source License 1.1)
- Language: TypeScript 5.4+
- Node.js minimum: 18.0.0
- Repository: https://github.com/aumos-ai/agent-did-framework

## Build Commands

```sh
# Install dependencies
npm install

# Compile CJS + ESM bundles and type declarations
npm run build

# Type-check without emitting
npm run typecheck

# Lint (zero warnings allowed)
npm run lint

# Auto-fix lint issues
npm run lint:fix

# Format source
npm run format

# Check formatting without writing
npm run format:check
```

## Source Layout

```
src/
  index.ts               Public API surface (single entry point)
  config.ts              FrameworkConfig and default factories
  agent/
    manager.ts           AgentDIDManager — primary facade
    identity.ts          AgentDIDIdentity value object
    types.ts             All agent-layer TypeScript types
  did/
    key.ts               did:key provider (Ed25519, self-contained)
    web.ts               did:web provider (HTTPS fetch)
    ethr.ts              did:ethr provider (ERC-1056, optional)
    resolver.ts          UniversalResolver with pluggable providers + cache
  credentials/
    issuer.ts            CredentialIssuer (JWT/EdDSA signing)
    verifier.ts          CredentialVerifier (signature + expiry + schema)
    presentation.ts      PresentationBuilder (VP assembly)
    util.ts              Internal utilities (UUID generation)
    schemas/
      agent-identity.json
      agent-capability.json
      agent-delegation.json
  storage/
    interface.ts         DIDStore and CredentialStore interfaces
    memory.ts            In-memory implementations
examples/
  basic-agent-did.ts
  verify-agent-credential.ts
  delegation-chain.ts
docs/
  architecture.md
  did-methods.md
  credential-schemas.md
  veramo-integration.md
scripts/
  fire-line-audit.sh
```

## Code Style

- TypeScript strict mode — no `any`, no type assertions without comments
- Named exports everywhere — no default exports
- Functional patterns preferred over class hierarchies
- Every public function has a TSDoc comment with at least one `@example`
- Every source file starts with the license header:

```typescript
// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation
```

## Fire Line

Read [FIRE_LINE.md](FIRE_LINE.md) before making any changes. The forbidden identifier
list is enforced by `scripts/fire-line-audit.sh` in CI. If you introduce any of those
identifiers, the audit will fail and the PR will be blocked.

Key rules:
- No trust scoring, behavioural analysis, or adaptive budget logic
- No ZK proofs, ERC-8004, or on-chain writes
- No AumOS-proprietary schemas in the three generic VC types
- Veramo packages are peer dependencies only — do not add them to `dependencies`

## Commit Convention

```
feat(agent-did): description
fix(agent-did): description
docs(agent-did): description
test(agent-did): description
chore(agent-did): description
```

Commit messages explain WHY, not WHAT.
