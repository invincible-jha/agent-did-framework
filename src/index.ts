// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * @aumos/agent-did — W3C Decentralized Identifiers and Verifiable Credentials
 * for AI agent trust attestation.
 *
 * Public API surface. Everything else is internal.
 *
 * @example
 * ```typescript
 * import { AgentDIDManager } from "@aumos/agent-did";
 *
 * const manager = new AgentDIDManager();
 * const identity = await manager.createAgentDID({
 *   method: "did:key",
 *   agentAlias: "my-agent",
 * });
 * ```
 */

// ---------------------------------------------------------------------------
// Primary facade
// ---------------------------------------------------------------------------
export { AgentDIDManager } from "./agent/manager.js";
export type { AgentDIDManagerOptions } from "./agent/manager.js";

// ---------------------------------------------------------------------------
// Agent identity
// ---------------------------------------------------------------------------
export { AgentDIDIdentity } from "./agent/identity.js";

// ---------------------------------------------------------------------------
// Agent types
// ---------------------------------------------------------------------------
export type {
  DIDMethod,
  CreateAgentDIDOptions,
  AgentCredentialType,
  IssueCredentialOptions,
  AgentIdentityClaims,
  AgentCapabilityClaims,
  AgentDelegationClaims,
  VerificationResult,
  VerifiableCredential,
  VerifiablePresentation,
  AgentDIDSummary,
} from "./agent/types.js";
export { buildAgentDIDSummary } from "./agent/types.js";

// ---------------------------------------------------------------------------
// DID providers
// ---------------------------------------------------------------------------
export { KeyDIDProvider, generateKeyPair, publicKeyToDid, publicKeyFromDid } from "./did/key.js";
export type { GeneratedKeyPair } from "./did/key.js";

export { WebDIDProvider, didToHttpUrl } from "./did/web.js";
export type { WebDIDProviderOptions } from "./did/web.js";

export { EthrDIDProvider } from "./did/ethr.js";
export type {
  EthrDIDProviderOptions,
  EthereumNetworkConfig,
} from "./did/ethr.js";

// ---------------------------------------------------------------------------
// Universal resolver
// ---------------------------------------------------------------------------
export { UniversalResolver } from "./did/resolver.js";
export type {
  DIDMethodResolver,
  UniversalResolverOptions,
  DIDDocument,
  DIDResolutionResult,
} from "./did/resolver.js";

// ---------------------------------------------------------------------------
// Credential components (for advanced/custom use)
// ---------------------------------------------------------------------------
export { CredentialIssuer } from "./credentials/issuer.js";
export { CredentialVerifier } from "./credentials/verifier.js";
export { PresentationBuilder } from "./credentials/presentation.js";
export type { BuildPresentationOptions } from "./credentials/presentation.js";

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------
export { InMemoryDIDStore, InMemoryCredentialStore } from "./storage/memory.js";
export type {
  DIDStore,
  CredentialStore,
  DIDRecord,
  CredentialRecord,
  DIDStoreErrorCode,
} from "./storage/interface.js";
export { DIDStoreError } from "./storage/interface.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
export type {
  FrameworkConfig,
  CredentialConfig,
  ResolverConfig,
  ProofAlgorithm,
} from "./config.js";
export {
  buildDefaultCredentialConfig,
  buildDefaultResolverConfig,
} from "./config.js";

// ---------------------------------------------------------------------------
// Governance Verifiable Credentials
// ---------------------------------------------------------------------------
export { GovernanceVCIssuer, GovernanceVCVerifier } from "./credentials/governance-vc.js";
export type {
  GovernanceComplianceCredential,
  GovernanceClaimSet,
  GovernanceFramework,
  ConformanceLevel,
  CheckResult,
  GovernanceCheckName,
  VerificationResult as GovernanceVerificationResult,
} from "./credentials/governance-vc.js";

// ---------------------------------------------------------------------------
// Trust bridge (DID → Trust Gate)
// ---------------------------------------------------------------------------
export { DIDTrustBridge } from './agent/trust-bridge.js';
export type {
  TrustLevelMapping,
  TrustBridgeResult,
  TrustBridgeConfig,
} from './agent/trust-bridge.js';

// ---------------------------------------------------------------------------
// Cross-organisation mutual authentication
// ---------------------------------------------------------------------------
export { CrossOrgAuthenticator } from "./auth/cross-org.js";
export type {
  OrgTrustPolicy,
  AuthChallenge,
  MutualAuthResult,
} from "./auth/cross-org.js";

// ---------------------------------------------------------------------------
// Audit trail non-repudiation
// ---------------------------------------------------------------------------
export { NonRepudiationSigner, NonRepudiationChain, exportForCompliance } from "./audit/non-repudiation.js";
export type {
  AuditEntry,
  SignedAuditEntry,
  ChainVerificationResult,
} from "./audit/non-repudiation.js";
