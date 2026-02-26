// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * Agent-specific DID types used throughout the framework.
 */

import type { DIDDocument } from "did-resolver";

// ---------------------------------------------------------------------------
// DID method discriminant
// ---------------------------------------------------------------------------

/** The three supported DID methods. */
export type DIDMethod = "did:key" | "did:web" | "did:ethr";

// ---------------------------------------------------------------------------
// Agent creation options
// ---------------------------------------------------------------------------

/**
 * Options for creating a new agent DID identity.
 */
export interface CreateAgentDIDOptions {
  /** Which DID method to use for this agent. */
  readonly method: DIDMethod;
  /**
   * Human-readable alias for this agent (stored locally — not published in
   * the DID document). Must be unique within the local store.
   */
  readonly agentAlias: string;
  /**
   * For `did:web` only — the domain and optional path under which the DID
   * document will be hosted. Example: `"example.com:agents:my-agent"`.
   */
  readonly webDomain?: string | undefined;
  /**
   * For `did:ethr` only — the Ethereum address to use as the DID subject.
   * Example: `"0xabc123..."`.
   */
  readonly ethrAddress?: string | undefined;
}

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

/**
 * The three generic agent credential types.
 *
 * These are W3C Verifiable Credential types — not AumOS-specific.
 */
export type AgentCredentialType =
  | "AgentIdentity"
  | "AgentCapability"
  | "AgentDelegation";

/**
 * Options for issuing an agent Verifiable Credential.
 */
export interface IssueCredentialOptions {
  /** DID of the issuing party. Must be present in the local DID store. */
  readonly issuerDID: string;
  /** DID of the agent being attested. */
  readonly agentDID: string;
  /** The type of credential to issue. */
  readonly credentialType: AgentCredentialType;
  /**
   * Credential-specific claims.
   * These must conform to the corresponding JSON schema in `src/credentials/schemas/`.
   */
  readonly claims: AgentIdentityClaims | AgentCapabilityClaims | AgentDelegationClaims;
  /**
   * Proof format. Only `"jwt"` is supported in this version.
   * @defaultValue `"jwt"`
   */
  readonly proofFormat?: "jwt";
  /**
   * Optional credential expiry in seconds from now.
   * Overrides the framework default.
   */
  readonly expirySeconds?: number | undefined;
  /**
   * Optional credential ID (URI). Auto-generated via `urn:uuid:` if absent.
   */
  readonly credentialId?: string | undefined;
}

// ---------------------------------------------------------------------------
// Claim shapes — one per credential type
// ---------------------------------------------------------------------------

/**
 * Claims for an `AgentIdentity` credential.
 * Attests that the subject DID belongs to an AI agent.
 */
export interface AgentIdentityClaims {
  readonly credentialType: "AgentIdentity";
  /**
   * A display name for the agent. May be shown in UIs.
   */
  readonly agentName: string;
  /**
   * The agent's software version string. Semver preferred.
   */
  readonly agentVersion: string;
  /**
   * Opaque agent type tag chosen by the operator.
   * Examples: "assistant", "worker", "orchestrator".
   */
  readonly agentType: string;
  /**
   * ISO-8601 timestamp of when the agent was first registered.
   */
  readonly registeredAt: string;
}

/**
 * Claims for an `AgentCapability` credential.
 * Attests that the subject agent is authorised to perform a named capability.
 */
export interface AgentCapabilityClaims {
  readonly credentialType: "AgentCapability";
  /**
   * The capability name. Dot-namespaced convention is recommended.
   * Examples: "file.read", "api.call.openai", "database.query".
   */
  readonly capability: string;
  /**
   * Human-readable description of what this capability grants.
   */
  readonly description: string;
  /**
   * Optional list of resource URIs this capability applies to.
   * Absent means the capability is resource-agnostic.
   */
  readonly resourceScope?: readonly string[] | undefined;
}

/**
 * Claims for an `AgentDelegation` credential.
 * Attests that the subject agent is authorised to act on behalf of the owner.
 */
export interface AgentDelegationClaims {
  readonly credentialType: "AgentDelegation";
  /**
   * DID of the human or organisational owner granting the delegation.
   */
  readonly ownerDID: string;
  /**
   * The scope of the delegation.
   * Examples: "read-only", "admin", "scoped:invoice.create".
   */
  readonly delegationScope: string;
  /**
   * Optional list of specific capabilities the delegation covers.
   * When absent, the delegation scope applies broadly.
   */
  readonly delegatedCapabilities?: readonly string[] | undefined;
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/**
 * Result returned by `AgentDIDManager.verifyCredential`.
 */
export interface VerificationResult {
  /** Whether the credential signature, expiry, and schema are all valid. */
  readonly valid: boolean;
  /** DID of the issuer. Populated even when `valid` is false. */
  readonly issuer: string;
  /** ISO-8601 expiry timestamp, or undefined for non-expiring credentials. */
  readonly expiry: string | undefined;
  /**
   * Decoded credential claims. Present when `valid` is true; may be partial
   * or absent when `valid` is false.
   */
  readonly claims:
    | AgentIdentityClaims
    | AgentCapabilityClaims
    | AgentDelegationClaims
    | undefined;
  /** Human-readable reason for failure. Empty string on success. */
  readonly failureReason: string;
}

// ---------------------------------------------------------------------------
// Verifiable Credential / Presentation shapes
// ---------------------------------------------------------------------------

/**
 * A W3C Verifiable Credential in JWT-based compact serialisation.
 * The opaque JWT string is the canonical form used by this framework.
 */
export interface VerifiableCredential {
  /** Compact JWT string: `<header>.<payload>.<signature>`. */
  readonly jwt: string;
  /** Decoded issuer DID — extracted from the JWT payload without full verification. */
  readonly issuerDID: string;
  /** Decoded subject DID. */
  readonly subjectDID: string;
  /** Credential type. */
  readonly credentialType: AgentCredentialType;
  /** ISO-8601 issuance date. */
  readonly issuedAt: string;
  /** ISO-8601 expiry date, or undefined. */
  readonly expiresAt: string | undefined;
}

/**
 * A W3C Verifiable Presentation wrapping one or more Verifiable Credentials.
 */
export interface VerifiablePresentation {
  /** Compact JWT string for the presentation envelope. */
  readonly jwt: string;
  /** DID of the holder presenting the credentials. */
  readonly holderDID: string;
  /** The credentials bundled inside this presentation. */
  readonly credentials: readonly VerifiableCredential[];
  /** ISO-8601 creation timestamp. */
  readonly createdAt: string;
}

// ---------------------------------------------------------------------------
// DID document summary (agent-facing view)
// ---------------------------------------------------------------------------

/**
 * Slimmed-down view of a DID document used within the agent layer.
 * The full {@link DIDDocument} is always available from the manager.
 */
export interface AgentDIDSummary {
  readonly did: string;
  readonly method: DIDMethod;
  readonly alias: string;
  readonly deactivated: boolean;
  readonly createdAt: string;
  /** Public key IDs listed in the DID document verification methods. */
  readonly verificationMethodIds: readonly string[];
}

/**
 * Extract a summary from a full DID document and local metadata.
 */
export function buildAgentDIDSummary(
  document: DIDDocument,
  alias: string,
  method: DIDMethod,
  createdAt: string,
  deactivated: boolean
): AgentDIDSummary {
  const verificationMethodIds =
    document.verificationMethod?.map((vm) =>
      typeof vm === "string" ? vm : vm.id
    ) ?? [];

  return {
    did: document.id,
    method,
    alias,
    deactivated,
    createdAt,
    verificationMethodIds,
  };
}
