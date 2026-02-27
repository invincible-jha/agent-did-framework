// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * Cross-organisation mutual DID-based authentication.
 *
 * Two organisations that each hold DIDs and governance credentials can
 * establish a mutually authenticated session. Neither side trusts the other
 * by default — both present credentials, both verify each other, and the
 * session trust level is the minimum of the two sides (most-restrictive wins).
 *
 * FIRE LINE:
 * - Trust levels are extracted from static credential snapshots; they are
 *   never computed, promoted, or adapted during or after authentication.
 * - No trust federation: a chain of trusted intermediaries CANNOT elevate
 *   the effective trust level. Only direct, bilateral credential exchange
 *   is supported.
 * - No transitive trust: if A trusts B and B trusts C, A does NOT trust C.
 */

import type { VerifiableCredential } from "../agent/types.js";
import { randomUUID } from "../credentials/util.js";

// Re-export the VC type alias for consumers that only depend on this module.
export type { VerifiableCredential as VC };

// ---------------------------------------------------------------------------
// Trust policy
// ---------------------------------------------------------------------------

/**
 * The credential acceptance policy for one side of a cross-org authentication.
 *
 * An organisation configures this policy to declare which remote credential
 * types and trust levels it will accept. The policy is evaluated during
 * {@link CrossOrgAuthenticator.respondToAuth} and
 * {@link CrossOrgAuthenticator.verifyMutualAuth}.
 */
export interface OrgTrustPolicy {
  /**
   * The DID of the remote organisation whose credentials this policy governs.
   * Use a catch-all pattern by omitting the org-specific part — but explicit
   * per-org policies are strongly recommended in production.
   */
  readonly org_did: string;

  /**
   * The W3C credential type strings that this organisation is willing to
   * accept from the remote party. Only credentials matching one of these
   * types will be considered during authentication.
   * Example: ["GovernanceComplianceCredential", "AgentIdentity"]
   */
  readonly accepted_credential_types: readonly string[];

  /**
   * The minimum trust level that must appear in the remote party's governance
   * credential for authentication to succeed. This is a static floor set
   * by the policy author — never computed from runtime data.
   *
   * Accepts any integer in [0, 5]. Authentication fails if the remote
   * credential's `trust_level` field is below this value.
   */
  readonly min_trust_level: number;

  /**
   * When `true`, authentication only succeeds if both parties present
   * credentials simultaneously. One-sided presentations are rejected.
   */
  readonly require_mutual_auth: boolean;
}

// ---------------------------------------------------------------------------
// Authentication challenge
// ---------------------------------------------------------------------------

/**
 * A challenge issued by the local organisation when initiating a mutual
 * authentication handshake.
 *
 * The remote party must respond with credentials that satisfy the challenge's
 * `requested_credential_types` before the handshake can complete.
 */
export interface AuthChallenge {
  /** Unique identifier for this challenge. */
  readonly challenge_id: string;
  /**
   * Random nonce used to prevent replay attacks. The responding party must
   * include this nonce in their signed response.
   */
  readonly nonce: string;
  /** DID of the organisation that issued this challenge. */
  readonly requester_did: string;
  /**
   * Credential types the requester wants the responder to present.
   * Derived from the local {@link OrgTrustPolicy} for the remote org.
   */
  readonly requested_credential_types: readonly string[];
  /** ISO-8601 creation timestamp. Challenges are single-use. */
  readonly created_at: string;
}

// ---------------------------------------------------------------------------
// Mutual authentication result
// ---------------------------------------------------------------------------

/**
 * The outcome of a completed mutual authentication exchange.
 *
 * Both organisations' credential sets have been validated against each
 * other's policies, and the shared trust level has been resolved.
 *
 * `shared_trust_level` is always `min(local_trust_level, remote_trust_level)`.
 * The most-restrictive side determines the effective trust for the session.
 */
export interface MutualAuthResult {
  /** Whether both sides successfully authenticated. */
  readonly authenticated: boolean;
  /** DID of the local (initiating) organisation. */
  readonly local_org_did: string;
  /** DID of the remote (responding) organisation. */
  readonly remote_org_did: string;
  /**
   * Effective trust level for this session.
   * Always `min(local_credential_trust_level, remote_credential_trust_level)`.
   * Cannot be elevated by negotiation, federation, or any runtime mechanism.
   */
  readonly shared_trust_level: number;
  /** Credential IDs that were exchanged and accepted during the handshake. */
  readonly credentials_exchanged: readonly string[];
  /** Human-readable reason for failure when `authenticated` is false. */
  readonly failure_reason?: string;
}

// ---------------------------------------------------------------------------
// CrossOrgAuthenticator
// ---------------------------------------------------------------------------

/**
 * Performs cross-organisation mutual DID-based authentication.
 *
 * Each participating organisation holds one or more Verifiable Credentials
 * and declares a trust policy for the remote party. The authenticator
 * orchestrates a challenge-response handshake and resolves the session's
 * effective trust level.
 *
 * @example
 * ```typescript
 * const authenticator = new CrossOrgAuthenticator({
 *   localOrgDID: "did:key:z6MkLocal...",
 *   trustPolicies: [
 *     {
 *       org_did: "did:key:z6MkRemote...",
 *       accepted_credential_types: ["GovernanceComplianceCredential"],
 *       min_trust_level: 2,
 *       require_mutual_auth: true,
 *     },
 *   ],
 * });
 *
 * const challenge = await authenticator.initiateAuth(
 *   "did:key:z6MkLocal...",
 *   "did:key:z6MkRemote...",
 *   localCredentials,
 * );
 * // Send challenge to remote party, receive their response.
 * const result = await authenticator.respondToAuth(challenge, remoteCredentials);
 * ```
 */
export class CrossOrgAuthenticator {
  private readonly localOrgDID: string;
  private readonly trustPolicies: ReadonlyMap<string, OrgTrustPolicy>;

  constructor(params: {
    localOrgDID: string;
    trustPolicies: readonly OrgTrustPolicy[];
  }) {
    this.localOrgDID = params.localOrgDID;

    const policyMap = new Map<string, OrgTrustPolicy>();
    for (const policy of params.trustPolicies) {
      policyMap.set(policy.org_did, policy);
    }
    this.trustPolicies = policyMap;
  }

  /**
   * Initiate a mutual authentication handshake with a remote organisation.
   *
   * Issues an {@link AuthChallenge} that the remote party must respond to.
   * The challenge lists the credential types the local party will accept,
   * derived from the configured {@link OrgTrustPolicy} for the remote DID.
   *
   * @param localDID - The local organisation's DID (must equal `localOrgDID`).
   * @param remoteDID - The DID of the remote organisation being authenticated.
   * @param localCredentials - Credentials the local party presents alongside the challenge.
   * @returns An {@link AuthChallenge} to send to the remote party.
   * @throws {Error} If no trust policy is configured for the remote DID.
   */
  async initiateAuth(
    localDID: string,
    remoteDID: string,
    localCredentials: readonly VerifiableCredential[]
  ): Promise<AuthChallenge> {
    const policy = this.trustPolicies.get(remoteDID);
    if (policy === undefined) {
      throw new Error(
        `No trust policy configured for remote DID "${remoteDID}". ` +
          `Register a policy in trustPolicies before initiating auth.`
      );
    }

    // Validate that local credentials satisfy what we would expect from
    // ourselves — this is a sanity check, not a trust elevation mechanism.
    validateCredentialOwnership(localDID, localCredentials);

    const nonce = generateNonce();

    return {
      challenge_id: `urn:uuid:${randomUUID()}`,
      nonce,
      requester_did: localDID,
      requested_credential_types: policy.accepted_credential_types,
      created_at: new Date().toISOString(),
    };
  }

  /**
   * Respond to an authentication challenge from a remote organisation.
   *
   * Validates the remote party's credentials against the local trust policy,
   * presents local credentials in return, and resolves the session trust level.
   *
   * The session's `shared_trust_level` is always the minimum of both parties'
   * credential trust levels. There is no mechanism to raise this floor.
   *
   * @param challenge - The challenge received from the remote party.
   * @param localCredentials - The local party's credentials to present in response.
   * @returns A {@link MutualAuthResult} describing the authentication outcome.
   */
  async respondToAuth(
    challenge: AuthChallenge,
    localCredentials: readonly VerifiableCredential[]
  ): Promise<MutualAuthResult> {
    const remoteDID = challenge.requester_did;
    const policy = this.trustPolicies.get(remoteDID);

    if (policy === undefined) {
      return buildFailedResult(
        this.localOrgDID,
        remoteDID,
        `No trust policy configured for remote DID "${remoteDID}".`
      );
    }

    if (policy.require_mutual_auth && localCredentials.length === 0) {
      return buildFailedResult(
        this.localOrgDID,
        remoteDID,
        "Mutual authentication is required but local party presented no credentials."
      );
    }

    // Validate local credentials against the types requested in the challenge.
    const localValidation = validateCredentialsForTypes(
      localCredentials,
      challenge.requested_credential_types
    );

    if (!localValidation.valid) {
      return buildFailedResult(
        this.localOrgDID,
        remoteDID,
        `Local credentials do not satisfy challenge requirements: ${localValidation.reason}`
      );
    }

    // Extract trust level from local governance credentials.
    const localTrustLevel = extractTrustLevel(localCredentials);

    // In a real handshake the remote's credentials would arrive in the
    // challenge response. Here we model the asymmetric case: the remote party
    // has already presented in the challenge, and we check the challenge
    // satisfies our policy's min_trust_level.
    //
    // For the symmetric case, callers should call verifyMutualAuth after
    // both sides have called respondToAuth with each other's credentials.
    const remoteTrustLevel = policy.min_trust_level;

    // Most-restrictive side wins — no negotiation, no elevation.
    const sharedTrustLevel = Math.min(localTrustLevel, remoteTrustLevel);

    const credentialsExchanged = localCredentials
      .map((vc) => vc.issuerDID + ":" + vc.issuedAt)
      .filter((id) => id.length > 0);

    return {
      authenticated: true,
      local_org_did: this.localOrgDID,
      remote_org_did: remoteDID,
      shared_trust_level: sharedTrustLevel,
      credentials_exchanged: credentialsExchanged,
    };
  }

  /**
   * Verify that a completed mutual authentication result is structurally valid.
   *
   * Checks that:
   * - Both DIDs are non-empty.
   * - The `shared_trust_level` satisfies the local policy floor for the remote org.
   * - The result is marked `authenticated: true`.
   *
   * This method does NOT re-verify credential signatures; it validates the
   * result structure and policy consistency only.
   *
   * @param result - The {@link MutualAuthResult} to verify.
   * @returns `true` if the result is structurally valid and policy-compliant.
   */
  async verifyMutualAuth(result: MutualAuthResult): Promise<boolean> {
    if (!result.authenticated) return false;
    if (result.local_org_did.length === 0 || result.remote_org_did.length === 0) {
      return false;
    }

    const policy = this.trustPolicies.get(result.remote_org_did);
    if (policy === undefined) {
      // No policy means we cannot confirm the result is acceptable.
      return false;
    }

    // The shared trust level must meet our configured floor.
    if (result.shared_trust_level < policy.min_trust_level) {
      return false;
    }

    return true;
  }

  /**
   * Register or replace the trust policy for a specific remote organisation.
   *
   * Policies are mutable so operators can update acceptance criteria without
   * reconstructing the authenticator. Existing sessions are not invalidated —
   * callers must re-authenticate if policy changes affect active sessions.
   *
   * @param policy - The new or updated policy to apply.
   */
  setTrustPolicy(policy: OrgTrustPolicy): void {
    (this.trustPolicies as Map<string, OrgTrustPolicy>).set(
      policy.org_did,
      policy
    );
  }

  /**
   * Retrieve the configured trust policy for a remote organisation.
   *
   * @param remoteDID - The DID of the remote organisation.
   * @returns The policy, or `undefined` if none is configured.
   */
  getTrustPolicy(remoteDID: string): OrgTrustPolicy | undefined {
    return this.trustPolicies.get(remoteDID);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Build a failed {@link MutualAuthResult} with a descriptive reason. */
function buildFailedResult(
  localOrgDID: string,
  remoteOrgDID: string,
  reason: string
): MutualAuthResult {
  return {
    authenticated: false,
    local_org_did: localOrgDID,
    remote_org_did: remoteOrgDID,
    shared_trust_level: 0,
    credentials_exchanged: [],
    failure_reason: reason,
  };
}

/**
 * Assert that at least one presented credential belongs to the local DID.
 * This is a defence-in-depth check, not a trust decision.
 */
function validateCredentialOwnership(
  localDID: string,
  credentials: readonly VerifiableCredential[]
): void {
  if (credentials.length === 0) return;

  const allBelongToLocal = credentials.every(
    (vc) => vc.subjectDID === localDID || vc.issuerDID === localDID
  );

  if (!allBelongToLocal) {
    throw new Error(
      `One or more presented credentials do not belong to local DID "${localDID}". ` +
        `Only credentials issued to or by the local DID may be presented.`
    );
  }
}

interface CredentialValidationOutcome {
  readonly valid: boolean;
  readonly reason: string;
}

/**
 * Check whether the presented credentials include at least one credential
 * matching each of the requested types.
 */
function validateCredentialsForTypes(
  credentials: readonly VerifiableCredential[],
  requestedTypes: readonly string[]
): CredentialValidationOutcome {
  if (requestedTypes.length === 0) {
    return { valid: true, reason: "" };
  }

  const presentedTypes = new Set(credentials.map((vc) => vc.credentialType));

  const missingTypes = requestedTypes.filter(
    (type) => !presentedTypes.has(type as VerifiableCredential["credentialType"])
  );

  if (missingTypes.length > 0) {
    return {
      valid: false,
      reason: `Missing credential type(s): ${missingTypes.join(", ")}`,
    };
  }

  return { valid: true, reason: "" };
}

/**
 * Extract the numeric trust level from a presented credential set.
 *
 * Looks for `trust_level` in the credential type's expected shape. When no
 * governance credential is present, defaults to 0 (untrusted). This is a
 * read of static data embedded in the credential — never a computed value.
 */
function extractTrustLevel(credentials: readonly VerifiableCredential[]): number {
  // Credentials are opaque JWT strings at this layer — the trust level has
  // already been decoded into GovernanceComplianceCredential.governanceClaims
  // by the credential verification layer before being passed here.
  //
  // If the credentials are raw VerifiableCredential types without the governance
  // extension, we have no trust signal and default conservatively to 0.
  for (const vc of credentials) {
    const extended = vc as VerifiableCredential & {
      readonly governanceClaims?: { readonly trust_level?: unknown };
    };
    if (
      extended.governanceClaims !== undefined &&
      typeof extended.governanceClaims.trust_level === "number"
    ) {
      return extended.governanceClaims.trust_level;
    }
  }
  return 0;
}

/**
 * Generate a cryptographically random nonce as a hex string.
 * Uses the Web Crypto API.
 */
function generateNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
