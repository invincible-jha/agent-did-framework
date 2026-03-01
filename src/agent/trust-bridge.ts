// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

import type { VerifiableCredential, VerificationResult } from './types.js';

/**
 * Trust level mapping from Verifiable Credential attributes.
 *
 * Maps credential properties to a numeric trust level (0-5) that can be
 * used by the trust gate to make governance decisions.
 */
export interface TrustLevelMapping {
  /** Credential type that this mapping applies to. */
  credentialType: string;
  /** Field in the credential subject to extract the trust indicator from. */
  subjectField: string;
  /** Map of field values to trust levels (0-5). */
  valueMappings: Record<string, number>;
  /** Default trust level if no mapping matches. Defaults to 0. */
  defaultLevel?: number;
}

/**
 * Result of resolving a trust level from a Verifiable Credential.
 */
export interface TrustBridgeResult {
  /** The resolved trust level (0-5). */
  trustLevel: number;
  /** The DID of the agent. */
  agentDid: string;
  /** The credential type that was used for resolution. */
  credentialType: string;
  /** Whether the credential was verified successfully. */
  verified: boolean;
  /** The raw verification result. */
  verificationResult: VerificationResult;
  /** Timestamp of the resolution. */
  resolvedAt: string;
}

/**
 * Configuration for the DID-to-trust bridge.
 */
export interface TrustBridgeConfig {
  /** Trust level mappings for different credential types. */
  mappings: TrustLevelMapping[];
  /** Default trust level for agents without credentials. Defaults to 0 (Observer). */
  defaultTrustLevel?: number;
  /** Whether to require credential verification. Defaults to true. */
  requireVerification?: boolean;
}

/**
 * DIDTrustBridge resolves agent trust levels from Verifiable Credentials.
 *
 * When an agent presents a Verifiable Credential to the trust gate, this
 * bridge extracts trust-relevant attributes and maps them to a numeric
 * trust level that the gate can enforce.
 *
 * Trust changes through this bridge are still manual — the bridge provides
 * a recommendation based on credential attributes, not automatic promotion.
 * The calling system must explicitly call setLevel() with the bridged value.
 *
 * @example
 * ```typescript
 * import { DIDTrustBridge } from '@aumos/agent-did';
 *
 * const bridge = new DIDTrustBridge({
 *   mappings: [{
 *     credentialType: 'AgentIdentityCredential',
 *     subjectField: 'clearanceLevel',
 *     valueMappings: {
 *       'public': 1,
 *       'internal': 3,
 *       'confidential': 4,
 *     },
 *   }],
 * });
 *
 * const result = bridge.resolveTrustLevel(credential, verificationResult);
 * if (result.verified) {
 *   trustGate.setTrustLevel(result.trustLevel);
 * }
 * ```
 */
export class DIDTrustBridge {
  readonly #config: TrustBridgeConfig;

  constructor(config: TrustBridgeConfig) {
    this.#config = config;
  }

  /**
   * Resolves a trust level from a Verifiable Credential and its verification result.
   *
   * The resolution process:
   * 1. Check that the credential was verified (if requireVerification is true).
   * 2. Find a matching trust level mapping for the credential type.
   * 3. Extract the subject field value from the credential.
   * 4. Map the value to a trust level.
   *
   * @param credential - The Verifiable Credential presented by the agent.
   * @param verificationResult - The result of verifying the credential.
   * @returns A TrustBridgeResult with the resolved trust level.
   */
  resolveTrustLevel(
    credential: VerifiableCredential,
    verificationResult: VerificationResult,
  ): TrustBridgeResult {
    const agentDid = typeof credential.issuer === 'string'
      ? credential.issuer
      : (credential.issuer as { id: string }).id;

    const requireVerification = this.#config.requireVerification ?? true;

    if (requireVerification && !verificationResult.valid) {
      return {
        trustLevel: 0,
        agentDid,
        credentialType: this.#extractType(credential),
        verified: false,
        verificationResult,
        resolvedAt: new Date().toISOString(),
      };
    }

    const credentialType = this.#extractType(credential);
    const mapping = this.#config.mappings.find(
      (m) => m.credentialType === credentialType,
    );

    if (mapping === undefined) {
      return {
        trustLevel: this.#config.defaultTrustLevel ?? 0,
        agentDid,
        credentialType,
        verified: verificationResult.valid,
        verificationResult,
        resolvedAt: new Date().toISOString(),
      };
    }

    const subject = credential.credentialSubject;
    const fieldValue = typeof subject === 'object' && subject !== null
      ? String((subject as Record<string, unknown>)[mapping.subjectField] ?? '')
      : '';

    const trustLevel = mapping.valueMappings[fieldValue] ?? mapping.defaultLevel ?? 0;

    return {
      trustLevel: Math.min(5, Math.max(0, trustLevel)),
      agentDid,
      credentialType,
      verified: verificationResult.valid,
      verificationResult,
      resolvedAt: new Date().toISOString(),
    };
  }

  /**
   * Resolves trust levels from multiple credentials, returning the highest.
   *
   * When an agent presents multiple credentials, the bridge evaluates each
   * and returns the one that grants the highest trust level.
   *
   * @param credentials - Array of (credential, verificationResult) pairs.
   * @returns The TrustBridgeResult with the highest trust level.
   */
  resolveHighestTrustLevel(
    credentials: ReadonlyArray<{
      credential: VerifiableCredential;
      verificationResult: VerificationResult;
    }>,
  ): TrustBridgeResult | undefined {
    if (credentials.length === 0) return undefined;

    let best: TrustBridgeResult | undefined;

    for (const { credential, verificationResult } of credentials) {
      const result = this.resolveTrustLevel(credential, verificationResult);
      if (best === undefined || result.trustLevel > best.trustLevel) {
        best = result;
      }
    }

    return best;
  }

  #extractType(credential: VerifiableCredential): string {
    if (Array.isArray(credential.type)) {
      const filtered = credential.type.filter((t: string) => t !== 'VerifiableCredential');
      return filtered[0] ?? 'VerifiableCredential';
    }
    return typeof credential.type === 'string' ? credential.type : 'VerifiableCredential';
  }
}
