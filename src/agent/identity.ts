// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * AgentDIDIdentity — wraps a DID document with agent-specific helpers.
 *
 * This is the primary object returned when a new agent DID is created.
 * It provides convenient access to key material and document structure
 * without exposing raw cryptographic primitives unnecessarily.
 */

import type { DIDDocument } from "did-resolver";
import type { DIDMethod, AgentDIDSummary, AgentIdentityClaims } from "./types.js";
import { buildAgentDIDSummary } from "./types.js";

/**
 * Represents a fully-initialised agent DID identity.
 *
 * Instances are created exclusively by {@link AgentDIDManager.createAgentDID}.
 * The private key is held in memory for the lifetime of this object and is
 * never serialised automatically.
 */
export class AgentDIDIdentity {
  /** The fully-qualified DID string, e.g. `did:key:z6Mk...`. */
  readonly did: string;

  /** The resolved DID document for this identity. */
  readonly document: DIDDocument;

  /** Human-readable alias assigned at creation time. */
  readonly alias: string;

  /** DID method used. */
  readonly method: DIDMethod;

  /** ISO-8601 timestamp when this identity was created. */
  readonly createdAt: string;

  /** Whether this identity has been deactivated. */
  readonly deactivated: boolean;

  /**
   * Raw Ed25519 private key bytes (32 bytes).
   * Present for `did:key` identities created locally.
   * `undefined` for externally-managed identities (e.g. did:web, did:ethr).
   */
  private readonly _privateKey: Uint8Array | undefined;

  /** @internal — use {@link AgentDIDManager.createAgentDID} to construct. */
  constructor(params: {
    did: string;
    document: DIDDocument;
    alias: string;
    method: DIDMethod;
    createdAt: string;
    deactivated: boolean;
    privateKey?: Uint8Array | undefined;
  }) {
    this.did = params.did;
    this.document = params.document;
    this.alias = params.alias;
    this.method = params.method;
    this.createdAt = params.createdAt;
    this.deactivated = params.deactivated;
    this._privateKey = params.privateKey;
  }

  // ---------------------------------------------------------------------------
  // Key access
  // ---------------------------------------------------------------------------

  /**
   * Whether this identity has a locally-held private key.
   * Always `true` for `did:key`; may be `false` for `did:web` / `did:ethr`.
   */
  get hasLocalKey(): boolean {
    return this._privateKey !== undefined;
  }

  /**
   * Retrieve a copy of the private key bytes.
   *
   * @throws {Error} If no local private key is available.
   */
  exportPrivateKey(): Uint8Array {
    if (this._privateKey === undefined) {
      throw new Error(
        `AgentDIDIdentity "${this.did}" has no locally-held private key. ` +
          `did:web and did:ethr identities are managed externally.`
      );
    }
    return new Uint8Array(this._privateKey);
  }

  // ---------------------------------------------------------------------------
  // Document helpers
  // ---------------------------------------------------------------------------

  /**
   * Return the IDs of all verification methods listed in the DID document.
   */
  get verificationMethodIds(): readonly string[] {
    return (
      this.document.verificationMethod?.map((vm) =>
        typeof vm === "string" ? vm : vm.id
      ) ?? []
    );
  }

  /**
   * Return the first authentication key ID, or `undefined` if none.
   */
  get primaryAuthenticationKeyId(): string | undefined {
    const auth = this.document.authentication;
    if (auth === undefined || auth.length === 0) return undefined;
    const first = auth[0];
    if (first === undefined) return undefined;
    return typeof first === "string" ? first : first.id;
  }

  /**
   * Build the agent-facing summary view of this identity.
   */
  toSummary(): AgentDIDSummary {
    return buildAgentDIDSummary(
      this.document,
      this.alias,
      this.method,
      this.createdAt,
      this.deactivated
    );
  }

  /**
   * Produce a minimal set of `AgentIdentity` claims for use in credential issuance.
   *
   * @param agentType - Operator-assigned type tag, e.g. `"assistant"`.
   * @param agentVersion - Software version string.
   */
  toIdentityClaims(
    agentType: string,
    agentVersion: string
  ): AgentIdentityClaims {
    return {
      credentialType: "AgentIdentity",
      agentName: this.alias,
      agentVersion,
      agentType,
      registeredAt: this.createdAt,
    };
  }

  // ---------------------------------------------------------------------------
  // Serialisation
  // ---------------------------------------------------------------------------

  /**
   * Return a JSON-safe representation of this identity.
   * Private key bytes are intentionally excluded.
   */
  toJSON(): Record<string, unknown> {
    return {
      did: this.did,
      alias: this.alias,
      method: this.method,
      createdAt: this.createdAt,
      deactivated: this.deactivated,
      document: this.document,
      hasLocalKey: this.hasLocalKey,
    };
  }

  toString(): string {
    return `AgentDIDIdentity(${this.did}, alias="${this.alias}", method=${this.method})`;
  }
}
