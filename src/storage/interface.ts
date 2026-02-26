// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * Pluggable storage interface for DID documents and agent key material.
 *
 * Concrete implementations can use in-memory, Redis, Postgres, or any
 * other backend — provided they satisfy this contract.
 */

import type { DIDDocument } from "did-resolver";

// ---------------------------------------------------------------------------
// DID storage
// ---------------------------------------------------------------------------

/** A stored DID record pairing a DID document with its private key material. */
export interface DIDRecord {
  /** The DID string (primary key). */
  readonly did: string;
  /** The resolved DID document. */
  readonly document: DIDDocument;
  /** Raw Ed25519 private key bytes (32 bytes). Absent for externally controlled DIDs. */
  readonly privateKey?: Uint8Array | undefined;
  /** Human-readable alias for this DID, e.g. "my-research-agent". */
  readonly alias: string;
  /** DID method used: "key", "web", or "ethr". */
  readonly method: "key" | "web" | "ethr";
  /** ISO-8601 creation timestamp. */
  readonly createdAt: string;
  /** ISO-8601 last-updated timestamp. */
  readonly updatedAt: string;
  /** Whether this DID has been deactivated. Deactivated DIDs cannot issue credentials. */
  readonly deactivated: boolean;
}

/**
 * Pluggable store interface for {@link DIDRecord}s.
 *
 * Implementations must be thread-safe if used in concurrent environments.
 */
export interface DIDStore {
  /**
   * Persist a new DID record.
   *
   * @throws {DIDStoreError} with code `"already_exists"` if the DID is already stored.
   */
  create(record: DIDRecord): Promise<void>;

  /**
   * Retrieve a DID record by its DID string.
   *
   * @returns The record, or `undefined` when not found.
   */
  get(did: string): Promise<DIDRecord | undefined>;

  /**
   * Replace an existing DID record.
   *
   * @throws {DIDStoreError} with code `"not_found"` if the DID does not exist.
   */
  update(did: string, patch: Partial<DIDRecord>): Promise<DIDRecord>;

  /**
   * Remove a DID record from the store.
   *
   * @throws {DIDStoreError} with code `"not_found"` if the DID does not exist.
   */
  delete(did: string): Promise<void>;

  /**
   * Return all stored DID records.
   * Implementations may support pagination in future via options.
   */
  list(): Promise<readonly DIDRecord[]>;
}

// ---------------------------------------------------------------------------
// Credential storage
// ---------------------------------------------------------------------------

/** A stored Verifiable Credential record. */
export interface CredentialRecord {
  /** Opaque credential ID (typically the `id` field of the VC). */
  readonly id: string;
  /** The raw JWT string. */
  readonly jwt: string;
  /** The issuer DID. */
  readonly issuerDID: string;
  /** The subject (agent) DID. */
  readonly subjectDID: string;
  /** The credential type: AgentIdentity, AgentCapability, or AgentDelegation. */
  readonly credentialType: string;
  /** ISO-8601 issuance date. */
  readonly issuedAt: string;
  /** ISO-8601 expiry date. Absent for non-expiring credentials. */
  readonly expiresAt?: string | undefined;
  /** Whether the credential has been revoked. */
  readonly revoked: boolean;
}

/**
 * Pluggable store interface for issued {@link CredentialRecord}s.
 */
export interface CredentialStore {
  /**
   * Persist an issued credential.
   *
   * @throws {DIDStoreError} with code `"already_exists"` if the credential ID is duplicate.
   */
  create(record: CredentialRecord): Promise<void>;

  /**
   * Retrieve a credential by its ID.
   *
   * @returns The record, or `undefined` when not found.
   */
  get(id: string): Promise<CredentialRecord | undefined>;

  /**
   * List credentials, optionally filtered by issuer or subject DID.
   */
  list(filter?: {
    issuerDID?: string;
    subjectDID?: string;
    credentialType?: string;
  }): Promise<readonly CredentialRecord[]>;

  /**
   * Mark a credential as revoked.
   *
   * @throws {DIDStoreError} with code `"not_found"` if the credential does not exist.
   */
  revoke(id: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

export type DIDStoreErrorCode = "not_found" | "already_exists" | "storage_error";

/** Typed error thrown by DID and Credential store implementations. */
export class DIDStoreError extends Error {
  readonly code: DIDStoreErrorCode;

  constructor(code: DIDStoreErrorCode, message: string) {
    super(message);
    this.name = "DIDStoreError";
    this.code = code;
  }
}
