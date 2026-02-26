// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * In-memory implementations of {@link DIDStore} and {@link CredentialStore}.
 *
 * Suitable for development, testing, and single-process deployments.
 * Data is lost when the process exits.
 */

import type {
  DIDRecord,
  DIDStore,
  CredentialRecord,
  CredentialStore,
} from "./interface.js";
import { DIDStoreError } from "./interface.js";

/**
 * Volatile in-memory DID store.
 *
 * All operations are synchronous internally but expose the standard async
 * interface to remain interchangeable with persistent backends.
 */
export class InMemoryDIDStore implements DIDStore {
  private readonly store: Map<string, DIDRecord>;

  constructor() {
    this.store = new Map();
  }

  async create(record: DIDRecord): Promise<void> {
    if (this.store.has(record.did)) {
      throw new DIDStoreError(
        "already_exists",
        `DID already stored: ${record.did}`
      );
    }
    this.store.set(record.did, deepCopyDIDRecord(record));
  }

  async get(did: string): Promise<DIDRecord | undefined> {
    const record = this.store.get(did);
    return record !== undefined ? deepCopyDIDRecord(record) : undefined;
  }

  async update(did: string, patch: Partial<DIDRecord>): Promise<DIDRecord> {
    const existing = this.store.get(did);
    if (existing === undefined) {
      throw new DIDStoreError("not_found", `DID not found: ${did}`);
    }
    const updated: DIDRecord = {
      ...existing,
      ...patch,
      did: existing.did, // DID is immutable
      updatedAt: new Date().toISOString(),
    };
    this.store.set(did, updated);
    return deepCopyDIDRecord(updated);
  }

  async delete(did: string): Promise<void> {
    if (!this.store.has(did)) {
      throw new DIDStoreError("not_found", `DID not found: ${did}`);
    }
    this.store.delete(did);
  }

  async list(): Promise<readonly DIDRecord[]> {
    return Array.from(this.store.values()).map(deepCopyDIDRecord);
  }

  /** Return the number of stored DID records. */
  get size(): number {
    return this.store.size;
  }

  /** Remove all records. Useful for test teardown. */
  clear(): void {
    this.store.clear();
  }
}

/**
 * Volatile in-memory credential store.
 */
export class InMemoryCredentialStore implements CredentialStore {
  private readonly store: Map<string, CredentialRecord>;

  constructor() {
    this.store = new Map();
  }

  async create(record: CredentialRecord): Promise<void> {
    if (this.store.has(record.id)) {
      throw new DIDStoreError(
        "already_exists",
        `Credential already stored: ${record.id}`
      );
    }
    this.store.set(record.id, Object.freeze({ ...record }));
  }

  async get(id: string): Promise<CredentialRecord | undefined> {
    return this.store.get(id);
  }

  async list(filter?: {
    issuerDID?: string;
    subjectDID?: string;
    credentialType?: string;
  }): Promise<readonly CredentialRecord[]> {
    const all = Array.from(this.store.values());
    if (filter === undefined) return all;

    return all.filter((record) => {
      if (
        filter.issuerDID !== undefined &&
        record.issuerDID !== filter.issuerDID
      ) {
        return false;
      }
      if (
        filter.subjectDID !== undefined &&
        record.subjectDID !== filter.subjectDID
      ) {
        return false;
      }
      if (
        filter.credentialType !== undefined &&
        record.credentialType !== filter.credentialType
      ) {
        return false;
      }
      return true;
    });
  }

  async revoke(id: string): Promise<void> {
    const existing = this.store.get(id);
    if (existing === undefined) {
      throw new DIDStoreError("not_found", `Credential not found: ${id}`);
    }
    this.store.set(id, Object.freeze({ ...existing, revoked: true }));
  }

  /** Return the number of stored credential records. */
  get size(): number {
    return this.store.size;
  }

  /** Remove all records. Useful for test teardown. */
  clear(): void {
    this.store.clear();
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Deep-copy a DIDRecord so that callers cannot mutate the stored value.
 * The `Uint8Array` private key is cloned to prevent external modification.
 */
function deepCopyDIDRecord(record: DIDRecord): DIDRecord {
  return {
    ...record,
    privateKey:
      record.privateKey !== undefined
        ? new Uint8Array(record.privateKey)
        : undefined,
    document: JSON.parse(JSON.stringify(record.document)) as typeof record.document,
  };
}
