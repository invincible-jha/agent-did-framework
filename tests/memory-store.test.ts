// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * Tests for InMemoryDIDStore and InMemoryCredentialStore.
 *
 * These stores are the primary implementation used during development and
 * testing. Tests exercise all CRUD operations and error conditions.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryDIDStore, InMemoryCredentialStore } from "../src/storage/memory.js";
import { DIDStoreError } from "../src/storage/interface.js";
import type { DIDRecord, CredentialRecord } from "../src/storage/interface.js";
import type { DIDDocument } from "did-resolver";

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

function makeDocument(did: string): DIDDocument {
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [],
  };
}

function makeDIDRecord(did: string, alias: string = "test-agent"): DIDRecord {
  return {
    did,
    document: makeDocument(did),
    alias,
    method: "key",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    deactivated: false,
  };
}

function makeCredentialRecord(id: string, issuerDID: string, subjectDID: string): CredentialRecord {
  return {
    id,
    jwt: `header.payload.signature-${id}`,
    issuerDID,
    subjectDID,
    credentialType: "AgentIdentity",
    issuedAt: "2026-01-01T00:00:00.000Z",
    revoked: false,
  };
}

// ---------------------------------------------------------------------------
// InMemoryDIDStore
// ---------------------------------------------------------------------------

describe("InMemoryDIDStore", () => {
  let store: InMemoryDIDStore;

  beforeEach(() => {
    store = new InMemoryDIDStore();
  });

  it("starts empty", () => {
    expect(store.size).toBe(0);
  });

  it("creates a record and reports size 1", async () => {
    const record = makeDIDRecord("did:key:z6MkAgent1");
    await store.create(record);
    expect(store.size).toBe(1);
  });

  it("retrieves a created record by DID", async () => {
    const record = makeDIDRecord("did:key:z6MkAgent1");
    await store.create(record);
    const retrieved = await store.get("did:key:z6MkAgent1");
    expect(retrieved).toBeDefined();
    expect(retrieved?.did).toBe("did:key:z6MkAgent1");
    expect(retrieved?.alias).toBe("test-agent");
  });

  it("returns undefined when DID is not found", async () => {
    const result = await store.get("did:key:z6MkNonExistent");
    expect(result).toBeUndefined();
  });

  it("throws DIDStoreError with already_exists when creating a duplicate DID", async () => {
    const record = makeDIDRecord("did:key:z6MkDuplicate");
    await store.create(record);
    await expect(store.create(record)).rejects.toThrow(DIDStoreError);
    await expect(store.create(record)).rejects.toMatchObject({ code: "already_exists" });
  });

  it("updates an existing record and returns the updated record", async () => {
    const record = makeDIDRecord("did:key:z6MkAgent1");
    await store.create(record);
    const updated = await store.update("did:key:z6MkAgent1", { alias: "renamed-agent" });
    expect(updated.alias).toBe("renamed-agent");
    // DID must remain immutable
    expect(updated.did).toBe("did:key:z6MkAgent1");
  });

  it("update throws DIDStoreError with not_found for unknown DID", async () => {
    await expect(
      store.update("did:key:z6MkUnknown", { alias: "new-alias" })
    ).rejects.toThrow(DIDStoreError);
    await expect(
      store.update("did:key:z6MkUnknown", { alias: "new-alias" })
    ).rejects.toMatchObject({ code: "not_found" });
  });

  it("update does not change the DID even when patch includes did", async () => {
    const record = makeDIDRecord("did:key:z6MkAgent1");
    await store.create(record);
    // Patch with a did field — should be ignored (DID is immutable per implementation)
    const updated = await store.update("did:key:z6MkAgent1", {
      did: "did:key:z6MkShouldNotChange",
      alias: "patched",
    } as Partial<DIDRecord>);
    // DID must not change
    expect(updated.did).toBe("did:key:z6MkAgent1");
    expect(updated.alias).toBe("patched");
  });

  it("deletes a record and size decreases", async () => {
    const record = makeDIDRecord("did:key:z6MkAgent1");
    await store.create(record);
    await store.delete("did:key:z6MkAgent1");
    expect(store.size).toBe(0);
    expect(await store.get("did:key:z6MkAgent1")).toBeUndefined();
  });

  it("delete throws DIDStoreError with not_found for unknown DID", async () => {
    await expect(store.delete("did:key:z6MkUnknown")).rejects.toThrow(DIDStoreError);
    await expect(store.delete("did:key:z6MkUnknown")).rejects.toMatchObject({ code: "not_found" });
  });

  it("lists all records", async () => {
    await store.create(makeDIDRecord("did:key:z6MkA", "agent-a"));
    await store.create(makeDIDRecord("did:key:z6MkB", "agent-b"));
    const all = await store.list();
    expect(all.length).toBe(2);
  });

  it("list returns empty array when store is empty", async () => {
    const all = await store.list();
    expect(all).toEqual([]);
  });

  it("clear removes all records", async () => {
    await store.create(makeDIDRecord("did:key:z6MkA"));
    await store.create(makeDIDRecord("did:key:z6MkB"));
    store.clear();
    expect(store.size).toBe(0);
  });

  it("returned records are deep copies — mutating them does not affect store", async () => {
    const record = makeDIDRecord("did:key:z6MkAgent1");
    await store.create(record);
    const retrieved = await store.get("did:key:z6MkAgent1");
    // Mutate the retrieved record's document
    if (retrieved !== undefined) {
      (retrieved.document as { id: string }).id = "tampered";
    }
    const refetched = await store.get("did:key:z6MkAgent1");
    expect(refetched?.document.id).toBe("did:key:z6MkAgent1");
  });

  it("private key bytes are deep-copied — mutation does not affect store", async () => {
    const privateKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
      13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
    const record: DIDRecord = {
      ...makeDIDRecord("did:key:z6MkWithKey"),
      privateKey,
    };
    await store.create(record);
    const retrieved = await store.get("did:key:z6MkWithKey");
    // Mutate the retrieved private key
    if (retrieved?.privateKey !== undefined) {
      retrieved.privateKey[0] = 0xff;
    }
    const refetched = await store.get("did:key:z6MkWithKey");
    expect(refetched?.privateKey?.[0]).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// InMemoryCredentialStore
// ---------------------------------------------------------------------------

describe("InMemoryCredentialStore", () => {
  let store: InMemoryCredentialStore;
  const issuerDID = "did:key:z6MkIssuer";
  const subjectDID = "did:key:z6MkSubject";

  beforeEach(() => {
    store = new InMemoryCredentialStore();
  });

  it("starts empty", () => {
    expect(store.size).toBe(0);
  });

  it("creates a credential and reports size 1", async () => {
    const record = makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID);
    await store.create(record);
    expect(store.size).toBe(1);
  });

  it("retrieves a credential by ID", async () => {
    const record = makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID);
    await store.create(record);
    const retrieved = await store.get("urn:uuid:001");
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe("urn:uuid:001");
    expect(retrieved?.issuerDID).toBe(issuerDID);
  });

  it("returns undefined for unknown credential ID", async () => {
    const result = await store.get("urn:uuid:nonexistent");
    expect(result).toBeUndefined();
  });

  it("throws DIDStoreError with already_exists for duplicate credential ID", async () => {
    const record = makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID);
    await store.create(record);
    await expect(store.create(record)).rejects.toThrow(DIDStoreError);
    await expect(store.create(record)).rejects.toMatchObject({ code: "already_exists" });
  });

  it("lists all credentials when no filter is applied", async () => {
    await store.create(makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID));
    await store.create(makeCredentialRecord("urn:uuid:002", issuerDID, subjectDID));
    const all = await store.list();
    expect(all.length).toBe(2);
  });

  it("list returns empty array for empty store", async () => {
    const all = await store.list();
    expect(all).toEqual([]);
  });

  it("filters by issuerDID", async () => {
    const otherIssuer = "did:key:z6MkOtherIssuer";
    await store.create(makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID));
    await store.create(makeCredentialRecord("urn:uuid:002", otherIssuer, subjectDID));
    const filtered = await store.list({ issuerDID });
    expect(filtered.length).toBe(1);
    expect(filtered[0]?.issuerDID).toBe(issuerDID);
  });

  it("filters by subjectDID", async () => {
    const otherSubject = "did:key:z6MkOtherSubject";
    await store.create(makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID));
    await store.create(makeCredentialRecord("urn:uuid:002", issuerDID, otherSubject));
    const filtered = await store.list({ subjectDID });
    expect(filtered.length).toBe(1);
    expect(filtered[0]?.subjectDID).toBe(subjectDID);
  });

  it("filters by credentialType", async () => {
    const record1 = makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID);
    const record2: CredentialRecord = {
      ...makeCredentialRecord("urn:uuid:002", issuerDID, subjectDID),
      credentialType: "AgentCapability",
    };
    await store.create(record1);
    await store.create(record2);
    const filtered = await store.list({ credentialType: "AgentCapability" });
    expect(filtered.length).toBe(1);
    expect(filtered[0]?.credentialType).toBe("AgentCapability");
  });

  it("revokes an existing credential", async () => {
    const record = makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID);
    await store.create(record);
    await store.revoke("urn:uuid:001");
    const retrieved = await store.get("urn:uuid:001");
    expect(retrieved?.revoked).toBe(true);
  });

  it("revoke throws DIDStoreError with not_found for unknown credential", async () => {
    await expect(store.revoke("urn:uuid:nonexistent")).rejects.toThrow(DIDStoreError);
    await expect(store.revoke("urn:uuid:nonexistent")).rejects.toMatchObject({ code: "not_found" });
  });

  it("clear removes all credentials", async () => {
    await store.create(makeCredentialRecord("urn:uuid:001", issuerDID, subjectDID));
    store.clear();
    expect(store.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// DIDStoreError
// ---------------------------------------------------------------------------

describe("DIDStoreError", () => {
  it("has name 'DIDStoreError'", () => {
    const error = new DIDStoreError("not_found", "test message");
    expect(error.name).toBe("DIDStoreError");
  });

  it("stores the error code", () => {
    const error = new DIDStoreError("already_exists", "already exists");
    expect(error.code).toBe("already_exists");
  });

  it("is an instance of Error", () => {
    const error = new DIDStoreError("storage_error", "storage failure");
    expect(error).toBeInstanceOf(Error);
  });
});
