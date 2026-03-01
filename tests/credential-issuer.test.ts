// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * Tests for CredentialIssuer — JWT issuance, error conditions, and
 * credential persistence to the credential store.
 *
 * CredentialIssuer requires Web Crypto API (crypto.subtle). Node.js 18+
 * provides this globally.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { CredentialIssuer } from "../src/credentials/issuer.js";
import { InMemoryDIDStore, InMemoryCredentialStore } from "../src/storage/memory.js";
import { generateKeyPair } from "../src/did/key.js";
import { buildDefaultCredentialConfig } from "../src/config.js";
import type { DIDRecord } from "../src/storage/interface.js";
import type { DIDDocument } from "did-resolver";
import type { AgentIdentityClaims, AgentCapabilityClaims, AgentDelegationClaims } from "../src/agent/types.js";

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

function buildDocument(did: string): DIDDocument {
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [],
  };
}

async function createIssuerRecord(didStore: InMemoryDIDStore): Promise<{ did: string; record: DIDRecord }> {
  const { did, privateKey, publicKey: _publicKey } = await generateKeyPair();
  const record: DIDRecord = {
    did,
    document: buildDocument(did),
    privateKey,
    alias: "test-issuer",
    method: "key",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    deactivated: false,
  };
  await didStore.create(record);
  return { did, record };
}

const agentDID = "did:key:z6MkAgentSubject";

const agentIdentityClaims: AgentIdentityClaims = {
  credentialType: "AgentIdentity",
  agentName: "TestAgent",
  agentVersion: "1.0.0",
  agentType: "worker",
  registeredAt: "2026-01-01T00:00:00.000Z",
};

const agentCapabilityClaims: AgentCapabilityClaims = {
  credentialType: "AgentCapability",
  capability: "file.read",
  description: "Read access to the filesystem",
};

const agentDelegationClaims: AgentDelegationClaims = {
  credentialType: "AgentDelegation",
  ownerDID: "did:key:z6MkOwner",
  delegationScope: "read-only",
};

// ---------------------------------------------------------------------------
// CredentialIssuer — error conditions
// ---------------------------------------------------------------------------

describe("CredentialIssuer — error conditions", () => {
  let didStore: InMemoryDIDStore;
  let credentialStore: InMemoryCredentialStore;
  let issuer: CredentialIssuer;

  beforeEach(() => {
    didStore = new InMemoryDIDStore();
    credentialStore = new InMemoryCredentialStore();
    issuer = new CredentialIssuer({
      didStore,
      credentialStore,
      config: buildDefaultCredentialConfig(),
    });
  });

  it("throws when issuer DID is not found in the local store", async () => {
    await expect(
      issuer.issue({
        issuerDID: "did:key:z6MkNotFound",
        agentDID,
        credentialType: "AgentIdentity",
        claims: agentIdentityClaims,
      })
    ).rejects.toThrow(/Issuer DID not found in local store/);
  });

  it("throws when issuer DID is deactivated", async () => {
    const { did } = await generateKeyPair();
    const record: DIDRecord = {
      did,
      document: buildDocument(did),
      privateKey: new Uint8Array(32),
      alias: "deactivated-issuer",
      method: "key",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      deactivated: true,
    };
    await didStore.create(record);
    await expect(
      issuer.issue({
        issuerDID: did,
        agentDID,
        credentialType: "AgentIdentity",
        claims: agentIdentityClaims,
      })
    ).rejects.toThrow(/deactivated/);
  });

  it("throws when issuer DID has no local private key", async () => {
    const { did } = await generateKeyPair();
    const record: DIDRecord = {
      did,
      document: buildDocument(did),
      // no privateKey
      alias: "no-key-issuer",
      method: "key",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      deactivated: false,
    };
    await didStore.create(record);
    await expect(
      issuer.issue({
        issuerDID: did,
        agentDID,
        credentialType: "AgentIdentity",
        claims: agentIdentityClaims,
      })
    ).rejects.toThrow(/no locally-held private key/);
  });
});

// ---------------------------------------------------------------------------
// CredentialIssuer — successful issuance
// ---------------------------------------------------------------------------

describe("CredentialIssuer — successful issuance", () => {
  let didStore: InMemoryDIDStore;
  let credentialStore: InMemoryCredentialStore;
  let issuer: CredentialIssuer;
  let issuerDID: string;

  beforeEach(async () => {
    didStore = new InMemoryDIDStore();
    credentialStore = new InMemoryCredentialStore();
    issuer = new CredentialIssuer({
      didStore,
      credentialStore,
      config: buildDefaultCredentialConfig(),
    });
    const result = await createIssuerRecord(didStore);
    issuerDID = result.did;
  });

  it("issues an AgentIdentity credential and returns a VerifiableCredential", async () => {
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });

    expect(vc).toBeDefined();
    expect(vc.issuerDID).toBe(issuerDID);
    expect(vc.subjectDID).toBe(agentDID);
    expect(vc.credentialType).toBe("AgentIdentity");
  });

  it("returned VC contains a compact JWT string", async () => {
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });

    // Compact JWT format: header.payload.signature
    expect(typeof vc.jwt).toBe("string");
    const parts = vc.jwt.split(".");
    expect(parts.length).toBe(3);
  });

  it("issued credential is persisted to the credential store", async () => {
    await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });

    expect(credentialStore.size).toBe(1);
    const all = await credentialStore.list();
    expect(all[0]?.issuerDID).toBe(issuerDID);
    expect(all[0]?.subjectDID).toBe(agentDID);
    expect(all[0]?.revoked).toBe(false);
  });

  it("issues an AgentCapability credential", async () => {
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentCapability",
      claims: agentCapabilityClaims,
    });

    expect(vc.credentialType).toBe("AgentCapability");
    expect(vc.issuerDID).toBe(issuerDID);
  });

  it("issues an AgentDelegation credential", async () => {
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentDelegation",
      claims: agentDelegationClaims,
    });

    expect(vc.credentialType).toBe("AgentDelegation");
    expect(vc.issuerDID).toBe(issuerDID);
  });

  it("uses provided credentialId when given", async () => {
    const customId = "urn:uuid:custom-credential-id-001";
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
      credentialId: customId,
    });

    // The credential with this ID should be in the store
    const stored = await credentialStore.get(customId);
    expect(stored).toBeDefined();
    expect(stored?.id).toBe(customId);
    expect(vc.jwt).toBeDefined();
  });

  it("auto-generates a urn:uuid credential ID when none is provided", async () => {
    await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });

    const all = await credentialStore.list();
    expect(all[0]?.id).toMatch(/^urn:uuid:/);
  });

  it("VC has an issuedAt ISO-8601 timestamp", async () => {
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });

    expect(typeof vc.issuedAt).toBe("string");
    expect(() => new Date(vc.issuedAt)).not.toThrow();
  });

  it("VC has an expiresAt when default expiry is set", async () => {
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });

    // Default expiry is 86400 seconds — expiresAt must be defined
    expect(vc.expiresAt).toBeDefined();
    expect(typeof vc.expiresAt).toBe("string");
    const issuedMs = new Date(vc.issuedAt).getTime();
    const expiresMs = new Date(vc.expiresAt!).getTime();
    expect(expiresMs).toBeGreaterThan(issuedMs);
  });

  it("VC has no expiresAt when config defaultExpirySeconds is undefined", async () => {
    const noExpiryIssuer = new CredentialIssuer({
      didStore,
      credentialStore: new InMemoryCredentialStore(),
      config: { proofAlgorithm: "EdDSA", defaultExpirySeconds: undefined },
    });
    const vc = await noExpiryIssuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });

    expect(vc.expiresAt).toBeUndefined();
  });

  it("custom expirySeconds overrides the config default", async () => {
    const vc = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
      expirySeconds: 3600,
    });

    const issuedMs = new Date(vc.issuedAt).getTime();
    const expiresMs = new Date(vc.expiresAt!).getTime();
    const diffSeconds = (expiresMs - issuedMs) / 1000;
    // Should be approximately 3600 seconds (allow small clock drift)
    expect(diffSeconds).toBeGreaterThanOrEqual(3598);
    expect(diffSeconds).toBeLessThanOrEqual(3602);
  });

  it("each issued credential has a unique ID when not provided", async () => {
    const vc1 = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentIdentity",
      claims: agentIdentityClaims,
    });
    const vc2 = await issuer.issue({
      issuerDID,
      agentDID,
      credentialType: "AgentCapability",
      claims: agentCapabilityClaims,
    });

    const stored1 = await credentialStore.list({ credentialType: "AgentIdentity" });
    const stored2 = await credentialStore.list({ credentialType: "AgentCapability" });

    expect(stored1[0]?.id).not.toBe(stored2[0]?.id);
    // VCs have distinct JWT strings
    expect(vc1.jwt).not.toBe(vc2.jwt);
  });
});
