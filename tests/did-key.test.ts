// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * Tests for the did:key provider — key generation, DID derivation, and
 * sign/verify round-trips using Ed25519.
 */

import { describe, it, expect } from "vitest";
import {
  generateKeyPair,
  publicKeyToDid,
  publicKeyFromDid,
  signWithKey,
  verifyKeySignature,
  KeyDIDProvider,
} from "../src/did/key.js";

// ---------------------------------------------------------------------------
// generateKeyPair
// ---------------------------------------------------------------------------

describe("generateKeyPair", () => {
  it("returns a DID string starting with did:key:", async () => {
    const { did } = await generateKeyPair();
    expect(did).toMatch(/^did:key:/);
  });

  it("DID contains base58btc multibase prefix z", async () => {
    const { did } = await generateKeyPair();
    const keyPart = did.slice("did:key:".length);
    // Base58btc multibase prefix is 'z'
    expect(keyPart.startsWith("z")).toBe(true);
  });

  it("returns 32-byte public and private keys", async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(32);
  });

  it("generates unique DIDs on every call", async () => {
    const first = await generateKeyPair();
    const second = await generateKeyPair();
    expect(first.did).not.toBe(second.did);
  });

  it("public key encoded in the DID matches the returned publicKey", async () => {
    const { did, publicKey } = await generateKeyPair();
    const recovered = publicKeyFromDid(did);
    expect(recovered).toEqual(publicKey);
  });
});

// ---------------------------------------------------------------------------
// publicKeyToDid / publicKeyFromDid round-trip
// ---------------------------------------------------------------------------

describe("publicKeyToDid and publicKeyFromDid", () => {
  it("round-trips: encode then decode returns the original bytes", async () => {
    const { publicKey } = await generateKeyPair();
    const did = publicKeyToDid(publicKey);
    const recovered = publicKeyFromDid(did);
    expect(recovered).toEqual(publicKey);
  });

  it("different public keys produce different DIDs", async () => {
    const first = await generateKeyPair();
    const second = await generateKeyPair();
    expect(publicKeyToDid(first.publicKey)).not.toBe(publicKeyToDid(second.publicKey));
  });

  it("publicKeyFromDid accepts a full did:key: URI", async () => {
    const { did, publicKey } = await generateKeyPair();
    const recovered = publicKeyFromDid(did);
    expect(recovered).toEqual(publicKey);
  });

  it("publicKeyFromDid accepts just the key part without did:key: prefix", async () => {
    const { did, publicKey } = await generateKeyPair();
    const keyPart = did.slice("did:key:".length);
    const recovered = publicKeyFromDid(keyPart);
    expect(recovered).toEqual(publicKey);
  });

  it("throws Error for DID with unsupported multicodec prefix", () => {
    // Construct a fake DID with a non-Ed25519 prefix by encoding different bytes
    // We pass a raw string that won't decode to 0xed 0x01
    // Using a minimal invalid base58 payload that would decode to wrong prefix
    expect(() => publicKeyFromDid("did:key:zinvalidprefixXXXXXXXXXXXXXXXXXXXXXXX")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// signWithKey / verifyKeySignature
// ---------------------------------------------------------------------------

describe("signWithKey and verifyKeySignature", () => {
  it("verifies a valid signature as true", async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const payload = new TextEncoder().encode("hello agent");
    const signature = await signWithKey(payload, privateKey);
    const valid = await verifyKeySignature(signature, payload, publicKey);
    expect(valid).toBe(true);
  });

  it("returns false when the signature is tampered", async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const payload = new TextEncoder().encode("hello agent");
    const signature = await signWithKey(payload, privateKey);
    // Flip one byte in the signature
    const tampered = new Uint8Array(signature);
    tampered[0] = tampered[0] ^ 0xff;
    const valid = await verifyKeySignature(tampered, payload, publicKey);
    expect(valid).toBe(false);
  });

  it("returns false when the payload is different from what was signed", async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    const original = new TextEncoder().encode("original payload");
    const different = new TextEncoder().encode("tampered payload");
    const signature = await signWithKey(original, privateKey);
    const valid = await verifyKeySignature(signature, different, publicKey);
    expect(valid).toBe(false);
  });

  it("returns false when the public key does not match the signing key", async () => {
    const signer = await generateKeyPair();
    const other = await generateKeyPair();
    const payload = new TextEncoder().encode("test message");
    const signature = await signWithKey(payload, signer.privateKey);
    const valid = await verifyKeySignature(signature, payload, other.publicKey);
    expect(valid).toBe(false);
  });

  it("sign returns a 64-byte Ed25519 signature", async () => {
    const { privateKey } = await generateKeyPair();
    const payload = new TextEncoder().encode("test");
    const signature = await signWithKey(payload, privateKey);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });
});

// ---------------------------------------------------------------------------
// KeyDIDProvider
// ---------------------------------------------------------------------------

describe("KeyDIDProvider", () => {
  it("has method = 'key'", () => {
    const provider = new KeyDIDProvider();
    expect(provider.method).toBe("key");
  });

  it("resolves a valid did:key DID and returns a DID document", async () => {
    const { did } = await generateKeyPair();
    const provider = new KeyDIDProvider();
    // Minimal mock for Resolvable — not used by did:key (pure computation)
    const resolver = {} as Parameters<typeof provider.resolve>[2];
    const parsedDID = { did, method: "key", id: did.slice("did:key:".length), params: null, path: "", query: "", fragment: "" };
    const result = await provider.resolve(did, parsedDID, resolver);

    expect(result.didDocument).toBeDefined();
    expect(result.didDocument?.id).toBe(did);
    expect(result.resolutionMetadata.error).toBeUndefined();
  });

  it("DID document contains an Ed25519VerificationKey2020 verification method", async () => {
    const { did } = await generateKeyPair();
    const provider = new KeyDIDProvider();
    const resolver = {} as Parameters<typeof provider.resolve>[2];
    const parsedDID = { did, method: "key", id: did.slice("did:key:".length), params: null, path: "", query: "", fragment: "" };
    const result = await provider.resolve(did, parsedDID, resolver);

    const vm = result.didDocument?.verificationMethod?.[0];
    expect(vm).toBeDefined();
    if (typeof vm === "object" && vm !== null && !Array.isArray(vm)) {
      expect((vm as { type: string }).type).toBe("Ed25519VerificationKey2020");
    }
  });

  it("returns an error result for an invalid DID", async () => {
    const provider = new KeyDIDProvider();
    const resolver = {} as Parameters<typeof provider.resolve>[2];
    const badDID = "did:key:invalidXXXXXXXXXXXXXXXXXXXX";
    const parsedDID = { did: badDID, method: "key", id: "invalidXXXXXXXXXXXXXXXXXXXX", params: null, path: "", query: "", fragment: "" };
    const result = await provider.resolve(badDID, parsedDID, resolver);

    expect(result.resolutionMetadata.error).toBeDefined();
    expect(result.didDocument).toBeNull();
  });
});
