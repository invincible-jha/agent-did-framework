// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * did:key provider — self-contained DID method backed by Ed25519 key pairs.
 *
 * A did:key DID encodes the raw public key using multibase + multicodec.
 * No external server or registry is required. Resolution is pure computation.
 *
 * Spec: https://w3c-ccg.github.io/did-method-key/
 */

import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { base58btc } from "multiformats/bases/base58";
import type { DIDDocument, DIDResolutionResult, ParsedDID, Resolvable } from "did-resolver";
import type { DIDMethodResolver } from "./resolver.js";
import { buildErrorResult } from "./resolver.js";

// noble/ed25519 requires a SHA-512 implementation to be wired in.
ed25519.etc.sha512Sync = (...messages) => sha512(...messages);

// Multicodec prefix for Ed25519 public key: 0xed01
const ED25519_PUB_CODEC = new Uint8Array([0xed, 0x01]);

export interface GeneratedKeyPair {
  /** The full did:key DID string. */
  readonly did: string;
  /** Raw 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** Raw 32-byte Ed25519 private key. */
  readonly privateKey: Uint8Array;
}

/**
 * Generate a fresh Ed25519 key pair and derive the corresponding did:key DID.
 *
 * @returns A {@link GeneratedKeyPair} containing the DID and both key bytes.
 *
 * @example
 * ```typescript
 * const { did, privateKey } = await generateKeyPair();
 * console.log(did); // did:key:z6Mk...
 * ```
 */
export async function generateKeyPair(): Promise<GeneratedKeyPair> {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  const did = publicKeyToDid(publicKey);
  return { did, publicKey, privateKey };
}

/**
 * Derive the did:key DID for a given raw Ed25519 public key.
 */
export function publicKeyToDid(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(ED25519_PUB_CODEC.length + publicKey.length);
  prefixed.set(ED25519_PUB_CODEC, 0);
  prefixed.set(publicKey, ED25519_PUB_CODEC.length);
  const multibaseEncoded = base58btc.encode(prefixed);
  return `did:key:${multibaseEncoded}`;
}

/**
 * Decode a did:key DID and extract the raw Ed25519 public key bytes.
 *
 * @throws {Error} If the DID is not a valid did:key or uses an unsupported codec.
 */
export function publicKeyFromDid(did: string): Uint8Array {
  const keyPart = did.startsWith("did:key:") ? did.slice("did:key:".length) : did;
  const decoded = base58btc.decode(keyPart);

  if (
    decoded[0] !== ED25519_PUB_CODEC[0] ||
    decoded[1] !== ED25519_PUB_CODEC[1]
  ) {
    throw new Error(
      `Unsupported multicodec prefix. Expected Ed25519 (0xed 0x01), got 0x${decoded[0]?.toString(16)} 0x${decoded[1]?.toString(16)}.`
    );
  }

  return decoded.slice(2);
}

/**
 * Sign a payload using an Ed25519 private key.
 */
export async function signWithKey(
  payload: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  return ed25519.signAsync(payload, privateKey);
}

/**
 * Verify an Ed25519 signature.
 */
export async function verifyKeySignature(
  signature: Uint8Array,
  payload: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  return ed25519.verifyAsync(signature, payload, publicKey);
}

// ---------------------------------------------------------------------------
// DID method resolver
// ---------------------------------------------------------------------------

/**
 * did:key DID method resolver.
 *
 * Resolution is entirely local — it reconstructs the DID document from the
 * public key encoded in the DID itself.
 */
export class KeyDIDProvider implements DIDMethodResolver {
  readonly method = "key";

  async resolve(
    did: string,
    parsed: ParsedDID,
    _resolver: Resolvable
  ): Promise<DIDResolutionResult> {
    let publicKey: Uint8Array;
    try {
      publicKey = publicKeyFromDid(did);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "Failed to decode did:key";
      return buildErrorResult("invalidDid", message);
    }

    const keyId = `${did}#${parsed.id}`;
    const document = buildKeyDocument(did, keyId, publicKey);

    return {
      resolutionMetadata: {},
      didDocument: document,
      didDocumentMetadata: {
        created: new Date().toISOString(),
      },
    };
  }
}

function buildKeyDocument(
  did: string,
  keyId: string,
  publicKey: Uint8Array
): DIDDocument {
  const publicKeyBase58 = base58btc.encode(publicKey);

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyBase58,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    keyAgreement: [keyId],
    capabilityInvocation: [keyId],
    capabilityDelegation: [keyId],
  };
}
