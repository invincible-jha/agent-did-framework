// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * CredentialVerifier — verifies W3C Verifiable Credentials in JWT format.
 *
 * Verification checks:
 * 1. JWT signature — validated against the issuer's public key from their DID document.
 * 2. Expiry — the credential must not be expired.
 * 3. Revocation — the credential must not be revoked in the local store.
 * 4. Structural validity — the JWT payload must contain a well-formed `vc` claim.
 *
 * FIRE LINE: verification never assigns trust scores and never modifies any state.
 */

import { jwtVerify, importSPKI, decodeJwt } from "jose";
import { base58btc } from "multiformats/bases/base58";
import type { VerifiableCredential, VerificationResult } from "../agent/types.js";
import type { CredentialStore } from "../storage/interface.js";
import type { UniversalResolver } from "../did/resolver.js";
import type { DIDDocument } from "did-resolver";

/**
 * Verifies agent Verifiable Credentials.
 *
 * @example
 * ```typescript
 * const verifier = new CredentialVerifier({ credentialStore, resolver });
 * const result = await verifier.verify(vc);
 * if (!result.valid) console.error(result.failureReason);
 * ```
 */
export class CredentialVerifier {
  private readonly credentialStore: CredentialStore;
  private readonly resolver: UniversalResolver;

  constructor(params: {
    credentialStore: CredentialStore;
    resolver: UniversalResolver;
  }) {
    this.credentialStore = params.credentialStore;
    this.resolver = params.resolver;
  }

  /**
   * Verify a Verifiable Credential.
   *
   * @param vc - The credential to verify. Only the `jwt` field is used for
   *             cryptographic verification; the other fields are informational.
   * @returns A {@link VerificationResult} describing whether the credential is valid.
   */
  async verify(vc: VerifiableCredential): Promise<VerificationResult> {
    // Step 1: Decode header + payload without verifying the signature yet.
    let decodedPayload: Record<string, unknown>;
    let issuerDID: string;
    try {
      decodedPayload = decodeJwt(vc.jwt) as Record<string, unknown>;
      issuerDID = extractString(decodedPayload, "iss");
    } catch {
      return failResult("", undefined, "JWT is malformed and cannot be decoded");
    }

    // Step 2: Resolve the issuer DID document.
    let issuerDocument: DIDDocument;
    try {
      const resolution = await this.resolver.resolve(issuerDID);
      if (
        resolution.resolutionMetadata.error !== undefined ||
        resolution.didDocument === null
      ) {
        return failResult(
          issuerDID,
          undefined,
          `Failed to resolve issuer DID "${issuerDID}": ${resolution.resolutionMetadata.error ?? "not found"}`
        );
      }
      issuerDocument = resolution.didDocument;
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "DID resolution error";
      return failResult(issuerDID, undefined, message);
    }

    // Step 3: Extract the public key from the DID document.
    let publicKeyCrypto: CryptoKey;
    try {
      publicKeyCrypto = await extractPublicKey(issuerDocument);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "Failed to extract issuer public key";
      return failResult(issuerDID, undefined, message);
    }

    // Step 4: Cryptographically verify the JWT signature and expiry.
    let verifiedPayload: Record<string, unknown>;
    try {
      const { payload } = await jwtVerify(vc.jwt, publicKeyCrypto, {
        algorithms: ["EdDSA"],
      });
      verifiedPayload = payload as Record<string, unknown>;
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "JWT verification failed";
      return failResult(issuerDID, extractExpiry(decodedPayload), message);
    }

    // Step 5: Check revocation in the local credential store.
    const jti = extractStringOptional(verifiedPayload, "jti");
    if (jti !== undefined) {
      const storedRecord = await this.credentialStore.get(jti);
      if (storedRecord !== undefined && storedRecord.revoked) {
        return failResult(
          issuerDID,
          extractExpiry(verifiedPayload),
          `Credential "${jti}" has been revoked`
        );
      }
    }

    // Step 6: Extract and validate the vc claim structure.
    const vcClaim = verifiedPayload["vc"];
    if (typeof vcClaim !== "object" || vcClaim === null) {
      return failResult(
        issuerDID,
        extractExpiry(verifiedPayload),
        'JWT payload is missing the "vc" claim'
      );
    }

    const vcObject = vcClaim as Record<string, unknown>;
    const credentialSubject = vcObject["credentialSubject"];
    if (typeof credentialSubject !== "object" || credentialSubject === null) {
      return failResult(
        issuerDID,
        extractExpiry(verifiedPayload),
        "VC credentialSubject is missing or invalid"
      );
    }

    const claims = parseCredentialSubject(
      credentialSubject as Record<string, unknown>,
      vcObject["type"]
    );

    return {
      valid: true,
      issuer: issuerDID,
      expiry: extractExpiry(verifiedPayload),
      claims,
      failureReason: "",
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function failResult(
  issuerDID: string,
  expiry: string | undefined,
  reason: string
): VerificationResult {
  return {
    valid: false,
    issuer: issuerDID,
    expiry,
    claims: undefined,
    failureReason: reason,
  };
}

function extractString(payload: Record<string, unknown>, key: string): string {
  const value = payload[key];
  if (typeof value !== "string") {
    throw new Error(`JWT payload missing required string field: "${key}"`);
  }
  return value;
}

function extractStringOptional(
  payload: Record<string, unknown>,
  key: string
): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}

function extractExpiry(payload: Record<string, unknown>): string | undefined {
  const exp = payload["exp"];
  if (typeof exp !== "number") return undefined;
  return new Date(exp * 1_000).toISOString();
}

/**
 * Extract the first Ed25519 public key from a DID document and import it as
 * a Web Crypto `CryptoKey`.
 */
async function extractPublicKey(document: DIDDocument): Promise<CryptoKey> {
  const methods = document.verificationMethod ?? [];
  if (methods.length === 0) {
    throw new Error(
      `Issuer DID document "${document.id}" contains no verification methods`
    );
  }

  for (const vm of methods) {
    if (typeof vm === "string") continue;

    // did:key — publicKeyBase58 with Ed25519VerificationKey2020
    if (
      vm.type === "Ed25519VerificationKey2020" &&
      typeof vm["publicKeyBase58"] === "string"
    ) {
      const rawBytes = base58btc.decode(vm["publicKeyBase58"]);
      return importEd25519PublicKey(rawBytes);
    }

    // did:key — publicKeyMultibase (z-prefix = base58btc)
    if (
      typeof vm["publicKeyMultibase"] === "string" &&
      vm["publicKeyMultibase"].startsWith("z")
    ) {
      const rawBytes = base58btc.decode(vm["publicKeyMultibase"]);
      // Strip multicodec prefix if present (0xed 0x01).
      const stripped =
        rawBytes[0] === 0xed && rawBytes[1] === 0x01
          ? rawBytes.slice(2)
          : rawBytes;
      return importEd25519PublicKey(stripped);
    }
  }

  throw new Error(
    `No supported Ed25519 verification method found in DID document "${document.id}"`
  );
}

/**
 * Import a raw 32-byte Ed25519 public key as a Web Crypto `CryptoKey`.
 */
async function importEd25519PublicKey(rawBytes: Uint8Array): Promise<CryptoKey> {
  // SubjectPublicKeyInfo (SPKI) DER encoding for Ed25519:
  // SEQUENCE {
  //   SEQUENCE { OID 1.3.101.112 }
  //   BIT STRING { <32-byte public key> }
  // }
  const spkiHeader = new Uint8Array([
    0x30, 0x2a,             // SEQUENCE (42 bytes)
    0x30, 0x05,             // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x03, 0x21,             // BIT STRING (33 bytes)
    0x00,                   // no unused bits
  ]);

  const spki = new Uint8Array(spkiHeader.length + rawBytes.length);
  spki.set(spkiHeader, 0);
  spki.set(rawBytes, spkiHeader.length);

  return crypto.subtle.importKey(
    "spki",
    spki.buffer,
    { name: "Ed25519" },
    false,
    ["verify"]
  );
}

type AnyAgentClaims =
  | import("../agent/types.js").AgentIdentityClaims
  | import("../agent/types.js").AgentCapabilityClaims
  | import("../agent/types.js").AgentDelegationClaims;

/**
 * Parse the `credentialSubject` object into one of the three typed claim shapes.
 */
function parseCredentialSubject(
  subject: Record<string, unknown>,
  vcTypes: unknown
): AnyAgentClaims | undefined {
  const types = Array.isArray(vcTypes) ? (vcTypes as unknown[]) : [];

  if (types.includes("AgentIdentity")) {
    return {
      credentialType: "AgentIdentity",
      agentName: String(subject["agentName"] ?? ""),
      agentVersion: String(subject["agentVersion"] ?? ""),
      agentType: String(subject["agentType"] ?? ""),
      registeredAt: String(subject["registeredAt"] ?? ""),
    };
  }

  if (types.includes("AgentCapability")) {
    const resourceScope = subject["resourceScope"];
    return {
      credentialType: "AgentCapability",
      capability: String(subject["capability"] ?? ""),
      description: String(subject["description"] ?? ""),
      resourceScope: Array.isArray(resourceScope)
        ? resourceScope.map(String)
        : undefined,
    };
  }

  if (types.includes("AgentDelegation")) {
    const delegatedCapabilities = subject["delegatedCapabilities"];
    return {
      credentialType: "AgentDelegation",
      ownerDID: String(subject["ownerDID"] ?? ""),
      delegationScope: String(subject["delegationScope"] ?? ""),
      delegatedCapabilities: Array.isArray(delegatedCapabilities)
        ? delegatedCapabilities.map(String)
        : undefined,
    };
  }

  return undefined;
}
