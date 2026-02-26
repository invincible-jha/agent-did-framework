// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * CredentialIssuer — issues W3C Verifiable Credentials for agents as JWT proofs.
 *
 * Credentials are signed with Ed25519 (EdDSA) using the issuer's local private key.
 * Only `did:key` issuers with a locally-held key are supported for signing.
 *
 * FIRE LINE: no trust level fields in any VC. Credentials attest capability or
 * delegation — never behavioural scores or inferred trust.
 */

import { SignJWT } from "jose";
import { sha512 } from "@noble/hashes/sha512";
import * as ed25519Raw from "@noble/ed25519";
import type {
  IssueCredentialOptions,
  VerifiableCredential,
  AgentCredentialType,
  AgentIdentityClaims,
  AgentCapabilityClaims,
  AgentDelegationClaims,
} from "../agent/types.js";
import type { DIDStore } from "../storage/interface.js";
import type { CredentialStore } from "../storage/interface.js";
import type { CredentialConfig } from "../config.js";
import { randomUUID } from "./util.js";

// noble/ed25519 SHA-512 wiring (idempotent across multiple imports).
ed25519Raw.etc.sha512Sync = (...messages) => sha512(...messages);

/**
 * Issues Verifiable Credentials with JWT proofs for agents.
 *
 * @example
 * ```typescript
 * const issuer = new CredentialIssuer({ didStore, credentialStore, config });
 * const vc = await issuer.issue({
 *   issuerDID: "did:key:z6Mk...",
 *   agentDID: "did:key:z6Mk...",
 *   credentialType: "AgentCapability",
 *   claims: { credentialType: "AgentCapability", capability: "file.read", description: "Read access" },
 * });
 * ```
 */
export class CredentialIssuer {
  private readonly didStore: DIDStore;
  private readonly credentialStore: CredentialStore;
  private readonly config: CredentialConfig;

  constructor(params: {
    didStore: DIDStore;
    credentialStore: CredentialStore;
    config: CredentialConfig;
  }) {
    this.didStore = params.didStore;
    this.credentialStore = params.credentialStore;
    this.config = params.config;
  }

  /**
   * Issue a signed Verifiable Credential and persist it to the credential store.
   *
   * @throws {Error} If the issuer DID is not found or has no local private key.
   * @throws {Error} If the issuer DID is deactivated.
   */
  async issue(options: IssueCredentialOptions): Promise<VerifiableCredential> {
    const issuerRecord = await this.didStore.get(options.issuerDID);
    if (issuerRecord === undefined) {
      throw new Error(
        `Issuer DID not found in local store: ${options.issuerDID}. ` +
          `Only locally-managed DIDs can issue credentials.`
      );
    }

    if (issuerRecord.deactivated) {
      throw new Error(
        `Issuer DID is deactivated and cannot sign credentials: ${options.issuerDID}`
      );
    }

    if (issuerRecord.privateKey === undefined) {
      throw new Error(
        `Issuer DID "${options.issuerDID}" has no locally-held private key. ` +
          `Only did:key identities created by this manager can act as issuers.`
      );
    }

    const credentialId =
      options.credentialId ?? `urn:uuid:${randomUUID()}`;
    const issuedAt = new Date();
    const expirySeconds =
      options.expirySeconds ?? this.config.defaultExpirySeconds;
    const expiresAt =
      expirySeconds !== undefined
        ? new Date(issuedAt.getTime() + expirySeconds * 1_000)
        : undefined;

    const vcPayload = buildVCPayload({
      credentialId,
      issuerDID: options.issuerDID,
      agentDID: options.agentDID,
      credentialType: options.credentialType,
      claims: options.claims,
      issuedAt,
      expiresAt,
    });

    // Import the private key into a jose-compatible CryptoKey.
    const privateKeyBytes = issuerRecord.privateKey;
    const cryptoPrivateKey = await importEd25519PrivateKey(privateKeyBytes);

    // Sign the JWT.
    const verificationMethodId = buildVerificationMethodId(options.issuerDID);
    let jwtBuilder = new SignJWT(vcPayload)
      .setProtectedHeader({
        alg: "EdDSA",
        typ: "JWT",
        kid: verificationMethodId,
      })
      .setIssuer(options.issuerDID)
      .setSubject(options.agentDID)
      .setJti(credentialId)
      .setIssuedAt(issuedAt);

    if (expiresAt !== undefined) {
      jwtBuilder = jwtBuilder.setExpirationTime(expiresAt);
    }

    const jwt = await jwtBuilder.sign(cryptoPrivateKey);

    // Persist to the credential store.
    await this.credentialStore.create({
      id: credentialId,
      jwt,
      issuerDID: options.issuerDID,
      subjectDID: options.agentDID,
      credentialType: options.credentialType,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt?.toISOString(),
      revoked: false,
    });

    return {
      jwt,
      issuerDID: options.issuerDID,
      subjectDID: options.agentDID,
      credentialType: options.credentialType,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt?.toISOString(),
    };
  }
}

// ---------------------------------------------------------------------------
// JWT payload builder
// ---------------------------------------------------------------------------

interface VCPayloadInput {
  credentialId: string;
  issuerDID: string;
  agentDID: string;
  credentialType: AgentCredentialType;
  claims: AgentIdentityClaims | AgentCapabilityClaims | AgentDelegationClaims;
  issuedAt: Date;
  expiresAt: Date | undefined;
}

function buildVCPayload(input: VCPayloadInput): Record<string, unknown> {
  const credentialSubject = buildCredentialSubject(input.agentDID, input.claims);

  return {
    vc: {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
      ],
      type: ["VerifiableCredential", input.credentialType],
      id: input.credentialId,
      issuer: input.issuerDID,
      issuanceDate: input.issuedAt.toISOString(),
      expirationDate: input.expiresAt?.toISOString(),
      credentialSubject,
    },
  };
}

function buildCredentialSubject(
  agentDID: string,
  claims: AgentIdentityClaims | AgentCapabilityClaims | AgentDelegationClaims
): Record<string, unknown> {
  const base: Record<string, unknown> = { id: agentDID };

  switch (claims.credentialType) {
    case "AgentIdentity":
      return {
        ...base,
        agentName: claims.agentName,
        agentVersion: claims.agentVersion,
        agentType: claims.agentType,
        registeredAt: claims.registeredAt,
      };

    case "AgentCapability":
      return {
        ...base,
        capability: claims.capability,
        description: claims.description,
        ...(claims.resourceScope !== undefined
          ? { resourceScope: claims.resourceScope }
          : {}),
      };

    case "AgentDelegation":
      return {
        ...base,
        ownerDID: claims.ownerDID,
        delegationScope: claims.delegationScope,
        ...(claims.delegatedCapabilities !== undefined
          ? { delegatedCapabilities: claims.delegatedCapabilities }
          : {}),
      };
  }
}

// ---------------------------------------------------------------------------
// Key import helper
// ---------------------------------------------------------------------------

/**
 * Derive the verification method fragment ID for a did:key issuer.
 * For non-key DIDs this falls back to `#key-1`.
 */
function buildVerificationMethodId(issuerDID: string): string {
  if (issuerDID.startsWith("did:key:")) {
    const keyPart = issuerDID.slice("did:key:".length);
    return `${issuerDID}#${keyPart}`;
  }
  return `${issuerDID}#key-1`;
}

/**
 * Import a raw 32-byte Ed25519 private key as a `CryptoKey` via the Web Crypto API.
 */
async function importEd25519PrivateKey(
  privateKeyBytes: Uint8Array
): Promise<CryptoKey> {
  // Derive the public key from the private key.
  const publicKeyBytes = await ed25519Raw.getPublicKeyAsync(privateKeyBytes);

  // PKCS#8 Ed25519 private key DER encoding:
  // SEQUENCE {
  //   INTEGER 0 (version)
  //   SEQUENCE { OID 1.3.101.112 (Ed25519) }
  //   OCTET STRING { OCTET STRING { <32-byte private key> } }
  // }
  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,             // SEQUENCE (46 bytes)
    0x02, 0x01, 0x00,       // INTEGER 0 (version)
    0x30, 0x05,             // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22,             // OCTET STRING (34 bytes)
    0x04, 0x20,             // OCTET STRING (32 bytes = private key)
  ]);

  const pkcs8 = new Uint8Array(pkcs8Header.length + privateKeyBytes.length);
  pkcs8.set(pkcs8Header, 0);
  pkcs8.set(privateKeyBytes, pkcs8Header.length);

  // suppress unused variable — publicKeyBytes not needed in this path
  void publicKeyBytes;

  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8.buffer,
    { name: "Ed25519" },
    false,
    ["sign"]
  );
}
