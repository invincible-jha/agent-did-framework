// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * PresentationBuilder — creates W3C Verifiable Presentations from multiple VCs.
 *
 * A Verifiable Presentation (VP) is a JWT-enveloped container that holds one
 * or more Verifiable Credentials. The holder signs the VP with their own
 * private key to prove control of the contained credentials.
 *
 * Spec: https://www.w3.org/TR/vc-data-model/#presentations-0
 */

import { SignJWT } from "jose";
import { sha512 } from "@noble/hashes/sha512";
import * as ed25519Raw from "@noble/ed25519";
import type { VerifiableCredential, VerifiablePresentation } from "../agent/types.js";
import type { DIDStore } from "../storage/interface.js";
import { randomUUID } from "./util.js";

// noble/ed25519 SHA-512 wiring (idempotent).
ed25519Raw.etc.sha512Sync = (...messages) => sha512(...messages);

/**
 * Options for building a Verifiable Presentation.
 */
export interface BuildPresentationOptions {
  /**
   * DID of the holder presenting the credentials.
   * Must be a locally-managed `did:key` identity with a private key.
   */
  readonly holderDID: string;
  /**
   * The credentials to bundle into the presentation.
   * Must not be empty.
   */
  readonly credentials: readonly VerifiableCredential[];
  /**
   * Optional challenge nonce provided by the verifier.
   * Including a challenge prevents replay attacks.
   */
  readonly challenge?: string | undefined;
  /**
   * Optional domain for the presentation (verifier's domain).
   */
  readonly domain?: string | undefined;
  /**
   * Optional expiry in seconds from now for the presentation JWT.
   */
  readonly expirySeconds?: number | undefined;
}

/**
 * Builds signed Verifiable Presentations from one or more VCs.
 *
 * @example
 * ```typescript
 * const builder = new PresentationBuilder({ didStore });
 * const vp = await builder.build({
 *   holderDID: "did:key:z6Mk...",
 *   credentials: [identityVC, capabilityVC],
 *   challenge: "abc123",
 *   domain: "https://verifier.example.com",
 * });
 * ```
 */
export class PresentationBuilder {
  private readonly didStore: DIDStore;

  constructor(params: { didStore: DIDStore }) {
    this.didStore = params.didStore;
  }

  /**
   * Build and sign a Verifiable Presentation.
   *
   * @throws {Error} If `credentials` is empty.
   * @throws {Error} If the holder DID is not found or has no local private key.
   * @throws {Error} If the holder DID is deactivated.
   */
  async build(
    options: BuildPresentationOptions
  ): Promise<VerifiablePresentation> {
    if (options.credentials.length === 0) {
      throw new Error("Cannot build a Verifiable Presentation with zero credentials");
    }

    const holderRecord = await this.didStore.get(options.holderDID);
    if (holderRecord === undefined) {
      throw new Error(
        `Holder DID not found in local store: ${options.holderDID}`
      );
    }

    if (holderRecord.deactivated) {
      throw new Error(
        `Holder DID is deactivated and cannot create presentations: ${options.holderDID}`
      );
    }

    if (holderRecord.privateKey === undefined) {
      throw new Error(
        `Holder DID "${options.holderDID}" has no locally-held private key. ` +
          `Only locally-created did:key identities can act as presentation holders.`
      );
    }

    const presentationId = `urn:uuid:${randomUUID()}`;
    const createdAt = new Date();
    const expiresAt =
      options.expirySeconds !== undefined
        ? new Date(createdAt.getTime() + options.expirySeconds * 1_000)
        : undefined;

    const vpPayload = buildVPPayload({
      presentationId,
      holderDID: options.holderDID,
      credentials: options.credentials,
      challenge: options.challenge,
      domain: options.domain,
      createdAt,
      expiresAt,
    });

    const cryptoPrivateKey = await importEd25519PrivateKey(
      holderRecord.privateKey
    );

    const verificationMethodId = buildVerificationMethodId(options.holderDID);
    let jwtBuilder = new SignJWT(vpPayload)
      .setProtectedHeader({
        alg: "EdDSA",
        typ: "JWT",
        kid: verificationMethodId,
      })
      .setIssuer(options.holderDID)
      .setSubject(options.holderDID)
      .setJti(presentationId)
      .setIssuedAt(createdAt);

    if (expiresAt !== undefined) {
      jwtBuilder = jwtBuilder.setExpirationTime(expiresAt);
    }

    const jwt = await jwtBuilder.sign(cryptoPrivateKey);

    return {
      jwt,
      holderDID: options.holderDID,
      credentials: options.credentials,
      createdAt: createdAt.toISOString(),
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface VPPayloadInput {
  presentationId: string;
  holderDID: string;
  credentials: readonly VerifiableCredential[];
  challenge: string | undefined;
  domain: string | undefined;
  createdAt: Date;
  expiresAt: Date | undefined;
}

function buildVPPayload(input: VPPayloadInput): Record<string, unknown> {
  return {
    vp: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      id: input.presentationId,
      holder: input.holderDID,
      verifiableCredential: input.credentials.map((vc) => vc.jwt),
    },
    ...(input.challenge !== undefined ? { nonce: input.challenge } : {}),
    ...(input.domain !== undefined ? { aud: input.domain } : {}),
  };
}

function buildVerificationMethodId(holderDID: string): string {
  if (holderDID.startsWith("did:key:")) {
    const keyPart = holderDID.slice("did:key:".length);
    return `${holderDID}#${keyPart}`;
  }
  return `${holderDID}#key-1`;
}

async function importEd25519PrivateKey(
  privateKeyBytes: Uint8Array
): Promise<CryptoKey> {
  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  const pkcs8 = new Uint8Array(pkcs8Header.length + privateKeyBytes.length);
  pkcs8.set(pkcs8Header, 0);
  pkcs8.set(privateKeyBytes, pkcs8Header.length);

  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8.buffer,
    { name: "Ed25519" },
    false,
    ["sign"]
  );
}
