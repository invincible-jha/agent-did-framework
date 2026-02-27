// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * DID-signed audit trail with non-repudiation guarantees.
 *
 * Audit entries are signed by the recording agent's DID key using the Web
 * Crypto API (Ed25519/SubtleCrypto). Entries are chained: each entry's
 * signature covers a hash of the previous entry, creating a tamper-evident
 * append-only log.
 *
 * FIRE LINE:
 * - The audit chain is RECORDING ONLY. Entries are never read back for
 *   governance decisions, trust adjustments, or policy enforcement.
 * - No anomaly detection, pattern recognition, or counterfactual reasoning.
 * - No write-back to any store at verification time — verification is purely
 *   a cryptographic read operation.
 */

import { randomUUID } from "../credentials/util.js";

// ---------------------------------------------------------------------------
// Core audit entry type
// ---------------------------------------------------------------------------

/**
 * A single record in an immutable audit trail.
 *
 * Entries describe discrete events — actions taken by an agent, policy
 * decisions recorded by a governance controller, or lifecycle transitions.
 * They are structurally plain objects so they can be serialised without loss.
 *
 * Consumers should treat all fields as immutable after creation.
 */
export interface AuditEntry {
  /** Opaque unique identifier for this entry. */
  readonly entry_id: string;
  /**
   * Machine-readable event code.
   * Examples: "credential.issued", "auth.initiated", "agent.deactivated".
   */
  readonly event_type: string;
  /** DID of the agent or system that performed the recorded action. */
  readonly actor_did: string;
  /** ISO-8601 timestamp when the event occurred. */
  readonly occurred_at: string;
  /**
   * Arbitrary structured context for the event.
   * Keys and values must be JSON-serialisable. No `undefined` values.
   */
  readonly context: Readonly<Record<string, string | number | boolean | null>>;
  /**
   * Human-readable summary of what occurred.
   * Must not contain PII or secret material.
   */
  readonly description: string;
}

// ---------------------------------------------------------------------------
// Signed audit entry type
// ---------------------------------------------------------------------------

/**
 * An {@link AuditEntry} together with its DID-backed Ed25519 signature.
 *
 * The signature covers the canonical JSON serialisation of the entry combined
 * with the hash of the previous entry in the chain. This provides both
 * individual entry authenticity and chain integrity.
 */
export interface SignedAuditEntry {
  /** The original audit entry being attested. */
  readonly entry: AuditEntry;
  /**
   * Base64url-encoded Ed25519 signature over the signing payload.
   * The signing payload is the SHA-256 hash of
   * `JSON.stringify(entry) + ":" + previousHash`.
   */
  readonly signature: string;
  /** DID of the agent that signed this entry. */
  readonly signer_did: string;
  /** ISO-8601 timestamp at which the signature was applied. */
  readonly signed_at: string;
  /** Web Crypto algorithm name — always "Ed25519" in this implementation. */
  readonly signature_algorithm: string;
  /**
   * SHA-256 hex digest of the canonical JSON of the previous
   * {@link SignedAuditEntry} in the chain.
   * Empty string for the first (genesis) entry in a chain.
   */
  readonly previous_entry_hash: string;
}

// ---------------------------------------------------------------------------
// Chain verification result
// ---------------------------------------------------------------------------

/**
 * The outcome of verifying all entries in a {@link NonRepudiationChain}.
 *
 * `valid` is true only when every signature is intact and every link in the
 * hash chain is unbroken.
 */
export interface ChainVerificationResult {
  /** Whether the entire chain is intact and all signatures are valid. */
  readonly valid: boolean;
  /** Number of entries that were successfully verified. */
  readonly entries_verified: number;
  /**
   * Zero-based index of the first entry that failed verification.
   * `null` when the chain is fully valid.
   */
  readonly first_invalid_index: number | null;
  /**
   * Indices of all entries where the hash link to the previous entry is broken.
   * An empty array means the chain is structurally continuous.
   */
  readonly broken_links: readonly number[];
}

// ---------------------------------------------------------------------------
// NonRepudiationSigner
// ---------------------------------------------------------------------------

/**
 * Signs individual audit entries with an agent's Ed25519 DID key.
 *
 * Uses the Web Crypto API exclusively — no external crypto libraries.
 *
 * @example
 * ```typescript
 * const signer = new NonRepudiationSigner();
 * const signedEntry = await signer.sign(entry, signingKey, "did:key:z6Mk...");
 * const isValid = await signer.verify(signedEntry, publicKey);
 * ```
 */
export class NonRepudiationSigner {
  /**
   * Sign an audit entry with an Ed25519 private key.
   *
   * The signing payload is the UTF-8 encoding of
   * `SHA-256(canonical-json(entry)):previousHash`. When this entry starts
   * a chain, pass `""` as `previousHash`.
   *
   * @param entry - The audit entry to sign.
   * @param signingKey - An Ed25519 `CryptoKey` with `sign` usage.
   * @param signerDID - The DID of the signing agent.
   * @param previousHash - Hex SHA-256 of the previous entry. Empty string for genesis.
   * @returns A {@link SignedAuditEntry} with a valid signature.
   */
  async sign(
    entry: AuditEntry,
    signingKey: CryptoKey,
    signerDID: string,
    previousHash: string = ""
  ): Promise<SignedAuditEntry> {
    const signingPayload = buildSigningPayload(entry, previousHash);
    const payloadBytes = new TextEncoder().encode(signingPayload);

    const signatureBuffer = await crypto.subtle.sign(
      { name: "Ed25519" },
      signingKey,
      payloadBytes
    );

    const signature = base64urlEncodeBytes(new Uint8Array(signatureBuffer));

    return {
      entry,
      signature,
      signer_did: signerDID,
      signed_at: new Date().toISOString(),
      signature_algorithm: "Ed25519",
      previous_entry_hash: previousHash,
    };
  }

  /**
   * Verify the Ed25519 signature on a signed audit entry.
   *
   * Reconstructs the signing payload from the stored entry and
   * `previous_entry_hash`, then verifies against the public key.
   *
   * @param signedEntry - The entry to verify.
   * @param publicKey - An Ed25519 `CryptoKey` with `verify` usage.
   * @returns `true` if the signature is cryptographically valid; `false` otherwise.
   */
  async verify(
    signedEntry: SignedAuditEntry,
    publicKey: CryptoKey
  ): Promise<boolean> {
    const signingPayload = buildSigningPayload(
      signedEntry.entry,
      signedEntry.previous_entry_hash
    );
    const payloadBytes = new TextEncoder().encode(signingPayload);

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = base64urlDecodeBytes(signedEntry.signature);
    } catch {
      return false;
    }

    try {
      return await crypto.subtle.verify(
        { name: "Ed25519" },
        publicKey,
        signatureBytes,
        payloadBytes
      );
    } catch {
      return false;
    }
  }
}

// ---------------------------------------------------------------------------
// NonRepudiationChain
// ---------------------------------------------------------------------------

/**
 * An append-only, hash-chained sequence of DID-signed audit entries.
 *
 * Each call to {@link append} produces a new {@link SignedAuditEntry} whose
 * `previous_entry_hash` references the SHA-256 digest of the preceding entry.
 * This makes any tampering with historical entries detectable by
 * {@link verifyChain}.
 *
 * The chain is held in memory. Callers are responsible for persisting entries
 * to durable storage after each append.
 *
 * @example
 * ```typescript
 * const chain = new NonRepudiationChain();
 * const entry = await chain.append(auditEntry, signingKey, "did:key:z6Mk...");
 * await persistToStore(entry); // caller's responsibility
 *
 * const verificationResult = await chain.verifyChain();
 * console.log(verificationResult.valid); // true
 * ```
 */
export class NonRepudiationChain {
  private readonly entries: SignedAuditEntry[];
  private readonly signer: NonRepudiationSigner;

  constructor() {
    this.entries = [];
    this.signer = new NonRepudiationSigner();
  }

  /**
   * Append a signed audit entry to the chain.
   *
   * The new entry's `previous_entry_hash` is set to the SHA-256 hash of the
   * last entry's canonical JSON. This is computed inside this method — callers
   * do not need to manage hash state.
   *
   * @param entry - The audit entry to record.
   * @param signingKey - An Ed25519 `CryptoKey` with `sign` usage.
   * @param signerDID - The DID of the agent signing this entry.
   * @returns The newly created {@link SignedAuditEntry}.
   */
  async append(
    entry: AuditEntry,
    signingKey: CryptoKey,
    signerDID: string
  ): Promise<SignedAuditEntry> {
    const previousHash = await this.computeLastEntryHash();
    const signedEntry = await this.signer.sign(
      entry,
      signingKey,
      signerDID,
      previousHash
    );
    this.entries.push(signedEntry);
    return signedEntry;
  }

  /**
   * Verify the integrity of the entire chain.
   *
   * Checks:
   * 1. Each entry's `previous_entry_hash` matches the SHA-256 of the
   *    preceding entry's canonical JSON.
   * 2. The genesis entry has an empty `previous_entry_hash`.
   *
   * Note: signature cryptographic verification requires caller-supplied public
   * keys. This method verifies hash-chain continuity only. For full signature
   * verification use {@link NonRepudiationSigner.verify} per-entry.
   *
   * @returns A {@link ChainVerificationResult} describing the outcome.
   */
  async verifyChain(): Promise<ChainVerificationResult> {
    if (this.entries.length === 0) {
      return {
        valid: true,
        entries_verified: 0,
        first_invalid_index: null,
        broken_links: [],
      };
    }

    const brokenLinks: number[] = [];
    let firstInvalidIndex: number | null = null;

    for (let index = 0; index < this.entries.length; index++) {
      const currentEntry = this.entries[index];
      if (currentEntry === undefined) continue;

      if (index === 0) {
        // Genesis entry must have an empty previous hash.
        if (currentEntry.previous_entry_hash !== "") {
          brokenLinks.push(index);
          if (firstInvalidIndex === null) firstInvalidIndex = index;
        }
      } else {
        const precedingEntry = this.entries[index - 1];
        if (precedingEntry === undefined) continue;

        const expectedHash = await computeEntryHash(precedingEntry);
        if (currentEntry.previous_entry_hash !== expectedHash) {
          brokenLinks.push(index);
          if (firstInvalidIndex === null) firstInvalidIndex = index;
        }
      }
    }

    return {
      valid: brokenLinks.length === 0,
      entries_verified: this.entries.length,
      first_invalid_index: firstInvalidIndex,
      broken_links: brokenLinks,
    };
  }

  /**
   * Return all entries in the chain in append order.
   *
   * Returns a shallow copy — the underlying array is not exposed.
   */
  getEntries(): readonly SignedAuditEntry[] {
    return [...this.entries];
  }

  /**
   * Return the number of entries currently in the chain.
   */
  get length(): number {
    return this.entries.length;
  }

  private async computeLastEntryHash(): Promise<string> {
    if (this.entries.length === 0) return "";
    const lastEntry = this.entries[this.entries.length - 1];
    if (lastEntry === undefined) return "";
    return computeEntryHash(lastEntry);
  }
}

// ---------------------------------------------------------------------------
// Compliance export
// ---------------------------------------------------------------------------

/**
 * Export a chain of signed audit entries as a JSON-LD document for
 * regulatory submission.
 *
 * The output is a W3C JSON-LD graph containing each entry as a named node.
 * The format is intended for archival and compliance auditor consumption —
 * it is NOT used for any governance decision within the framework.
 *
 * @example
 * ```typescript
 * const jsonLd = exportForCompliance(chain.getEntries());
 * await fs.writeFile("audit-report.jsonld", jsonLd, "utf-8");
 * ```
 *
 * @param chain - The array of signed audit entries to export.
 * @returns A formatted JSON-LD string suitable for regulatory submission.
 */
export function exportForCompliance(chain: readonly SignedAuditEntry[]): string {
  const exportId = `urn:uuid:${randomUUID()}`;
  const exportedAt = new Date().toISOString();

  const graph = chain.map((signedEntry, index) => ({
    "@id": `urn:audit-entry:${signedEntry.entry.entry_id}`,
    "@type": "aumos:SignedAuditEntry",
    "aumos:sequenceIndex": index,
    "aumos:entry": {
      "@type": "aumos:AuditEntry",
      "aumos:entryId": signedEntry.entry.entry_id,
      "aumos:eventType": signedEntry.entry.event_type,
      "aumos:actorDID": signedEntry.entry.actor_did,
      "aumos:occurredAt": signedEntry.entry.occurred_at,
      "aumos:description": signedEntry.entry.description,
      "aumos:context": signedEntry.entry.context,
    },
    "aumos:signature": signedEntry.signature,
    "aumos:signerDID": signedEntry.signer_did,
    "aumos:signedAt": signedEntry.signed_at,
    "aumos:signatureAlgorithm": signedEntry.signature_algorithm,
    "aumos:previousEntryHash": signedEntry.previous_entry_hash,
  }));

  const document = {
    "@context": {
      aumos: "https://aumos.io/vocab/audit/v1#",
      xsd: "http://www.w3.org/2001/XMLSchema#",
    },
    "@id": exportId,
    "@type": "aumos:AuditChainExport",
    "aumos:exportedAt": exportedAt,
    "aumos:entryCount": chain.length,
    "@graph": graph,
  };

  return JSON.stringify(document, null, 2);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build the canonical signing payload string for an entry.
 *
 * Format: `<sha256-hex-of-canonical-json>:<previousHash>`
 *
 * The outer string (not the hash) is what gets signed, so the signer
 * commits to both the entry content (via its hash) and the chain link.
 */
function buildSigningPayload(entry: AuditEntry, previousHash: string): string {
  const canonicalJson = canonicaliseEntry(entry);
  return `${canonicalJson}:${previousHash}`;
}

/**
 * Produce a deterministic JSON string for an entry.
 *
 * Keys are sorted alphabetically at each level so the output is stable
 * across JavaScript engine versions and does not depend on insertion order.
 */
function canonicaliseEntry(entry: AuditEntry): string {
  const sortedContext = Object.fromEntries(
    Object.entries(entry.context).sort(([a], [b]) => a.localeCompare(b))
  );

  const canonical = {
    actor_did: entry.actor_did,
    context: sortedContext,
    description: entry.description,
    entry_id: entry.entry_id,
    event_type: entry.event_type,
    occurred_at: entry.occurred_at,
  };

  return JSON.stringify(canonical);
}

/**
 * Compute the SHA-256 hex digest of a signed entry's canonical JSON.
 * Uses the Web Crypto API — no external hashing library required.
 */
async function computeEntryHash(signedEntry: SignedAuditEntry): Promise<string> {
  const canonical = JSON.stringify({
    entry: canonicaliseEntry(signedEntry.entry),
    previous_entry_hash: signedEntry.previous_entry_hash,
    signature: signedEntry.signature,
    signature_algorithm: signedEntry.signature_algorithm,
    signed_at: signedEntry.signed_at,
    signer_did: signedEntry.signer_did,
  });

  const bytes = new TextEncoder().encode(canonical);
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
  return hexEncode(new Uint8Array(hashBuffer));
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function base64urlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlDecodeBytes(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const withPadding = padded + "=".repeat((4 - (padded.length % 4)) % 4);
  const binaryString = atob(withPadding);
  const bytes = new Uint8Array(binaryString.length);
  for (let index = 0; index < binaryString.length; index++) {
    bytes[index] = binaryString.charCodeAt(index);
  }
  return bytes;
}
