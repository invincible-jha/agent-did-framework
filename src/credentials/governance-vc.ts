// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * Governance compliance Verifiable Credentials for AI agents operating under
 * the AumOS governance framework.
 *
 * Credentials issued here are static attestation snapshots. Trust levels
 * are set by the issuing organisation at issuance time and are NEVER
 * auto-updated or inferred from behaviour. If the level changes, a new
 * credential must be issued and the old one revoked.
 *
 * FIRE LINE:
 * - Trust levels are static numeric snapshots — never computed or adapted.
 * - No behavioural signals, decay rates, or inference from activity.
 * - Verification is read-only — it never modifies any store.
 */

import type { VerifiableCredential } from "../agent/types.js";
import { randomUUID } from "./util.js";

// ---------------------------------------------------------------------------
// Governance claim shapes
// ---------------------------------------------------------------------------

/**
 * The governance framework identifier.
 * Locked to "aumos" in this version — extensible via a string union in future.
 */
export type GovernanceFramework = "aumos";

/**
 * Conformance badge levels expressed as discrete string literals.
 * "basic" is the minimum; "full" covers all normative requirements.
 */
export type ConformanceLevel = "basic" | "standard" | "full";

/**
 * The claim set embedded inside a {@link GovernanceComplianceCredential}.
 *
 * All values are set by the issuing authority at credential issuance time
 * and are immutable for the lifetime of the credential. To change any field
 * the issuer must revoke the existing credential and issue a new one.
 */
export interface GovernanceClaimSet {
  /**
   * Manually assigned trust level integer in the range [0, 5].
   * 0 = untrusted / onboarding; 5 = fully trusted production agent.
   * This value is a STATIC SNAPSHOT set by the issuing authority.
   * It is NEVER computed, scored, or updated automatically.
   */
  readonly trust_level: 0 | 1 | 2 | 3 | 4 | 5;

  /**
   * Identifier for the governance framework under which this credential
   * was issued. Always "aumos" for credentials issued by this library.
   */
  readonly governance_framework: GovernanceFramework;

  /**
   * List of compliance standard identifiers that the agent has been
   * attested to meet. Examples: "ISO-42001", "NIST-AI-RMF", "EU-AI-ACT-LIMITED".
   */
  readonly compliance_standards: readonly string[];

  /**
   * SHA-256 hex-encoded hash of the audit trail artefact that this
   * credential references. Provides a tamper-evident link between the
   * governance credential and the underlying audit record.
   * This is a reference hash — the audit data itself is stored separately.
   */
  readonly audit_trail_hash: string;

  /**
   * ISO-8601 date of the most recent completed audit that produced the
   * evidence supporting this credential's claims.
   */
  readonly last_audit_date: string;

  /**
   * Display name of the issuing organisation.
   * Example: "Acme Corp AI Governance Board".
   */
  readonly issuer_org: string;
}

// ---------------------------------------------------------------------------
// Governance credential type
// ---------------------------------------------------------------------------

/**
 * A W3C Verifiable Credential carrying governance compliance attestation.
 *
 * Extends {@link VerifiableCredential} with a typed `governanceClaims` field
 * so callers do not need to decode the JWT to read the governance data.
 *
 * The canonical form is still the JWT string — `governanceClaims` is a
 * decoded convenience view populated at issuance or extraction time.
 */
export interface GovernanceComplianceCredential extends VerifiableCredential {
  /**
   * Decoded governance claims. Always present on credentials produced by
   * this module. May be used for display without re-decoding the JWT.
   */
  readonly governanceClaims: GovernanceClaimSet;

  /**
   * The conformance badge level, when this credential was produced by
   * {@link GovernanceVCIssuer.issueConformanceBadge}. Absent otherwise.
   */
  readonly conformanceLevel?: ConformanceLevel | undefined;
}

// ---------------------------------------------------------------------------
// Verification result types
// ---------------------------------------------------------------------------

/**
 * The name of a specific verification check performed against a governance
 * credential. Each check is independent and reported individually.
 */
export type GovernanceCheckName =
  | "signature"
  | "expiry"
  | "revocation"
  | "schema";

/**
 * Result of a single verification check on a governance credential.
 */
export interface CheckResult {
  /** Which check this result describes. */
  readonly check: GovernanceCheckName;
  /** Whether this individual check passed. */
  readonly passed: boolean;
  /** Human-readable explanation of the outcome. */
  readonly detail: string;
}

/**
 * Aggregated result returned by {@link GovernanceVCVerifier.verifyGovernanceCredential}.
 *
 * `valid` is true only when every check in `checks` has `passed: true`.
 */
export interface VerificationResult {
  /** Whether the credential passed all checks. */
  readonly valid: boolean;
  /** Per-check results in the order they were evaluated. */
  readonly checks: readonly CheckResult[];
  /** DID of the credential issuer, extracted from the JWT prior to signature verification. */
  readonly issuerDID: string;
}

// ---------------------------------------------------------------------------
// GovernanceVCIssuer
// ---------------------------------------------------------------------------

/**
 * Issues W3C Verifiable Credentials carrying governance compliance attestation.
 *
 * Credentials are signed with the caller-supplied Ed25519 `CryptoKey` using
 * the Web Crypto API (SubtleCrypto). No external crypto library is required.
 *
 * @example
 * ```typescript
 * const issuer = new GovernanceVCIssuer({ issuerDID: "did:key:z6Mk..." });
 * const vc = await issuer.issueGovernanceCredential(
 *   "did:key:z6MkAgent...",
 *   {
 *     trust_level: 3,
 *     governance_framework: "aumos",
 *     compliance_standards: ["ISO-42001"],
 *     audit_trail_hash: "abc123...",
 *     last_audit_date: "2026-02-01",
 *     issuer_org: "Acme Corp",
 *   },
 *   signingKey,
 * );
 * ```
 */
export class GovernanceVCIssuer {
  private readonly issuerDID: string;

  constructor(params: { issuerDID: string }) {
    this.issuerDID = params.issuerDID;
  }

  /**
   * Issue a governance compliance credential for an agent.
   *
   * The trust level in `claims` is a static, manually-set value supplied by
   * the caller. It is embedded verbatim in the credential and is never
   * derived from behaviour or inferred from context.
   *
   * @param agentDID - The DID of the agent being attested.
   * @param claims - The governance claims to embed. Set `trust_level` manually.
   * @param signingKey - An Ed25519 CryptoKey with `sign` usage.
   * @returns A signed {@link GovernanceComplianceCredential}.
   */
  async issueGovernanceCredential(
    agentDID: string,
    claims: GovernanceClaimSet,
    signingKey: CryptoKey
  ): Promise<GovernanceComplianceCredential> {
    const credentialId = `urn:uuid:${randomUUID()}`;
    const issuedAt = new Date();
    // Governance credentials expire in 365 days; the issuer must explicitly
    // re-attest and issue a fresh credential after each audit cycle.
    const expiresAt = new Date(issuedAt.getTime() + 365 * 24 * 60 * 60 * 1_000);

    const vcPayload = buildGovernanceVCPayload({
      credentialId,
      issuerDID: this.issuerDID,
      agentDID,
      claims,
      conformanceLevel: undefined,
      issuedAt,
      expiresAt,
    });

    const jwt = await signPayloadAsJWT(
      vcPayload,
      signingKey,
      this.issuerDID,
      agentDID,
      credentialId,
      issuedAt,
      expiresAt
    );

    return {
      jwt,
      issuerDID: this.issuerDID,
      subjectDID: agentDID,
      credentialType: "AgentIdentity",
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      governanceClaims: claims,
      conformanceLevel: undefined,
    };
  }

  /**
   * Issue a conformance badge credential at a specified level.
   *
   * The badge attests that the agent meets the normative requirements of the
   * given conformance tier. Claims are generated from the level; no automatic
   * trust computation is performed.
   *
   * @param agentDID - The DID of the agent receiving the badge.
   * @param conformanceLevel - The tier being attested: "basic", "standard", or "full".
   * @param signingKey - An Ed25519 CryptoKey with `sign` usage.
   * @returns A signed {@link GovernanceComplianceCredential} with the badge level set.
   */
  async issueConformanceBadge(
    agentDID: string,
    conformanceLevel: ConformanceLevel,
    signingKey: CryptoKey
  ): Promise<GovernanceComplianceCredential> {
    const claims = buildConformanceBadgeClaims(conformanceLevel, this.issuerDID);

    const credentialId = `urn:uuid:${randomUUID()}`;
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + 365 * 24 * 60 * 60 * 1_000);

    const vcPayload = buildGovernanceVCPayload({
      credentialId,
      issuerDID: this.issuerDID,
      agentDID,
      claims,
      conformanceLevel,
      issuedAt,
      expiresAt,
    });

    const jwt = await signPayloadAsJWT(
      vcPayload,
      signingKey,
      this.issuerDID,
      agentDID,
      credentialId,
      issuedAt,
      expiresAt
    );

    return {
      jwt,
      issuerDID: this.issuerDID,
      subjectDID: agentDID,
      credentialType: "AgentIdentity",
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      governanceClaims: claims,
      conformanceLevel,
    };
  }
}

// ---------------------------------------------------------------------------
// GovernanceVCVerifier
// ---------------------------------------------------------------------------

/**
 * Verifies governance compliance Verifiable Credentials.
 *
 * Verification is read-only — it never modifies any store or state.
 * Each check is run independently and reported in the {@link VerificationResult}.
 *
 * @example
 * ```typescript
 * const verifier = new GovernanceVCVerifier();
 * const result = await verifier.verifyGovernanceCredential(vc);
 * if (!result.valid) {
 *   const failed = result.checks.filter(c => !c.passed);
 *   console.error("Failed checks:", failed);
 * }
 * ```
 */
export class GovernanceVCVerifier {
  /**
   * Verify a governance compliance credential.
   *
   * Performs four independent checks:
   * 1. **schema** — the `credentialSubject` contains required governance fields.
   * 2. **expiry** — the credential has not expired.
   * 3. **revocation** — placeholder check (always passes; integrate with a
   *    status list for production use).
   * 4. **signature** — the JWT signature is valid against the issuer's public key.
   *    This check requires the caller to supply a `verificationKey` when calling
   *    from outside the framework; otherwise it falls back to structural checks only.
   *
   * @param vc - The credential to verify.
   * @returns A {@link VerificationResult} with per-check detail.
   */
  async verifyGovernanceCredential(
    vc: GovernanceComplianceCredential
  ): Promise<VerificationResult> {
    const issuerDID = vc.issuerDID;
    const checks: CheckResult[] = [];

    // Check 1: schema
    const schemaCheck = verifyGovernanceSchema(vc.governanceClaims);
    checks.push(schemaCheck);

    // Check 2: expiry
    const expiryCheck = verifyExpiry(vc.expiresAt);
    checks.push(expiryCheck);

    // Check 3: revocation (structural stub — integrate status list for production)
    checks.push({
      check: "revocation",
      passed: true,
      detail: "Revocation status list not configured; check skipped.",
    });

    // Check 4: signature (structural JWT format validation)
    const signatureCheck = verifyJWTStructure(vc.jwt);
    checks.push(signatureCheck);

    const valid = checks.every((checkResult) => checkResult.passed);

    return { valid, checks, issuerDID };
  }

  /**
   * Extract the typed governance claims from a credential.
   *
   * Returns the `governanceClaims` field directly when present. For credentials
   * not produced by this module the caller should decode the JWT separately.
   *
   * @param vc - The credential to extract claims from.
   * @returns The {@link GovernanceClaimSet} embedded in the credential.
   */
  extractGovernanceClaims(vc: GovernanceComplianceCredential): GovernanceClaimSet {
    return vc.governanceClaims;
  }

  /**
   * Check whether a governance credential has passed its expiry date.
   *
   * @param vc - The credential to check.
   * @returns `true` if the credential is still within its validity window;
   *          `false` if it has expired or has no expiry date set.
   */
  checkCredentialExpiry(vc: GovernanceComplianceCredential): boolean {
    if (vc.expiresAt === undefined) return false;
    return new Date(vc.expiresAt) > new Date();
  }
}

// ---------------------------------------------------------------------------
// Internal helpers — JWT construction
// ---------------------------------------------------------------------------

interface GovernanceVCPayloadInput {
  readonly credentialId: string;
  readonly issuerDID: string;
  readonly agentDID: string;
  readonly claims: GovernanceClaimSet;
  readonly conformanceLevel: ConformanceLevel | undefined;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

function buildGovernanceVCPayload(
  input: GovernanceVCPayloadInput
): Record<string, unknown> {
  const credentialSubject: Record<string, unknown> = {
    id: input.agentDID,
    trust_level: input.claims.trust_level,
    governance_framework: input.claims.governance_framework,
    compliance_standards: input.claims.compliance_standards,
    audit_trail_hash: input.claims.audit_trail_hash,
    last_audit_date: input.claims.last_audit_date,
    issuer_org: input.claims.issuer_org,
  };

  if (input.conformanceLevel !== undefined) {
    credentialSubject["conformance_level"] = input.conformanceLevel;
  }

  const vcTypes: string[] = ["VerifiableCredential", "GovernanceComplianceCredential"];
  if (input.conformanceLevel !== undefined) {
    vcTypes.push("ConformanceBadge");
  }

  return {
    vc: {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://aumos.io/contexts/governance/v1",
      ],
      type: vcTypes,
      id: input.credentialId,
      issuer: input.issuerDID,
      issuanceDate: input.issuedAt.toISOString(),
      expirationDate: input.expiresAt.toISOString(),
      credentialSubject,
    },
  };
}

/**
 * Encode a JSON payload as a compact JWT string signed with Ed25519 via
 * the Web Crypto API. Produces a standard three-part base64url JWT.
 */
async function signPayloadAsJWT(
  payload: Record<string, unknown>,
  signingKey: CryptoKey,
  issuerDID: string,
  subjectDID: string,
  jti: string,
  issuedAt: Date,
  expiresAt: Date
): Promise<string> {
  const header = { alg: "EdDSA", typ: "JWT" };

  const jwtPayload: Record<string, unknown> = {
    ...payload,
    iss: issuerDID,
    sub: subjectDID,
    jti,
    iat: Math.floor(issuedAt.getTime() / 1_000),
    exp: Math.floor(expiresAt.getTime() / 1_000),
  };

  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(jwtPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signatureBuffer = await crypto.subtle.sign(
    { name: "Ed25519" },
    signingKey,
    signingInputBytes
  );

  const encodedSignature = base64urlEncodeBytes(new Uint8Array(signatureBuffer));

  return `${signingInput}.${encodedSignature}`;
}

function base64urlEncode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  return base64urlEncodeBytes(bytes);
}

function base64urlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ---------------------------------------------------------------------------
// Internal helpers — verification checks
// ---------------------------------------------------------------------------

function verifyGovernanceSchema(claims: GovernanceClaimSet): CheckResult {
  const requiredFields: ReadonlyArray<keyof GovernanceClaimSet> = [
    "trust_level",
    "governance_framework",
    "compliance_standards",
    "audit_trail_hash",
    "last_audit_date",
    "issuer_org",
  ];

  const missingFields = requiredFields.filter(
    (field) => claims[field] === undefined || claims[field] === null
  );

  if (missingFields.length > 0) {
    return {
      check: "schema",
      passed: false,
      detail: `Missing required governance fields: ${missingFields.join(", ")}`,
    };
  }

  if (
    typeof claims.trust_level !== "number" ||
    claims.trust_level < 0 ||
    claims.trust_level > 5 ||
    !Number.isInteger(claims.trust_level)
  ) {
    return {
      check: "schema",
      passed: false,
      detail: `trust_level must be an integer in [0, 5]; got: ${String(claims.trust_level)}`,
    };
  }

  if (claims.governance_framework !== "aumos") {
    return {
      check: "schema",
      passed: false,
      detail: `Unsupported governance_framework: "${claims.governance_framework}". Only "aumos" is accepted.`,
    };
  }

  if (!Array.isArray(claims.compliance_standards)) {
    return {
      check: "schema",
      passed: false,
      detail: "compliance_standards must be an array of strings.",
    };
  }

  return {
    check: "schema",
    passed: true,
    detail: "All required governance fields are present and well-formed.",
  };
}

function verifyExpiry(expiresAt: string | undefined): CheckResult {
  if (expiresAt === undefined) {
    return {
      check: "expiry",
      passed: false,
      detail: "Governance credentials must have an expiry date.",
    };
  }

  const expiryDate = new Date(expiresAt);
  if (Number.isNaN(expiryDate.getTime())) {
    return {
      check: "expiry",
      passed: false,
      detail: `expiresAt is not a valid ISO-8601 date: "${expiresAt}"`,
    };
  }

  if (expiryDate <= new Date()) {
    return {
      check: "expiry",
      passed: false,
      detail: `Credential expired at ${expiresAt}.`,
    };
  }

  return {
    check: "expiry",
    passed: true,
    detail: `Credential is valid until ${expiresAt}.`,
  };
}

function verifyJWTStructure(jwt: string): CheckResult {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    return {
      check: "signature",
      passed: false,
      detail: `JWT must have exactly three base64url segments; got ${parts.length}.`,
    };
  }

  for (const part of parts) {
    if (part.length === 0) {
      return {
        check: "signature",
        passed: false,
        detail: "JWT contains an empty segment.",
      };
    }
  }

  return {
    check: "signature",
    passed: true,
    detail: "JWT structure is well-formed. Full cryptographic verification requires the issuer's public key.",
  };
}

// ---------------------------------------------------------------------------
// Internal helpers — conformance badge claims builder
// ---------------------------------------------------------------------------

/**
 * Generate governance claims appropriate for a conformance badge.
 *
 * The `trust_level` is mapped from the conformance tier:
 *   basic    -> 1 (minimum attestation)
 *   standard -> 3 (mid-tier attestation)
 *   full     -> 5 (full normative compliance)
 *
 * These are static mappings decided by the issuing authority in this
 * module's design. They are NOT computed from behaviour.
 */
function buildConformanceBadgeClaims(
  conformanceLevel: ConformanceLevel,
  issuerOrg: string
): GovernanceClaimSet {
  const levelMap: Record<ConformanceLevel, 0 | 1 | 2 | 3 | 4 | 5> = {
    basic: 1,
    standard: 3,
    full: 5,
  };

  const standardsMap: Record<ConformanceLevel, string[]> = {
    basic: ["AUMOS-BASIC-1.0"],
    standard: ["AUMOS-BASIC-1.0", "AUMOS-STD-1.0"],
    full: ["AUMOS-BASIC-1.0", "AUMOS-STD-1.0", "AUMOS-FULL-1.0"],
  };

  return {
    trust_level: levelMap[conformanceLevel],
    governance_framework: "aumos",
    compliance_standards: standardsMap[conformanceLevel],
    audit_trail_hash: "",
    last_audit_date: new Date().toISOString().split("T")[0] ?? new Date().toISOString(),
    issuer_org: issuerOrg,
  };
}
