// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * AgentDIDManager — the primary entry point for the agent-did-framework.
 *
 * Orchestrates DID creation, resolution, credential issuance and verification,
 * and DID deactivation. All state is delegated to the injected stores.
 *
 * FIRE LINE:
 * - No ZK proof generation or verification.
 * - No trust level fields in VC schemas.
 * - No ERC-8004 or on-chain smart contract interaction.
 * - Credentials are generic agent credentials; not AumOS-proprietary.
 */

import type { DIDDocument } from "did-resolver";
import { AgentDIDIdentity } from "./identity.js";
import type {
  CreateAgentDIDOptions,
  IssueCredentialOptions,
  VerifiableCredential,
  VerificationResult,
  DIDMethod,
} from "./types.js";
import type { FrameworkConfig } from "../config.js";
import { buildDefaultCredentialConfig, buildDefaultResolverConfig } from "../config.js";
import { InMemoryDIDStore, InMemoryCredentialStore } from "../storage/memory.js";
import type { DIDStore, CredentialStore } from "../storage/interface.js";
import { UniversalResolver } from "../did/resolver.js";
import { KeyDIDProvider, generateKeyPair } from "../did/key.js";
import { WebDIDProvider } from "../did/web.js";
import { EthrDIDProvider } from "../did/ethr.js";
import { CredentialIssuer } from "../credentials/issuer.js";
import { CredentialVerifier } from "../credentials/verifier.js";
import { PresentationBuilder } from "../credentials/presentation.js";
import type { BuildPresentationOptions } from "../credentials/presentation.js";
import type { VerifiablePresentation } from "./types.js";

// ---------------------------------------------------------------------------
// Factory options
// ---------------------------------------------------------------------------

/**
 * Constructor options for {@link AgentDIDManager}.
 * All fields are optional — sensible defaults are used when omitted.
 */
export interface AgentDIDManagerOptions {
  readonly didStore?: DIDStore | undefined;
  readonly credentialStore?: CredentialStore | undefined;
  readonly config?: Partial<
    Pick<FrameworkConfig, "credential" | "resolver" | "additionalResolvers">
  > | undefined;
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/**
 * Primary facade for the agent-did-framework.
 *
 * @example
 * ```typescript
 * const manager = new AgentDIDManager();
 * const identity = await manager.createAgentDID({
 *   method: "did:key",
 *   agentAlias: "my-research-agent",
 * });
 * const vc = await manager.issueAgentCredential({
 *   issuerDID: identity.did,
 *   agentDID: identity.did,
 *   credentialType: "AgentIdentity",
 *   claims: {
 *     credentialType: "AgentIdentity",
 *     agentName: "my-research-agent",
 *     agentVersion: "1.0.0",
 *     agentType: "assistant",
 *     registeredAt: new Date().toISOString(),
 *   },
 * });
 * ```
 */
export class AgentDIDManager {
  private readonly didStore: DIDStore;
  private readonly credentialStore: CredentialStore;
  private readonly resolver: UniversalResolver;
  private readonly issuer: CredentialIssuer;
  private readonly verifier: CredentialVerifier;
  private readonly presentationBuilder: PresentationBuilder;

  constructor(options: AgentDIDManagerOptions = {}) {
    this.didStore = options.didStore ?? new InMemoryDIDStore();
    this.credentialStore =
      options.credentialStore ?? new InMemoryCredentialStore();

    const credentialConfig =
      options.config?.credential ?? buildDefaultCredentialConfig();
    const resolverConfig =
      options.config?.resolver ?? buildDefaultResolverConfig();
    const additionalResolvers = options.config?.additionalResolvers ?? [];

    const builtInResolvers = [
      new KeyDIDProvider(),
      new WebDIDProvider({ timeoutMs: resolverConfig.httpTimeoutMs }),
    ];

    if (resolverConfig.ethereumNetworks.length > 0) {
      builtInResolvers.push(
        new EthrDIDProvider({ networks: resolverConfig.ethereumNetworks })
      );
    }

    this.resolver = new UniversalResolver({
      resolvers: [...builtInResolvers, ...additionalResolvers],
      cacheTtlMs: resolverConfig.cacheTtlMs,
    });

    this.issuer = new CredentialIssuer({
      didStore: this.didStore,
      credentialStore: this.credentialStore,
      config: credentialConfig,
    });

    this.verifier = new CredentialVerifier({
      credentialStore: this.credentialStore,
      resolver: this.resolver,
    });

    this.presentationBuilder = new PresentationBuilder({
      didStore: this.didStore,
    });
  }

  // ---------------------------------------------------------------------------
  // DID management
  // ---------------------------------------------------------------------------

  /**
   * Create a new agent DID identity and persist it to the local store.
   *
   * For `did:key`, a fresh Ed25519 key pair is generated automatically.
   * For `did:web` and `did:ethr`, the DID is registered locally but key
   * management is the caller's responsibility.
   *
   * @throws {Error} If `opts.method` is `"did:web"` and `opts.webDomain` is absent.
   * @throws {Error} If `opts.method` is `"did:ethr"` and `opts.ethrAddress` is absent.
   */
  async createAgentDID(
    opts: CreateAgentDIDOptions
  ): Promise<AgentDIDIdentity> {
    const now = new Date().toISOString();

    switch (opts.method) {
      case "did:key":
        return this.createKeyDID(opts.agentAlias, now);

      case "did:web":
        return this.createWebDID(opts, now);

      case "did:ethr":
        return this.createEthrDID(opts, now);

      default: {
        const _exhaustive: never = opts.method;
        throw new Error(`Unsupported DID method: ${String(_exhaustive)}`);
      }
    }
  }

  private async createKeyDID(
    alias: string,
    now: string
  ): Promise<AgentDIDIdentity> {
    const { did, publicKey, privateKey } = await generateKeyPair();

    const resolution = await this.resolver.resolve(did);
    if (
      resolution.didDocument === null ||
      resolution.resolutionMetadata.error !== undefined
    ) {
      throw new Error(
        `Unexpected failure resolving newly created did:key "${did}": ` +
          (resolution.resolutionMetadata.error ?? "unknown")
      );
    }

    const document: DIDDocument = resolution.didDocument;

    await this.didStore.create({
      did,
      document,
      privateKey,
      alias,
      method: "key",
      createdAt: now,
      updatedAt: now,
      deactivated: false,
    });

    // Suppress unused publicKey — stored in DID document via multibase encoding.
    void publicKey;

    return new AgentDIDIdentity({
      did,
      document,
      alias,
      method: "did:key",
      createdAt: now,
      deactivated: false,
      privateKey,
    });
  }

  private async createWebDID(
    opts: CreateAgentDIDOptions,
    now: string
  ): Promise<AgentDIDIdentity> {
    if (opts.webDomain === undefined || opts.webDomain.length === 0) {
      throw new Error(
        'opts.webDomain is required when method is "did:web". ' +
          'Example: "example.com:agents:my-agent"'
      );
    }

    const did = `did:web:${opts.webDomain}`;

    // did:web documents are hosted externally — generate a placeholder document
    // so the manager has something to store. The caller is responsible for
    // publishing the actual document at the well-known URL.
    const keyPair = await generateKeyPair();
    const resolution = await this.resolver.resolve(keyPair.did);
    if (resolution.didDocument === null) {
      throw new Error("Failed to generate key document for did:web placeholder");
    }

    const document: DIDDocument = {
      ...resolution.didDocument,
      id: did,
    };

    await this.didStore.create({
      did,
      document,
      privateKey: keyPair.privateKey,
      alias: opts.agentAlias,
      method: "web",
      createdAt: now,
      updatedAt: now,
      deactivated: false,
    });

    return new AgentDIDIdentity({
      did,
      document,
      alias: opts.agentAlias,
      method: "did:web",
      createdAt: now,
      deactivated: false,
      privateKey: keyPair.privateKey,
    });
  }

  private async createEthrDID(
    opts: CreateAgentDIDOptions,
    now: string
  ): Promise<AgentDIDIdentity> {
    if (opts.ethrAddress === undefined || opts.ethrAddress.length === 0) {
      throw new Error(
        'opts.ethrAddress is required when method is "did:ethr". ' +
          'Example: "0xabc123..."'
      );
    }

    const did = `did:ethr:${opts.ethrAddress}`;

    // did:ethr documents are resolved from the Ethereum network.
    // Store a minimal placeholder locally.
    const document: DIDDocument = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: [],
    };

    await this.didStore.create({
      did,
      document,
      alias: opts.agentAlias,
      method: "ethr",
      createdAt: now,
      updatedAt: now,
      deactivated: false,
    });

    return new AgentDIDIdentity({
      did,
      document,
      alias: opts.agentAlias,
      method: "did:ethr",
      createdAt: now,
      deactivated: false,
    });
  }

  /**
   * Resolve a DID string to its {@link DIDDocument}.
   *
   * @throws {Error} If resolution fails or the method is unsupported.
   */
  async resolveAgentDID(did: string): Promise<DIDDocument> {
    const result = await this.resolver.resolve(did);
    if (
      result.resolutionMetadata.error !== undefined ||
      result.didDocument === null
    ) {
      throw new Error(
        `DID resolution failed for "${did}": ` +
          (result.resolutionMetadata.error ?? "not found")
      );
    }
    return result.didDocument;
  }

  /**
   * Deactivate a locally-managed agent DID.
   *
   * Deactivated DIDs remain in the store but cannot issue or present credentials.
   *
   * @throws {Error} If the DID is not found in the local store.
   */
  async deactivateAgentDID(did: string): Promise<void> {
    const existing = await this.didStore.get(did);
    if (existing === undefined) {
      throw new Error(
        `Cannot deactivate DID "${did}": not found in local store`
      );
    }
    await this.didStore.update(did, { deactivated: true });
  }

  // ---------------------------------------------------------------------------
  // Credential operations
  // ---------------------------------------------------------------------------

  /**
   * Issue a Verifiable Credential for an agent.
   * The issuer must be a locally-managed `did:key` identity with a private key.
   */
  async issueAgentCredential(
    opts: IssueCredentialOptions
  ): Promise<VerifiableCredential> {
    return this.issuer.issue(opts);
  }

  /**
   * Verify a Verifiable Credential.
   *
   * Checks signature validity, expiry, revocation, and structural conformance.
   * Never mutates any state.
   */
  async verifyCredential(
    vc: VerifiableCredential
  ): Promise<VerificationResult> {
    return this.verifier.verify(vc);
  }

  // ---------------------------------------------------------------------------
  // Presentation operations
  // ---------------------------------------------------------------------------

  /**
   * Build a signed Verifiable Presentation from one or more VCs.
   */
  async buildPresentation(
    options: BuildPresentationOptions
  ): Promise<VerifiablePresentation> {
    return this.presentationBuilder.build(options);
  }

  // ---------------------------------------------------------------------------
  // Store accessors
  // ---------------------------------------------------------------------------

  /**
   * Retrieve a locally-stored agent identity by DID.
   *
   * @returns The identity, or `undefined` when not found.
   */
  async getAgentIdentity(did: string): Promise<AgentDIDIdentity | undefined> {
    const record = await this.didStore.get(did);
    if (record === undefined) return undefined;

    return new AgentDIDIdentity({
      did: record.did,
      document: record.document,
      alias: record.alias,
      method: storageMethodToDIDMethod(record.method),
      createdAt: record.createdAt,
      deactivated: record.deactivated,
      privateKey: record.privateKey,
    });
  }

  /**
   * List all locally-stored agent identities.
   */
  async listAgentIdentities(): Promise<readonly AgentDIDIdentity[]> {
    const records = await this.didStore.list();
    return records.map(
      (record) =>
        new AgentDIDIdentity({
          did: record.did,
          document: record.document,
          alias: record.alias,
          method: storageMethodToDIDMethod(record.method),
          createdAt: record.createdAt,
          deactivated: record.deactivated,
          privateKey: record.privateKey,
        })
    );
  }

  /**
   * Expose the underlying Universal Resolver for advanced use cases.
   */
  get universalResolver(): UniversalResolver {
    return this.resolver;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function storageMethodToDIDMethod(method: "key" | "web" | "ethr"): DIDMethod {
  switch (method) {
    case "key":
      return "did:key";
    case "web":
      return "did:web";
    case "ethr":
      return "did:ethr";
  }
}
