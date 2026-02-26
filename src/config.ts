// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * Framework-wide configuration for @aumos/agent-did.
 *
 * All tunables live here. No defaults are hard-coded in individual modules.
 */

import type { DIDStore, CredentialStore } from "./storage/interface.js";
import type { DIDMethodResolver } from "./did/resolver.js";
import type { EthereumNetworkConfig } from "./did/ethr.js";

// ---------------------------------------------------------------------------
// Credential options
// ---------------------------------------------------------------------------

/**
 * Which JWT signing algorithm to use for issued Verifiable Credentials.
 * `EdDSA` (Ed25519) is the default and strongly recommended.
 */
export type ProofAlgorithm = "EdDSA";

/**
 * Configuration for the credential issuer component.
 */
export interface CredentialConfig {
  /**
   * Default JWT proof algorithm for issued credentials.
   * @defaultValue `"EdDSA"`
   */
  readonly proofAlgorithm: ProofAlgorithm;
  /**
   * Default credential lifetime in seconds.
   * Credentials issued without an explicit expiry will expire after this duration.
   * Set to `undefined` to issue non-expiring credentials by default.
   * @defaultValue `86400` (24 hours)
   */
  readonly defaultExpirySeconds: number | undefined;
}

// ---------------------------------------------------------------------------
// Resolver options
// ---------------------------------------------------------------------------

/**
 * Configuration for the DID resolver component.
 */
export interface ResolverConfig {
  /**
   * Cache resolved DID documents for this duration in milliseconds.
   * Set to `0` to disable caching.
   * @defaultValue `300_000` (5 minutes)
   */
  readonly cacheTtlMs: number;
  /**
   * HTTP request timeout for did:web and did:ethr resolution.
   * @defaultValue `5_000` (5 seconds)
   */
  readonly httpTimeoutMs: number;
  /**
   * Ethereum network configurations for did:ethr resolution.
   * An empty array disables the did:ethr provider.
   */
  readonly ethereumNetworks: readonly EthereumNetworkConfig[];
}

// ---------------------------------------------------------------------------
// Top-level framework configuration
// ---------------------------------------------------------------------------

/**
 * Top-level configuration object for the agent-did-framework.
 *
 * Pass an instance of this to {@link AgentDIDManager} at construction time.
 *
 * @example
 * ```typescript
 * const config = FrameworkConfig.create({
 *   credential: { defaultExpirySeconds: 3600 },
 * });
 * ```
 */
export interface FrameworkConfig {
  /** Credential issuer options. */
  readonly credential: CredentialConfig;
  /** DID resolver options. */
  readonly resolver: ResolverConfig;
  /**
   * Backing store for DID records.
   * Defaults to {@link InMemoryDIDStore} when not provided.
   */
  readonly didStore: DIDStore;
  /**
   * Backing store for issued credential records.
   * Defaults to {@link InMemoryCredentialStore} when not provided.
   */
  readonly credentialStore: CredentialStore;
  /**
   * Additional DID method resolvers beyond the built-in did:key and did:web.
   * Register custom method plugins here.
   */
  readonly additionalResolvers: readonly DIDMethodResolver[];
}

// ---------------------------------------------------------------------------
// Default factory
// ---------------------------------------------------------------------------

/**
 * Runtime defaults — split out so they can be imported lazily to avoid
 * circular dependency issues during module initialisation.
 */
export function buildDefaultCredentialConfig(): CredentialConfig {
  return {
    proofAlgorithm: "EdDSA",
    defaultExpirySeconds: 86_400,
  };
}

export function buildDefaultResolverConfig(): ResolverConfig {
  return {
    cacheTtlMs: 300_000,
    httpTimeoutMs: 5_000,
    ethereumNetworks: [],
  };
}
