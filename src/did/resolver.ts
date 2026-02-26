// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * Universal DID resolver that dispatches to registered per-method providers.
 * Implements the W3C DID Resolution specification interface.
 */

import type {
  DIDDocument,
  DIDResolutionResult,
  DIDResolutionMetadata,
  DIDDocumentMetadata,
  ParsedDID,
  Resolvable,
  ResolverRegistry,
} from "did-resolver";

export type { DIDDocument, DIDResolutionResult, ParsedDID };

/**
 * A single DID method resolver plugin.
 * Each concrete provider (WebDIDProvider, KeyDIDProvider, etc.) implements this.
 */
export interface DIDMethodResolver {
  /** The DID method prefix this resolver handles, e.g. "web" or "key". */
  readonly method: string;

  /**
   * Resolve a DID to its DID document.
   *
   * @param did - The full DID string being resolved.
   * @param parsed - The parsed DID components from `did-resolver`.
   * @param resolver - The universal resolver instance (for recursive resolution).
   * @returns The resolution result including document, metadata, and any errors.
   */
  resolve(
    did: string,
    parsed: ParsedDID,
    resolver: Resolvable
  ): Promise<DIDResolutionResult>;
}

/**
 * Options for constructing the {@link UniversalResolver}.
 */
export interface UniversalResolverOptions {
  /** One or more method-specific resolver plugins. */
  readonly resolvers: readonly DIDMethodResolver[];
  /** Cache resolved documents for this duration in milliseconds. 0 disables caching. */
  readonly cacheTtlMs?: number;
}

interface CacheEntry {
  readonly result: DIDResolutionResult;
  readonly expiresAt: number;
}

/**
 * Universal DID resolver that multiplexes resolution across registered
 * method-specific providers.
 *
 * @example
 * ```typescript
 * const resolver = new UniversalResolver({
 *   resolvers: [new KeyDIDProvider(), new WebDIDProvider()],
 *   cacheTtlMs: 60_000,
 * });
 * const doc = await resolver.resolve("did:key:z6Mk...");
 * ```
 */
export class UniversalResolver implements Resolvable {
  private readonly registry: Map<string, DIDMethodResolver>;
  private readonly cache: Map<string, CacheEntry>;
  private readonly cacheTtlMs: number;

  constructor(options: UniversalResolverOptions) {
    this.registry = new Map();
    this.cache = new Map();
    this.cacheTtlMs = options.cacheTtlMs ?? 0;

    for (const resolver of options.resolvers) {
      this.registry.set(resolver.method, resolver);
    }
  }

  /**
   * Register an additional DID method resolver at runtime.
   * Overwrites any previously registered resolver for the same method.
   */
  registerMethod(resolver: DIDMethodResolver): void {
    this.registry.set(resolver.method, resolver);
  }

  /**
   * Resolve a DID string to a {@link DIDDocument}.
   * Throws if the DID is malformed or no resolver is registered for its method.
   */
  async resolve(
    did: string,
    _options?: Record<string, unknown>
  ): Promise<DIDResolutionResult> {
    const cachedEntry = this.cache.get(did);
    if (cachedEntry !== undefined && cachedEntry.expiresAt > Date.now()) {
      return cachedEntry.result;
    }

    const parsed = parseDID(did);
    if (parsed === null) {
      return buildErrorResult("invalidDid", `Malformed DID: ${did}`);
    }

    const methodResolver = this.registry.get(parsed.method);
    if (methodResolver === undefined) {
      return buildErrorResult(
        "unsupportedDidMethod",
        `No resolver registered for method: ${parsed.method}`
      );
    }

    let result: DIDResolutionResult;
    try {
      result = await methodResolver.resolve(did, parsed, this);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "Unknown resolution error";
      return buildErrorResult("notFound", message);
    }

    if (this.cacheTtlMs > 0 && result.resolutionMetadata.error === undefined) {
      this.cache.set(did, {
        result,
        expiresAt: Date.now() + this.cacheTtlMs,
      });
    }

    return result;
  }

  /**
   * Build a `did-resolver` compatible {@link ResolverRegistry} for use with
   * third-party libraries that accept that interface.
   */
  toResolverRegistry(): ResolverRegistry {
    const registry: ResolverRegistry = {};
    for (const [method, resolver] of this.registry) {
      registry[method] = (
        did: string,
        parsed: ParsedDID,
        resolvable: Resolvable
      ) => resolver.resolve(did, parsed, resolvable);
    }
    return registry;
  }

  /** Remove all cached resolution results. */
  clearCache(): void {
    this.cache.clear();
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse a raw DID string into its components.
 * Returns null for strings that do not match the DID syntax.
 *
 * DID syntax: did:<method>:<method-specific-id>
 */
function parseDID(did: string): ParsedDID | null {
  const match = /^did:([a-z0-9]+):([^#?]+)([#?].*)?$/.exec(did);
  if (match === null) return null;

  const method = match[1];
  const id = match[2];
  const fragment = match[3] ?? "";

  if (method === undefined || id === undefined) return null;

  return {
    did,
    method,
    id,
    didUrl: did + fragment,
    path: undefined,
    query: undefined,
    fragment: fragment.startsWith("#") ? fragment.slice(1) : undefined,
    params: undefined,
  };
}

function buildErrorResult(
  error: string,
  message: string
): DIDResolutionResult {
  const resolutionMetadata: DIDResolutionMetadata = { error, message };
  const docMeta: DIDDocumentMetadata = {};
  return {
    resolutionMetadata,
    didDocument: null,
    didDocumentMetadata: docMeta,
  };
}

export { buildErrorResult, parseDID };
