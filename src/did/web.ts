// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * did:web provider — HTTP-based DID method.
 *
 * A did:web DID maps to a HTTPS URL where the DID document is hosted.
 * Resolution fetches `/.well-known/did.json` (or a path-specific document).
 *
 * Spec: https://w3c-ccg.github.io/did-method-web/
 */

import type { DIDDocument, DIDResolutionResult, ParsedDID, Resolvable } from "did-resolver";
import type { DIDMethodResolver } from "./resolver.js";
import { buildErrorResult } from "./resolver.js";

/**
 * Options for {@link WebDIDProvider}.
 */
export interface WebDIDProviderOptions {
  /**
   * Override the HTTP client used for fetching DID documents.
   * Defaults to the global `fetch` when not provided.
   * Useful for injecting a custom fetch in Node.js environments that
   * require certificate pinning or proxy configuration.
   */
  readonly fetchImplementation?: (url: string) => Promise<Response>;
  /**
   * Request timeout in milliseconds. Defaults to 5000.
   */
  readonly timeoutMs?: number;
}

/**
 * did:web DID method resolver.
 *
 * Fetches the DID document from the HTTPS URL encoded in the DID.
 *
 * @example
 * ```typescript
 * const provider = new WebDIDProvider({ timeoutMs: 3000 });
 * const resolver = new UniversalResolver({ resolvers: [provider] });
 * const result = await resolver.resolve("did:web:example.com");
 * ```
 */
export class WebDIDProvider implements DIDMethodResolver {
  readonly method = "web";

  private readonly fetchFn: (url: string) => Promise<Response>;
  private readonly timeoutMs: number;

  constructor(options: WebDIDProviderOptions = {}) {
    this.fetchFn = options.fetchImplementation ?? globalFetch;
    this.timeoutMs = options.timeoutMs ?? 5_000;
  }

  async resolve(
    did: string,
    parsed: ParsedDID,
    _resolver: Resolvable
  ): Promise<DIDResolutionResult> {
    let url: string;
    try {
      url = didToHttpUrl(parsed.id);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "Cannot derive URL from DID";
      return buildErrorResult("invalidDid", message);
    }

    let response: Response;
    try {
      response = await fetchWithTimeout(this.fetchFn, url, this.timeoutMs);
    } catch (error: unknown) {
      const message =
        error instanceof Error
          ? error.message
          : "Network error during DID resolution";
      return buildErrorResult("notFound", `Fetch failed for ${url}: ${message}`);
    }

    if (!response.ok) {
      return buildErrorResult(
        "notFound",
        `HTTP ${response.status} fetching DID document at ${url}`
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return buildErrorResult(
        "invalidDidDocument",
        `Response from ${url} is not valid JSON`
      );
    }

    if (!isValidDIDDocument(body)) {
      return buildErrorResult(
        "invalidDidDocument",
        `Document at ${url} does not conform to the DID Document data model`
      );
    }

    // Enforce that the document's id matches the DID being resolved.
    if (body.id !== did) {
      return buildErrorResult(
        "invalidDidDocument",
        `Document id "${body.id}" does not match requested DID "${did}"`
      );
    }

    return {
      resolutionMetadata: { contentType: "application/did+ld+json" },
      didDocument: body,
      didDocumentMetadata: {},
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Derive the HTTPS URL for a did:web document from the method-specific identifier.
 *
 * Rules (per spec):
 * - Replace each colon (after the domain) with a forward slash.
 * - Percent-decode the domain and path components.
 * - Append `/.well-known/did.json` when there is no path component.
 * - Append `/did.json` when a path component is present.
 */
export function didToHttpUrl(methodSpecificId: string): string {
  // The first segment is the domain (colons encode path separators after it).
  const segments = methodSpecificId.split(":");
  const rawDomain = segments[0];
  if (rawDomain === undefined || rawDomain.length === 0) {
    throw new Error("did:web method-specific ID must begin with a domain name");
  }

  const domain = decodeURIComponent(rawDomain);

  if (segments.length === 1) {
    // No path — use .well-known
    return `https://${domain}/.well-known/did.json`;
  }

  const pathParts = segments.slice(1).map(decodeURIComponent);
  const path = pathParts.join("/");
  return `https://${domain}/${path}/did.json`;
}

function isValidDIDDocument(value: unknown): value is DIDDocument {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate["id"] === "string" && candidate["id"].startsWith("did:");
}

async function fetchWithTimeout(
  fetchFn: (url: string) => Promise<Response>,
  url: string,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url);
  } finally {
    clearTimeout(timer);
  }
}

function globalFetch(url: string): Promise<Response> {
  return fetch(url);
}
