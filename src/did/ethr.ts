// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @packageDocumentation
 * did:ethr provider — Ethereum-based DID method (optional).
 *
 * did:ethr DIDs are anchored to an Ethereum address. Resolution looks up the
 * on-chain ERC-1056 `DIDAttributeChanged` / `DIDDelegateChanged` event log
 * to build the DID document.
 *
 * This provider is intentionally minimal: it resolves against a pre-configured
 * RPC endpoint and does NOT interact with any on-chain smart contracts during
 * DID creation (creation is purely local — an Ethereum address IS a DID).
 *
 * FIRE LINE: no ERC-8004, no on-chain smart contract writes.
 *
 * Spec: https://github.com/decentralized-identity/ethr-did-resolver
 */

import type { DIDDocument, DIDResolutionResult, ParsedDID, Resolvable } from "did-resolver";
import type { DIDMethodResolver } from "./resolver.js";
import { buildErrorResult } from "./resolver.js";

/**
 * The Ethereum network configuration for a single chain.
 */
export interface EthereumNetworkConfig {
  /** Chain ID (e.g. 1 for Ethereum mainnet, 11155111 for Sepolia). */
  readonly chainId: number;
  /** Human-readable name (e.g. "mainnet", "sepolia"). */
  readonly name: string;
  /** JSON-RPC endpoint URL. */
  readonly rpcUrl: string;
  /**
   * Address of the ERC-1056 EthereumDIDRegistry contract on this chain.
   * Defaults to the canonical deployment: 0xdca7ef03e98e0dc2b855be647c39abe984fcf21b
   */
  readonly registryAddress?: string;
}

/**
 * Options for {@link EthrDIDProvider}.
 */
export interface EthrDIDProviderOptions {
  /** One or more Ethereum network configurations. */
  readonly networks: readonly EthereumNetworkConfig[];
  /**
   * HTTP client for JSON-RPC calls.
   * Defaults to the global `fetch`.
   */
  readonly fetchImplementation?: (
    url: string,
    init: RequestInit
  ) => Promise<Response>;
}

/** Default ERC-1056 registry address (canonical deployment). */
const DEFAULT_REGISTRY_ADDRESS =
  "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b";

/**
 * did:ethr DID method resolver (Ethereum-based, optional).
 *
 * Supports multi-network resolution via the `chainId` encoded in the DID.
 *
 * @example
 * ```typescript
 * const provider = new EthrDIDProvider({
 *   networks: [
 *     { chainId: 1, name: "mainnet", rpcUrl: "https://rpc.example.com" },
 *   ],
 * });
 * const result = await resolver.resolve("did:ethr:0x123...");
 * ```
 */
export class EthrDIDProvider implements DIDMethodResolver {
  readonly method = "ethr";

  private readonly networks: Map<number, EthereumNetworkConfig>;
  private readonly fetchFn: (url: string, init: RequestInit) => Promise<Response>;

  constructor(options: EthrDIDProviderOptions) {
    this.networks = new Map();
    this.fetchFn = options.fetchImplementation ?? globalFetch;

    for (const network of options.networks) {
      this.networks.set(network.chainId, network);
    }
  }

  async resolve(
    did: string,
    parsed: ParsedDID,
    _resolver: Resolvable
  ): Promise<DIDResolutionResult> {
    let parsed2: ParsedEthrDID;
    try {
      parsed2 = parseEthrDID(parsed.id);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "Invalid did:ethr format";
      return buildErrorResult("invalidDid", message);
    }

    const network = this.resolveNetwork(parsed2.chainId);
    if (network === undefined) {
      return buildErrorResult(
        "unsupportedDidMethod",
        `No Ethereum network configured for chainId ${parsed2.chainId}`
      );
    }

    let document: DIDDocument;
    try {
      document = await this.fetchDIDDocument(
        did,
        parsed2.address,
        network
      );
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "RPC resolution failed";
      return buildErrorResult("notFound", message);
    }

    return {
      resolutionMetadata: {},
      didDocument: document,
      didDocumentMetadata: {},
    };
  }

  private resolveNetwork(
    chainId: number | undefined
  ): EthereumNetworkConfig | undefined {
    if (chainId !== undefined) {
      return this.networks.get(chainId);
    }
    // Fall back to chainId 1 (mainnet) when no chainId is encoded in the DID.
    return this.networks.get(1);
  }

  /**
   * Fetch the DID document by querying the EthereumDIDRegistry for attribute
   * and delegate events on the given address.
   *
   * This implementation constructs a minimal conforming DID document from the
   * controller address alone. A production integration should replay the
   * full ERC-1056 event log to include additional verification methods and
   * service endpoints.
   */
  private async fetchDIDDocument(
    did: string,
    address: string,
    network: EthereumNetworkConfig
  ): Promise<DIDDocument> {
    const registryAddress =
      network.registryAddress ?? DEFAULT_REGISTRY_ADDRESS;
    const controller = await this.lookupController(
      address,
      registryAddress,
      network.rpcUrl
    );

    const keyId = `${did}#controller`;

    return {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/secp256k1recovery-2020/v2",
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: "EcdsaSecp256k1RecoveryMethod2020",
          controller: did,
          blockchainAccountId: `eip155:${network.chainId}:${controller}`,
        },
      ],
      authentication: [keyId],
      assertionMethod: [keyId],
    };
  }

  /**
   * Call `identityOwner(address)` on the ERC-1056 registry contract via eth_call.
   * Returns the controller address (may differ from `address` if ownership was transferred).
   */
  private async lookupController(
    address: string,
    registryAddress: string,
    rpcUrl: string
  ): Promise<string> {
    // Function selector for identityOwner(address): keccak256 first 4 bytes = 0x8733d4e8
    const selector = "0x8733d4e8";
    const paddedAddress = address.slice(2).padStart(64, "0");
    const callData = selector + paddedAddress;

    const requestBody = JSON.stringify({
      jsonrpc: "2.0",
      method: "eth_call",
      params: [
        { to: registryAddress, data: callData },
        "latest",
      ],
      id: 1,
    });

    const response = await this.fetchFn(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: requestBody,
    });

    if (!response.ok) {
      throw new Error(`JSON-RPC request failed: HTTP ${response.status}`);
    }

    const json = await response.json() as { result?: string; error?: { message: string } };

    if (json.error !== undefined) {
      throw new Error(`eth_call error: ${json.error.message}`);
    }

    if (typeof json.result !== "string") {
      throw new Error("Unexpected eth_call response: result is not a string");
    }

    // The result is a 32-byte hex-encoded address — take the last 20 bytes.
    const rawHex = json.result.slice(2);
    const controllerHex = rawHex.slice(rawHex.length - 40);
    return `0x${controllerHex}`;
  }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

interface ParsedEthrDID {
  readonly address: string;
  readonly chainId: number | undefined;
}

/**
 * Parse the method-specific part of a did:ethr DID.
 *
 * Supported formats:
 * - `did:ethr:0x<address>`          (mainnet, no chain prefix)
 * - `did:ethr:0x<chainId>:<address>` (hex chain ID prefix)
 * - `did:ethr:<networkName>:<address>` (unsupported — must use chainId)
 */
function parseEthrDID(methodSpecificId: string): ParsedEthrDID {
  // Format: [chainId:]address
  const colonIndex = methodSpecificId.indexOf(":");

  if (colonIndex === -1) {
    // No colon — the whole string is the address.
    validateEthAddress(methodSpecificId);
    return { address: methodSpecificId, chainId: undefined };
  }

  const prefix = methodSpecificId.slice(0, colonIndex);
  const address = methodSpecificId.slice(colonIndex + 1);

  validateEthAddress(address);

  // Prefix is either a hex chainId (0x...) or a decimal number.
  let chainId: number;
  if (prefix.startsWith("0x")) {
    chainId = parseInt(prefix, 16);
  } else {
    chainId = parseInt(prefix, 10);
  }

  if (isNaN(chainId) || chainId <= 0) {
    throw new Error(
      `Invalid chainId prefix in did:ethr DID: "${prefix}". Must be a decimal or hex integer.`
    );
  }

  return { address, chainId };
}

function validateEthAddress(address: string): void {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(
      `Invalid Ethereum address in did:ethr DID: "${address}". Must be a 20-byte hex string prefixed with 0x.`
    );
  }
}

function globalFetch(url: string, init: RequestInit): Promise<Response> {
  return fetch(url, init);
}
