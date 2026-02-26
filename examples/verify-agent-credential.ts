// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * Example: Verify an agent credential and check its claims.
 *
 * Demonstrates:
 * - Receiving a VC JWT from an untrusted party
 * - Running full cryptographic verification
 * - Inspecting the verified claims
 * - Handling verification failure cases
 *
 * Run:
 *   npx ts-node --esm examples/verify-agent-credential.ts
 */

import { AgentDIDManager } from "../src/index.js";
import type { VerifiableCredential } from "../src/index.js";

async function run(): Promise<void> {
  // -------------------------------------------------------------------------
  // Setup: create issuer and agent identities.
  // -------------------------------------------------------------------------
  const manager = new AgentDIDManager();

  const issuerIdentity = await manager.createAgentDID({
    method: "did:key",
    agentAlias: "operator-issuer",
  });

  const agentIdentity = await manager.createAgentDID({
    method: "did:key",
    agentAlias: "worker-agent",
  });

  console.log("Issuer DID:", issuerIdentity.did);
  console.log("Agent DID:", agentIdentity.did);

  // -------------------------------------------------------------------------
  // 1. Issue a capability credential from the operator to the agent.
  // -------------------------------------------------------------------------
  const vc = await manager.issueAgentCredential({
    issuerDID: issuerIdentity.did,
    agentDID: agentIdentity.did,
    credentialType: "AgentCapability",
    claims: {
      credentialType: "AgentCapability",
      capability: "database.query",
      description: "Read-only SQL query access to the reporting database",
      resourceScope: ["urn:db:reporting"],
    },
    expirySeconds: 7_200,
  });

  console.log("\n--- Issued Credential JWT ---");
  console.log(vc.jwt.slice(0, 80) + "...");

  // -------------------------------------------------------------------------
  // 2. Verify the credential (happy path).
  // -------------------------------------------------------------------------
  console.log("\n--- Verifying credential (should be valid) ---");
  const result = await manager.verifyCredential(vc);

  console.log("valid:", result.valid);
  console.log("issuer:", result.issuer);
  console.log("expiry:", result.expiry);
  if (result.valid && result.claims !== undefined) {
    const claims = result.claims;
    if (claims.credentialType === "AgentCapability") {
      console.log("capability:", claims.capability);
      console.log("resourceScope:", claims.resourceScope);
    }
  }

  // -------------------------------------------------------------------------
  // 3. Verify a tampered JWT (failure path — signature mismatch).
  //    Flip one character in the signature to simulate tampering.
  // -------------------------------------------------------------------------
  const parts = vc.jwt.split(".");
  if (parts.length === 3 && parts[2] !== undefined) {
    const tamperedSignature = parts[2].slice(0, -1) + (parts[2].endsWith("a") ? "b" : "a");
    const tamperedJWT = `${parts[0]}.${parts[1]}.${tamperedSignature}`;

    const tamperedVC: VerifiableCredential = {
      ...vc,
      jwt: tamperedJWT,
    };

    console.log("\n--- Verifying tampered credential (should fail) ---");
    const tamperedResult = await manager.verifyCredential(tamperedVC);
    console.log("valid:", tamperedResult.valid);
    console.log("failureReason:", tamperedResult.failureReason);
  }

  // -------------------------------------------------------------------------
  // 4. Deactivate the issuer and confirm that new credentials cannot be issued.
  // -------------------------------------------------------------------------
  await manager.deactivateAgentDID(issuerIdentity.did);
  console.log("\nIssuer DID deactivated.");

  try {
    await manager.issueAgentCredential({
      issuerDID: issuerIdentity.did,
      agentDID: agentIdentity.did,
      credentialType: "AgentIdentity",
      claims: {
        credentialType: "AgentIdentity",
        agentName: "worker-agent",
        agentVersion: "1.0.0",
        agentType: "worker",
        registeredAt: agentIdentity.createdAt,
      },
    });
    console.error("ERROR: Should have thrown for deactivated issuer.");
  } catch (error: unknown) {
    console.log(
      "Expected error for deactivated issuer:",
      error instanceof Error ? error.message.slice(0, 80) : "unknown"
    );
  }
}

run().catch((error: unknown) => {
  console.error(
    "Error:",
    error instanceof Error ? error.message : String(error)
  );
  process.exit(1);
});
