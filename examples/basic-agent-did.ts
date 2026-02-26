// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * Example: Create an agent DID and issue an AgentCapability credential.
 *
 * Demonstrates:
 * - Creating a did:key identity for an agent
 * - Issuing an AgentIdentity credential (self-attested)
 * - Issuing an AgentCapability credential
 * - Inspecting the resulting JWT credentials
 *
 * Run:
 *   npx ts-node --esm examples/basic-agent-did.ts
 */

import { AgentDIDManager } from "../src/index.js";

async function run(): Promise<void> {
  // -------------------------------------------------------------------------
  // 1. Initialise the manager with default in-memory stores.
  // -------------------------------------------------------------------------
  const manager = new AgentDIDManager();

  // -------------------------------------------------------------------------
  // 2. Create a did:key identity for the agent.
  //    A fresh Ed25519 key pair is generated automatically.
  // -------------------------------------------------------------------------
  const agentIdentity = await manager.createAgentDID({
    method: "did:key",
    agentAlias: "research-agent-v1",
  });

  console.log("Created agent DID:", agentIdentity.did);
  console.log("Alias:", agentIdentity.alias);
  console.log("Has local key:", agentIdentity.hasLocalKey);
  console.log(
    "Authentication key ID:",
    agentIdentity.primaryAuthenticationKeyId
  );

  // -------------------------------------------------------------------------
  // 3. Issue an AgentIdentity credential.
  //    The agent self-attests its own identity. In production an operator or
  //    identity authority would be the issuer.
  // -------------------------------------------------------------------------
  const identityVC = await manager.issueAgentCredential({
    issuerDID: agentIdentity.did,
    agentDID: agentIdentity.did,
    credentialType: "AgentIdentity",
    claims: {
      credentialType: "AgentIdentity",
      agentName: "Research Agent v1",
      agentVersion: "1.0.0",
      agentType: "assistant",
      registeredAt: agentIdentity.createdAt,
    },
    expirySeconds: 86_400, // 24 hours
  });

  console.log("\n--- AgentIdentity Credential ---");
  console.log("Issuer DID:", identityVC.issuerDID);
  console.log("Subject DID:", identityVC.subjectDID);
  console.log("Issued at:", identityVC.issuedAt);
  console.log("Expires at:", identityVC.expiresAt);
  console.log("JWT (truncated):", identityVC.jwt.slice(0, 60) + "...");

  // -------------------------------------------------------------------------
  // 4. Issue an AgentCapability credential.
  //    Attests that the agent can call the OpenAI API.
  // -------------------------------------------------------------------------
  const capabilityVC = await manager.issueAgentCredential({
    issuerDID: agentIdentity.did,
    agentDID: agentIdentity.did,
    credentialType: "AgentCapability",
    claims: {
      credentialType: "AgentCapability",
      capability: "api.call.openai",
      description: "Authorised to make calls to the OpenAI Chat Completions API",
      resourceScope: ["https://api.openai.com/v1/chat/completions"],
    },
    expirySeconds: 3_600, // 1 hour
  });

  console.log("\n--- AgentCapability Credential ---");
  console.log("Credential type:", capabilityVC.credentialType);
  console.log("Issuer DID:", capabilityVC.issuerDID);
  console.log("Expires at:", capabilityVC.expiresAt);

  // -------------------------------------------------------------------------
  // 5. Verify the capability credential.
  // -------------------------------------------------------------------------
  const verificationResult = await manager.verifyCredential(capabilityVC);

  console.log("\n--- Verification Result ---");
  console.log("Valid:", verificationResult.valid);
  console.log("Issuer:", verificationResult.issuer);
  console.log("Expiry:", verificationResult.expiry);

  if (verificationResult.valid && verificationResult.claims !== undefined) {
    const claims = verificationResult.claims;
    if (claims.credentialType === "AgentCapability") {
      console.log("Capability:", claims.capability);
      console.log("Description:", claims.description);
    }
  }

  // -------------------------------------------------------------------------
  // 6. List all identities in the local store.
  // -------------------------------------------------------------------------
  const allIdentities = await manager.listAgentIdentities();
  console.log(
    `\nTotal agent identities in store: ${allIdentities.length}`
  );
}

run().catch((error: unknown) => {
  console.error(
    "Error:",
    error instanceof Error ? error.message : String(error)
  );
  process.exit(1);
});
