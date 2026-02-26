// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * Example: Owner → Agent delegation using AgentDelegation credentials.
 *
 * Demonstrates the delegation pattern:
 *   Owner (human DID) issues an AgentDelegation VC to Agent A.
 *   Agent A packages its delegation VC into a Verifiable Presentation
 *   to prove authority when calling a downstream service.
 *
 * Run:
 *   npx ts-node --esm examples/delegation-chain.ts
 */

import { AgentDIDManager } from "../src/index.js";

async function run(): Promise<void> {
  const manager = new AgentDIDManager();

  // -------------------------------------------------------------------------
  // 1. Create the owner identity.
  //    In a real system this would be a human's DID managed externally.
  //    Here we create a local did:key for demonstration.
  // -------------------------------------------------------------------------
  const ownerIdentity = await manager.createAgentDID({
    method: "did:key",
    agentAlias: "alice-owner",
  });
  console.log("Owner DID:", ownerIdentity.did);

  // -------------------------------------------------------------------------
  // 2. Create the agent identity that will receive the delegation.
  // -------------------------------------------------------------------------
  const agentIdentity = await manager.createAgentDID({
    method: "did:key",
    agentAlias: "invoice-processor-agent",
  });
  console.log("Agent DID:", agentIdentity.did);

  // -------------------------------------------------------------------------
  // 3. Owner issues an AgentDelegation credential to the agent.
  //    The credential authorises the agent to create invoices on Alice's behalf.
  // -------------------------------------------------------------------------
  const delegationVC = await manager.issueAgentCredential({
    issuerDID: ownerIdentity.did,
    agentDID: agentIdentity.did,
    credentialType: "AgentDelegation",
    claims: {
      credentialType: "AgentDelegation",
      ownerDID: ownerIdentity.did,
      delegationScope: "scoped:invoice.create",
      delegatedCapabilities: ["invoice.create", "invoice.send"],
    },
    expirySeconds: 28_800, // 8 hours
  });

  console.log("\n--- Delegation Credential ---");
  console.log("Issuer (owner):", delegationVC.issuerDID);
  console.log("Subject (agent):", delegationVC.subjectDID);
  console.log("Type:", delegationVC.credentialType);
  console.log("Expires:", delegationVC.expiresAt);

  // -------------------------------------------------------------------------
  // 4. Also issue an AgentIdentity credential so the VP carries both.
  // -------------------------------------------------------------------------
  const identityVC = await manager.issueAgentCredential({
    issuerDID: ownerIdentity.did,
    agentDID: agentIdentity.did,
    credentialType: "AgentIdentity",
    claims: {
      credentialType: "AgentIdentity",
      agentName: "Invoice Processor Agent",
      agentVersion: "2.1.0",
      agentType: "worker",
      registeredAt: agentIdentity.createdAt,
    },
    expirySeconds: 86_400,
  });

  // -------------------------------------------------------------------------
  // 5. Agent builds a Verifiable Presentation containing both credentials.
  //    The agent signs the VP with its own private key.
  //    A nonce from the verifier prevents replay attacks.
  // -------------------------------------------------------------------------
  const presentation = await manager.buildPresentation({
    holderDID: agentIdentity.did,
    credentials: [identityVC, delegationVC],
    challenge: "verifier-nonce-8f2a9c1d",
    domain: "https://billing.example.com",
    expirySeconds: 300, // 5 minutes — presentations are short-lived
  });

  console.log("\n--- Verifiable Presentation ---");
  console.log("Holder:", presentation.holderDID);
  console.log("Credentials bundled:", presentation.credentials.length);
  console.log("Created at:", presentation.createdAt);
  console.log("VP JWT (truncated):", presentation.jwt.slice(0, 80) + "...");

  // -------------------------------------------------------------------------
  // 6. Verify the individual delegation credential.
  //    The downstream service can verify each credential independently.
  // -------------------------------------------------------------------------
  const delegationVerification = await manager.verifyCredential(delegationVC);

  console.log("\n--- Delegation Verification ---");
  console.log("Valid:", delegationVerification.valid);
  if (
    delegationVerification.valid &&
    delegationVerification.claims?.credentialType === "AgentDelegation"
  ) {
    const claims = delegationVerification.claims;
    console.log("Owner DID:", claims.ownerDID);
    console.log("Scope:", claims.delegationScope);
    console.log("Delegated capabilities:", claims.delegatedCapabilities);
  }

  // -------------------------------------------------------------------------
  // 7. Summarise the agent identity view.
  // -------------------------------------------------------------------------
  const summary = agentIdentity.toSummary();
  console.log("\n--- Agent Identity Summary ---");
  console.log("DID:", summary.did);
  console.log("Alias:", summary.alias);
  console.log("Method:", summary.method);
  console.log("Deactivated:", summary.deactivated);
  console.log(
    "Verification methods:",
    summary.verificationMethodIds.join(", ").slice(0, 60) + "..."
  );
}

run().catch((error: unknown) => {
  console.error(
    "Error:",
    error instanceof Error ? error.message : String(error)
  );
  process.exit(1);
});
