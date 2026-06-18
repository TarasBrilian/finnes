/**
 * demo.ts — end-to-end Finnes demo orchestration (SCAFFOLD).
 *
 * Narrates the headline flow from README "Demo flow":
 *
 *   1. shield                 transparent RWA -> confidential note
 *   2. confidential_transfer  move value A -> B (public sees only opaque data)
 *   3. regulator disclosure   auditor view key decrypts the mandatory ciphertext
 *   (stretch) settle_dvp      atomic two-asset settlement
 *
 * This is a SCAFFOLD: it does NOT run end-to-end. Every step that depends on an
 * unfinished component (@finnes/sdk, @finnes/prover, the deployed contract, the
 * compiled circuits, and the demo-only trusted setup) is a TODO stub that logs
 * what it WOULD do. Replace the stubs as those components land.
 *
 * Security:
 *   - invariant #8: never log or persist secrets (owner_sk, r, rho, witness,
 *     plaintext values, auditor_sk). This file logs only step descriptions and
 *     public data. Do not add secret values to console output.
 *
 * Run with: npm run demo   (tsx scripts/demo.ts)
 */

// NOTE: @finnes/sdk and @finnes/prover have no published surface yet (their
// src/ trees are empty). Import them once their public API exists, e.g.:
//
//   import { Wallet, Note, assemblePublicInputs } from "@finnes/sdk";
//   import { prove } from "@finnes/prover";
//
// TODO: wire real imports once sdk/src and prover/src export an API. Keeping them
// commented avoids a hard module-resolution failure while scaffolding.

// ---------------------------------------------------------------------------
// Tiny narration helpers (no framework dependency).
// ---------------------------------------------------------------------------

let stepNo = 0;

function step(title: string): void {
  stepNo += 1;
  console.log(`\n[${stepNo}] ${title}`);
}

function info(msg: string): void {
  console.log(`    ${msg}`);
}

function todo(msg: string): void {
  console.log(`    TODO(stub): ${msg}`);
}

// ---------------------------------------------------------------------------
// Demo configuration (public, non-secret values only).
// ---------------------------------------------------------------------------

interface DemoConfig {
  /** Stellar network alias. */
  readonly network: string;
  /** Deployed contract id; read from setup/build/deploy.testnet.json by deploy.sh. */
  readonly contractId: string | null;
  /** A demo RWA asset_id (Poseidon(sac_address)); placeholder until SDK derives it. */
  readonly assetIdLabel: string;
  /** Raw SAC units to shield then transfer (range-checked in-circuit, 64-bit). */
  readonly amountRaw: bigint;
}

const config: DemoConfig = {
  network: process.env.STELLAR_NETWORK ?? "testnet",
  // TODO: load from setup/build/deploy.testnet.json (written by scripts/deploy.sh).
  contractId: process.env.FINNES_CONTRACT_ID ?? null,
  assetIdLabel: "DEMO-RWA",
  amountRaw: 1_000_000n,
};

// ---------------------------------------------------------------------------
// Step implementations — all stubbed.
// ---------------------------------------------------------------------------

/** Bootstrap demo identities (institution A, institution B, regulator/auditor). */
async function setupActors(): Promise<void> {
  step("Set up demo actors (institution A, institution B, regulator)");
  info("A and B each hold a spending key + viewing key (client-zone only).");
  info("The regulator holds the auditor view key (read authority).");
  todo(
    "Generate keypairs via @finnes/sdk (Wallet). Keys stay client-side and are " +
      "NEVER logged (invariant #8). auditor_pk is distinct from issuer_authority.",
  );
}

/** Step 1: shield — transparent RWA token -> confidential note for A. */
async function shield(): Promise<void> {
  step("shield — deposit transparent RWA into a confidential note (owner: A)");
  info(`asset: ${config.assetIdLabel}, amount(raw): ${config.amountRaw} (PUBLIC on shield)`);
  info("Public inputs reveal (asset_id, amount); (owner, rho, r_note) stay hidden.");
  todo("Build the shield witness via @finnes/sdk (note opening + auditor encryption).");
  todo("Generate the shield Groth16 proof via @finnes/prover (setup/build/shield/shield.zkey).");
  todo(`Invoke contract '${config.contractId ?? "<unset>"}' shield(proof, publicInputs, ciphertexts).`);
  info("After this, A owns one shielded note; the public sees only its commitment.");
}

/** Step 2: confidential_transfer — A -> B, amounts/parties hidden. */
async function confidentialTransfer(): Promise<void> {
  step("confidential_transfer — move value A -> B (2-in / 2-out, single asset)");
  info("Public sees only: nullifier(s), output commitment(s), ciphertexts, new root.");
  info("In-circuit: per-asset conservation, 64-bit range checks, KYC membership,");
  info("            sanctions + frozen non-membership, assets membership + per-tx limit,");
  info("            mandatory auditor-encryption well-formedness, Merkle tree transition.");
  todo("Fetch Merkle path + recent anchor_root + compliance roots from the API/indexer.");
  todo("Assemble public inputs in the canonical order (docs/PUBLIC_IO.md transfer layout).");
  todo("Generate the transfer proof via @finnes/prover (setup/build/transfer/transfer.zkey).");
  todo("Invoke contract confidential_transfer(proof, publicInputs, c_auditor, c_recipient).");
  info("B can now scan ciphertexts and discover the incoming note.");
}

/** Step 3: regulator disclosure — auditor view key decrypts the mandatory ciphertext. */
async function regulatorDisclosure(): Promise<void> {
  step("regulator disclosure — auditor decrypts the mandatory c_auditor");
  info("Auditor encryption is mandatory and circuit-enforced (invariant #5), so every");
  info("output note carries a c_auditor bound to the proof as a public input.");
  todo("Decrypt c_auditor with the auditor view key via @finnes/sdk (auditor zone).");
  todo(
    "Display the disclosed transaction (amount, parties) to the regulator ONLY. In a " +
      "real run this prints real values to the auditor's screen — never to shared logs " +
      "and never persisted by this script (invariant #8).",
  );
  info("Narrative: public saw a valid compliant transfer; only the regulator sees details.");
}

/** Stretch: settle_dvp — atomic two-asset settlement (demo: single combined proof). */
async function settleDvp(): Promise<void> {
  step("(stretch) settle_dvp — atomic two-asset DvP");
  info("DEMO MODEL: one combined proof holds both parties' secrets (one pairing).");
  info("This is acceptable ONLY because a test harness controls both keypairs; it is");
  info("NOT the production model (production = escrow / two-phase). See ARCHITECTURE.md.");
  todo("Generate the dvp proof via @finnes/prover (setup/build/dvp/dvp.zkey).");
  todo("Both parties consent on-chain via require_auth; invoke settle_dvp(...).");
}

// ---------------------------------------------------------------------------
// Orchestration.
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("=".repeat(78));
  console.log("Finnes end-to-end demo (SCAFFOLD — does not run end-to-end yet)");
  console.log(`network=${config.network} contract=${config.contractId ?? "<unset>"}`);
  console.log("=".repeat(78));

  if (config.contractId === null) {
    info("No FINNES_CONTRACT_ID set — run 'npm run deploy' first, then export it.");
    info("Continuing in narration-only mode.");
  }

  await setupActors();
  await shield();
  await confidentialTransfer();
  await regulatorDisclosure();
  await settleDvp();

  console.log("\n" + "=".repeat(78));
  console.log("Demo narration complete.");
  console.log(
    "This was a SCAFFOLD: replace the TODO stubs above as @finnes/sdk, " +
      "@finnes/prover, the circuits, the trusted setup, and the contract land.",
  );
  console.log("=".repeat(78));
}

main().catch((err: unknown) => {
  // Log the error message only; never dump witness/secret-bearing objects.
  const message = err instanceof Error ? err.message : String(err);
  console.error(`demo failed: ${message}`);
  process.exitCode = 1;
});
