// Prove a REAL D=20 unshield against the deployed contract's LIVE post-transfer
// state (FIN-026) — the unshield analogue of scripts/prove-transfer-live.ts.
//
// Spends the FIN-025 change note (500 TBOND, Bank A) out to a transparent
// recipient as an exact spend (no change). Witness built by
// scripts/lib/unshield-live.ts against the live roots + the reconstructed
// post-transfer tree, so the proof's anchor/roots match contract state.
//
// PREREQUISITE: the FIN-025 transfer must already be on-chain (its change note is
// the input). Run on the Railway prover host that holds the D=20 unshield .zkey.
//
// Emits setup/build/unshield-proof-live.json (PUBLIC, no secret — invariant #8).
// Run: npx tsx scripts/prove-unshield-live.ts

import { writeFileSync } from 'node:fs';

import { buildLiveUnshieldWitness } from './lib/unshield-live.js';
import { toCmHex } from './lib/live-notes.js';
import { prove } from '../prover/src/prove.js';
import type { Witness } from '../prover/src/types.js';

// Unshield(20,5,5) -> 14 + 2*20 + 5 + 5 = 64 public signals (docs/PUBLIC_IO.md).
const EXPECTED_PUBLIC_SIGNALS = 64;

console.log('Building D=20 live unshield witness ...');
const { witness, derived, meta } = buildLiveUnshieldWitness();
console.log(`  anchor_root : ${toCmHex(meta.anchorRoot)}`);
console.log(`  next_index  : ${meta.nextIndex}`);
console.log(`  amount      : ${meta.amount} raw → ${meta.recipientLabel}`);
console.log(`  cm_change_0 : ${toCmHex(derived.cmChange)} (exact spend, no change)`);

const wasmPath = 'circuits/build/unshield/unshield_js/unshield.wasm';
const zkeyPath = 'setup/build/unshield/unshield.zkey';
const vkeyPath = 'setup/build/unshield/vk_unshield.json';

console.log('Generating Groth16 proof (BLS12-381, D=20) ...');
const bundle = await prove(witness as Witness, { wasmPath, zkeyPath, vkeyPath });

if (bundle.publicSignals.length !== EXPECTED_PUBLIC_SIGNALS) {
  console.error(`FAIL: expected ${EXPECTED_PUBLIC_SIGNALS} public signals, got ${bundle.publicSignals.length}`);
  process.exit(1);
}
// Sanity: published nullifier matches the derived witness value.
if (bundle.publicSignals[6] !== derived.nf.toString()) {
  console.error('FAIL: published nullifier does not match the derived witness value');
  process.exit(1);
}

const OUT = 'setup/build/unshield-proof-live.json';
writeFileSync(OUT, JSON.stringify({ proof: bundle.proof, publicSignals: bundle.publicSignals }, null, 2));
console.log(`OK — ${bundle.publicSignals.length} public signals; wrote ${OUT}`);
