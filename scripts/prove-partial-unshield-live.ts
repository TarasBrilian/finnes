// Prove the PARTIAL unshield (1-insert sentinel branch) against the deployed
// contract's live state (FIN-026 "0 vs 1 insert" completeness).
//
// Spends the transfer recipient note (1500 TBOND, Bank B, leaf 2) → 1000
// transparent + 500 change note (Bank B). Run on the Railway prover host with the
// D=20 unshield .zkey. Emits setup/build/unshield2-proof-live.json.
//
// Run: npx tsx scripts/prove-partial-unshield-live.ts

import { writeFileSync } from 'node:fs';

import { buildLivePartialUnshieldWitness } from './lib/unshield-live.js';
import { toCmHex } from './lib/live-notes.js';
import { prove } from '../prover/src/prove.js';
import type { Witness } from '../prover/src/types.js';

const EXPECTED_PUBLIC_SIGNALS = 64;

console.log('Building D=20 PARTIAL unshield witness ...');
const { witness, derived, meta } = buildLivePartialUnshieldWitness();
console.log(`  anchor_root : ${toCmHex(meta.anchorRoot)}`);
console.log(`  amount      : ${meta.amount} raw → ${meta.recipientLabel} (+ 500 change)`);
console.log(`  cm_change_0 : ${toCmHex(derived.cmChange)} (1-insert path)`);

const bundle = await prove(witness as Witness, {
  wasmPath: 'circuits/build/unshield/unshield_js/unshield.wasm',
  zkeyPath: 'setup/build/unshield/unshield.zkey',
  vkeyPath: 'setup/build/unshield/vk_unshield.json',
});

if (bundle.publicSignals.length !== EXPECTED_PUBLIC_SIGNALS) {
  console.error(`FAIL: expected ${EXPECTED_PUBLIC_SIGNALS} public signals, got ${bundle.publicSignals.length}`);
  process.exit(1);
}
if (bundle.publicSignals[6] !== derived.nf.toString()) {
  console.error('FAIL: published nullifier does not match the derived witness value');
  process.exit(1);
}

const OUT = 'setup/build/unshield2-proof-live.json';
writeFileSync(OUT, JSON.stringify({ proof: bundle.proof, publicSignals: bundle.publicSignals }, null, 2));
console.log(`OK — ${bundle.publicSignals.length} public signals; wrote ${OUT}`);
