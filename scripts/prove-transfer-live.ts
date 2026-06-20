// Prove a REAL D=20 confidential transfer against the DEPLOYED contract's live
// state (FIN-025) — the transfer analogue of scripts/prove-shield-live.ts.
//
// Spends the two on-chain shielded notes [genesis, shield2] (both Bank A) into a
// 1500 → Bank B recipient note + a 500 change note back to Bank A. The witness is
// built by scripts/lib/transfer-live.ts against buildDemoComplianceState(20) and
// the reconstructed live commitment tree, so the proof's public roots/anchor match
// contract state and `confidential_transfer` accepts it.
//
// PREREQUISITE: two on-chain shields owned by the sender must already exist
// (genesis from FIN-015 + scripts/prove-shield2-live.ts). Run this on the prover
// host that holds the D=20 transfer .zkey (the Railway `ceremony` service).
//
// Emits setup/build/transfer-proof-live.json = { proof, publicSignals } (PUBLIC, no
// secret — invariant #8) for on-chain submission via scripts/submit-transfer-live.ts.
//
// Run: npx tsx scripts/prove-transfer-live.ts

import { writeFileSync } from 'node:fs';

import { buildLiveTransferWitness } from './lib/transfer-live.js';
import { toCmHex } from './lib/live-notes.js';
import { prove } from '../prover/src/prove.js';
import type { Witness } from '../prover/src/types.js';

// Transfer(20,5,5) -> 13 + 2*20 + 2*5 + 2*5 = 73 public signals (docs/PUBLIC_IO.md).
const EXPECTED_PUBLIC_SIGNALS = 73;

console.log('Building D=20 live transfer witness ...');
const { witness, derived, meta } = buildLiveTransferWitness();
console.log(`  anchor_root : ${toCmHex(meta.anchorRoot)}`);
console.log(`  next_index  : ${meta.nextIndex}`);
console.log(`  spend       : ${meta.inValues[0]} + ${meta.inValues[1]} = ${meta.inValues[0] + meta.inValues[1]} raw`);
console.log(`  outputs     : recipient ${meta.outValues[0]} + change ${meta.outValues[1]}`);

const wasmPath = 'circuits/build/transfer/transfer_js/transfer.wasm';
const zkeyPath = 'setup/build/transfer/transfer.zkey';
const vkeyPath = 'setup/build/transfer/vk_transfer.json';

console.log('Generating Groth16 proof (BLS12-381, D=20) ...');
const bundle = await prove(witness as Witness, { wasmPath, zkeyPath, vkeyPath });

if (bundle.publicSignals.length !== EXPECTED_PUBLIC_SIGNALS) {
  console.error(
    `FAIL: expected ${EXPECTED_PUBLIC_SIGNALS} public signals, got ${bundle.publicSignals.length}`,
  );
  process.exit(1);
}

// Sanity: the proof's published nullifiers/commitments must equal the derived ones
// (public-IO order is asserted by submit-transfer-live.ts; this catches a builder
// drift before paying network fees).
const okNf = bundle.publicSignals[6] === derived.nf[0]!.toString() && bundle.publicSignals[7] === derived.nf[1]!.toString();
if (!okNf) {
  console.error('FAIL: published nullifiers do not match the derived witness values');
  process.exit(1);
}

const OUT = 'setup/build/transfer-proof-live.json';
writeFileSync(OUT, JSON.stringify({ proof: bundle.proof, publicSignals: bundle.publicSignals }, null, 2));
console.log(`OK — ${bundle.publicSignals.length} public signals; wrote ${OUT}`);
