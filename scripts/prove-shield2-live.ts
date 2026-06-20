// Prove the SECOND live shield (FIN-025 prerequisite) — a confidential transfer
// needs two on-chain notes to spend, and the FIN-015 genesis shield minted only
// one (index 0). This mints SHIELD2_NOTE at index 1.
//
// Unlike the genesis shield (scripts/prove-shield-live.ts: next_index 0, genesis
// frontier), the second shield must anchor to the POST-GENESIS state: old_frontier
// = the frontier after inserting the genesis commitment, next_index = 1. Both are
// reconstructed off-chain from the single genesis commitment (the indexer stand-in
// in scripts/lib/live-notes.ts), and the contract checks them against its stored
// state (old_frontier == state, next_index == leaf_count == 1).
//
// Emits setup/build/shield2-proof-live.json. Convert + submit via:
//   npx tsx scripts/submit-shield-live.ts setup/build/shield2-proof-live.json setup/build/shield2-args.json
//
// Run on the Railway prover host (holds shield.zkey). npx tsx scripts/prove-shield2-live.ts

import { writeFileSync } from 'node:fs';

import { IncrementalMerkleTree } from '../sdk/src/merkle.js';
import { commitNote, sacAddressToField } from '../sdk/src/note.js';
import { buildShieldWitness } from '../sdk/src/witness.js';
import { prove } from '../prover/src/prove.js';
import type { Witness } from '../prover/src/types.js';
import {
  DEPTH,
  GENESIS_NOTE,
  LIVE_ASSET,
  LIVE_STATE,
  LIVE_VIEW_KEY,
  SHIELD2_NOTE,
} from './lib/live-notes.js';

const EXPECTED_PUBLIC_SIGNALS = 59;
const st = LIVE_STATE;
const acct = st.accounts[0]!; // Meridian (Bank A) — same owner as the genesis note

// Post-genesis tree state: insert the genesis commitment, read the frontier.
const tree = new IncrementalMerkleTree(DEPTH);
tree.insert(commitNote(GENESIS_NOTE));
const oldFrontier = tree.frontier();
const nextIndex = tree.size; // == 1

console.log('Building D=20 shield #2 witness against post-genesis state ...');
console.log(`  owner      : ${acct.label}`);
console.log(`  asset      : ${LIVE_ASSET.label}`);
console.log(`  amount     : ${SHIELD2_NOTE.value} raw`);
console.log(`  next_index : ${nextIndex} (post-genesis)`);

const { witness } = buildShieldWitness({
  outNote: SHIELD2_NOTE,
  kycPath: acct.kycPath,
  kycRoot: st.kycRoot,
  sacAddress: sacAddressToField(LIVE_ASSET.sacAddress),
  decimals: BigInt(LIVE_ASSET.decimals),
  perTxLimitRaw: LIVE_ASSET.perTxLimitRaw,
  assetsPath: LIVE_ASSET.assetsPath,
  assetsRoot: st.assetsRoot,
  oldFrontier,
  nextIndex,
  fee: 0n,
  auditorPk: st.auditorPk,
  kView: LIVE_VIEW_KEY,
  kPair: 7n,
  rhoEncAuditor: 5103n,
  rhoEncRecipient: 6103n,
});

const bundle = await prove(witness as Witness, {
  wasmPath: 'circuits/build/shield/shield_js/shield.wasm',
  zkeyPath: 'setup/build/shield/shield.zkey',
  vkeyPath: 'setup/build/shield/vk_shield.json',
});

if (bundle.publicSignals.length !== EXPECTED_PUBLIC_SIGNALS) {
  console.error(`FAIL: expected ${EXPECTED_PUBLIC_SIGNALS} public signals, got ${bundle.publicSignals.length}`);
  process.exit(1);
}

const OUT = 'setup/build/shield2-proof-live.json';
writeFileSync(OUT, JSON.stringify({ proof: bundle.proof, publicSignals: bundle.publicSignals }, null, 2));
console.log(`OK — ${bundle.publicSignals.length} public signals; wrote ${OUT}`);
