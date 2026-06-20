// Prove a REAL D=20 shield against the DEPLOYED contract's genesis state (FIN-015).
//
// Unlike scripts/test-prove-shield.ts (a self-contained depth-4 gate), this builds
// the shield witness against `buildDemoComplianceState(20)` — the SAME kyc/assets
// roots, auditor_pk, and empty-tree genesis frontier that `npm run enroll:demo`
// produced and the post-deploy `init` stored on-chain. So the resulting proof's
// public roots MATCH contract state and the contract will accept it (windowed
// kyc/assets, exact auditor_pk, old_frontier == genesis, next_index == 0).
//
// Emits setup/build/shield-proof-live.json = { proof, publicSignals } (PUBLIC, no
// secret — invariant #8) for on-chain submission via scripts/submit-shield-live.ts.
//
// Run on the prover host that holds the D=20 shield .zkey (here: the Railway
// ceremony container). `npx tsx scripts/prove-shield-live.ts`.

import { writeFileSync } from 'node:fs';

import { buildDemoComplianceState, DEMO_AUDITOR_VIEW_KEY } from './lib/demo-state.js';
import { buildShieldWitness } from '../sdk/src/witness.js';
import { sacAddressToField } from '../sdk/src/note.js';
import { prove } from '../prover/src/prove.js';
import type { Witness } from '../prover/src/types.js';
import type { Note } from '../sdk/src/types.js';

const DEPTH = 20;
const EXPECTED_PUBLIC_SIGNALS = 59;

// Same deterministic state the contract was initialised with.
const st = buildDemoComplianceState(DEPTH);
const acct = st.accounts[0]!; // Meridian Capital (Bank A), enrolled in kyc_root
const asset = st.assets[0]!; // TBOND-2031, sac_address '777', limit 10_000_000

// The minted note: 1000 raw units of the asset, owned by the enrolled account.
const amount = 1000n;
const outNote: Note = {
  assetId: asset.assetId,
  value: amount,
  ownerPk: acct.ownerPk,
  rho: 3001n,
  rNote: 4001n,
};

console.log('Building D=20 shield witness against live genesis ...');
console.log(`  owner   : ${acct.label} (pk ${acct.ownerPk.toString().slice(0, 12)}…)`);
console.log(`  asset   : ${asset.label} (asset_id ${asset.assetId.toString().slice(0, 12)}…)`);
console.log(`  amount  : ${amount} raw`);

const { witness } = buildShieldWitness({
  outNote,
  kycPath: acct.kycPath,
  kycRoot: st.kycRoot,
  sacAddress: sacAddressToField(asset.sacAddress),
  decimals: BigInt(asset.decimals),
  perTxLimitRaw: asset.perTxLimitRaw,
  assetsPath: asset.assetsPath,
  assetsRoot: st.assetsRoot,
  oldFrontier: st.initialFrontier,
  nextIndex: 0,
  fee: 0n,
  auditorPk: st.auditorPk,
  kView: DEMO_AUDITOR_VIEW_KEY,
  kPair: 7n,
  rhoEncAuditor: 5101n,
  rhoEncRecipient: 6101n,
});

const wasmPath = 'circuits/build/shield/shield_js/shield.wasm';
const zkeyPath = 'setup/build/shield/shield.zkey';
const vkeyPath = 'setup/build/shield/vk_shield.json';

console.log('Generating Groth16 proof (BLS12-381, D=20) ...');
const bundle = await prove(witness as Witness, { wasmPath, zkeyPath, vkeyPath });

if (bundle.publicSignals.length !== EXPECTED_PUBLIC_SIGNALS) {
  console.error(
    `FAIL: expected ${EXPECTED_PUBLIC_SIGNALS} public signals, got ${bundle.publicSignals.length}`,
  );
  process.exit(1);
}

const OUT = 'setup/build/shield-proof-live.json';
writeFileSync(OUT, JSON.stringify({ proof: bundle.proof, publicSignals: bundle.publicSignals }, null, 2));
console.log(`OK — ${bundle.publicSignals.length} public signals; wrote ${OUT}`);
