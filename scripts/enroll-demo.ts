// Mock KYC enrollment + demo compliance-state admin script (FIN-015).
//
// Pre-enrolls the demo institutions into `kyc_root` and emits the public
// compliance state (roots + auditor_pk + empty-tree seed + account/asset
// registries) that the post-deploy `init`, the prover, and the frontend consume.
//
// The in-circuit KYC membership check is NEVER dropped (a non-goal to build a real
// identity provider); this script is the hand-run admin enrollment that stands in
// for one, exactly as ARCHITECTURE.md → Backend/API describes.
//
// Runs fully offline (pure SDK Poseidon/Merkle). It does NOT touch the chain — the
// emitted JSON is fed to `init` once a contract is deployed.
//
// SECURITY (invariant #8): writes PUBLIC values only — no owner_sk, no k_view.
// Run: npm run enroll:demo

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildDemoComplianceState,
  toPublicState,
  verifyEnrolled,
} from './lib/demo-state.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, '../setup/build/demo-state.json');

function main(): void {
  const state = buildDemoComplianceState(); // production depth D = 20

  // Sanity: every enrolled account must actually verify against kyc_root before
  // we publish it — a mis-enrolled account would make valid proofs unprovable.
  for (const acc of state.accounts) {
    if (!verifyEnrolled(state, acc)) {
      throw new Error(`enrollment inconsistent: ${acc.label} not provable in kyc_root`);
    }
  }

  const pub = toPublicState(state);
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, `${JSON.stringify(pub, null, 2)}\n`);

  console.log('Finnes — mock KYC enrollment + demo compliance state (FIN-015)');
  console.log(`  tree depth      : ${state.treeDepth}`);
  console.log(`  enrolled (KYC)  : ${state.accounts.length} accounts`);
  for (const a of state.accounts) console.log(`      - ${a.label}`);
  console.log(`  assets registry : ${state.assets.length} assets`);
  for (const a of state.assets) {
    console.log(`      - ${a.label} (asset_id ${a.assetId.toString().slice(0, 10)}…, limit ${a.perTxLimitRaw})`);
  }
  console.log('  roots:');
  console.log(`      kyc_root      ${state.kycRoot.toString().slice(0, 18)}…`);
  console.log(`      sanction_root ${state.sanctionRoot.toString().slice(0, 18)}… (empty set)`);
  console.log(`      assets_root   ${state.assetsRoot.toString().slice(0, 18)}…`);
  console.log(`      frozen_root   ${state.frozenRoot.toString().slice(0, 18)}… (empty set)`);
  console.log(`      auditor_pk    ${state.auditorPk.toString().slice(0, 18)}…`);
  console.log(`  wrote PUBLIC state -> ${OUT}`);
  console.log('  (no secret written — owner_sk / k_view stay in the demo script, invariant #8)');
  console.log('  NEXT: feed these roots + auditor_pk + initial frontier/root into the');
  console.log('        post-deploy `init` once the contract is deployed (FIN-015).');
}

main();
