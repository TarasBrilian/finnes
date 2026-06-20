// OFFLINE gate for the FIN-025 live transfer witness — runnable WITHOUT the
// (Railway-only) transfer.zkey.
//
// It builds the real D=20 transfer witness against the deployed contract's live
// state (`scripts/lib/transfer-live.ts`) and validates everything that does NOT
// need the proving key:
//   1. INDEXER PARITY — commitNote(GENESIS_NOTE) equals the on-chain cm_out_0
//      (setup/build/shield-args.json). If this fails the indexer stand-in has
//      drifted and any proof built on it would be silently wrong.
//   2. CONSERVATION — Σ inputs == Σ outputs + fee (per-asset, invariant #3).
//   3. RANGE — every spent commitment is bracketable (0 < cm < IMT_MAX) for the
//      frozen non-membership proof.
//   4. It writes the flat circom input to setup/build/transfer-live-input.json so
//      the npm gate can run `snarkjs wtns calculate` + `snarkjs wtns check`
//      (transfer.r1cs is local) — the authoritative "all 74k constraints satisfied"
//      check that the witness is sound, short of the Groth16 proof itself.
//
// SECURITY (invariant #8): the witness embeds demo secrets and is written ONLY to
// the gitignored setup/build/ for the local wtns tooling; it is never committed,
// logged, or transmitted. The derived/public values printed here carry no secret.
//
// Run: npm run transfer:live:witness

import { writeFileSync } from 'node:fs';

import { commitNote } from '../sdk/src/note.js';
import { buildLiveTransferWitness } from './lib/transfer-live.js';
import { GENESIS_NOTE, GENESIS_CM_HEX, toCmHex } from './lib/live-notes.js';
import { IMT_MAX } from './lib/demo-state.js';

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

console.log('Building D=20 live transfer witness (spend [genesis, shield2] → 1500 + 500) ...');
const { witness, derived, meta } = buildLiveTransferWitness();

// 1. INDEXER PARITY — the reconstructed genesis commitment must equal the on-chain one.
const genesisCm = toCmHex(commitNote(GENESIS_NOTE));
expect(
  `indexer parity: commitNote(GENESIS_NOTE) == on-chain cm_out_0 (${GENESIS_CM_HEX.slice(0, 12)}…)`,
  genesisCm === GENESIS_CM_HEX,
);

// 2. CONSERVATION — Σ inputs == Σ outputs + fee (fee 0).
const sumIn = meta.inValues[0] + meta.inValues[1];
const sumOut = meta.outValues[0] + meta.outValues[1];
expect(`conservation: Σin(${sumIn}) == Σout(${sumOut}) + fee(0)`, sumIn === sumOut);

// 3. RANGE — each spent commitment is bracketable for frozen non-membership.
for (let k = 0; k < 2; k++) {
  const cm = derived.cmIn[k]!;
  expect(`spent commitment ${k} in (0, IMT_MAX) for frozen non-membership`, cm > 0n && cm < IMT_MAX);
}

console.log('\nderived (public, no secret):');
console.log('  anchor_root :', toCmHex(meta.anchorRoot));
console.log('  next_index  :', meta.nextIndex);
console.log('  nf_in_0     :', toCmHex(derived.nf[0]!));
console.log('  nf_in_1     :', toCmHex(derived.nf[1]!));
console.log('  cm_out_0    :', toCmHex(derived.cmOut[0]!), '(recipient 1500)');
console.log('  cm_out_1    :', toCmHex(derived.cmOut[1]!), '(change 500)');
console.log('  new_root    :', toCmHex(derived.newRoot));

const OUT = 'setup/build/transfer-live-input.json';
writeFileSync(OUT, JSON.stringify(witness));
console.log(`\nwrote ${OUT} (flat circom input for snarkjs wtns calculate/check)`);

if (failed) {
  console.error('\nLIVE TRANSFER WITNESS GATE FAILED (pre-snarkjs checks).');
  process.exit(1);
}
console.log('\nPre-snarkjs checks PASS. Next: snarkjs wtns calculate + wtns check (npm gate chains these).');
