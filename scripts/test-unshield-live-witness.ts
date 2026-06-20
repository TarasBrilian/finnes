// OFFLINE gate for the FIN-026 live unshield witness — runnable WITHOUT the
// Railway-only unshield.zkey (validates everything short of the Groth16 proof).
//
//   1. ANCHOR PARITY — the 4-note post-transfer reconstruction root equals the
//      on-chain current root (069cbb56…); the spent commitment equals
//      commitNote(UNSHIELD_SPENT_NOTE).
//   2. EXACT SPEND — amount == in_value (500), so cm_change_0 == 0 (the no-change
//      sentinel) and new_root == anchor_root (the gated 0-leaf reproduces the
//      current root; the tree advances by 0). Exercises invariants #11/#12/#19.
//   3. RANGE — the spent commitment is bracketable for frozen non-membership.
//   4. Writes the flat circom input so the npm gate can run snarkjs wtns
//      calculate + wtns check on unshield.r1cs (the all-constraints check).
//
// SECURITY (invariant #8): the witness embeds demo secrets; written only to the
// gitignored setup/build/ for local wtns tooling, never committed/logged.
//
// Run: npm run unshield:live:witness

import { writeFileSync } from 'node:fs';

import { commitNote } from '../sdk/src/note.js';
import { buildLiveUnshieldWitness, UNSHIELD_SPENT_NOTE } from './lib/unshield-live.js';
import { POST_TRANSFER_ROOT_HEX, toCmHex } from './lib/live-notes.js';
import { IMT_MAX } from './lib/demo-state.js';

let failed = false;
const expect = (label: string, ok: boolean): void => {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
};

console.log('Building D=20 live unshield witness (spend change 500 Bank A → transparent, exact) ...');
const { witness, derived, meta } = buildLiveUnshieldWitness();

// 1. ANCHOR PARITY.
expect(
  `anchor parity: post-transfer 4-note root == on-chain current root (${POST_TRANSFER_ROOT_HEX.slice(0, 12)}…)`,
  toCmHex(meta.anchorRoot) === POST_TRANSFER_ROOT_HEX,
);
expect(
  'indexer parity: derived spent commitment == commitNote(UNSHIELD_SPENT_NOTE)',
  derived.cmIn === commitNote(UNSHIELD_SPENT_NOTE),
);

// 2. EXACT SPEND + no-change sentinel + gated 0-leaf transition.
expect(`exact spend: amount(${meta.amount}) == in_value(${UNSHIELD_SPENT_NOTE.value})`, meta.amount === UNSHIELD_SPENT_NOTE.value);
expect('no-change sentinel: cm_change_0 == 0 (hasChange false)', derived.cmChange === 0n && derived.hasChange === false);
expect('gated 0-leaf: new_root == anchor_root (tree advances by 0)', toCmHex(derived.newRoot) === toCmHex(meta.anchorRoot));

// 3. RANGE for frozen non-membership of the spent commitment.
expect('spent commitment in (0, IMT_MAX) for frozen non-membership', derived.cmIn > 0n && derived.cmIn < IMT_MAX);

console.log('\nderived (public, no secret):');
console.log('  anchor_root :', toCmHex(meta.anchorRoot));
console.log('  next_index  :', meta.nextIndex, '(leaf_count after transfer)');
console.log('  nf_in_0     :', toCmHex(derived.nf));
console.log('  amount      :', meta.amount.toString(), 'raw → recipient', meta.recipientLabel);
console.log('  cm_change_0 :', toCmHex(derived.cmChange), '(0 = no change)');
console.log('  new_root    :', toCmHex(derived.newRoot), '(== anchor; 0 inserts)');

const OUT = 'setup/build/unshield-live-input.json';
writeFileSync(OUT, JSON.stringify(witness));
console.log(`\nwrote ${OUT} (flat circom input for snarkjs wtns calculate/check)`);

if (failed) {
  console.error('\nLIVE UNSHIELD WITNESS GATE FAILED (pre-snarkjs checks).');
  process.exit(1);
}
console.log('\nPre-snarkjs checks PASS. Next: snarkjs wtns calculate + wtns check (npm gate chains these).');
