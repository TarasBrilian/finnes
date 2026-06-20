// OFFLINE gate for the FIN-026 PARTIAL unshield witness (the 1-insert sentinel
// branch). Complements test-unshield-live-witness.ts (0-insert) so BOTH sides of
// the change-note sentinel "(0 vs 1 insert)" are exercised.
//
//   1. ANCHOR PARITY — 4-note post-transfer root == on-chain current root; the
//      spent commitment == commitNote(TRANSFER_OUT_RECIPIENT) (leaf 2).
//   2. PARTIAL SPEND — amount(1000) + change(500) == in_value(1500); cm_change_0
//      != 0 (hasChange) and new_root != anchor_root (the change inserts at leaf 4,
//      the tree advances by 1).
//   3. MANDATORY change-note auditor ciphertext is non-zero (invariant #5).
//   4. Writes the flat circom input for snarkjs wtns calculate + wtns check.
//
// Run: npm run unshield2:live:witness

import { writeFileSync } from 'node:fs';

import { commitNote } from '../sdk/src/note.js';
import { buildLivePartialUnshieldWitness, PARTIAL_UNSHIELD_AMOUNT } from './lib/unshield-live.js';
import { POST_TRANSFER_ROOT_HEX, TRANSFER_OUT_RECIPIENT, UNSHIELD2_CHANGE_NOTE, toCmHex } from './lib/live-notes.js';

let failed = false;
const expect = (label: string, ok: boolean): void => {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
};

console.log('Building D=20 PARTIAL unshield witness (spend 1500 Bank B → 1000 transparent + 500 change) ...');
const { witness, derived, meta } = buildLivePartialUnshieldWitness();
const w = witness as Record<string, string | string[]>;

// 1. ANCHOR PARITY.
expect(
  `anchor parity: 4-note root == on-chain current root (${POST_TRANSFER_ROOT_HEX.slice(0, 12)}…)`,
  toCmHex(meta.anchorRoot) === POST_TRANSFER_ROOT_HEX,
);
expect('indexer parity: spent cm == commitNote(TRANSFER_OUT_RECIPIENT) (leaf 2)', derived.cmIn === commitNote(TRANSFER_OUT_RECIPIENT));

// 2. PARTIAL SPEND + 1-insert sentinel branch.
const inVal = TRANSFER_OUT_RECIPIENT.value;
expect(`conservation: amount(${meta.amount}) + change(500) == in_value(${inVal})`, meta.amount + 500n === inVal);
expect('1-insert sentinel: cm_change_0 != 0 (hasChange true)', derived.hasChange === true && derived.cmChange !== 0n);
expect('change cm == commitNote(UNSHIELD2_CHANGE_NOTE)', derived.cmChange === commitNote(UNSHIELD2_CHANGE_NOTE));
expect('tree advances by 1: new_root != anchor_root', toCmHex(derived.newRoot) !== toCmHex(meta.anchorRoot));

// 3. MANDATORY change-note auditor ciphertext non-zero (invariant #5).
const cAud = w.c_auditor as string[];
expect('change-note c_auditor is non-zero (mandatory auditor encryption, inv #5)', cAud.some((x) => x !== '0'));

console.log('\nderived (public, no secret):');
console.log('  anchor_root :', toCmHex(meta.anchorRoot));
console.log('  next_index  :', meta.nextIndex);
console.log('  nf_in_0     :', toCmHex(derived.nf));
console.log('  amount      :', meta.amount.toString(), 'raw → recipient', meta.recipientLabel);
console.log('  cm_change_0 :', toCmHex(derived.cmChange), '(500 change → Bank B)');
console.log('  new_root    :', toCmHex(derived.newRoot), '(!= anchor; 1 insert)');

const OUT = 'setup/build/unshield2-live-input.json';
writeFileSync(OUT, JSON.stringify(witness));
console.log(`\nwrote ${OUT} (flat circom input for snarkjs wtns calculate/check)`);

if (failed) {
  console.error('\nPARTIAL UNSHIELD WITNESS GATE FAILED (pre-snarkjs checks).');
  process.exit(1);
}
console.log('\nPre-snarkjs checks PASS. Next: snarkjs wtns calculate + wtns check (npm gate chains these).');
