// End-to-end prover gate (FIN-013): build a real unshield witness with the SDK
// builder, generate a Groth16 proof against BLS12-381 trusted-setup artifacts,
// and verify it locally against the exported verifying key. Proves the unshield
// circuit + trusted setup + prover agree on a real setup.
//
// DEMO DEPTH. Runs the depth-4 unshield harness (`unshield_test4`, same gadgets
// and public-IO STRUCTURE as the production `Unshield(20,5,5)`, only the tree
// depth differs). Its ~67k-constraint setup fits a 2^17 Powers-of-Tau (reuses the
// depth-4 demo's 2^18 ptau). The production D=20 procedure is identical
// (scripts/setup-ceremony.sh already iterates `unshield`).
//
// Requires (produced by the depth-4 demo ceremony for unshield):
//   - circuits/build/unshield_test4/unshield_test4_js/unshield_test4.wasm
//   - setup/build/unshield_test4/{unshield_test4.zkey, vk_unshield_test4.json}
//
// Run: `npx tsx scripts/test-prove-unshield.ts` (npm run unshield:prove).
//
// SECURITY (invariant #8): the witness embeds demo secrets; never logged. The
// proof + public signals contain NO secrets and are safe to print/submit.

import { existsSync } from 'node:fs';

import { buildUnshieldScenario } from './lib/unshield-scenario.js';
import { prove } from '../prover/src/prove.js';
import { verifyLocalFromFile } from '../prover/src/verifyLocal.js';
import type { Witness } from '../prover/src/types.js';

// unshield_test4 is `Unshield(4, 5, 5)` -> 14 + 2*4 + 5 + 5 = 32 public signals.
const DEPTH = 4;
const EXPECTED_PUBLIC_SIGNALS = 32;

const wasmPath = 'circuits/build/unshield_test4/unshield_test4_js/unshield_test4.wasm';
const zkeyPath = 'setup/build/unshield_test4/unshield_test4.zkey';
const vkeyPath = 'setup/build/unshield_test4/vk_unshield_test4.json';

for (const [label, p] of [
  ['circuit WASM (depth-4 harness build)', wasmPath],
  ['proving key (demo ceremony)', zkeyPath],
  ['verifying key (demo ceremony export)', vkeyPath],
] as const) {
  if (!existsSync(p)) {
    console.error(`MISSING ${label}: ${p}`);
    console.error('Run the depth-4 demo ceremony for unshield first (see this script header).');
    process.exit(1);
  }
}

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

console.log(`Building a depth-${DEPTH} unshield witness via @finnes/sdk ...`);
const { witness } = buildUnshieldScenario(DEPTH);

console.log('Generating Groth16 proof (BLS12-381) ...');
const bundle = await prove(witness as Witness, { wasmPath, zkeyPath, vkeyPath });

expect(
  `proof carries ${EXPECTED_PUBLIC_SIGNALS} public signals`,
  bundle.publicSignals.length === EXPECTED_PUBLIC_SIGNALS,
);

const ok = await verifyLocalFromFile(vkeyPath, bundle);
expect('groth16.verify accepts the proof against the exported VK', ok === true);

// Negative: tamper a public signal (frozen_root at index 4) - verification MUST
// fail, proving the VK genuinely binds the public IO (escape-hatch closure, #19).
const tampered = {
  proof: bundle.proof,
  publicSignals: bundle.publicSignals.map((s, i) => (i === 4 ? (BigInt(s) + 1n).toString() : s)),
};
const tamperedOk = await verifyLocalFromFile(vkeyPath, tampered);
expect('groth16.verify REJECTS a tampered public signal', tamperedOk === false);

if (failed) {
  console.error('\nUNSHIELD PROVE GATE FAILED.');
  process.exit(1);
}
console.log('\nUNSHIELD PROVE OK - witness -> proof -> local verify round-trips on a real BLS12-381 setup.');
