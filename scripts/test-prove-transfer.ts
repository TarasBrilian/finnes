// End-to-end prover gate (FIN-008): build a real transfer witness with the SDK
// builder, generate a Groth16 proof against BLS12-381 trusted-setup artifacts,
// and verify it locally against the exported verifying key. This proves circuit
// + trusted setup + prover agree BEFORE any on-chain verifier exists.
//
// DEMO DEPTH. This runs the depth-4 transfer harness (`transfer_test4`, same
// gadgets and public-IO STRUCTURE as the production `Transfer(20,5,5)`, only the
// tree depth differs). Its ~115k-constraint setup fits a 2^18 Powers-of-Tau, so
// the whole pipeline runs on a developer laptop. The production D=20 circuit is
// identical in procedure but needs a 2^20 ceremony (snarkjs requires
// 2^power >= 2*nConstraints; D=20 has ~295k constraints) - see
// scripts/setup-ceremony.sh.
//
// Requires (produced by the depth-4 demo ceremony):
//   - circuits/build/transfer_test4/transfer_test4_js/transfer_test4.wasm
//   - setup/build/transfer_test4/{transfer_test4.zkey, vk_transfer_test4.json}
//
// Run: `npx tsx scripts/test-prove-transfer.ts` (npm run transfer:prove).
//
// SECURITY (invariant #8): the witness embeds demo secrets; never logged. The
// proof + public signals contain NO secrets and are safe to print/submit.

import { existsSync } from 'node:fs';

import { buildTransferScenario } from './lib/transfer-scenario.js';
import { prove } from '../prover/src/prove.js';
import { verifyLocalFromFile } from '../prover/src/verifyLocal.js';
import type { Witness } from '../prover/src/types.js';

// transfer_test4 is `Transfer(4, 5, 5)` -> 13 + 2*4 + 2*5 + 2*5 = 41 public signals.
const DEPTH = 4;
const EXPECTED_PUBLIC_SIGNALS = 41;

const wasmPath = 'circuits/build/transfer_test4/transfer_test4_js/transfer_test4.wasm';
const zkeyPath = 'setup/build/transfer_test4/transfer_test4.zkey';
const vkeyPath = 'setup/build/transfer_test4/vk_transfer_test4.json';

for (const [label, p] of [
  ['circuit WASM (depth-4 harness build)', wasmPath],
  ['proving key (npm run setup:ceremony / demo ceremony)', zkeyPath],
  ['verifying key (demo ceremony export)', vkeyPath],
] as const) {
  if (!existsSync(p)) {
    console.error(`MISSING ${label}: ${p}`);
    console.error('Run the depth-4 demo ceremony first (see scripts/test-prove-transfer.ts header).');
    process.exit(1);
  }
}

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

console.log(`Building a depth-${DEPTH} transfer witness via @finnes/sdk ...`);
const { witness } = buildTransferScenario(DEPTH);

console.log('Generating Groth16 proof (BLS12-381) ...');
const bundle = await prove(witness as Witness, { wasmPath, zkeyPath, vkeyPath });

expect(
  `proof carries ${EXPECTED_PUBLIC_SIGNALS} public signals`,
  bundle.publicSignals.length === EXPECTED_PUBLIC_SIGNALS,
);

const ok = await verifyLocalFromFile(vkeyPath, bundle);
expect('groth16.verify accepts the proof against the exported VK', ok === true);

// Negative: tamper a public signal (nf_in_0 at index 6) - verification MUST fail,
// proving the VK genuinely binds the public IO.
const tampered = {
  proof: bundle.proof,
  publicSignals: bundle.publicSignals.map((s, i) =>
    i === 6 ? (BigInt(s) + 1n).toString() : s,
  ),
};
const tamperedOk = await verifyLocalFromFile(vkeyPath, tampered);
expect('groth16.verify REJECTS a tampered public signal', tamperedOk === false);

if (failed) {
  console.error('\nTRANSFER PROVE GATE FAILED.');
  process.exit(1);
}
console.log('\nTRANSFER PROVE OK - witness -> proof -> local verify round-trips on a real BLS12-381 setup.');
