// PRODUCTION-DEPTH prover gate (FIN-007/FIN-008): build a real D=20 transfer
// witness with the SDK builder, generate a Groth16 proof against the REAL
// production BLS12-381 trusted-setup artifacts (2^18 ceremony — D=20 transfer is
// ~74k constraints, so 2·74k < 2^18), and verify it locally against the exported
// production verifying key. This is the "it's real, not a simulation" capstone:
// the exact 73-public-signal Transfer(20,5,5) the deployed contract verifies.
//
// Requires (produced by `scripts/setup-ceremony.sh` at PTAU_POWER=18):
//   - circuits/build/transfer/transfer_js/transfer.wasm
//   - setup/build/transfer/{transfer.zkey, vk_transfer.json}
//
// Run: npx tsx scripts/test-prove-transfer-d20.ts  (npm run transfer:prove:d20)
//
// SECURITY (invariant #8): the witness embeds demo secrets; never logged. The
// proof + public signals contain NO secrets and are safe to print/submit.

import { existsSync } from 'node:fs';

import { buildTransferScenario } from './lib/transfer-scenario.js';
import { prove } from '../prover/src/prove.js';
import { verifyLocalFromFile } from '../prover/src/verifyLocal.js';
import type { Witness } from '../prover/src/types.js';

// Transfer(20,5,5) -> 13 + 2*20 + 2*5 + 2*5 = 73 public signals (docs/PUBLIC_IO.md).
const DEPTH = 20;
const EXPECTED_PUBLIC_SIGNALS = 73;

const wasmPath = 'circuits/build/transfer/transfer_js/transfer.wasm';
const zkeyPath = 'setup/build/transfer/transfer.zkey';
const vkeyPath = 'setup/build/transfer/vk_transfer.json';

for (const [label, p] of [
  ['circuit WASM (D=20 production build)', wasmPath],
  ['proving key (npm run setup:ceremony, PTAU_POWER=18)', zkeyPath],
  ['verifying key (production ceremony export)', vkeyPath],
] as const) {
  if (!existsSync(p)) {
    console.error(`MISSING ${label}: ${p}`);
    console.error('Run the D=20 ceremony first (scripts/setup-ceremony.sh, PTAU_POWER=18).');
    process.exit(1);
  }
}

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

console.log(`Building a depth-${DEPTH} (production) transfer witness via @finnes/sdk ...`);
const { witness } = buildTransferScenario(DEPTH);

console.log('Generating Groth16 proof (BLS12-381, D=20) ...');
const bundle = await prove(witness as Witness, { wasmPath, zkeyPath, vkeyPath });

expect(
  `proof carries ${EXPECTED_PUBLIC_SIGNALS} public signals (the contract's transfer layout)`,
  bundle.publicSignals.length === EXPECTED_PUBLIC_SIGNALS,
);

const ok = await verifyLocalFromFile(vkeyPath, bundle);
expect('groth16.verify accepts the REAL D=20 proof against the production VK', ok === true);

// Negative: tamper a public signal (nf_in_0 at index 6) -> verification MUST fail.
const tampered = {
  proof: bundle.proof,
  publicSignals: bundle.publicSignals.map((s, i) => (i === 6 ? (BigInt(s) + 1n).toString() : s)),
};
const tamperedOk = await verifyLocalFromFile(vkeyPath, tampered);
expect('groth16.verify REJECTS a tampered public signal', tamperedOk === false);

if (failed) {
  console.error('\nD=20 TRANSFER PROVE GATE FAILED.');
  process.exit(1);
}
console.log('\nD=20 TRANSFER PROVE OK — real witness -> proof -> verify on the production BLS12-381 setup.');
