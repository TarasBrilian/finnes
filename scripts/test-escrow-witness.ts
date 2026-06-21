// Production escrow-DvP acceptance gate (FIN-017, Phase B). Builds consistent
// witnesses with the SDK builders (via the shared scenario helpers) and drives the
// depth-6 harnesses, asserting the CLAUDE.md test rule: a valid witness is
// accepted, and >= 1 failing witness per constraint class is rejected. Covers:
//   - escrow_deposit (EscrowLeg(6,5,5,0)): valid; frozen spent note (#14); bad
//     input path; non-conserving value (#3); missing auditor ct (#5).
//   - escrow_refund  (EscrowLeg(6,5,5,1)): valid; sanctioned refund recipient
//     (#19); tampered new_root (#12).
//   - settle (the dvp circuit, both escrow inputs owned by sk_intent): valid.
// Run: `npx tsx scripts/test-escrow-witness.ts` (npm run escrow:witness).

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import {
  buildEscrowDepositScenario,
  buildEscrowRefundScenario,
  buildSettleScenario,
} from './lib/escrow-scenario.js';
import type { CircomWitness } from '../sdk/src/witness.js';

const DEPTH = 6;
function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}

/** Compile a test harness once and return a witness-calculator closure. */
function harness(name: string, dir: string, circomPath: string): (w: CircomWitness) => boolean {
  const build = `circuits/build/${dir}`;
  mkdirSync(build, { recursive: true });
  sh(`circom ${circomPath} --r1cs --wasm --sym --prime bls12381 -o ${build} -l circuits/lib`);
  return (input: CircomWitness): boolean => {
    writeFileSync(`${build}/${name}.input.json`, JSON.stringify(input));
    try {
      sh(`npx --no-install snarkjs wtns calculate ${build}/${name}_js/${name}.wasm ${build}/${name}.input.json ${build}/${name}.wtns`);
      return true;
    } catch {
      return false;
    }
  };
}

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}
function clone(w: CircomWitness): CircomWitness {
  return JSON.parse(JSON.stringify(w)) as CircomWitness;
}

const depositOk = harness('deposit_test', 'escrow_deposit_test', 'circuits/test/escrow/deposit_test.circom');
const refundOk = harness('refund_test', 'escrow_refund_test', 'circuits/test/escrow/refund_test.circom');
const dvpOk = harness('dvp_test', 'dvp_test', 'circuits/test/dvp/dvp_test.circom'); // settle == dvp

// ---- escrow_deposit ----
expect('escrow_deposit: valid witness accepted', depositOk(buildEscrowDepositScenario(DEPTH).witness) === true);
expect('escrow_deposit: frozen spent note rejected (#14)', depositOk(buildEscrowDepositScenario(DEPTH, { frozenMember: true }).witness) === false);
{
  const w = clone(buildEscrowDepositScenario(DEPTH).witness);
  w.in_path_elements = (w.in_path_elements as string[]).map((x, i) => (i === 0 ? (BigInt(x) + 1n).toString() : x));
  expect('escrow_deposit: bad input Merkle path rejected', depositOk(w) === false);
}
{
  const w = clone(buildEscrowDepositScenario(DEPTH).witness);
  w.out_value = (BigInt(w.out_value as string) - 1n).toString(); // breaks in == out + fee (and cm binding)
  expect('escrow_deposit: non-conserving value rejected (#3)', depositOk(w) === false);
}
{
  const w = clone(buildEscrowDepositScenario(DEPTH).witness);
  w.c_auditor = (w.c_auditor as string[]).map(() => '0');
  expect('escrow_deposit: missing auditor ciphertext rejected (#5)', depositOk(w) === false);
}

// ---- escrow_refund ----
expect('escrow_refund: valid witness accepted', refundOk(buildEscrowRefundScenario(DEPTH).witness) === true);
expect('escrow_refund: sanctioned recipient rejected (#19)', refundOk(buildEscrowRefundScenario(DEPTH, { sanctionedRecipient: true }).witness) === false);
{
  const w = clone(buildEscrowRefundScenario(DEPTH).witness);
  w.new_root = (BigInt(w.new_root as string) + 1n).toString();
  expect('escrow_refund: tampered new_root rejected (#12)', refundOk(w) === false);
}

// ---- settle (= dvp circuit, both escrow inputs owned by sk_intent) ----
expect('settle (dvp): valid two-escrow swap accepted', dvpOk(buildSettleScenario(DEPTH).witness) === true);

console.log(failed ? '\nFAILED' : '\nAll escrow-DvP witness gates passed.');
process.exit(failed ? 1 : 0);
