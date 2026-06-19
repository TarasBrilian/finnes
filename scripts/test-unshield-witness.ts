// Full unshield-circuit acceptance gate (FIN-013). Builds a complete, consistent
// unshield (shielded -> transparent) witness with the SDK builder, drives
// circuits/test/unshield/unshield_test.circom (Unshield at depth 6), and asserts
// the CLAUDE.md test rule: valid witnesses are accepted (with AND without a change
// note), and >= 1 failing witness per constraint class is rejected:
//   - frozen note spent (frozen-set non-membership, invariant #19b),
//   - sanctioned recipient (sanctions non-membership, invariant #19a),
//   - bad input Merkle path (inclusion under anchor_root),
//   - unbalanced value (conservation amount + change == input, invariant #3),
//   - over-limit amount (assets registry per-tx limit, invariant #17),
//   - missing auditor ciphertext on a change note (invariant #5),
//   - wrong spending key (ownership / nullifier, invariant #4),
//   - tampered new_root (frontier transition, invariant #12).
// Run: `npx tsx scripts/test-unshield-witness.ts` (npm run unshield:witness).

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import { buildUnshieldScenario } from './lib/unshield-scenario.js';
import type { CircomWitness } from '../sdk/src/witness.js';

const DEPTH = 6;
const NAME = 'unshield_test';
const BUILD = 'circuits/build/unshield_test';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
sh(
  `circom circuits/test/unshield/${NAME}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`,
);

function witnessOk(input: CircomWitness): boolean {
  writeFileSync(`${BUILD}/${NAME}.input.json`, JSON.stringify(input));
  try {
    sh(
      `npx --no-install snarkjs wtns calculate ${BUILD}/${NAME}_js/${NAME}.wasm ${BUILD}/${NAME}.input.json ${BUILD}/${NAME}.wtns`,
    );
    return true;
  } catch {
    return false;
  }
}

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

function clone(w: CircomWitness): CircomWitness {
  return JSON.parse(JSON.stringify(w)) as CircomWitness;
}

// ---------------------------------------------------------------------------
// Positive cases: with a change note AND an exact spend (no change) - both MUST
// satisfy every constraint (the no-change case exercises the gated 0-leaf
// transition + all-zero ciphertexts).
// ---------------------------------------------------------------------------
const pass = buildUnshieldScenario(DEPTH).witness;
expect('valid unshield witness accepted (with change)', witnessOk(pass) === true);
expect(
  'valid unshield witness accepted (exact spend, no change)',
  witnessOk(buildUnshieldScenario(DEPTH, { noChange: true }).witness) === true,
);

// ---------------------------------------------------------------------------
// Negative cases: one per constraint class, each MUST be rejected.
// ---------------------------------------------------------------------------

// 1. Frozen-set non-membership (#19b): spend a note that IS in the frozen set.
expect(
  'frozen note rejected (frozen non-membership #19b)',
  witnessOk(buildUnshieldScenario(DEPTH, { frozenMemberInput: true }).witness) === false,
);

// 2. Sanctions non-membership (#19a): pay a SANCTIONED transparent recipient.
expect(
  'sanctioned recipient rejected (sanctions non-membership #19a)',
  witnessOk(buildUnshieldScenario(DEPTH, { recipientSanctioned: true }).witness) === false,
);

// 3. Input inclusion: tamper a sibling on the input's Merkle path.
{
  const w = clone(pass);
  const sibs = w.in_path_elements as string[];
  sibs[0] = (BigInt(sibs[0]) + 1n).toString();
  expect('bad input Merkle path rejected (inclusion under anchor_root)', witnessOk(w) === false);
}

// 4. Conservation (#3): bump only `amount` (700 -> 701) so amount + change (300)
//    no longer equals the input value (1000). The scenario auto-balances change
//    from amount, so we tamper the assembled witness directly to break it.
{
  const w = clone(pass);
  w.amount = (BigInt(w.amount as string) + 1n).toString();
  expect('unbalanced value rejected (conservation #3)', witnessOk(w) === false);
}

// 5. Per-tx limit (#17): amount 700 exceeds a per_tx_limit_raw of 500.
expect(
  'over-limit amount rejected (assets per-tx limit #17)',
  witnessOk(buildUnshieldScenario(DEPTH, { perTxLimitRaw: 500n }).witness) === false,
);

// 6. Mandatory auditor ciphertext on the change note (#5): zero it out while
//    has_change == 1 (the circuit then expects the real keystream).
{
  const w = clone(pass);
  w.c_auditor = ['0', '0', '0', '0', '0'];
  expect('missing auditor ciphertext rejected (invariant #5)', witnessOk(w) === false);
}

// 7. Ownership / nullifier (#4): wrong spending key (owner_pk != Poseidon(sk)).
{
  const w = clone(pass);
  w.owner_sk = '43';
  expect('wrong spending key rejected (ownership/nullifier #4)', witnessOk(w) === false);
}

// 8. Frontier transition (#12): tamper the public new_root.
{
  const w = clone(pass);
  w.new_root = (BigInt(w.new_root as string) + 1n).toString();
  expect('tampered new_root rejected (frontier transition #12)', witnessOk(w) === false);
}

if (failed) {
  console.error('\nUNSHIELD WITNESS GATE FAILED - a constraint is missing or the SDK builder drifted.');
  process.exit(1);
}
console.log(
  '\nUNSHIELD WITNESS OK - valid witnesses (change + no-change) accepted; every constraint class rejects a bad witness.',
);
