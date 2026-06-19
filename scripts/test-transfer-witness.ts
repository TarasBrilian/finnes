// Full transfer-circuit acceptance gate (FIN-006). Builds a complete, consistent
// 2-in / 2-out transfer witness with the SDK witness builder (via the shared
// scenario helper), drives circuits/test/transfer/transfer_test.circom (Transfer
// at depth 6), and asserts the CLAUDE.md test rule: a valid witness is accepted,
// and >= 1 failing witness per constraint class is rejected:
//   - unbalanced value (per-asset conservation, invariant #3),
//   - bad Merkle path (input inclusion under anchor_root),
//   - missing auditor ciphertext (invariant #5),
//   - frozen note (frozen-set non-membership, invariant #14),
//   - over-limit value (assets registry per-tx limit, invariant #17),
//   - tampered new_root (frontier transition, invariant #12),
//   - wrong spending key (ownership / nullifier, invariant #4).
// Run: `npx tsx scripts/test-transfer-witness.ts` (npm run transfer:witness).

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import { buildTransferScenario } from './lib/transfer-scenario.js';
import type { CircomWitness } from '../sdk/src/witness.js';

const DEPTH = 6;
const NAME = 'transfer_test';
const BUILD = 'circuits/build/transfer_test';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
sh(
  `circom circuits/test/transfer/${NAME}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`,
);

// Use `snarkjs wtns calculate` (not circom's generate_witness.js, which is a
// CommonJS script that fails under this package's `"type": "module"`). Witness
// calculation throws iff a constraint is violated.
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

/** Deep-clone a witness record (all values are JSON-safe strings/arrays). */
function clone(w: CircomWitness): CircomWitness {
  return JSON.parse(JSON.stringify(w)) as CircomWitness;
}

// ---------------------------------------------------------------------------
// Positive case: a fully consistent witness MUST satisfy every constraint.
// ---------------------------------------------------------------------------
const pass = buildTransferScenario(DEPTH).witness;
expect('valid 2-in/2-out transfer witness accepted', witnessOk(pass) === true);

// ---------------------------------------------------------------------------
// Negative cases: one per constraint class, each MUST be rejected.
// ---------------------------------------------------------------------------

// 1. Per-asset conservation (#3): outputs sum to 1001 != inputs 1000.
expect(
  'unbalanced value rejected (conservation #3)',
  witnessOk(buildTransferScenario(DEPTH, { outVals: [700n, 301n] }).witness) === false,
);

// 2. Input inclusion: tamper a sibling on input 0's Merkle path.
{
  const w = clone(pass);
  const paths = w.in_path_elements as string[][];
  paths[0][0] = (BigInt(paths[0][0]) + 1n).toString();
  expect('bad Merkle path rejected (input inclusion)', witnessOk(w) === false);
}

// 3. Mandatory auditor ciphertext (#5): zero out output 0's auditor ciphertext.
{
  const w = clone(pass);
  (w.c_auditor as string[][])[0] = ['0', '0', '0', '0', '0'];
  expect('missing auditor ciphertext rejected (invariant #5)', witnessOk(w) === false);
}

// 4. Frozen-set non-membership (#14): spend a note that IS in the frozen set.
expect(
  'frozen note rejected (frozen non-membership #14)',
  witnessOk(buildTransferScenario(DEPTH, { frozenMemberInput0: true }).witness) === false,
);

// 5. Per-tx limit (#17): output value 700 exceeds a per_tx_limit_raw of 500.
expect(
  'over-limit value rejected (assets per-tx limit #17)',
  witnessOk(buildTransferScenario(DEPTH, { perTxLimitRaw: 500n }).witness) === false,
);

// 6. Frontier transition (#12): tamper the public new_root.
{
  const w = clone(pass);
  w.new_root = (BigInt(w.new_root as string) + 1n).toString();
  expect('tampered new_root rejected (frontier transition #12)', witnessOk(w) === false);
}

// 7. Ownership / nullifier (#4): wrong spending key (owner_pk != Poseidon(sk)).
{
  const w = clone(pass);
  w.owner_sk = '43';
  expect('wrong spending key rejected (ownership/nullifier #4)', witnessOk(w) === false);
}

if (failed) {
  console.error('\nTRANSFER WITNESS GATE FAILED - a constraint is missing or the SDK builder drifted.');
  process.exit(1);
}
console.log(
  '\nTRANSFER WITNESS OK - valid witness accepted; every constraint class rejects a bad witness.',
);
