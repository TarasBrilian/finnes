// Full shield-circuit acceptance gate (FIN-012). Builds a complete, consistent
// shield (transparent -> shielded) witness with the SDK witness builder, drives
// circuits/test/shield/shield_test.circom (Shield at depth 6), and asserts the
// CLAUDE.md test rule: a valid witness is accepted, and >= 1 failing witness per
// constraint class is rejected:
//   - tampered cm_out_0 (output opening to (asset_id, amount), invariant #18),
//   - bad KYC path (depositor/owner KYC membership, invariant #6),
//   - missing auditor ciphertext (invariant #5),
//   - over-limit amount (assets registry per-tx limit, invariant #17),
//   - wrong asset binding (asset_id != Poseidon(sac_address), invariant #18),
//   - tampered new_root (frontier transition, invariant #12).
// Run: `npx tsx scripts/test-shield-witness.ts` (npm run shield:witness).

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import { buildShieldScenario } from './lib/shield-scenario.js';
import type { CircomWitness } from '../sdk/src/witness.js';

const DEPTH = 6;
const NAME = 'shield_test';
const BUILD = 'circuits/build/shield_test';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
sh(
  `circom circuits/test/shield/${NAME}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`,
);

// `snarkjs wtns calculate` throws iff a constraint is violated.
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
// Positive case: a fully consistent witness MUST satisfy every constraint.
// ---------------------------------------------------------------------------
const pass = buildShieldScenario(DEPTH).witness;
expect('valid shield witness accepted', witnessOk(pass) === true);

// ---------------------------------------------------------------------------
// Negative cases: one per constraint class, each MUST be rejected.
// ---------------------------------------------------------------------------

// 1. Output opening (#18): tamper cm_out_0 so it no longer equals the note hash.
{
  const w = clone(pass);
  w.cm_out_0 = (BigInt(w.cm_out_0 as string) + 1n).toString();
  expect('tampered cm_out_0 rejected (output opening #18)', witnessOk(w) === false);
}

// 2. Depositor KYC membership (#6): tamper a sibling on the KYC path.
{
  const w = clone(pass);
  const sibs = w.kyc_path_elements as string[];
  sibs[0] = (BigInt(sibs[0]) + 1n).toString();
  expect('bad KYC path rejected (depositor KYC membership #6)', witnessOk(w) === false);
}

// 3. Mandatory auditor ciphertext (#5): zero out the auditor ciphertext.
{
  const w = clone(pass);
  w.c_auditor = ['0', '0', '0', '0', '0'];
  expect('missing auditor ciphertext rejected (invariant #5)', witnessOk(w) === false);
}

// 4. Per-tx limit (#17): amount 700 exceeds a per_tx_limit_raw of 500.
expect(
  'over-limit amount rejected (assets per-tx limit #17)',
  witnessOk(buildShieldScenario(DEPTH, { perTxLimitRaw: 500n }).witness) === false,
);

// 5. Asset self-binding (#18): tamper sac_address so asset_id != Poseidon(sac).
{
  const w = clone(pass);
  w.sac_address = (BigInt(w.sac_address as string) + 1n).toString();
  expect('wrong asset binding rejected (self-binding #18)', witnessOk(w) === false);
}

// 6. Frontier transition (#12): tamper the public new_root.
{
  const w = clone(pass);
  w.new_root = (BigInt(w.new_root as string) + 1n).toString();
  expect('tampered new_root rejected (frontier transition #12)', witnessOk(w) === false);
}

if (failed) {
  console.error('\nSHIELD WITNESS GATE FAILED - a constraint is missing or the SDK builder drifted.');
  process.exit(1);
}
console.log('\nSHIELD WITNESS OK - valid witness accepted; every constraint class rejects a bad witness.');
