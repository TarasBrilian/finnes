// Full DvP-circuit acceptance gate (FIN-016). Builds a complete, consistent
// two-leg settlement witness with the SDK witness builder (via the shared
// scenario helper), drives circuits/test/dvp/dvp_test.circom (Dvp at depth 6),
// and asserts the CLAUDE.md test rule: a valid witness is accepted, and >= 1
// failing witness per constraint class is rejected:
//   - per-leg conservation (#3): leg X out != in (no cross-leg netting),
//   - bad Merkle path (leg Y input inclusion under anchor_root),
//   - missing auditor ciphertext (#5, leg X),
//   - frozen note (#14, leg X spent cm in the frozen set),
//   - over-limit value (#17, leg Y),
//   - tampered new_root (#12, frontier transition),
//   - wrong nullifier (#4, leg X owner binding),
//   - cross-leg asset confusion (#3, leg Y output asset != its input asset).
// Run: `npx tsx scripts/test-dvp-witness.ts` (npm run dvp:witness).

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import { buildDvpScenario } from './lib/dvp-scenario.js';
import type { CircomWitness } from '../sdk/src/witness.js';

const DEPTH = 6;
const NAME = 'dvp_test';
const BUILD = 'circuits/build/dvp_test';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
sh(`circom circuits/test/dvp/${NAME}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`);

function witnessOk(input: CircomWitness): boolean {
  writeFileSync(`${BUILD}/${NAME}.input.json`, JSON.stringify(input));
  try {
    sh(`npx --no-install snarkjs wtns calculate ${BUILD}/${NAME}_js/${NAME}.wasm ${BUILD}/${NAME}.input.json ${BUILD}/${NAME}.wtns`);
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
// Positive case: a fully consistent two-leg witness MUST satisfy every constraint.
// ---------------------------------------------------------------------------
const pass = buildDvpScenario(DEPTH).witness;
expect('valid two-leg DvP witness accepted', witnessOk(pass) === true);

// ---------------------------------------------------------------------------
// Negative cases: one per constraint class, each MUST be rejected.
// ---------------------------------------------------------------------------

// 1. Per-leg conservation (#3): leg X out 999 != in 1000 (cm_out_X is bound, so a
//    raw out_value tweak desyncs the commitment; this exercises the conservation +
//    commitment binding together). Build a scenario with a wrong output value.
{
  const w = clone(pass);
  const v = (w.out_value as string[]).slice();
  v[0] = (BigInt(v[0]!) - 1n).toString(); // 999 != 1000
  w.out_value = v;
  expect('leg X non-conserving value rejected (#3)', witnessOk(w) === false);
}

// 2. Bad Merkle path: corrupt leg Y's first input path element.
{
  const w = clone(pass);
  const pe = (w.in_path_elements as string[][]).map((r) => r.slice());
  pe[1]![0] = (BigInt(pe[1]![0]!) + 1n).toString();
  w.in_path_elements = pe;
  expect('leg Y bad input Merkle path rejected', witnessOk(w) === false);
}

// 3. Missing auditor ciphertext (#5): zero leg X's auditor ct.
{
  const w = clone(pass);
  w.c_auditor_X = (w.c_auditor_X as string[]).map(() => '0');
  expect('leg X missing auditor ciphertext rejected (#5)', witnessOk(w) === false);
}

// 4. Frozen note (#14): leg X's spent cm is in the frozen set.
{
  const w = buildDvpScenario(DEPTH, { frozenMemberLegX: true }).witness;
  expect('leg X frozen spent note rejected (#14)', witnessOk(w) === false);
}

// 5. Over-limit value (#17): leg Y value exceeds the per-tx limit.
{
  const w = buildDvpScenario(DEPTH, { outVals: [1000n, 500n], perTxLimitRaw: 400n }).witness;
  // leg Y out 500 > limit 400 (leg X out 1000 also > 400, either way rejected).
  expect('over per-tx limit rejected (#17)', witnessOk(w) === false);
}

// 6. Tampered new_root (#12): flip the bound transition output.
{
  const w = clone(pass);
  w.new_root = (BigInt(w.new_root as string) + 1n).toString();
  expect('tampered new_root rejected (#12)', witnessOk(w) === false);
}

// 7. Wrong nullifier (#4): tamper leg X's published nullifier.
{
  const w = clone(pass);
  w.nf_legX_0 = (BigInt(w.nf_legX_0 as string) + 1n).toString();
  expect('tampered leg X nullifier rejected (#4)', witnessOk(w) === false);
}

// 8. Cross-leg asset confusion (#3/#16): leg Y spends asset Y but its registry
//    witness/limit must match asset Y — swap leg Y's asset_id to leg X's.
{
  const w = clone(pass);
  const ids = (w.in_asset_id as string[]).slice();
  ids[1] = ids[0]!; // leg Y claims asset X while its registry leaf is asset Y
  w.in_asset_id = ids;
  expect('leg Y asset/registry mismatch rejected (#3/#16)', witnessOk(w) === false);
}

console.log(failed ? '\nFAILED' : '\nAll DvP witness gates passed.');
process.exit(failed ? 1 : 0);
