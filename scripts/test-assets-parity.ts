// Authorized-assets registry parity/acceptance gate (FIN-005, invariants #17/#18).
//
// Builds a small registry tree in the SDK (leaf = assetsLeafHash, mirroring
// circuits/lib/assets.circom), then drives AssetsMembership and asserts:
//   - a leaf with value <= per_tx_limit_raw and a correct path is accepted,
//   - an over-limit value is rejected (the limit comes from the leaf, not a
//     public input),
//   - a forged asset_id (asset_id != Poseidon(sac_address)) is rejected,
//   - a tampered Merkle root is rejected.
// Run: `npx tsx scripts/test-assets-parity.ts`.

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

import { IncrementalMerkleTree, assetsLeafHash } from '../sdk/src/merkle.js';
import { poseidonBLS } from '../sdk/src/poseidon.js';
import type { Fr } from '../sdk/src/types.js';

const DEPTH = 4;
const NAME = 'assets4';
const BUILD = 'circuits/build/assets';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
sh(`circom circuits/test/assets/${NAME}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`);

function witnessOk(input: unknown): boolean {
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

// --- build the registry tree -------------------------------------------------
// asset_id = Poseidon(sac_address) (self-binding); leaf padded to arity 5.
interface RegLeaf { sacAddress: Fr; decimals: Fr; perTxLimitRaw: Fr }
const regLeaves: RegLeaf[] = [
  { sacAddress: 111n, decimals: 7n, perTxLimitRaw: 10_000_000n },
  { sacAddress: 222n, decimals: 2n, perTxLimitRaw: 500n },
  { sacAddress: 333n, decimals: 6n, perTxLimitRaw: 1_000n },
];
const assetIdOf = (sac: Fr): Fr => poseidonBLS([sac]);
const tree = new IncrementalMerkleTree(DEPTH);
regLeaves.forEach((l) =>
  tree.insert(assetsLeafHash(assetIdOf(l.sacAddress), l.sacAddress, l.decimals, l.perTxLimitRaw)),
);
const assetsRoot = tree.root();

function inputFor(leafIndex: number, value: Fr, overrides: Record<string, unknown> = {}): unknown {
  const l = regLeaves[leafIndex]!;
  const path = tree.inclusionPath(leafIndex);
  return {
    asset_id: assetIdOf(l.sacAddress).toString(),
    value: value.toString(),
    sac_address: l.sacAddress.toString(),
    decimals: l.decimals.toString(),
    per_tx_limit_raw: l.perTxLimitRaw.toString(),
    pathElements: path.siblings.map(String),
    pathIndices: path.pathBits.map(String),
    assets_root: assetsRoot.toString(),
    ...overrides,
  };
}

// leaf 0: limit 10M, value 5M <= limit and correct path → accepted.
expect('value <= per_tx_limit_raw with valid path accepted', witnessOk(inputFor(0, 5_000_000n)) === true);
// leaf 1: limit 500, value 501 > limit → rejected (limit comes from the leaf).
expect('over-limit value (501 > 500) rejected', witnessOk(inputFor(1, 501n)) === false);
// leaf 1 boundary: value == limit accepted (LessEqThan).
expect('value == per_tx_limit_raw accepted', witnessOk(inputFor(1, 500n)) === true);
// forged asset_id (not Poseidon(sac_address)) → self-binding fails.
expect('forged asset_id rejected', witnessOk(inputFor(0, 5_000_000n, { asset_id: '999' })) === false);
// tampered root → inclusion fails.
expect('tampered assets_root rejected', witnessOk(inputFor(0, 5_000_000n, { assets_root: (assetsRoot + 1n).toString() })) === false);

if (failed) {
  console.error('\nASSETS PARITY FAILED - circuit and SDK disagree, or a constraint is missing.');
  process.exit(1);
}
console.log('\nASSETS PARITY OK - membership + self-binding + per-tx limit enforced; forgeries rejected.');
