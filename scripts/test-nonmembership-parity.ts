// IMT non-membership soundness gate (FIN-003, fund-critical: invariants #14/#19).
//
// Builds a small Indexed Merkle Tree (sorted linked list) in the SDK, then drives
// circuits/lib/merkle.circom MerkleNonMembership and asserts:
//   - a value in a GAP is provably absent (witness succeeds),
//   - the tail/maximum branch (low_next_value == 0) works,
//   - a value that IS in the set CANNOT be proven absent (witness fails) - this is
//     the property that keeps a frozen note unspendable.
// Run: `npx tsx scripts/test-nonmembership-parity.ts`.

import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { IncrementalMerkleTree, imtLeafHash } from '../sdk/src/merkle.js';
import type { Fr } from '../sdk/src/types.js';

const DEPTH = 6;
const BUILD = 'circuits/build/merkle';
mkdirSync(BUILD, { recursive: true });

function sh(cmd: string): void {
  execSync(cmd, { stdio: ['ignore', 'ignore', 'pipe'] });
}
const NAME = 'nonmember6';
sh(`circom circuits/test/merkle/${NAME}.circom --r1cs --wasm --sym --prime bls12381 -o ${BUILD} -l circuits/lib`);

function tryWitness(input: unknown): boolean {
  writeFileSync(`${BUILD}/${NAME}.input.json`, JSON.stringify(input));
  try {
    sh(`npx --no-install snarkjs wtns calculate ${BUILD}/${NAME}_js/${NAME}.wasm ${BUILD}/${NAME}.input.json ${BUILD}/${NAME}.wtns`);
    return true;
  } catch {
    return false;
  }
}

// --- Build the IMT: a sorted linked list over {0, 10, 50, 90} ------------------
// leaf[i] = Poseidon(value, next_index, next_value, 0, 0); next_value 0 = tail.
interface ImtLeaf { value: Fr; nextIndex: Fr; nextValue: Fr }
const leaves: ImtLeaf[] = [
  { value: 0n, nextIndex: 1n, nextValue: 10n }, // head sentinel
  { value: 10n, nextIndex: 2n, nextValue: 50n },
  { value: 50n, nextIndex: 3n, nextValue: 90n },
  { value: 90n, nextIndex: 0n, nextValue: 0n }, // tail (max)
];
const tree = new IncrementalMerkleTree(DEPTH);
leaves.forEach((l) => tree.insert(imtLeafHash(l.value, l.nextIndex, l.nextValue)));
const root = tree.root();

function witnessFor(target: Fr, lowIndex: number): unknown {
  const low = leaves[lowIndex]!;
  const path = tree.inclusionPath(lowIndex);
  return {
    target: target.toString(),
    low_value: low.value.toString(),
    low_next_index: low.nextIndex.toString(),
    low_next_value: low.nextValue.toString(),
    pathElements: path.siblings.map(String),
    pathIndices: path.pathBits.map(String),
    root: root.toString(),
  };
}

let failed = false;
function expect(label: string, ok: boolean): void {
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
}

// non-member in the gap (10 < 30 < 50): low leaf is index 1 → MUST succeed.
expect('30 absent (gap 10..50) accepted', tryWitness(witnessFor(30n, 1)) === true);
// non-member above the max (90 < 200, tail): low leaf is index 3, next_value 0 → succeed.
expect('200 absent (tail/max branch) accepted', tryWitness(witnessFor(200n, 3)) === true);
// member 50: no low leaf can bracket it → every attempt MUST fail.
expect('50 present, low=index1 (10,next50) rejected', tryWitness(witnessFor(50n, 1)) === false);
expect('50 present, low=index2 (50,next90) rejected', tryWitness(witnessFor(50n, 2)) === false);
// member 10: likewise unprovable as absent.
expect('10 present, low=index0 (0,next10) rejected', tryWitness(witnessFor(10n, 0)) === false);
// lying about the low leaf (wrong next_value to fake a gap) → inclusion fails.
expect(
  '30 with forged low_next_value rejected',
  tryWitness({
    ...(witnessFor(30n, 1) as Record<string, unknown>),
    low_next_value: '40', // not the real leaf → leaf hash ≠ tree leaf → inclusion fails
  }) === false,
);

if (failed) {
  console.error('\nIMT NON-MEMBERSHIP FAILED.');
  process.exit(1);
}
console.log('\nIMT NON-MEMBERSHIP OK - gaps/tail accepted, members + forged low leaves rejected.');
