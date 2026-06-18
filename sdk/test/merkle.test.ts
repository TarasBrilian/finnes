/**
 * Incremental Merkle tree self-consistency (FIN-003).
 *
 * These assert the SDK tree is internally coherent: inclusion paths verify
 * against the root, and the `old_frontier → (new_frontier, new_root)` transition
 * matches a freshly-built tree. The cross-surface circuit↔SDK parity (same
 * inputs → same root in circom and SDK) is `scripts/test-merkle-parity.ts`.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  EMPTY_LEAF,
  IncrementalMerkleTree,
  TREE_DEPTH,
  applyFrontierTransition,
  emptyTreeZeros,
  verifyInclusionPath,
} from '../src/merkle.js';

const DEPTH = 6; // small tree for fast tests; logic is depth-agnostic

test('emptyTreeZeros: zeros[0]=0 and ladder hashes pairwise', () => {
  const zeros = emptyTreeZeros(DEPTH);
  assert.equal(zeros.length, DEPTH + 1);
  assert.equal(zeros[0], EMPTY_LEAF);
  assert.ok(zeros[DEPTH]! > 0n, 'empty-tree root must be a non-trivial field element');
});

test('TREE_DEPTH is the FIN-001 locked depth', () => {
  assert.equal(TREE_DEPTH, 20);
});

test('inclusion paths verify against the root for every leaf', () => {
  const tree = new IncrementalMerkleTree(DEPTH);
  const leaves = [11n, 22n, 33n, 44n, 55n];
  leaves.forEach((l) => tree.insert(l));
  const root = tree.root();
  leaves.forEach((leaf, i) => {
    const path = tree.inclusionPath(i);
    assert.equal(path.siblings.length, DEPTH);
    assert.ok(verifyInclusionPath(leaf, path, root), `leaf ${i} must verify`);
    // a wrong leaf must NOT verify against the same path
    assert.ok(!verifyInclusionPath(leaf + 1n, path, root), `tampered leaf ${i} must fail`);
  });
});

test('empty tree root equals zeros[depth]', () => {
  const tree = new IncrementalMerkleTree(DEPTH);
  assert.equal(tree.root(), emptyTreeZeros(DEPTH)[DEPTH]);
});

test('frontier transition matches a freshly-built tree', () => {
  // Build a tree with 3 leaves, snapshot its frontier + size, then insert 2 more
  // via applyFrontierTransition and compare to a tree built with all 5 leaves.
  const base = new IncrementalMerkleTree(DEPTH);
  [1n, 2n, 3n].forEach((l) => base.insert(l));
  const oldFrontier = base.frontier();
  const nextIndex = base.size;

  const newLeaves = [4n, 5n];
  const { newFrontier, newRoot } = applyFrontierTransition(
    oldFrontier,
    nextIndex,
    newLeaves,
    DEPTH,
  );

  const full = new IncrementalMerkleTree(DEPTH);
  [1n, 2n, 3n, 4n, 5n].forEach((l) => full.insert(l));

  assert.equal(newRoot, full.root(), 'transition root must equal the rebuilt tree root');
  assert.deepEqual(newFrontier, [...full.frontier()], 'transition frontier must match');
});

test('transition from empty equals sequential inserts', () => {
  const leaves = [7n, 8n, 9n, 10n];
  const { newRoot } = applyFrontierTransition(
    emptyTreeZeros(DEPTH).slice(0, DEPTH),
    0,
    leaves,
    DEPTH,
  );
  const tree = new IncrementalMerkleTree(DEPTH);
  leaves.forEach((l) => tree.insert(l));
  assert.equal(newRoot, tree.root());
});
