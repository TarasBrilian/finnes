/**
 * In-memory incremental Merkle trees (one per `Tree`), the hot path for serving
 * inclusion proofs. Uses the SDK's `IncrementalMerkleTree` so the hashing is
 * BYTE-IDENTICAL to the circuit (Poseidon-BLS parity, invariant #11/#13). Rebuilt
 * from the `leaves` table on boot; appended to as the worker ingests.
 */

import { IncrementalMerkleTree, TREE_DEPTH } from '@finnes/sdk';

const trees = new Map<number, IncrementalMerkleTree>();

function get(t: number): IncrementalMerkleTree {
  let x = trees.get(t);
  if (!x) {
    x = new IncrementalMerkleTree(TREE_DEPTH);
    trees.set(t, x);
  }
  return x;
}

export const size = (t: number): number => get(t).size;
export const rootBig = (t: number): bigint => get(t).root();
export const frontierBig = (t: number): bigint[] => [...get(t).frontier()];
export const append = (t: number, commitment: bigint): number => get(t).insert(commitment);

export function path(t: number, leafIndex: number): { siblings: bigint[]; pathBits: number[]; leafIndex: number } {
  const p = get(t).inclusionPath(leafIndex);
  return { siblings: [...p.siblings], pathBits: [...p.pathBits] as number[], leafIndex: p.leafIndex };
}
