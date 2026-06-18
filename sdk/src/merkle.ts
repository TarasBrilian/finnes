/**
 * Off-chain incremental Merkle tree helpers: leaf insertion, frontier
 * maintenance, and inclusion-path extraction.
 *
 * The on-chain contract performs NO hashing (invariant #11); the circuit proves
 * the tree transition `old_frontier → (new_frontier, new_root)` (invariant #12)
 * and the contract stores the outputs verbatim. This SDK tree mirrors that exact
 * hashing so the SDK/prover and circuit agree on roots/paths. The node hash is
 * Poseidon over the BLS12-381 scalar field (poseidon.ts) — the same one the
 * circuit's `merkle.circom` uses.
 *
 * Tree depth `D = 32` (docs/PUBLIC_IO.md §"Tree"; TODO: confirm capacity vs cost).
 */

import type { Commitment, Fr, Frontier, MerklePath, MerkleRoot } from './types.js';
import { poseidonBLS } from './poseidon.js';

/** Tree depth `D`. SCAFFOLD value from docs/PUBLIC_IO.md (TODO: confirm). */
export const TREE_DEPTH = 32 as const;

/**
 * The empty-subtree hashes, `zeros[i]` = hash of an all-empty subtree of height
 * `i`. `zeros[0]` is the empty-leaf sentinel.
 *
 * TODO(crypto): define the canonical empty-leaf value and compute the
 * `zeros[]` ladder via Poseidon to match `circuits/lib/merkle.circom`. Throws
 * until the leaf sentinel and node-hash domain are fixed.
 */
export function emptyTreeZeros(_depth: number = TREE_DEPTH): readonly Fr[] {
  throw new Error(
    'TODO: emptyTreeZeros undefined. Fix the empty-leaf sentinel and the ' +
      'Poseidon node-hash domain to match circuits/lib/merkle.circom.',
  );
}

/** Hash two child nodes into their parent. Order: `Poseidon(left, right)`. */
export function hashNode(left: Fr, right: Fr): Fr {
  return poseidonBLS([left, right]);
}

/**
 * An append-only incremental Merkle tree over commitments. Tracks the frontier
 * (filled subtrees) and the full leaf list so inclusion paths can be produced.
 */
export class IncrementalMerkleTree {
  readonly depth: number;
  private readonly leaves: Fr[] = [];

  constructor(depth: number = TREE_DEPTH) {
    this.depth = depth;
  }

  /** Number of leaves appended so far. */
  get size(): number {
    return this.leaves.length;
  }

  /**
   * Append a commitment as the next leaf; returns its leaf index.
   * (Pure bookkeeping — root/frontier are computed lazily on request.)
   */
  insert(commitment: Commitment): number {
    const index = this.leaves.length;
    this.leaves.push(commitment);
    return index;
  }

  /**
   * Current root.
   *
   * TODO(crypto): compute the root by hashing the leaf level up to the root
   * using `hashNode` and `emptyTreeZeros` for empty siblings. Depends on the
   * empty-leaf sentinel (see emptyTreeZeros). Throws until that is fixed.
   */
  root(): MerkleRoot {
    throw new Error('TODO: IncrementalMerkleTree.root requires emptyTreeZeros (see merkle.ts).');
  }

  /**
   * Current frontier (filled subtrees), `depth` field elements — the public
   * input `old_frontier` (invariant #12).
   *
   * TODO(crypto): derive the filled-subtree array from the leaf list; layout
   * must match the circuit's `old_frontier` ordering exactly.
   */
  frontier(): Frontier {
    throw new Error('TODO: IncrementalMerkleTree.frontier not implemented (invariant #12 layout).');
  }

  /**
   * Inclusion path for the leaf at `leafIndex`: sibling hashes leaf→root and
   * the path bits. Used as private witness for inclusion proofs.
   *
   * TODO(crypto): build siblings using `hashNode`/`emptyTreeZeros`; `pathBits`
   * are the bit decomposition of `leafIndex` (LSB = level 0). Throws until the
   * node hashing is implemented.
   */
  inclusionPath(leafIndex: number): MerklePath {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`leafIndex ${leafIndex} out of range [0, ${this.leaves.length})`);
    }
    throw new Error('TODO: IncrementalMerkleTree.inclusionPath requires node hashing (see merkle.ts).');
  }
}

/**
 * Verify an inclusion path against a root by recomputing the path hashes.
 *
 * TODO(crypto): fold `leaf` up through `path.siblings` using `path.pathBits`
 * and `hashNode`, then compare to `root`. Depends on `hashNode` (Poseidon),
 * which is itself a stub. Throws until Poseidon is implemented.
 */
export function verifyInclusionPath(
  _leaf: Fr,
  _path: MerklePath,
  _root: MerkleRoot,
): boolean {
  throw new Error('TODO: verifyInclusionPath requires poseidonBLS/hashNode (see poseidon.ts).');
}
