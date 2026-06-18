/**
 * Off-chain incremental Merkle tree helpers: leaf insertion, frontier
 * maintenance, inclusion-path extraction, and the `old_frontier →
 * (new_frontier, new_root)` transition.
 *
 * The on-chain contract performs NO hashing (invariant #11); the circuit proves
 * the tree transition `old_frontier → (new_frontier, new_root)` (invariant #12)
 * and the contract stores the outputs verbatim. This SDK tree MIRRORS the exact
 * hashing of `circuits/lib/merkle.circom` so the SDK/prover, the circuit, and the
 * indexer agree on roots/paths/frontiers. The node hash is Poseidon over the
 * BLS12-381 scalar field (poseidon.ts) — the same one the circuit uses.
 *
 * CANONICAL CONVENTIONS (must match circuit + contract genesis + indexer):
 *   - Binary tree, node = Poseidon(left, right)  (hashNode).
 *   - EMPTY_LEAF = 0; zeros[0] = 0, zeros[i] = Poseidon(zeros[i-1], zeros[i-1]).
 *     zeros[depth] is the all-empty-tree root.
 *   - Incremental "filled-subtrees" frontier (Tornado/Semaphore style): on insert
 *     at index `idx`, climb levels 0..depth-1; at level `level` the bit
 *     (idx >> level) & 1 selects left (0) or right (1) child. The frontier holds
 *     `depth` elements; the empty-tree frontier is zeros[0..depth-1].
 *   - pathBits: LSB = level 0; 0 = current node is the LEFT child (sibling on the
 *     right), 1 = current is the RIGHT child (sibling on the left). This matches
 *     `MerkleInclusion`'s pathIndices in merkle.circom.
 *
 * Tree depth `D = 20` (docs/PUBLIC_IO.md §"Tree", LOCKED FIN-001).
 */

import type { Commitment, Fr, Frontier, MerklePath, MerkleRoot } from './types.js';
import { poseidonBLS } from './poseidon.js';

/** Tree depth `D` (LOCKED, FIN-001). Capacity 2^20 ≈ 1.05M leaves. */
export const TREE_DEPTH = 20 as const;

/** The empty-leaf sentinel (invariant: a real Poseidon commitment is never 0). */
export const EMPTY_LEAF: Fr = 0n;

/** Hash two child nodes into their parent. Order: `Poseidon(left, right)`. */
export function hashNode(left: Fr, right: Fr): Fr {
  return poseidonBLS([left, right]);
}

/**
 * Empty-subtree hashes: `zeros[i]` = root of an all-empty subtree of height `i`.
 * Returns `depth + 1` elements; `zeros[0] = EMPTY_LEAF`, `zeros[depth]` is the
 * empty-tree root. Must match `circuits/lib/merkle.circom`'s in-circuit zeros and
 * the contract's genesis frontier/root.
 */
export function emptyTreeZeros(depth: number = TREE_DEPTH): readonly Fr[] {
  const zeros: Fr[] = [EMPTY_LEAF];
  for (let i = 1; i <= depth; i++) zeros.push(hashNode(zeros[i - 1]!, zeros[i - 1]!));
  return zeros;
}

/**
 * Single incremental insert of `leaf` at `index` into `frontier` (filled
 * subtrees). Returns the updated frontier and the resulting tree root (empty
 * positions taken as `zeros`). Pure; does not mutate `frontier`.
 *
 * This is the exact step `FrontierTransition` proves in-circuit.
 */
function insertInto(
  frontier: readonly Fr[],
  index: number,
  leaf: Fr,
  zeros: readonly Fr[],
  depth: number,
): { frontier: Fr[]; root: Fr } {
  const f = frontier.slice();
  let cur = leaf;
  let idx = index;
  for (let level = 0; level < depth; level++) {
    if (idx % 2 === 0) {
      // current node is a LEFT child: it becomes the filled subtree at this level,
      // its right sibling is still empty (zeros[level]).
      f[level] = cur;
      cur = hashNode(cur, zeros[level]!);
    } else {
      // current node is a RIGHT child: combine with the stored left subtree.
      cur = hashNode(f[level]!, cur);
    }
    idx = Math.floor(idx / 2);
  }
  return { frontier: f, root: cur };
}

/**
 * Apply the `old_frontier → (new_frontier, new_root)` transition for inserting
 * `newLeaves` (the output commitments) starting at append index `nextIndex`.
 * Mirrors `FrontierTransition(depth, newLeaves.length)` in merkle.circom exactly.
 *
 * `nextIndex` is the current leaf count before the inserts (the contract pins it
 * via state). Requires at least one leaf.
 */
export function applyFrontierTransition(
  oldFrontier: readonly Fr[],
  nextIndex: number,
  newLeaves: readonly Fr[],
  depth: number = TREE_DEPTH,
): { newFrontier: Fr[]; newRoot: Fr } {
  if (oldFrontier.length !== depth) {
    throw new Error(`old_frontier length ${oldFrontier.length} != depth ${depth}`);
  }
  if (newLeaves.length === 0) throw new Error('applyFrontierTransition requires >= 1 leaf');
  const zeros = emptyTreeZeros(depth);
  let frontier: Fr[] = oldFrontier.slice();
  let root: Fr = zeros[depth]!;
  for (let j = 0; j < newLeaves.length; j++) {
    const res = insertInto(frontier, nextIndex + j, newLeaves[j]!, zeros, depth);
    frontier = res.frontier;
    root = res.root;
  }
  return { newFrontier: frontier, newRoot: root };
}

/**
 * An append-only incremental Merkle tree over commitments. Tracks the full leaf
 * list so inclusion paths can be produced, and derives the root/frontier via the
 * same incremental hashing the circuit proves.
 */
export class IncrementalMerkleTree {
  readonly depth: number;
  private readonly leaves: Fr[] = [];
  private readonly zeros: readonly Fr[];

  constructor(depth: number = TREE_DEPTH) {
    this.depth = depth;
    this.zeros = emptyTreeZeros(depth);
  }

  /** Number of leaves appended so far (the next append index). */
  get size(): number {
    return this.leaves.length;
  }

  /** Append a commitment as the next leaf; returns its leaf index. */
  insert(commitment: Commitment): number {
    const index = this.leaves.length;
    this.leaves.push(commitment);
    return index;
  }

  /** Replay all inserts to derive the current (frontier, root). */
  private state(): { frontier: Fr[]; root: Fr } {
    let frontier: Fr[] = this.zeros.slice(0, this.depth);
    let root: Fr = this.zeros[this.depth]!;
    for (let idx = 0; idx < this.leaves.length; idx++) {
      const res = insertInto(frontier, idx, this.leaves[idx]!, this.zeros, this.depth);
      frontier = res.frontier;
      root = res.root;
    }
    return { frontier, root };
  }

  /** Current root (empty tree → zeros[depth]). */
  root(): MerkleRoot {
    return this.state().root;
  }

  /**
   * Current frontier (filled subtrees), `depth` field elements — the public
   * input `old_frontier` (invariant #12). Empty tree → zeros[0..depth-1].
   */
  frontier(): Frontier {
    return this.state().frontier;
  }

  /**
   * Inclusion path for the leaf at `leafIndex`: sibling hashes leaf→root and the
   * path bits (LSB = level 0). Used as private witness for inclusion proofs.
   */
  inclusionPath(leafIndex: number): MerklePath {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`leafIndex ${leafIndex} out of range [0, ${this.leaves.length})`);
    }
    const siblings: Fr[] = [];
    const pathBits: (0 | 1)[] = [];
    let level: Fr[] = this.leaves.slice();
    let idx = leafIndex;
    for (let d = 0; d < this.depth; d++) {
      const isRight = idx % 2 === 1;
      const sibIdx = isRight ? idx - 1 : idx + 1;
      siblings.push(sibIdx < level.length ? level[sibIdx]! : this.zeros[d]!);
      pathBits.push(isRight ? 1 : 0);
      const next: Fr[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const l = level[i]!;
        const r = i + 1 < level.length ? level[i + 1]! : this.zeros[d]!;
        next.push(hashNode(l, r));
      }
      level = next;
      idx = Math.floor(idx / 2);
    }
    return { siblings, pathBits, leafIndex };
  }
}

/**
 * Verify an inclusion path against a root by recomputing the path hashes.
 * `pathBits[d] == 0` ⇒ current node is the left child (sibling on the right).
 */
export function verifyInclusionPath(leaf: Fr, path: MerklePath, root: MerkleRoot): boolean {
  if (path.siblings.length !== path.pathBits.length) {
    throw new Error('inclusion path siblings/pathBits length mismatch');
  }
  let cur = leaf;
  for (let d = 0; d < path.siblings.length; d++) {
    const sib = path.siblings[d]!;
    cur = path.pathBits[d] === 0 ? hashNode(cur, sib) : hashNode(sib, cur);
  }
  return cur === root;
}
