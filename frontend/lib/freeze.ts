'use client';

/**
 * Frozen-set (clawback) IMT helpers (FIN-018, invariant #14).
 *
 * The issuer-managed frozen set is an Indexed Merkle Tree (IMT): every spend
 * proves NON-MEMBERSHIP of each spent commitment against `frozen_root`, so a
 * frozen note simply becomes unspendable. The contract does NO hashing
 * (invariant #11) — it stores the issuer-supplied `new_frozen_root` verbatim and
 * matches it STRICTLY on every transfer. So the off-chain side MUST compute the
 * exact same root the circuit proves against.
 *
 * We rebuild the IMT from the SORTED frozen commitments as `[head, …cms, tail]`,
 * byte-for-byte the construction in scripts/lib/*-scenario.ts (`buildImt`) and the
 * demo's empty IMT — so an empty set reproduces the genesis `frozen_root` exactly
 * (zero drift for the untouched demo) and each freeze advances it consistently.
 *
 * SECURITY (invariant #8): these are PUBLIC commitments + roots, never openings.
 */

import type { Fr, MerklePath, ImtLowLeaf } from '@finnes/sdk';
import { FR_MODULUS, IncrementalMerkleTree, imtLeafHash, TREE_DEPTH } from '@finnes/sdk';

/** IMT tail sentinel value (r − 1); brackets the top of the range. */
export const IMT_MAX: Fr = FR_MODULUS - 1n;

/** 32-byte field element as 0x-less hex (the contract's BytesN<32> arg form). */
export const toHex = (x: Fr): string => x.toString(16).padStart(64, '0');

/** Dedup + ascending sort (the canonical IMT node order). */
export function sortedFrozen(cms: readonly Fr[]): Fr[] {
  return [...new Set(cms)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * Rebuild the frozen IMT from the sorted commitments: leaf 0 = head `{0 → cm₁}`,
 * leaf i+1 = node `{cmᵢ → cmᵢ₊₁}` (last → MAX), final leaf = tail `{MAX → 0}`.
 * Insertion order == physical leaf index, so `nextIndex` pointers are sequential.
 */
function buildFrozenImt(sorted: readonly Fr[]): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(TREE_DEPTH);
  t.insert(imtLeafHash(0n, 1n, sorted[0] ?? IMT_MAX)); // head at index 0
  sorted.forEach((cm, i) => {
    t.insert(imtLeafHash(cm, BigInt(i + 2), sorted[i + 1] ?? IMT_MAX)); // node at index i+1
  });
  t.insert(imtLeafHash(IMT_MAX, 0n, 0n)); // tail at index sorted.length+1
  return t;
}

/** The `frozen_root` for a set of frozen commitments (any order; deduped/sorted). */
export function frozenRootOf(cms: readonly Fr[]): Fr {
  return buildFrozenImt(sortedFrozen(cms)).root();
}

/**
 * Insert `cmTarget` into the frozen set → the new sorted set + the new
 * `frozen_root` (hex, the `freeze` arg). Throws if `cmTarget` is out of range or
 * already frozen (the contract also rejects a repeat with `AlreadyFrozen`).
 */
export function computeFreeze(
  current: readonly Fr[],
  cmTarget: Fr,
): { sorted: Fr[]; rootHex: string } {
  if (cmTarget <= 0n || cmTarget >= IMT_MAX) {
    throw new Error('cm_target must be a field element in (0, MAX).');
  }
  const sorted = sortedFrozen(current);
  if (sorted.includes(cmTarget)) throw new Error('This commitment is already frozen.');
  const next = sortedFrozen([...sorted, cmTarget]);
  return { sorted: next, rootHex: toHex(buildFrozenImt(next).root()) };
}

/**
 * Non-membership witness for `cmSpend` against the live frozen set: the bracketing
 * low leaf `{value < cmSpend < nextValue}` + its inclusion path + the live
 * `frozen_root`. THROWS if `cmSpend` is itself frozen — a frozen note's
 * non-membership is unprovable, which is exactly why it can no longer be spent
 * (invariant #14/#19). The empty-set case returns the head low `{0 → MAX}` at
 * index 0, byte-identical to the demo's genesis frozen witness (zero regression).
 */
export function frozenNonMembership(
  current: readonly Fr[],
  cmSpend: Fr,
): { low: ImtLowLeaf; path: MerklePath; root: Fr } {
  const sorted = sortedFrozen(current);
  if (sorted.includes(cmSpend)) {
    throw new Error('FROZEN: this note is in the issuer frozen set and cannot be spent.');
  }
  const tree = buildFrozenImt(sorted);

  // Head `{0 → …}` is the default low (value 0 < any cmSpend > 0). Walk up while a
  // frozen node value is still strictly below cmSpend; the last such node is the low.
  let lowIdx = 0;
  let low: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: sorted[0] ?? IMT_MAX };
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i]! >= cmSpend) break;
    lowIdx = i + 1;
    low = { value: sorted[i]!, nextIndex: BigInt(i + 2), nextValue: sorted[i + 1] ?? IMT_MAX };
  }
  return { low, path: tree.inclusionPath(lowIdx), root: tree.root() };
}
