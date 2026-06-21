/**
 * Ordered public-input assembly, one builder per circuit.
 *
 * ============================================================================
 * SINGLE SOURCE OF TRUTH: docs/PUBLIC_IO.md
 * ============================================================================
 * The field order produced here MUST match docs/PUBLIC_IO.md EXACTLY, which is
 * in turn mirrored by each `circuits/*.circom` `main`, the contract's
 * `PublicInputs::to_vec()`, and the prover. A mismatch surfaces as a bogus
 * "invalid proof" (CLAUDE.md → "When adding a new circuit..."). Do not reorder
 * casually - reordering requires a fresh phase-2 ceremony and a new VK.
 *
 * Layout notes carried verbatim from docs/PUBLIC_IO.md:
 *   - Tree depth D (frontier length) - TODO confirm; default 32 (see merkle.ts).
 *   - Ciphertext packing lengths K_a / K_r - TODO (scheme not fixed). The
 *     builders append `c*.fields` in document order; correctness of K_a/K_r is
 *     enforced once the scheme lands.
 *   - `auditor_pk` is a single field placeholder (may expand to _x/_y - TODO).
 *   - `fee` is per-asset and 0 in the demo (invariant #3) but always present.
 *   - All amounts are raw SAC units (invariant #16); never rescaled here.
 *
 * These builders assemble PUBLIC values only - they never touch secrets
 * (invariant #8).
 * ============================================================================
 */

import type {
  AuditorPublicKey,
  Ciphertext,
  Commitment,
  Fr,
  Frontier,
  MerkleRoot,
  Nullifier,
  RawAmount,
  StateRoots,
} from './types.js';

/** Ordered public-input vector handed to the Groth16 verifier. */
export type PublicInputVector = Fr[];

/** Assert both frontiers have the agreed depth (invariant #12 layout). */
function checkFrontier(name: string, frontier: Frontier, expectedDepth: number): void {
  if (frontier.length !== expectedDepth) {
    throw new Error(
      `${name} length ${frontier.length} != tree depth ${expectedDepth} (docs/PUBLIC_IO.md §Tree)`,
    );
  }
}

/**
 * transfer.circom - 2-in / 2-out, single asset.
 * Order (docs/PUBLIC_IO.md §transfer.circom, 73 signals):
 *   0 anchor_root, 1 kyc_root, 2 sanction_root, 3 assets_root, 4 frozen_root,
 *   5 auditor_pk, 6 nf_in_0, 7 nf_in_1, 8 cm_out_0, 9 cm_out_1, 10 new_root,
 *   11 fee, 12 next_index, 13.. old_frontier[D], ..new_frontier[D],
 *   ..c_auditor_0[K_a], ..c_auditor_1[K_a], ..c_recipient_0[K_r], ..c_recipient_1[K_r].
 *
 * EVERY output note carries a MANDATORY auditor ciphertext (invariant #5), so
 * `cAuditor` and `cRecipient` are 2-tuples (note 0 = recipient, note 1 = change).
 * `nextIndex` is the current leaf count; the contract checks it equals state.
 */
export function buildTransferPublicInputs(args: {
  roots: StateRoots;
  auditorPk: AuditorPublicKey;
  nfIn: readonly [Nullifier, Nullifier];
  cmOut: readonly [Commitment, Commitment];
  newRoot: MerkleRoot;
  fee: RawAmount;
  nextIndex: Fr;
  oldFrontier: Frontier;
  newFrontier: Frontier;
  /** One ciphertext per output note [note0, note1]; both auditor cts mandatory. */
  cAuditor: readonly [Ciphertext, Ciphertext];
  cRecipient: readonly [Ciphertext, Ciphertext];
  treeDepth: number;
}): PublicInputVector {
  checkFrontier('oldFrontier', args.oldFrontier, args.treeDepth);
  checkFrontier('newFrontier', args.newFrontier, args.treeDepth);
  return [
    args.roots.anchorRoot,
    args.roots.kycRoot,
    args.roots.sanctionRoot,
    args.roots.assetsRoot,
    args.roots.frozenRoot,
    args.auditorPk.pk,
    args.nfIn[0],
    args.nfIn[1],
    args.cmOut[0],
    args.cmOut[1],
    args.newRoot,
    args.fee,
    args.nextIndex,
    ...args.oldFrontier,
    ...args.newFrontier,
    ...args.cAuditor[0].fields,
    ...args.cAuditor[1].fields,
    ...args.cRecipient[0].fields,
    ...args.cRecipient[1].fields,
  ];
}

/**
 * shield.circom - transparent → shielded (0 shielded inputs, 1 transparent in).
 * Order (docs/PUBLIC_IO.md §shield.circom, 59 signals):
 *   0 asset_id, 1 amount, 2 kyc_root, 3 assets_root, 4 auditor_pk, 5 cm_out_0,
 *   6 new_root, 7 fee, 8 next_index, 9.. old_frontier[D], ..new_frontier[D],
 *   ..c_auditor[K_a], ..c_recipient[K_r].
 *
 * NOTE: shield exposes only kyc_root + assets_root (no anchor/sanction/frozen -
 * there are no shielded inputs to anchor or freeze-check). `nextIndex` is the
 * current leaf count; the contract checks it equals state (FIN-012, inv #11/#12).
 */
export function buildShieldPublicInputs(args: {
  assetId: Fr;
  amount: RawAmount;
  kycRoot: MerkleRoot;
  assetsRoot: MerkleRoot;
  auditorPk: AuditorPublicKey;
  cmOut0: Commitment;
  newRoot: MerkleRoot;
  fee: RawAmount;
  nextIndex: Fr;
  oldFrontier: Frontier;
  newFrontier: Frontier;
  cAuditor: Ciphertext;
  cRecipient: Ciphertext;
  treeDepth: number;
}): PublicInputVector {
  checkFrontier('oldFrontier', args.oldFrontier, args.treeDepth);
  checkFrontier('newFrontier', args.newFrontier, args.treeDepth);
  return [
    args.assetId,
    args.amount,
    args.kycRoot,
    args.assetsRoot,
    args.auditorPk.pk,
    args.cmOut0,
    args.newRoot,
    args.fee,
    args.nextIndex,
    ...args.oldFrontier,
    ...args.newFrontier,
    ...args.cAuditor.fields,
    ...args.cRecipient.fields,
  ];
}

/**
 * unshield.circom - shielded → transparent (1 shielded input, transparent out).
 * Order (docs/PUBLIC_IO.md §unshield.circom, 64 signals):
 *   0 anchor_root, 1 kyc_root, 2 sanction_root, 3 assets_root, 4 frozen_root,
 *   5 auditor_pk, 6 nf_in_0, 7 asset_id, 8 amount, 9 recipient, 10 cm_change_0,
 *   11 new_root, 12 fee, 13 next_index, 14.. old_frontier[D], ..new_frontier[D],
 *   ..c_auditor[K_a], ..c_recipient[K_r] (both for the change note, all-zero when
 *   cm_change_0 == 0).
 *
 * `recipient` is the transparent Stellar address encoded as a field element
 * (demo: a single field; must match the circuit / contract). `cmChange0` is the
 * 0 sentinel if there is no change note. `nextIndex` is the current leaf count;
 * the contract checks it equals state (FIN-013, inv #11/#12).
 */
export function buildUnshieldPublicInputs(args: {
  roots: StateRoots;
  auditorPk: AuditorPublicKey;
  nfIn0: Nullifier;
  assetId: Fr;
  amount: RawAmount;
  recipient: Fr;
  cmChange0: Commitment;
  newRoot: MerkleRoot;
  fee: RawAmount;
  nextIndex: Fr;
  oldFrontier: Frontier;
  newFrontier: Frontier;
  cAuditor: Ciphertext;
  cRecipient: Ciphertext;
  treeDepth: number;
}): PublicInputVector {
  checkFrontier('oldFrontier', args.oldFrontier, args.treeDepth);
  checkFrontier('newFrontier', args.newFrontier, args.treeDepth);
  return [
    args.roots.anchorRoot,
    args.roots.kycRoot,
    args.roots.sanctionRoot,
    args.roots.assetsRoot,
    args.roots.frozenRoot,
    args.auditorPk.pk,
    args.nfIn0,
    args.assetId,
    args.amount,
    args.recipient,
    args.cmChange0,
    args.newRoot,
    args.fee,
    args.nextIndex,
    ...args.oldFrontier,
    ...args.newFrontier,
    ...args.cAuditor.fields,
    ...args.cRecipient.fields,
  ];
}

/**
 * dvp.circom - atomic two-asset settlement (demo: single combined proof).
 * Order (docs/PUBLIC_IO.md §dvp.circom):
 *   0 anchor_root, 1 kyc_root, 2 sanction_root, 3 assets_root, 4 frozen_root,
 *   5 auditor_pk, 6 nf_legX_0, 7 nf_legY_0, 8 cm_out_X, 9 cm_out_Y, 10 new_root,
 *   11 fee_X, 12 fee_Y, 13 next_index, 14.. old_frontier[D], ..new_frontier[D],
 *   ..c_auditor_X[K_a], ..c_auditor_Y[K_a], ..c_recipient_X[K_r],
 *   ..c_recipient_Y[K_r]. Total 74 (D=20, K_a=K_r=5).
 *
 * The single combined-proof form is DEMO-ONLY (invariant #15 / ARCHITECTURE.md
 * §Settlement); production DvP uses the escrow / two-phase flow built from
 * transfer/shield variants.
 */
export function buildDvpPublicInputs(args: {
  roots: StateRoots;
  auditorPk: AuditorPublicKey;
  nfLegX0: Nullifier;
  nfLegY0: Nullifier;
  cmOutX: Commitment;
  cmOutY: Commitment;
  newRoot: MerkleRoot;
  feeX: RawAmount;
  feeY: RawAmount;
  /** Current leaf count the contract pins to state (invariants #11/#12). */
  nextIndex: bigint;
  oldFrontier: Frontier;
  newFrontier: Frontier;
  cAuditorX: Ciphertext;
  cAuditorY: Ciphertext;
  cRecipientX: Ciphertext;
  cRecipientY: Ciphertext;
  treeDepth: number;
}): PublicInputVector {
  checkFrontier('oldFrontier', args.oldFrontier, args.treeDepth);
  checkFrontier('newFrontier', args.newFrontier, args.treeDepth);
  return [
    args.roots.anchorRoot,
    args.roots.kycRoot,
    args.roots.sanctionRoot,
    args.roots.assetsRoot,
    args.roots.frozenRoot,
    args.auditorPk.pk,
    args.nfLegX0,
    args.nfLegY0,
    args.cmOutX,
    args.cmOutY,
    args.newRoot,
    args.feeX,
    args.feeY,
    args.nextIndex,
    ...args.oldFrontier,
    ...args.newFrontier,
    ...args.cAuditorX.fields,
    ...args.cAuditorY.fields,
    ...args.cRecipientX.fields,
    ...args.cRecipientY.fields,
  ];
}
