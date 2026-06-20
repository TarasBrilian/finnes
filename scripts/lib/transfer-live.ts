// Build a REAL D=20 confidential-transfer witness against the DEPLOYED contract's
// LIVE state (FIN-025).
//
// This is the transfer analogue of `scripts/prove-shield-live.ts`'s witness step:
// unlike `scripts/lib/transfer-scenario.ts` (which fabricates its OWN self-contained
// anchor tree, compliance roots, and view key for the offline gates), this anchors
// to `buildDemoComplianceState(20)` — the SAME kyc/sanction/assets/frozen roots and
// `auditor_pk` the post-deploy `init` stored — and to the live commitment tree
// reconstructed from the two on-chain shields (`reconstructAnchorTree`). So the
// resulting proof's public roots MATCH contract state and the contract accepts it:
//   - anchor_root  = current tree root (in the recent-roots window),
//   - old_frontier = current frontier (== state), next_index = leaf_count (== 2),
//   - frozen_root  STRICT-equal to state; kyc/sanction/assets windowed; auditor_pk exact.
//
// SECURITY (invariant #8): the returned witness embeds demo secrets (sender
// `owner_sk`, note openings, `k_view`, pairwise keys, nonces). Never log/persist it.

import { buildTransferWitness, type TransferWitnessResult } from '../../sdk/src/witness.js';
import { sacAddressToField } from '../../sdk/src/note.js';
import type { Fr, MerklePath } from '../../sdk/src/types.js';
import { IMT_MAX } from './demo-state.js';
import {
  GENESIS_NOTE,
  LIVE_ASSET,
  LIVE_STATE,
  LIVE_VIEW_KEY,
  RECIPIENT_PK,
  SENDER_SK,
  SHIELD2_NOTE,
  TRANSFER_OUT_CHANGE,
  TRANSFER_OUT_RECIPIENT,
  reconstructAnchorTree,
} from './live-notes.js';

/** Metadata surfaced alongside the witness for the gate / submit step. */
export interface LiveTransferMeta {
  readonly anchorRoot: Fr;
  readonly nextIndex: number;
  readonly inValues: readonly [Fr, Fr];
  readonly outValues: readonly [Fr, Fr];
}

export interface LiveTransferWitness extends TransferWitnessResult {
  readonly meta: LiveTransferMeta;
}

/**
 * Assemble the full `Transfer(20,5,5)` witness for the live transfer:
 *   spend [genesis, shield2] (Bank A) → [1500 → Bank B, 500 change → Bank A].
 *
 * The empty sanctions/frozen sets are proved via the head low-leaf `{0 → MAX}`
 * bracket (the same non-membership the in-circuit gadget checks); the recipient pk
 * is proved KYC-enrolled (kyc_leaf == out_owner_pk[0]); each spent commitment is
 * proved absent from the frozen set (invariant #14).
 */
export function buildLiveTransferWitness(): LiveTransferWitness {
  const st = LIVE_STATE;

  // Indexer stand-in: rebuild the live tree from the two on-chain commitments.
  const anchor = reconstructAnchorTree();
  const anchorRoot = anchor.root();
  const inPaths: [MerklePath, MerklePath] = [anchor.inclusionPath(0), anchor.inclusionPath(1)];
  const oldFrontier = anchor.frontier();
  const nextIndex = anchor.size; // == 2 (leaf_count after both shields)

  // Recipient compliance: Bank B is enrolled in kyc_root (membership) and absent
  // from the empty sanctions set (non-membership via the head bracket).
  const recipientKyc = st.accounts[1]!; // Cendrawasih Bank (Bank B)
  if (recipientKyc.ownerPk !== RECIPIENT_PK) {
    throw new Error('live-notes RECIPIENT_PK drifted from demo-state accounts[1]');
  }
  const headLow = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };

  const result = buildTransferWitness({
    ownerSk: SENDER_SK,
    inNotes: [GENESIS_NOTE, SHIELD2_NOTE],
    inPaths,
    anchorRoot,
    outNotes: [TRANSFER_OUT_RECIPIENT, TRANSFER_OUT_CHANGE],

    // KYC membership of the recipient (output note 0 owner).
    kycLeaf: RECIPIENT_PK,
    kycPath: recipientKyc.kycPath,
    kycRoot: st.kycRoot,

    // Sanctions non-membership of the recipient (empty set).
    sanctionLow: headLow,
    sanctionPath: st.sanctionLowPath,
    sanctionRoot: st.sanctionRoot,

    // Frozen non-membership of EACH spent commitment (empty set; invariant #14).
    frozenLow: [headLow, headLow],
    frozenPaths: [st.frozenLowPath, st.frozenLowPath],
    frozenRoot: st.frozenRoot,

    // Authorized-assets registry membership + per-tx limit (TBOND leaf).
    sacAddress: sacAddressToField(LIVE_ASSET.sacAddress),
    decimals: BigInt(LIVE_ASSET.decimals),
    perTxLimitRaw: LIVE_ASSET.perTxLimitRaw,
    assetsPath: LIVE_ASSET.assetsPath,
    assetsRoot: st.assetsRoot,

    // Tree transition input (pinned to live state).
    oldFrontier,
    nextIndex,

    fee: 0n,
    auditorPk: st.auditorPk,
    kView: LIVE_VIEW_KEY,
    kPair: [7n, 11n],
    rhoEncAuditor: [5101n, 5102n],
    rhoEncRecipient: [6101n, 6102n],
  });

  return {
    ...result,
    meta: {
      anchorRoot,
      nextIndex,
      inValues: [GENESIS_NOTE.value, SHIELD2_NOTE.value],
      outValues: [TRANSFER_OUT_RECIPIENT.value, TRANSFER_OUT_CHANGE.value],
    },
  };
}
