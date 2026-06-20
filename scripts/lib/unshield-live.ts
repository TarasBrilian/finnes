// Build a REAL D=20 unshield (shielded → transparent) witness against the deployed
// contract's LIVE post-transfer state (FIN-026) — the unshield analogue of
// scripts/lib/transfer-live.ts.
//
// Spends the change note (500 TBOND, Bank A) minted by the FIN-025 transfer
// (on-chain leaf index 3) out to a transparent recipient, as an EXACT spend (no
// change note): `amount == in_value`, so `cm_change_0 == 0` (the no-change
// sentinel) and the tree advances by 0 — exercising the gated 0-leaf transition
// (invariants #11/#12) and the top compliance checkpoint (invariant #19): the
// spent commitment proves frozen-set non-membership and the transparent recipient
// proves KYC membership + sanctions non-membership.
//
// The recipient is Bank A's own KYC identity (accounts[0].ownerPk); on-chain it
// resolves to a transparent G-address via `register_transparent` (FIN-010).
//
// SECURITY (invariant #8): the returned witness embeds demo secrets (owner_sk, the
// spent note opening, k_view). Never log/persist it.

import { buildUnshieldWitness, type UnshieldWitnessResult } from '../../sdk/src/witness.js';
import { sacAddressToField } from '../../sdk/src/note.js';
import type { Fr, MerklePath } from '../../sdk/src/types.js';
import { IMT_MAX } from './demo-state.js';
import {
  LIVE_ASSET,
  LIVE_STATE,
  LIVE_VIEW_KEY,
  PARTIAL_UNSHIELD_SPENT_INDEX,
  RECIPIENT_SK,
  SENDER_SK,
  TRANSFER_OUT_CHANGE,
  TRANSFER_OUT_RECIPIENT,
  UNSHIELD2_CHANGE_NOTE,
  UNSHIELD_SPENT_INDEX,
  reconstructPostTransferTree,
} from './live-notes.js';

/** The note spent by the unshield: the FIN-025 change note (500, Bank A). */
export const UNSHIELD_SPENT_NOTE = TRANSFER_OUT_CHANGE;
/** Raw amount leaving the shielded domain (full spend → no change). */
export const UNSHIELD_AMOUNT: Fr = UNSHIELD_SPENT_NOTE.value; // 500n

export interface LiveUnshieldMeta {
  readonly anchorRoot: Fr;
  readonly nextIndex: number;
  readonly amount: Fr;
  readonly recipientPk: Fr;
  readonly recipientLabel: string;
}

export interface LiveUnshieldWitness extends UnshieldWitnessResult {
  readonly meta: LiveUnshieldMeta;
}

/**
 * Assemble the full `Unshield(20,5,5)` witness for the live unshield:
 *   spend change note (500, Bank A) → transparent recipient, exact spend.
 */
export function buildLiveUnshieldWitness(): LiveUnshieldWitness {
  const st = LIVE_STATE;

  // Indexer stand-in: rebuild the post-transfer tree and prove inclusion of the
  // change note (index 3) under the current on-chain root.
  const tree = reconstructPostTransferTree();
  const anchorRoot = tree.root();
  const inPath: MerklePath = tree.inclusionPath(UNSHIELD_SPENT_INDEX);
  const oldFrontier = tree.frontier();
  const nextIndex = tree.size; // == 4 (leaf_count after the transfer)

  // Recipient = Bank A's own enrolled KYC identity; maps to a transparent G-addr
  // on-chain via register_transparent.
  const recipient = st.accounts[0]!; // Meridian Capital (Bank A)
  const headLow = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };

  const result = buildUnshieldWitness({
    inNote: UNSHIELD_SPENT_NOTE,
    ownerSk: SENDER_SK,
    inPath,
    anchorRoot,

    // Frozen-set non-membership of the spent commitment (invariant #19b).
    frozenLow: headLow,
    frozenPath: st.frozenLowPath,
    frozenRoot: st.frozenRoot,

    // Transparent recipient compliance (invariant #19a): KYC membership +
    // sanctions non-membership of the recipient identity.
    recipient: recipient.ownerPk,
    kycPath: recipient.kycPath,
    kycRoot: st.kycRoot,
    sanctionLow: headLow,
    sanctionPath: st.sanctionLowPath,
    sanctionRoot: st.sanctionRoot,

    // Exact spend: amount == in_value, no change note (cm_change_0 = 0 sentinel).
    amount: UNSHIELD_AMOUNT,

    // Authorized-assets registry membership + per-tx limit (TBOND leaf).
    sacAddress: sacAddressToField(LIVE_ASSET.sacAddress),
    decimals: BigInt(LIVE_ASSET.decimals),
    perTxLimitRaw: LIVE_ASSET.perTxLimitRaw,
    assetsPath: LIVE_ASSET.assetsPath,
    assetsRoot: st.assetsRoot,

    // Tree transition input (pinned to live state). With no change note the gated
    // 0-leaf reproduces the current root and new_frontier stays old_frontier.
    oldFrontier,
    nextIndex,

    fee: 0n,
    auditorPk: st.auditorPk,
    kView: LIVE_VIEW_KEY,
    kPair: 7n,
    // nonces ignored when there is no change note (ciphertexts forced all-zero).
    rhoEncAuditor: 0n,
    rhoEncRecipient: 0n,
  });

  return {
    ...result,
    meta: {
      anchorRoot,
      nextIndex,
      amount: UNSHIELD_AMOUNT,
      recipientPk: recipient.ownerPk,
      recipientLabel: recipient.label,
    },
  };
}

// ===========================================================================
// PARTIAL unshield (1-insert path) — the second sentinel branch (FIN-026 "0 vs 1
// insert"). Spends the transfer recipient note (1500, Bank B, leaf 2) and sends a
// PARTIAL amount (1000) out to a transparent recipient, minting a change note (500
// back to Bank B) — so cm_change_0 != 0, the tree advances by 1, and the change
// note carries a MANDATORY auditor ciphertext (invariant #5) the regulator decrypts.
// ===========================================================================

/** Partial amount leaving the shielded domain (the rest returns as a change note). */
export const PARTIAL_UNSHIELD_AMOUNT: Fr = 1000n;

/**
 * Assemble the `Unshield(20,5,5)` witness for the PARTIAL unshield:
 *   spend recipient note (1500, Bank B, leaf 2) → 1000 transparent + 500 change.
 * The exact-spend unshield (leaf 3) inserts 0 leaves, so the live anchor is still
 * the 4-leaf post-transfer tree at `next_index = 4`; the change note lands at leaf 4.
 */
export function buildLivePartialUnshieldWitness(): LiveUnshieldWitness {
  const st = LIVE_STATE;

  const tree = reconstructPostTransferTree();
  const anchorRoot = tree.root();
  const inPath: MerklePath = tree.inclusionPath(PARTIAL_UNSHIELD_SPENT_INDEX);
  const oldFrontier = tree.frontier();
  const nextIndex = tree.size; // == 4 (unchanged by the exact-spend unshield)

  // Recipient = Bank B's own enrolled KYC identity (the spender withdraws part of
  // its holdings); maps to a transparent G-addr on-chain via register_transparent.
  const recipient = st.accounts[1]!; // Cendrawasih Bank (Bank B)
  const headLow = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };

  const result = buildUnshieldWitness({
    inNote: TRANSFER_OUT_RECIPIENT, // 1500, Bank B
    ownerSk: RECIPIENT_SK,
    inPath,
    anchorRoot,

    frozenLow: headLow,
    frozenPath: st.frozenLowPath,
    frozenRoot: st.frozenRoot,

    recipient: recipient.ownerPk,
    kycPath: recipient.kycPath,
    kycRoot: st.kycRoot,
    sanctionLow: headLow,
    sanctionPath: st.sanctionLowPath,
    sanctionRoot: st.sanctionRoot,

    // Partial spend: amount + change == in_value (1000 + 500 == 1500).
    amount: PARTIAL_UNSHIELD_AMOUNT,
    changeNote: UNSHIELD2_CHANGE_NOTE, // 500 back to Bank B → cm_change_0 != 0, 1 insert

    sacAddress: sacAddressToField(LIVE_ASSET.sacAddress),
    decimals: BigInt(LIVE_ASSET.decimals),
    perTxLimitRaw: LIVE_ASSET.perTxLimitRaw,
    assetsPath: LIVE_ASSET.assetsPath,
    assetsRoot: st.assetsRoot,

    oldFrontier,
    nextIndex,

    fee: 0n,
    auditorPk: st.auditorPk,
    kView: LIVE_VIEW_KEY,
    kPair: 11n,
    rhoEncAuditor: 5201n, // real nonces (change note present → mandatory c_auditor)
    rhoEncRecipient: 6201n,
  });

  return {
    ...result,
    meta: {
      anchorRoot,
      nextIndex,
      amount: PARTIAL_UNSHIELD_AMOUNT,
      recipientPk: recipient.ownerPk,
      recipientLabel: recipient.label,
    },
  };
}
