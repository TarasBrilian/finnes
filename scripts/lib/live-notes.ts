// Single source of truth for the LIVE on-chain demo notes (FIN-025).
//
// The confidential-transfer flow spends notes that already exist on-chain, so the
// witness builder must reconstruct each note's opening (asset/value/owner/rho/r)
// EXACTLY as it was shielded — otherwise the recomputed commitment ≠ the on-chain
// commitment and the inclusion proof fails. This module is the indexer stand-in:
// it pins those openings in one place so the prover, the submit converter, and the
// offline gate cannot drift.
//
// LOCKSTEP (the drift gotcha): `GENESIS_NOTE` MUST byte-match the note minted by
// `scripts/prove-shield-live.ts` (Meridian/accounts[0], 1000 TBOND, rho 3001,
// r_note 4001). `GENESIS_CM_HEX` is its on-chain commitment as recorded in
// `setup/build/shield-args.json` (cm_out_0). The offline gate
// (`scripts/test-transfer-live-witness.ts`) asserts `commitNote(GENESIS_NOTE)`
// equals `GENESIS_CM_HEX` at runtime, so any drift here fails loudly instead of
// producing a silently-wrong proof.
//
// SECURITY (invariant #8): the spending keys reached through `DEMO_ACCOUNTS` are
// THROWAWAY demo constants, never real keys. This module derives PUBLIC openings;
// it never serializes a secret.

import { IncrementalMerkleTree } from '../../sdk/src/merkle.js';
import { commitNote, deriveOwnerPk } from '../../sdk/src/note.js';
import type { Fr, Note, OwnerSk } from '../../sdk/src/types.js';
import {
  buildDemoComplianceState,
  DEMO_ACCOUNTS,
  DEMO_AUDITOR_VIEW_KEY,
} from './demo-state.js';

/** Production commitment-tree depth (LOCKED FIN-001). */
export const DEPTH = 20;

/** The deterministic live compliance state the contract was `init`'d with. */
export const LIVE_STATE = buildDemoComplianceState(DEPTH);

// Parties. The SENDER (Bank A) owns BOTH input notes (a transfer has one spender,
// invariant: `owner_sk` is a single signal in transfer.circom). The RECIPIENT
// (Bank B) receives output note 0 and must be KYC-enrolled (kyc_leaf ==
// out_owner_pk[0]); the change note returns to the sender.
const senderSk = DEMO_ACCOUNTS[0]!.ownerSk; // Meridian Capital (Bank A)
const recipientSk = DEMO_ACCOUNTS[1]!.ownerSk; // Cendrawasih Bank (Bank B)

/** Sender spending key (owns both inputs). SECRET — never serialized. */
export const SENDER_SK: Fr = senderSk;
/** Recipient (Bank B) spending key — owns the transfer recipient note. SECRET. */
export const RECIPIENT_SK: Fr = recipientSk;
/** Sender public key (the change note's owner). */
export const SENDER_PK: Fr = deriveOwnerPk(senderSk as unknown as OwnerSk);
/** Recipient public key (output note 0's owner; KYC-enrolled). */
export const RECIPIENT_PK: Fr = deriveOwnerPk(recipientSk as unknown as OwnerSk);

/** The single asset moved (TBOND-2031; sac_address '777', limit 10_000_000). */
export const LIVE_ASSET = LIVE_STATE.assets[0]!;

/** The auditor view key the contract's `auditor_pk` commits to. */
export const LIVE_VIEW_KEY: Fr = DEMO_AUDITOR_VIEW_KEY;

// ---------------------------------------------------------------------------
// The two on-chain input notes.
// ---------------------------------------------------------------------------

/**
 * The GENESIS shielded note — index 0 of the live commitment tree. Its opening is
 * copied verbatim from `scripts/prove-shield-live.ts` (the script that minted it).
 */
export const GENESIS_NOTE: Note = {
  assetId: LIVE_ASSET.assetId,
  value: 1000n,
  ownerPk: SENDER_PK,
  rho: 3001n,
  rNote: 4001n,
};

/** The genesis note's on-chain commitment (setup/build/shield-args.json cm_out_0). */
export const GENESIS_CM_HEX =
  '577c94d2de641ad7984ee23eb434dca939fe802eb775f1982a0ec44c3d5d6440';

/**
 * The SECOND shielded note — index 1. FIN-025 requires ≥2 on-chain shields owned
 * by the same sender before a transfer can spend them. This is minted by
 * `scripts/prove-shield2-live.ts` (same owner/asset, fresh rho/r_note).
 */
export const SHIELD2_NOTE: Note = {
  assetId: LIVE_ASSET.assetId,
  value: 1000n,
  ownerPk: SENDER_PK,
  rho: 3003n,
  rNote: 4003n,
};

// ---------------------------------------------------------------------------
// The two transfer output notes (Σ outputs + fee == Σ inputs; fee 0, invariant #3).
//   inputs 1000 + 1000 = 2000  ==  recipient 1500 + change 500 + fee 0
// ---------------------------------------------------------------------------

/** Output note 0 → recipient (Bank B). */
export const TRANSFER_OUT_RECIPIENT: Note = {
  assetId: LIVE_ASSET.assetId,
  value: 1500n,
  ownerPk: RECIPIENT_PK,
  rho: 3005n,
  rNote: 4005n,
};

/** Output note 1 → change back to the sender (Bank A). */
export const TRANSFER_OUT_CHANGE: Note = {
  assetId: LIVE_ASSET.assetId,
  value: 500n,
  ownerPk: SENDER_PK,
  rho: 3006n,
  rNote: 4006n,
};

/** Hex (64-char, zero-padded) encoding of a field element, matching on-chain bytes. */
export const toCmHex = (x: Fr): string => x.toString(16).padStart(64, '0');

/**
 * Reconstruct the live commitment tree from the two on-chain commitments — the
 * indexer stand-in. After both shields the tree holds [genesis_cm, shield2_cm] at
 * indices 0 and 1, so:
 *   - `root()`      = the transfer's `anchor_root` (a recent root the inputs prove
 *                     inclusion against),
 *   - `frontier()`  = the transfer's `old_frontier` (checked == contract state),
 *   - `size`        = the transfer's `next_index` (== leaf_count == 2),
 *   - `inclusionPath(0|1)` = the input inclusion paths.
 */
export function reconstructAnchorTree(): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(DEPTH);
  t.insert(commitNote(GENESIS_NOTE));
  t.insert(commitNote(SHIELD2_NOTE));
  return t;
}

/**
 * Reconstruct the FULL post-transfer commitment tree (4 leaves) — the indexer
 * stand-in for FIN-026 (`unshield`). After the FIN-025 transfer the on-chain tree
 * holds, at indices 0..3: the two spent inputs (genesis, shield2) followed by the
 * two transfer outputs (recipient 1500 @ idx 2, change 500 @ idx 3). Its root is
 * the current on-chain root (`069cbb56…`) — the unshield's `anchor_root` — and its
 * `inclusionPath(3)` is the spend proof for the change note being unshielded.
 */
export function reconstructPostTransferTree(): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(DEPTH);
  t.insert(commitNote(GENESIS_NOTE));
  t.insert(commitNote(SHIELD2_NOTE));
  t.insert(commitNote(TRANSFER_OUT_RECIPIENT));
  t.insert(commitNote(TRANSFER_OUT_CHANGE));
  return t;
}

/** On-chain `current_root` after the FIN-025 transfer (the unshield anchor). */
export const POST_TRANSFER_ROOT_HEX =
  '069cbb56b27b6f070fb0563a3b837848b98f9a8d5f736c80ab6a5306a5291834';

/** Leaf index of the change note (500 TBOND, Bank A) the exact-spend unshield spends. */
export const UNSHIELD_SPENT_INDEX = 3;

/**
 * Leaf index of the transfer recipient note (1500 TBOND, Bank B) the PARTIAL
 * unshield spends. The exact-spend unshield (leaf 3) inserts 0 leaves, so after it
 * the tree is unchanged (still 4 leaves at root `069cbb56…`); this note (leaf 2) is
 * still unspent and spendable.
 */
export const PARTIAL_UNSHIELD_SPENT_INDEX = 2;

/**
 * Change note minted by the PARTIAL unshield (1-insert path): 500 TBOND back to
 * Bank B (the spender), inserted at the live `leaf_count`. Fresh rho/r_note so its
 * commitment is distinct from every existing note.
 */
export const UNSHIELD2_CHANGE_NOTE: Note = {
  assetId: LIVE_ASSET.assetId,
  value: 500n,
  ownerPk: RECIPIENT_PK,
  rho: 3007n,
  rNote: 4007n,
};
