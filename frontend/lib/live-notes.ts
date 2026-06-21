'use client';

/**
 * Frontend indexer stand-in (FIN-027): the deterministic set of notes that exist
 * on-chain after the FIN-025/026 demo sequence, plus the live tree reconstruction.
 * A production deployment reconstructs this from contract events (FIN-019); here it
 * is pinned because the demo sequence is deterministic. Each note's opening matches
 * exactly what was committed on-chain, so the recomputed commitments equal the live
 * leaves and inclusion proofs are valid.
 *
 * SECURITY (invariant #8): these openings are demo data; the spending keys live in
 * demo-state.ts (throwaway). Nothing here is a real secret.
 */

import type { Fr, Note } from '@finnes/sdk';
import { commitNote, deriveNullifier, IncrementalMerkleTree, TREE_DEPTH } from '@finnes/sdk';
import type { OwnerSk } from '@finnes/sdk';

import { demoState } from './demo-state.js';
import { loadStoredNotes } from './note-store.js';

const st = demoState();
const TBOND = st.assets[0]!.assetId;
const BANK_A = st.accounts[0]!; // Meridian
const BANK_B = st.accounts[1]!; // Cendrawasih

/** The on-chain notes, in leaf order (index 0..4), the live commitment tree. */
export interface LiveNote {
  readonly leafIndex: number;
  readonly note: Note;
  readonly ownerSk: OwnerSk;
  readonly ownerLabel: string;
}

export const LIVE_NOTES: readonly LiveNote[] = [
  { leafIndex: 0, ownerLabel: BANK_A.label, ownerSk: BANK_A.ownerSk, note: { assetId: TBOND, value: 1000n, ownerPk: BANK_A.ownerPk, rho: 3001n, rNote: 4001n } },
  { leafIndex: 1, ownerLabel: BANK_A.label, ownerSk: BANK_A.ownerSk, note: { assetId: TBOND, value: 1000n, ownerPk: BANK_A.ownerPk, rho: 3003n, rNote: 4003n } },
  { leafIndex: 2, ownerLabel: BANK_B.label, ownerSk: BANK_B.ownerSk, note: { assetId: TBOND, value: 1500n, ownerPk: BANK_B.ownerPk, rho: 3005n, rNote: 4005n } },
  { leafIndex: 3, ownerLabel: BANK_A.label, ownerSk: BANK_A.ownerSk, note: { assetId: TBOND, value: 500n, ownerPk: BANK_A.ownerPk, rho: 3006n, rNote: 4006n } },
  { leafIndex: 4, ownerLabel: BANK_B.label, ownerSk: BANK_B.ownerSk, note: { assetId: TBOND, value: 500n, ownerPk: BANK_B.ownerPk, rho: 3007n, rNote: 4007n } },
];

/** The seed notes (leaves 0..4) + any notes this frontend later shielded (leaf 5+,
 *  from the local note store), in on-chain leaf order, the full live note set. */
export function allLiveNotes(): readonly LiveNote[] {
  const stored: LiveNote[] = loadStoredNotes().map((s) => ({
    leafIndex: s.leafIndex,
    ownerLabel: 'You (shielded here)',
    ownerSk: BigInt(s.ownerSk) as unknown as OwnerSk,
    note: { assetId: BigInt(s.assetId), value: BigInt(s.value), ownerPk: BigInt(s.ownerPk), rho: BigInt(s.rho), rNote: BigInt(s.rNote) },
  }));
  return [...LIVE_NOTES, ...stored].sort((a, b) => a.leafIndex - b.leafIndex);
}

/** Reconstruct the live commitment tree from all on-chain leaves (seed + shielded). */
export function reconstructLiveTree(): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(TREE_DEPTH);
  for (const l of allLiveNotes()) t.insert(commitNote(l.note));
  return t;
}

/**
 * Commitments of the canonical on-chain demo leaves, in leaf order. The indexer
 * uses this as the seed for leaves that have aged out of RPC event retention
 * (~22h on Testnet): the genesis shield is older than the window, so a pure
 * event re-read would miss leaf 0 and mis-root the tree. PUBLIC data only, these
 * are commitments, never openings (invariant #8).
 */
export function liveSeedCommitments(): readonly Fr[] {
  return LIVE_NOTES.map((l) => commitNote(l.note));
}

/** Live tree state the write-path anchors to: root / frontier / leaf count. */
export function liveTreeState(): { root: Fr; frontier: readonly Fr[]; leafCount: number } {
  const t = reconstructLiveTree();
  return { root: t.root(), frontier: t.frontier(), leafCount: t.size };
}

/** The nullifier (hex, 0x-less) of a live note, to check spent status on-chain. */
export function liveNoteNullifier(l: LiveNote): string {
  return deriveNullifier(l.note.rho, l.ownerSk).toString(16).padStart(64, '0');
}
