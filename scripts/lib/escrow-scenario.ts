// Shared demo-scenario builders for the production escrow DvP circuits (FIN-017).
// See docs/DVP_ESCROW.md. Builds consistent witnesses for:
//   - escrow_deposit  : EscrowLeg(D,5,5,0) — depositor's MAIN note -> intent escrow
//   - escrow_refund   : EscrowLeg(D,5,5,1) — escrow note -> depositor refund (KYC'd)
//   - settle          : the dvp circuit — both escrow notes (sk_intent) -> swap
// Depth-parametric (fast gate at depth 6). Throwaway demo secrets only.

import { IncrementalMerkleTree, assetsLeafHash, imtLeafHash } from '../../sdk/src/merkle.js';
import { commitNote, deriveOwnerPk } from '../../sdk/src/note.js';
import { auditorPkFromKey } from '../../sdk/src/encrypt.js';
import { poseidonBLS, FR_MODULUS } from '../../sdk/src/poseidon.js';
import {
  buildEscrowLegWitness,
  buildDvpWitness,
  type ImtLowLeaf,
} from '../../sdk/src/witness.js';
import type { CircomWitness } from '../../sdk/src/witness.js';
import type { Fr, MerklePath, Note, OwnerSk } from '../../sdk/src/types.js';

const ownerPkOf = (sk: bigint): Fr => deriveOwnerPk(sk as unknown as OwnerSk);
export const IMT_MAX = FR_MODULUS - 1n;

function emptyImt(depth: number): IncrementalMerkleTree {
  const t = new IncrementalMerkleTree(depth);
  t.insert(imtLeafHash(0n, 1n, IMT_MAX));
  t.insert(imtLeafHash(IMT_MAX, 0n, 0n));
  return t;
}
const HEAD_LOW: ImtLowLeaf = { value: 0n, nextIndex: 1n, nextValue: IMT_MAX };

// Shared demo asset + parties + intent key.
const SAC_X = 777n;
const SAC_Y = 888n;
const ASSET_X = poseidonBLS([SAC_X]);
const ASSET_Y = poseidonBLS([SAC_Y]);
const DECIMALS = 7n;
const LIMIT = 10_000_000n;
const SK_A = 42n; // depositor A
const SK_B = 77n; // depositor B
const SK_INTENT = 555n; // fresh per-intent key shared by A & B (custody of the escrow)
const PK_A = ownerPkOf(SK_A);
const PK_B = ownerPkOf(SK_B);
const PK_INTENT = ownerPkOf(SK_INTENT);
const K_VIEW = 5n;
const AUDITOR_PK = auditorPkFromKey(K_VIEW).pk;

export interface EscrowScenario {
  witness: CircomWitness;
  /** The spent-note commitment, for negative-fixture construction. */
  cmIn: Fr;
}

/**
 * escrow_deposit: A spends a MAIN-tree asset-X note (1000) -> an ESCROW note owned
 * by the intent. No recipient compliance (the intent is not a KYC'd party); frozen
 * non-membership of the SPENT note IS enforced. The output is inserted into the
 * (initially empty) escrow tree.
 */
export function buildEscrowDepositScenario(depth: number, opts: { frozenMember?: boolean } = {}): EscrowScenario {
  const inNote: Note = { assetId: ASSET_X, value: 1000n, ownerPk: PK_A, rho: 1001n, rNote: 2001n };
  const cmIn = commitNote(inNote);
  const main = new IncrementalMerkleTree(depth);
  main.insert(cmIn);

  // Frozen IMT: empty, OR (negative fixture) containing the spent cm.
  let frozen: IncrementalMerkleTree;
  let frozenLow: ImtLowLeaf;
  if (opts.frozenMember) {
    frozen = new IncrementalMerkleTree(depth);
    frozen.insert(imtLeafHash(0n, 1n, cmIn));
    frozen.insert(imtLeafHash(cmIn, 2n, IMT_MAX));
    frozen.insert(imtLeafHash(IMT_MAX, 0n, 0n));
    frozenLow = { value: 0n, nextIndex: 1n, nextValue: cmIn };
  } else {
    frozen = emptyImt(depth);
    frozenLow = HEAD_LOW;
  }

  const assets = new IncrementalMerkleTree(depth);
  assets.insert(assetsLeafHash(ASSET_X, SAC_X, DECIMALS, LIMIT));
  const escrowTree = new IncrementalMerkleTree(depth); // empty; escrow note inserts at 0

  const outNote: Note = { assetId: ASSET_X, value: 1000n, ownerPk: PK_INTENT, rho: 3001n, rNote: 4001n };

  const { witness } = buildEscrowLegWitness({
    anchorRoot: main.root(),
    kycRoot: 0n, // unconstrained for deposit (CHECK_RECIPIENT=0)
    sanctionRoot: 0n,
    assetsRoot: assets.root(),
    frozenRoot: frozen.root(),
    auditorPk: AUDITOR_PK,
    kView: K_VIEW,
    inNote,
    ownerSk: SK_A,
    inPath: main.inclusionPath(0),
    frozenLow,
    frozenPath: frozen.inclusionPath(0),
    outNote,
    sacAddress: SAC_X,
    decimals: DECIMALS,
    perTxLimitRaw: LIMIT,
    assetsPath: assets.inclusionPath(0),
    // dummy recipient witnesses (unconstrained for deposit)
    kycPath: emptyImt(depth).inclusionPath(0),
    sanctionLow: HEAD_LOW,
    sanctionPath: emptyImt(depth).inclusionPath(0),
    oldFrontier: escrowTree.frontier(),
    nextIndex: escrowTree.size,
    fee: 0n,
    kPair: 7n,
    rhoEncAuditor: 5101n,
    rhoEncRecipient: 6101n,
  });
  return { witness, cmIn };
}

/**
 * escrow_refund: after the deadline, spend an ESCROW note (owner = sk_intent) ->
 * a MAIN-tree note paid to the depositor's refund_pk (A, a KYC'd party). Recipient
 * KYC membership + sanctions non-membership ARE enforced.
 */
export function buildEscrowRefundScenario(depth: number, opts: { sanctionedRecipient?: boolean } = {}): EscrowScenario {
  // The escrow note (owned by the intent) sits in the escrow tree.
  const escrowNote: Note = { assetId: ASSET_X, value: 1000n, ownerPk: PK_INTENT, rho: 3001n, rNote: 4001n };
  const cmIn = commitNote(escrowNote);
  const escrowTree = new IncrementalMerkleTree(depth);
  escrowTree.insert(cmIn);

  const frozen = emptyImt(depth);

  // Refund recipient = depositor A. KYC tree enrolls A (or, negative, leaves it out
  // by making A sanctioned).
  const kyc = new IncrementalMerkleTree(depth);
  kyc.insert(PK_A);

  let sanction: IncrementalMerkleTree;
  let sanctionLow: ImtLowLeaf;
  if (opts.sanctionedRecipient) {
    // A is in the sanctions set: 0 < PK_A < MAX with PK_A a node => non-membership unprovable.
    sanction = new IncrementalMerkleTree(depth);
    sanction.insert(imtLeafHash(0n, 1n, PK_A));
    sanction.insert(imtLeafHash(PK_A, 2n, IMT_MAX));
    sanction.insert(imtLeafHash(IMT_MAX, 0n, 0n));
    sanctionLow = { value: 0n, nextIndex: 1n, nextValue: PK_A };
  } else {
    sanction = emptyImt(depth);
    sanctionLow = HEAD_LOW;
  }

  const assets = new IncrementalMerkleTree(depth);
  assets.insert(assetsLeafHash(ASSET_X, SAC_X, DECIMALS, LIMIT));
  const main = new IncrementalMerkleTree(depth); // refund note inserts into the main tree at 0

  const refundNote: Note = { assetId: ASSET_X, value: 1000n, ownerPk: PK_A, rho: 3101n, rNote: 4101n };

  const { witness } = buildEscrowLegWitness({
    anchorRoot: escrowTree.root(),
    kycRoot: kyc.root(),
    sanctionRoot: sanction.root(),
    assetsRoot: assets.root(),
    frozenRoot: frozen.root(),
    auditorPk: AUDITOR_PK,
    kView: K_VIEW,
    inNote: escrowNote,
    ownerSk: SK_INTENT,
    inPath: escrowTree.inclusionPath(0),
    frozenLow: HEAD_LOW,
    frozenPath: frozen.inclusionPath(0),
    outNote: refundNote,
    sacAddress: SAC_X,
    decimals: DECIMALS,
    perTxLimitRaw: LIMIT,
    assetsPath: assets.inclusionPath(0),
    kycPath: kyc.inclusionPath(0),
    sanctionLow,
    sanctionPath: sanction.inclusionPath(0),
    oldFrontier: main.frontier(),
    nextIndex: main.size,
    fee: 0n,
    kPair: 11n,
    rhoEncAuditor: 5201n,
    rhoEncRecipient: 6201n,
  });
  return { witness, cmIn };
}

/**
 * settle: the dvp circuit, driven as a settlement — both escrow notes are owned by
 * SK_INTENT (the same key, legitimately) and anchored to the escrow tree; outputs
 * are the swap (asset X -> B, asset Y -> A) with recipient compliance. This proves
 * the existing dvp circuit IS the settle step (no new circuit, docs/DVP_ESCROW.md).
 */
export function buildSettleScenario(depth: number): { witness: CircomWitness } {
  // Two escrow notes (both owned by the intent) in the escrow tree.
  const escrowX: Note = { assetId: ASSET_X, value: 1000n, ownerPk: PK_INTENT, rho: 3001n, rNote: 4001n };
  const escrowY: Note = { assetId: ASSET_Y, value: 500n, ownerPk: PK_INTENT, rho: 3002n, rNote: 4002n };
  const escrow = new IncrementalMerkleTree(depth);
  escrow.insert(commitNote(escrowX));
  escrow.insert(commitNote(escrowY));

  // Swap recipients: asset X -> B, asset Y -> A (both KYC'd).
  const kyc = new IncrementalMerkleTree(depth);
  kyc.insert(PK_B); // index 0
  kyc.insert(PK_A); // index 1
  const sanction = emptyImt(depth);
  const frozen = emptyImt(depth);
  const assets = new IncrementalMerkleTree(depth);
  assets.insert(assetsLeafHash(ASSET_X, SAC_X, DECIMALS, LIMIT));
  assets.insert(assetsLeafHash(ASSET_Y, SAC_Y, DECIMALS, LIMIT));

  const outX: Note = { assetId: ASSET_X, value: 1000n, ownerPk: PK_B, rho: 7001n, rNote: 8001n };
  const outY: Note = { assetId: ASSET_Y, value: 500n, ownerPk: PK_A, rho: 7002n, rNote: 8002n };
  const mainOut = new IncrementalMerkleTree(depth); // swap outputs insert into the main tree

  const { witness } = buildDvpWitness({
    anchorRoot: escrow.root(),
    kycRoot: kyc.root(),
    sanctionRoot: sanction.root(),
    assetsRoot: assets.root(),
    frozenRoot: frozen.root(),
    auditorPk: AUDITOR_PK,
    kView: K_VIEW,
    oldFrontier: mainOut.frontier(),
    nextIndex: mainOut.size,
    inNotes: [escrowX, escrowY],
    ownerSk: [SK_INTENT, SK_INTENT], // both escrows owned by the intent — legitimate
    inPaths: [escrow.inclusionPath(0), escrow.inclusionPath(1)],
    outNotes: [outX, outY],
    frozenLow: [HEAD_LOW, HEAD_LOW],
    frozenPaths: [frozen.inclusionPath(0), frozen.inclusionPath(0)],
    sacAddress: [SAC_X, SAC_Y],
    decimals: [DECIMALS, DECIMALS],
    perTxLimitRaw: [LIMIT, LIMIT],
    assetsPaths: [assets.inclusionPath(0), assets.inclusionPath(1)],
    kycPaths: [kyc.inclusionPath(0), kyc.inclusionPath(1)],
    sanctionLow: [HEAD_LOW, HEAD_LOW],
    sanctionPaths: [sanction.inclusionPath(0), sanction.inclusionPath(0)],
    fee: [0n, 0n],
    kPair: [7n, 11n],
    rhoEncAuditor: [5101n, 5102n],
    rhoEncRecipient: [6101n, 6102n],
  });
  return { witness };
}
