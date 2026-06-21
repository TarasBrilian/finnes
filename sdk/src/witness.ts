/**
 * Full circuit-witness assembly for `transfer.circom` (FIN-006).
 *
 * `transfer.circom` declares many of its values as `signal input` even though the
 * circuit *constrains* them to internally-computed quantities (e.g. `cm_out_0`,
 * `nf_in_0`, `new_root`, `new_frontier`, the ciphertext slots). The witness
 * generator therefore needs EVERY one of those values supplied up front,
 * correctly derived, or the witness is unsatisfiable. This builder does that
 * "full commitment / nullifier / ciphertext / frontier computation" so the SDK,
 * the prover (FIN-008), and the circuit-test fixtures all agree on a single
 * source of derivations (mirrors docs/PUBLIC_IO.md §transfer.circom).
 *
 * The output is a flat record keyed by the EXACT circom signal names of the
 * `Transfer(D, K_a, K_r)` template, with every value rendered as a decimal
 * string (or nested arrays thereof) ready for `snarkjs wtns calculate`.
 *
 * Depth `D` is inferred from `oldFrontier.length`, so the same builder serves the
 * locked D=20 production circuit and the small-depth circuit-test harness.
 *
 * SECURITY (invariant #8): the returned witness embeds secrets (`owner_sk`,
 * `rho`, `r_note`, plaintext `value`, `k_view`, pairwise keys, nonces). NEVER
 * log/persist/transmit it. This builder runs only in the client/institution
 * trust zone.
 */

import type { Fr, MerklePath, Note, OwnerSk } from './types.js';
import { commitNote, deriveNullifier } from './note.js';
import { applyFrontierTransition } from './merkle.js';
import { encryptToAuditor, encryptToRecipient } from './encrypt.js';

/** A low-leaf witness for an Indexed-Merkle-Tree non-membership proof. */
export interface ImtLowLeaf {
  /** Greatest stored value `< target` (the "low" leaf's value). */
  readonly value: Fr;
  /** The low leaf's `next` pointer (index); part of the leaf hash. */
  readonly nextIndex: Fr;
  /** The low leaf's `next` pointer (value); `0` marks the list tail (maximum). */
  readonly nextValue: Fr;
}

/**
 * Fully-resolved inputs for a 2-in / 2-out single-asset transfer witness.
 *
 * All Merkle paths, roots, and IMT low-leaf witnesses are supplied by the caller
 * (production: fetched from the indexer; tests: built from an in-memory tree).
 * The builder computes the derived signals only.
 */
export interface TransferWitnessInput {
  /** Spender spending key (owns BOTH input notes). SECRET. */
  readonly ownerSk: Fr;
  /** The two input notes being spent. SECRET. */
  readonly inNotes: readonly [Note, Note];
  /** Inclusion paths for the two input commitments under `anchorRoot`. */
  readonly inPaths: readonly [MerklePath, MerklePath];
  /** Recent commitment-tree root the proof is anchored to. */
  readonly anchorRoot: Fr;
  /** The two output notes minted (note 0 = recipient, note 1 = change). SECRET. */
  readonly outNotes: readonly [Note, Note];
  /** The recipient pk proved KYC'd; the circuit binds `kyc_leaf == out_owner_pk[0]`. */
  readonly kycLeaf: Fr;
  readonly kycPath: MerklePath;
  readonly kycRoot: Fr;
  /** Sanctions non-membership of `kyc_leaf` (IMT low-leaf witness + path). */
  readonly sanctionLow: ImtLowLeaf;
  readonly sanctionPath: MerklePath;
  readonly sanctionRoot: Fr;
  /** Frozen-set non-membership of EACH spent commitment (invariant #14). */
  readonly frozenLow: readonly [ImtLowLeaf, ImtLowLeaf];
  readonly frozenPaths: readonly [MerklePath, MerklePath];
  readonly frozenRoot: Fr;
  /** Authorized-assets registry leaf witness (invariant #17). */
  readonly sacAddress: Fr;
  readonly decimals: Fr;
  readonly perTxLimitRaw: Fr;
  readonly assetsPath: MerklePath;
  readonly assetsRoot: Fr;
  /** Tree transition: frontier before the inserts + the current leaf count. */
  readonly oldFrontier: readonly Fr[];
  readonly nextIndex: number;
  /** Per-asset fee (0 in the demo, invariant #3). */
  readonly fee: Fr;
  /** Auditor public key `= Poseidon(kView)`; checked against contract state. */
  readonly auditorPk: Fr;
  /** Sender↔auditor shared key. SECRET. */
  readonly kView: Fr;
  /** Sender↔recipient pairwise secret per output note (demo: OOB). SECRET. */
  readonly kPair: readonly [Fr, Fr];
  /** Published auditor-ciphertext nonce per output note. */
  readonly rhoEncAuditor: readonly [Fr, Fr];
  /** Published recipient-ciphertext nonce per output note. */
  readonly rhoEncRecipient: readonly [Fr, Fr];
}

/** A flat circom input record: signal name → decimal string(s). */
export type CircomWitness = Record<string, string | string[] | string[][]>;

/** The values the builder derived, handy for negative-fixture construction. */
export interface TransferWitnessDerived {
  /** Input-note commitments (the Merkle leaves spent). */
  readonly cmIn: readonly [Fr, Fr];
  /** Output-note commitments folded into the tree. */
  readonly cmOut: readonly [Fr, Fr];
  /** Published nullifiers of the two spent notes. */
  readonly nf: readonly [Fr, Fr];
  readonly newRoot: Fr;
  readonly newFrontier: readonly Fr[];
}

export interface TransferWitnessResult {
  readonly witness: CircomWitness;
  readonly derived: TransferWitnessDerived;
}

const S = (x: Fr): string => x.toString();
const pe = (p: MerklePath): string[] => p.siblings.map(String);
const pi = (p: MerklePath): string[] => p.pathBits.map(String);

/**
 * Assemble the complete `Transfer(D, 5, 5)` witness from resolved inputs.
 * Depth `D` is taken from `oldFrontier.length`. The two output commitments are
 * inserted at `nextIndex` and `nextIndex + 1` to derive `new_frontier`/`new_root`
 * exactly as `FrontierTransition` proves in-circuit (invariant #12).
 */
export function buildTransferWitness(input: TransferWitnessInput): TransferWitnessResult {
  const depth = input.oldFrontier.length;
  const sk = input.ownerSk as OwnerSk;

  const cmIn: [Fr, Fr] = [commitNote(input.inNotes[0]), commitNote(input.inNotes[1])];
  const nf: [Fr, Fr] = [
    deriveNullifier(input.inNotes[0].rho, sk),
    deriveNullifier(input.inNotes[1].rho, sk),
  ];
  const cmOut: [Fr, Fr] = [commitNote(input.outNotes[0]), commitNote(input.outNotes[1])];

  const cAud: [readonly Fr[], readonly Fr[]] = [
    encryptToAuditor(input.outNotes[0], input.kView, { rhoEnc: input.rhoEncAuditor[0] }).fields,
    encryptToAuditor(input.outNotes[1], input.kView, { rhoEnc: input.rhoEncAuditor[1] }).fields,
  ];
  const cRec: [readonly Fr[], readonly Fr[]] = [
    encryptToRecipient(input.outNotes[0], input.kPair[0], { rhoEnc: input.rhoEncRecipient[0] })
      .fields,
    encryptToRecipient(input.outNotes[1], input.kPair[1], { rhoEnc: input.rhoEncRecipient[1] })
      .fields,
  ];

  const { newFrontier, newRoot } = applyFrontierTransition(
    input.oldFrontier,
    input.nextIndex,
    [cmOut[0], cmOut[1]],
    depth,
  );

  const witness: CircomWitness = {
    // --- public inputs (declared on `main`; still witness inputs to wtns) ---
    anchor_root: S(input.anchorRoot),
    kyc_root: S(input.kycRoot),
    sanction_root: S(input.sanctionRoot),
    assets_root: S(input.assetsRoot),
    frozen_root: S(input.frozenRoot),
    auditor_pk: S(input.auditorPk),
    nf_in_0: S(nf[0]),
    nf_in_1: S(nf[1]),
    cm_out_0: S(cmOut[0]),
    cm_out_1: S(cmOut[1]),
    new_root: S(newRoot),
    fee: S(input.fee),
    next_index: String(input.nextIndex),
    old_frontier: input.oldFrontier.map(String),
    new_frontier: newFrontier.map(String),
    c_auditor: [cAud[0].map(String), cAud[1].map(String)],
    c_recipient: [cRec[0].map(String), cRec[1].map(String)],

    // --- private witness: input notes ---
    in_asset_id: [S(input.inNotes[0].assetId), S(input.inNotes[1].assetId)],
    in_value: [S(input.inNotes[0].value), S(input.inNotes[1].value)],
    in_owner_pk: [S(input.inNotes[0].ownerPk), S(input.inNotes[1].ownerPk)],
    in_rho: [S(input.inNotes[0].rho), S(input.inNotes[1].rho)],
    in_r_note: [S(input.inNotes[0].rNote), S(input.inNotes[1].rNote)],
    owner_sk: S(input.ownerSk),
    in_path_elements: [pe(input.inPaths[0]), pe(input.inPaths[1])],
    in_path_indices: [pi(input.inPaths[0]), pi(input.inPaths[1])],

    // --- private witness: output notes ---
    out_asset_id: [S(input.outNotes[0].assetId), S(input.outNotes[1].assetId)],
    out_value: [S(input.outNotes[0].value), S(input.outNotes[1].value)],
    out_owner_pk: [S(input.outNotes[0].ownerPk), S(input.outNotes[1].ownerPk)],
    out_rho: [S(input.outNotes[0].rho), S(input.outNotes[1].rho)],
    out_r_note: [S(input.outNotes[0].rNote), S(input.outNotes[1].rNote)],

    // --- KYC membership (recipient) ---
    kyc_path_elements: pe(input.kycPath),
    kyc_path_indices: pi(input.kycPath),
    kyc_leaf: S(input.kycLeaf),

    // --- sanctions non-membership ---
    sanction_low_value: S(input.sanctionLow.value),
    sanction_low_next_index: S(input.sanctionLow.nextIndex),
    sanction_low_next_value: S(input.sanctionLow.nextValue),
    sanction_path_elements: pe(input.sanctionPath),
    sanction_path_indices: pi(input.sanctionPath),

    // --- frozen non-membership (per spent commitment) ---
    frozen_low_value: [S(input.frozenLow[0].value), S(input.frozenLow[1].value)],
    frozen_low_next_index: [S(input.frozenLow[0].nextIndex), S(input.frozenLow[1].nextIndex)],
    frozen_low_next_value: [S(input.frozenLow[0].nextValue), S(input.frozenLow[1].nextValue)],
    frozen_path_elements: [pe(input.frozenPaths[0]), pe(input.frozenPaths[1])],
    frozen_path_indices: [pi(input.frozenPaths[0]), pi(input.frozenPaths[1])],

    // --- assets registry membership + per-tx limit ---
    sac_address: S(input.sacAddress),
    decimals: S(input.decimals),
    per_tx_limit_raw: S(input.perTxLimitRaw),
    assets_path_elements: pe(input.assetsPath),
    assets_path_indices: pi(input.assetsPath),

    // --- encryption keying ---
    k_view: S(input.kView),
    k_pair: [S(input.kPair[0]), S(input.kPair[1])],
    rho_enc_auditor: [S(input.rhoEncAuditor[0]), S(input.rhoEncAuditor[1])],
    rho_enc_recipient: [S(input.rhoEncRecipient[0]), S(input.rhoEncRecipient[1])],
  };

  return {
    witness,
    derived: { cmIn, cmOut, nf, newRoot, newFrontier },
  };
}

// ===========================================================================
// shield.circom - transparent -> shielded (0 shielded inputs, 1 output) (FIN-012)
// ===========================================================================

/**
 * Fully-resolved inputs for a shield (transparent -> shielded) witness.
 *
 * The output note value IS the publicly-deposited `amount` and its asset is the
 * public `asset_id` (invariant #18 - the cm opens to the deposited
 * `(asset_id, amount)`); both are taken from `outNote` so they cannot drift. All
 * Merkle paths/roots are supplied by the caller; the builder computes the derived
 * signals (commitment, ciphertexts, frontier transition).
 */
export interface ShieldWitnessInput {
  /** The freshly-minted output note. `assetId`/`value` are the PUBLIC deposit. SECRET opening. */
  readonly outNote: Note;
  /** Depositor/owner KYC membership of `outNote.ownerPk` against `kycRoot`. */
  readonly kycPath: MerklePath;
  readonly kycRoot: Fr;
  /** Authorized-assets registry leaf witness (invariant #17). */
  readonly sacAddress: Fr;
  readonly decimals: Fr;
  readonly perTxLimitRaw: Fr;
  readonly assetsPath: MerklePath;
  readonly assetsRoot: Fr;
  /** Tree transition: frontier before the insert + the current leaf count. */
  readonly oldFrontier: readonly Fr[];
  readonly nextIndex: number;
  /** Per-asset fee (0 in the demo, invariant #3). */
  readonly fee: Fr;
  /** Auditor public key `= Poseidon(kView)`; checked against contract state. */
  readonly auditorPk: Fr;
  /** Sender↔auditor shared key. SECRET. */
  readonly kView: Fr;
  /** Sender↔recipient pairwise secret (demo: OOB). SECRET. */
  readonly kPair: Fr;
  /** Published auditor-ciphertext nonce. */
  readonly rhoEncAuditor: Fr;
  /** Published recipient-ciphertext nonce. */
  readonly rhoEncRecipient: Fr;
}

/** The values the shield builder derived, handy for negative-fixture construction. */
export interface ShieldWitnessDerived {
  /** Output-note commitment folded into the tree. */
  readonly cmOut: Fr;
  readonly newRoot: Fr;
  readonly newFrontier: readonly Fr[];
}

export interface ShieldWitnessResult {
  readonly witness: CircomWitness;
  readonly derived: ShieldWitnessDerived;
}

/**
 * Assemble the complete `Shield(D, 5, 5)` witness from resolved inputs.
 * Depth `D` is taken from `oldFrontier.length`. The single output commitment is
 * inserted at `nextIndex` to derive `new_frontier`/`new_root` exactly as
 * `FrontierTransition` proves in-circuit (invariant #12).
 */
export function buildShieldWitness(input: ShieldWitnessInput): ShieldWitnessResult {
  const depth = input.oldFrontier.length;
  const assetId = input.outNote.assetId;
  const amount = input.outNote.value;

  const cmOut = commitNote(input.outNote);
  const cAud = encryptToAuditor(input.outNote, input.kView, {
    rhoEnc: input.rhoEncAuditor,
  }).fields;
  const cRec = encryptToRecipient(input.outNote, input.kPair, {
    rhoEnc: input.rhoEncRecipient,
  }).fields;

  const { newFrontier, newRoot } = applyFrontierTransition(
    input.oldFrontier,
    input.nextIndex,
    [cmOut],
    depth,
  );

  const witness: CircomWitness = {
    // --- public inputs (declared on `main`; still witness inputs to wtns) ---
    asset_id: S(assetId),
    amount: S(amount),
    kyc_root: S(input.kycRoot),
    assets_root: S(input.assetsRoot),
    auditor_pk: S(input.auditorPk),
    cm_out_0: S(cmOut),
    new_root: S(newRoot),
    fee: S(input.fee),
    next_index: String(input.nextIndex),
    old_frontier: input.oldFrontier.map(String),
    new_frontier: newFrontier.map(String),
    c_auditor: cAud.map(String),
    c_recipient: cRec.map(String),

    // --- private witness: output note opening ---
    out_owner_pk: S(input.outNote.ownerPk),
    out_rho: S(input.outNote.rho),
    out_r_note: S(input.outNote.rNote),

    // --- assets registry membership + per-tx limit ---
    sac_address: S(input.sacAddress),
    decimals: S(input.decimals),
    per_tx_limit_raw: S(input.perTxLimitRaw),
    assets_path_elements: pe(input.assetsPath),
    assets_path_indices: pi(input.assetsPath),

    // --- depositor/owner KYC membership ---
    kyc_path_elements: pe(input.kycPath),
    kyc_path_indices: pi(input.kycPath),

    // --- encryption keying ---
    k_view: S(input.kView),
    k_pair: S(input.kPair),
    rho_enc_auditor: S(input.rhoEncAuditor),
    rho_enc_recipient: S(input.rhoEncRecipient),
  };

  return { witness, derived: { cmOut, newRoot, newFrontier } };
}

// ===========================================================================
// unshield.circom - shielded -> transparent (1 input, optional change) (FIN-013)
// ===========================================================================

/**
 * Fully-resolved inputs for an unshield (shielded -> transparent) witness.
 *
 * The transparent leg `(asset_id, amount, recipient)` is public; the public
 * `asset_id` equals the spent note's asset. The OPTIONAL change note goes back to
 * the sender: pass `changeNote` to mint one (`has_change = 1`), or omit it for an
 * exact spend (`has_change = 0`, `cm_change_0 = 0`, all-zero ciphertexts). All
 * Merkle paths/roots and IMT low-leaf witnesses are supplied by the caller.
 */
export interface UnshieldWitnessInput {
  /** The single spent input note. `assetId` is the publicly-revealed asset. SECRET. */
  readonly inNote: Note;
  /** Spender spending key. SECRET. */
  readonly ownerSk: Fr;
  /** Inclusion path for the input commitment under `anchorRoot`. */
  readonly inPath: MerklePath;
  readonly anchorRoot: Fr;
  /** Frozen-set non-membership of the spent commitment (invariant #19b). */
  readonly frozenLow: ImtLowLeaf;
  readonly frozenPath: MerklePath;
  readonly frozenRoot: Fr;
  /** Public transparent recipient address (field) - also the KYC-enrolled identity. */
  readonly recipient: Fr;
  /** KYC membership of `recipient` (invariant #19a). */
  readonly kycPath: MerklePath;
  readonly kycRoot: Fr;
  /** Sanctions non-membership of `recipient` (invariant #19a). */
  readonly sanctionLow: ImtLowLeaf;
  readonly sanctionPath: MerklePath;
  readonly sanctionRoot: Fr;
  /** Public raw amount leaving the shielded domain. */
  readonly amount: Fr;
  /** Optional change note back to the sender; omit for an exact spend. SECRET. */
  readonly changeNote?: Note;
  /** Authorized-assets registry leaf witness (invariant #17). */
  readonly sacAddress: Fr;
  readonly decimals: Fr;
  readonly perTxLimitRaw: Fr;
  readonly assetsPath: MerklePath;
  readonly assetsRoot: Fr;
  /** Tree transition: frontier before the (conditional) insert + leaf count. */
  readonly oldFrontier: readonly Fr[];
  readonly nextIndex: number;
  /** Per-asset fee (0 in the demo, invariant #3). */
  readonly fee: Fr;
  /** Auditor public key `= Poseidon(kView)`; checked against contract state. */
  readonly auditorPk: Fr;
  /** Sender↔auditor shared key. SECRET. */
  readonly kView: Fr;
  /** Sender↔self pairwise secret for the change note (demo: OOB). SECRET. */
  readonly kPair: Fr;
  /** Published auditor-ciphertext nonce (ignored when there is no change). */
  readonly rhoEncAuditor: Fr;
  /** Published recipient-ciphertext nonce (ignored when there is no change). */
  readonly rhoEncRecipient: Fr;
}

export interface UnshieldWitnessDerived {
  readonly cmIn: Fr;
  readonly nf: Fr;
  /** Change-note commitment, or 0n when there is no change (sentinel). */
  readonly cmChange: Fr;
  readonly hasChange: boolean;
  readonly newRoot: Fr;
  readonly newFrontier: readonly Fr[];
}

export interface UnshieldWitnessResult {
  readonly witness: CircomWitness;
  readonly derived: UnshieldWitnessDerived;
}

const ZERO_CT: string[] = ['0', '0', '0', '0', '0'];

/**
 * Assemble the complete `Unshield(D, 5, 5)` witness from resolved inputs.
 * Depth `D` is taken from `oldFrontier.length`. When a change note is present it
 * is inserted at `nextIndex`; otherwise the (gated) 0 leaf reproduces the current
 * root and `new_frontier` is the unchanged `old_frontier` (mirrors the in-circuit
 * MUX, invariants #11/#12).
 */
export function buildUnshieldWitness(input: UnshieldWitnessInput): UnshieldWitnessResult {
  const depth = input.oldFrontier.length;
  const sk = input.ownerSk as OwnerSk;
  const assetId = input.inNote.assetId;

  const cmIn = commitNote(input.inNote);
  const nf = deriveNullifier(input.inNote.rho, sk);

  const hasChange = input.changeNote !== undefined;
  const change = input.changeNote;
  const cmChange: Fr = hasChange ? commitNote(change!) : 0n;

  // Change-note ciphertexts: real keystream when present, all-zero otherwise
  // (the circuit gates every published slot on has_change).
  const cAud: string[] = hasChange
    ? encryptToAuditor(change!, input.kView, { rhoEnc: input.rhoEncAuditor }).fields.map(String)
    : [...ZERO_CT];
  const cRec: string[] = hasChange
    ? encryptToRecipient(change!, input.kPair, { rhoEnc: input.rhoEncRecipient }).fields.map(String)
    : [...ZERO_CT];

  // Frontier transition. With a change note: a normal 1-leaf insert. Without:
  // inserting the gated 0 leaf yields the CURRENT root, and new_frontier stays
  // old_frontier (the in-circuit MUX) since no filled subtree advances.
  const tt = applyFrontierTransition(input.oldFrontier, input.nextIndex, [cmChange], depth);
  const newFrontier: readonly Fr[] = hasChange ? tt.newFrontier : input.oldFrontier;
  const newRoot = tt.newRoot;

  const witness: CircomWitness = {
    // --- public inputs ---
    anchor_root: S(input.anchorRoot),
    kyc_root: S(input.kycRoot),
    sanction_root: S(input.sanctionRoot),
    assets_root: S(input.assetsRoot),
    frozen_root: S(input.frozenRoot),
    auditor_pk: S(input.auditorPk),
    nf_in_0: S(nf),
    asset_id: S(assetId),
    amount: S(input.amount),
    recipient: S(input.recipient),
    cm_change_0: S(cmChange),
    new_root: S(newRoot),
    fee: S(input.fee),
    next_index: String(input.nextIndex),
    old_frontier: input.oldFrontier.map(String),
    new_frontier: newFrontier.map(String),
    c_auditor: cAud,
    c_recipient: cRec,

    // --- private witness: spent input note ---
    in_asset_id: S(input.inNote.assetId),
    in_value: S(input.inNote.value),
    in_owner_pk: S(input.inNote.ownerPk),
    in_rho: S(input.inNote.rho),
    in_r_note: S(input.inNote.rNote),
    owner_sk: S(input.ownerSk),
    in_path_elements: pe(input.inPath),
    in_path_indices: pi(input.inPath),

    // --- frozen non-membership of the spent commitment ---
    frozen_low_value: S(input.frozenLow.value),
    frozen_low_next_index: S(input.frozenLow.nextIndex),
    frozen_low_next_value: S(input.frozenLow.nextValue),
    frozen_path_elements: pe(input.frozenPath),
    frozen_path_indices: pi(input.frozenPath),

    // --- recipient compliance ---
    kyc_path_elements: pe(input.kycPath),
    kyc_path_indices: pi(input.kycPath),
    sanction_low_value: S(input.sanctionLow.value),
    sanction_low_next_index: S(input.sanctionLow.nextIndex),
    sanction_low_next_value: S(input.sanctionLow.nextValue),
    sanction_path_elements: pe(input.sanctionPath),
    sanction_path_indices: pi(input.sanctionPath),

    // --- change-note opening + selector ---
    change_owner_pk: S(change?.ownerPk ?? 0n),
    change_value: S(change?.value ?? 0n),
    change_rho: S(change?.rho ?? 0n),
    change_r_note: S(change?.rNote ?? 0n),
    has_change: hasChange ? '1' : '0',

    // --- assets registry membership + per-tx limit ---
    sac_address: S(input.sacAddress),
    decimals: S(input.decimals),
    per_tx_limit_raw: S(input.perTxLimitRaw),
    assets_path_elements: pe(input.assetsPath),
    assets_path_indices: pi(input.assetsPath),

    // --- change-note encryption keying ---
    k_view: S(input.kView),
    k_pair: S(input.kPair),
    rho_enc_auditor: S(hasChange ? input.rhoEncAuditor : 0n),
    rho_enc_recipient: S(hasChange ? input.rhoEncRecipient : 0n),
  };

  return { witness, derived: { cmIn, nf, cmChange, hasChange, newRoot, newFrontier } };
}

// ===========================================================================
// dvp.circom - atomic two-asset settlement (DEMO: single combined proof) (FIN-016)
// ===========================================================================

/**
 * Fully-resolved inputs for a two-leg DvP witness. Per-leg arrays are indexed
 * [0]=X (A spends asset X -> B), [1]=Y (B spends asset Y -> A). Each leg spends a
 * single note of ONE asset to one output; the legs use DIFFERENT assets and
 * DIFFERENT spending keys (one combined proof — DEMO only, invariant #15).
 *
 * SECRET: this embeds BOTH parties' spending keys + note openings (invariant #8).
 */
export interface DvpWitnessInput {
  // shared state (one of each, both legs)
  readonly anchorRoot: Fr;
  readonly kycRoot: Fr;
  readonly sanctionRoot: Fr;
  readonly assetsRoot: Fr;
  readonly frozenRoot: Fr;
  readonly auditorPk: Fr;
  /** Single sender↔auditor shared key for both legs; `auditor_pk = Poseidon(kView)`. */
  readonly kView: Fr;
  readonly oldFrontier: readonly Fr[];
  readonly nextIndex: number;
  // per leg [0]=X, [1]=Y
  readonly inNotes: readonly [Note, Note];
  /** Each leg's own spender key (no key sharing across legs). SECRET. */
  readonly ownerSk: readonly [Fr, Fr];
  readonly inPaths: readonly [MerklePath, MerklePath];
  /** Output notes (each leg's output asset == its input asset; normalised here). */
  readonly outNotes: readonly [Note, Note];
  readonly frozenLow: readonly [ImtLowLeaf, ImtLowLeaf];
  readonly frozenPaths: readonly [MerklePath, MerklePath];
  readonly sacAddress: readonly [Fr, Fr];
  readonly decimals: readonly [Fr, Fr];
  readonly perTxLimitRaw: readonly [Fr, Fr];
  readonly assetsPaths: readonly [MerklePath, MerklePath];
  /** KYC membership of each leg's recipient (= outNotes[L].ownerPk). */
  readonly kycPaths: readonly [MerklePath, MerklePath];
  readonly sanctionLow: readonly [ImtLowLeaf, ImtLowLeaf];
  readonly sanctionPaths: readonly [MerklePath, MerklePath];
  /** Per-leg fee (fee_X, fee_Y); 0 in the demo (invariant #3). */
  readonly fee: readonly [Fr, Fr];
  readonly kPair: readonly [Fr, Fr];
  readonly rhoEncAuditor: readonly [Fr, Fr];
  readonly rhoEncRecipient: readonly [Fr, Fr];
}

export interface DvpWitnessDerived {
  readonly nf: readonly [Fr, Fr];
  readonly cmOut: readonly [Fr, Fr];
  readonly newRoot: Fr;
  readonly newFrontier: readonly Fr[];
}

export interface DvpWitnessResult {
  readonly witness: CircomWitness;
  readonly derived: DvpWitnessDerived;
}

/**
 * Assemble the complete `Dvp(D, 5, 5)` witness from resolved inputs. Depth `D` is
 * taken from `oldFrontier.length`. Each leg's output commitment + ciphertexts use
 * the leg's INPUT asset_id (the circuit binds `outNote.asset_id <== in_asset_id`),
 * so the output note's asset is normalised to the input's here to stay consistent.
 * The two output commitments are inserted at `nextIndex` and `nextIndex + 1`.
 */
export function buildDvpWitness(input: DvpWitnessInput): DvpWitnessResult {
  const depth = input.oldFrontier.length;
  // Normalise each leg's output asset to its input asset (the circuit uses
  // in_asset_id for the output commitment + the encryption binding).
  const outLeg = (L: 0 | 1): Note => ({ ...input.outNotes[L], assetId: input.inNotes[L].assetId });
  const out0 = outLeg(0);
  const out1 = outLeg(1);

  const nf: [Fr, Fr] = [
    deriveNullifier(input.inNotes[0].rho, input.ownerSk[0] as OwnerSk),
    deriveNullifier(input.inNotes[1].rho, input.ownerSk[1] as OwnerSk),
  ];
  const cmOut: [Fr, Fr] = [commitNote(out0), commitNote(out1)];
  const cAud: [readonly Fr[], readonly Fr[]] = [
    encryptToAuditor(out0, input.kView, { rhoEnc: input.rhoEncAuditor[0] }).fields,
    encryptToAuditor(out1, input.kView, { rhoEnc: input.rhoEncAuditor[1] }).fields,
  ];
  const cRec: [readonly Fr[], readonly Fr[]] = [
    encryptToRecipient(out0, input.kPair[0], { rhoEnc: input.rhoEncRecipient[0] }).fields,
    encryptToRecipient(out1, input.kPair[1], { rhoEnc: input.rhoEncRecipient[1] }).fields,
  ];

  const { newFrontier, newRoot } = applyFrontierTransition(
    input.oldFrontier,
    input.nextIndex,
    [cmOut[0], cmOut[1]],
    depth,
  );

  const witness: CircomWitness = {
    // --- public inputs (canonical order) ---
    anchor_root: S(input.anchorRoot),
    kyc_root: S(input.kycRoot),
    sanction_root: S(input.sanctionRoot),
    assets_root: S(input.assetsRoot),
    frozen_root: S(input.frozenRoot),
    auditor_pk: S(input.auditorPk),
    nf_legX_0: S(nf[0]),
    nf_legY_0: S(nf[1]),
    cm_out_X: S(cmOut[0]),
    cm_out_Y: S(cmOut[1]),
    new_root: S(newRoot),
    fee_X: S(input.fee[0]),
    fee_Y: S(input.fee[1]),
    next_index: String(input.nextIndex),
    old_frontier: input.oldFrontier.map(String),
    new_frontier: newFrontier.map(String),
    c_auditor_X: cAud[0].map(String),
    c_auditor_Y: cAud[1].map(String),
    c_recipient_X: cRec[0].map(String),
    c_recipient_Y: cRec[1].map(String),

    // --- private witness (per leg [0]=X, [1]=Y) ---
    in_asset_id: [S(input.inNotes[0].assetId), S(input.inNotes[1].assetId)],
    in_value: [S(input.inNotes[0].value), S(input.inNotes[1].value)],
    in_owner_pk: [S(input.inNotes[0].ownerPk), S(input.inNotes[1].ownerPk)],
    in_rho: [S(input.inNotes[0].rho), S(input.inNotes[1].rho)],
    in_r_note: [S(input.inNotes[0].rNote), S(input.inNotes[1].rNote)],
    owner_sk: [S(input.ownerSk[0]), S(input.ownerSk[1])],
    in_path_elements: [pe(input.inPaths[0]), pe(input.inPaths[1])],
    in_path_indices: [pi(input.inPaths[0]), pi(input.inPaths[1])],

    frozen_low_value: [S(input.frozenLow[0].value), S(input.frozenLow[1].value)],
    frozen_low_next_index: [S(input.frozenLow[0].nextIndex), S(input.frozenLow[1].nextIndex)],
    frozen_low_next_value: [S(input.frozenLow[0].nextValue), S(input.frozenLow[1].nextValue)],
    frozen_path_elements: [pe(input.frozenPaths[0]), pe(input.frozenPaths[1])],
    frozen_path_indices: [pi(input.frozenPaths[0]), pi(input.frozenPaths[1])],

    out_value: [S(out0.value), S(out1.value)],
    out_owner_pk: [S(out0.ownerPk), S(out1.ownerPk)],
    out_rho: [S(out0.rho), S(out1.rho)],
    out_r_note: [S(out0.rNote), S(out1.rNote)],

    sac_address: [S(input.sacAddress[0]), S(input.sacAddress[1])],
    decimals: [S(input.decimals[0]), S(input.decimals[1])],
    per_tx_limit_raw: [S(input.perTxLimitRaw[0]), S(input.perTxLimitRaw[1])],
    assets_path_elements: [pe(input.assetsPaths[0]), pe(input.assetsPaths[1])],
    assets_path_indices: [pi(input.assetsPaths[0]), pi(input.assetsPaths[1])],

    kyc_path_elements: [pe(input.kycPaths[0]), pe(input.kycPaths[1])],
    kyc_path_indices: [pi(input.kycPaths[0]), pi(input.kycPaths[1])],

    sanction_low_value: [S(input.sanctionLow[0].value), S(input.sanctionLow[1].value)],
    sanction_low_next_index: [S(input.sanctionLow[0].nextIndex), S(input.sanctionLow[1].nextIndex)],
    sanction_low_next_value: [S(input.sanctionLow[0].nextValue), S(input.sanctionLow[1].nextValue)],
    sanction_path_elements: [pe(input.sanctionPaths[0]), pe(input.sanctionPaths[1])],
    sanction_path_indices: [pi(input.sanctionPaths[0]), pi(input.sanctionPaths[1])],

    k_view: S(input.kView),
    k_pair: [S(input.kPair[0]), S(input.kPair[1])],
    rho_enc_auditor: [S(input.rhoEncAuditor[0]), S(input.rhoEncAuditor[1])],
    rho_enc_recipient: [S(input.rhoEncRecipient[0]), S(input.rhoEncRecipient[1])],
  };

  return { witness, derived: { nf, cmOut, newRoot, newFrontier } };
}
