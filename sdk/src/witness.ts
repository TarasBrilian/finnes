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
