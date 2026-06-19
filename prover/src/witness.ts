/**
 * Witness assembly for the four Finnes circuits.
 *
 * The public-signal ORDER produced here is normative and MUST match, byte-for-
 * field, all four surfaces (docs/PUBLIC_IO.md):
 *   - circuits/<circuit>.circom `main` public signal order,
 *   - contracts/finnes/src/types.rs `PublicInputs::to_vec()`,
 *   - this file (prover assembly),
 *   - sdk/src/ helpers.
 *
 * REUSE OVER DUPLICATION: the ordered public-input builders are intended to live
 * in `@finnes/sdk` (sdk/src/publicInputs.ts) so the order is defined exactly once
 * and shared between prover and SDK. That module does not exist yet, so the order
 * is encoded locally below behind a thin indirection.
 *   TODO(sdk): replace the local `PUBLIC_IO_ORDER` constants with imports from
 *   "@finnes/sdk" (e.g. `import { transferPublicInputs } from "@finnes/sdk"`)
 *   once sdk/src/publicInputs.ts lands. Until then, this constant is the
 *   duplicated source of truth and MUST be kept in sync with docs/PUBLIC_IO.md.
 *
 * SECURITY (CLAUDE.md invariant #8): the returned `Witness` embeds secrets
 * (owner_sk, rho, r_note, plaintext value, encryption randomness). Callers must
 * never log it. The prover is single-tenant, runs in the client/institution zone.
 */

import type { CircuitName, FieldElement, MerklePath, Note, Witness } from "./types.js";

/**
 * Public-signal field NAMES per circuit, in canonical order (docs/PUBLIC_IO.md).
 * These are the *public* signals only; the private witness fields are added by
 * the per-circuit assemblers below.
 *
 * NOTE on variable-length tails: `old_frontier` / `new_frontier` are each `D`
 * elements (Tree depth D = 20, LOCKED FIN-001) and the ciphertexts `c_auditor` /
 * `c_recipient` are `K_a` / `K_r` = 5 packed field elements each (additive
 * Poseidon keystream, LOCKED FIN-001 / FIN-004). They occupy the documented
 * positions but are represented as named array signals in the SnarkJS input
 * object rather than flattened here.
 *
 * KEEP IN SYNC WITH docs/PUBLIC_IO.md AND the contract's PublicInputs::to_vec().
 */
export const PUBLIC_IO_ORDER: Record<CircuitName, readonly string[]> = {
  // docs/PUBLIC_IO.md → transfer.circom (2-in / 2-out, single asset)
  transfer: [
    "anchor_root", // 0
    "kyc_root", // 1
    "sanction_root", // 2
    "assets_root", // 3
    "frozen_root", // 4
    "auditor_pk", // 5  (= Poseidon(k_view); single field, LOCKED FIN-001)
    "nf_in_0", // 6
    "nf_in_1", // 7
    "cm_out_0", // 8
    "cm_out_1", // 9
    "new_root", // 10
    "fee", // 11 (per-asset; 0 in demo)
    "next_index", // 12 (current leaf count; contract checks == state)
    "old_frontier", // 13 .. 13+D-1   (D elements)
    "new_frontier", // .. +D          (D elements)
    "c_auditor", // .. +2·K_a      ([2][K_a]: note 0 ‖ note 1; BOTH mandatory #5)
    "c_recipient", // .. +2·K_r      ([2][K_r]: note 0 ‖ note 1)
  ],
  // docs/PUBLIC_IO.md → shield.circom (transparent → shielded)
  shield: [
    "asset_id", // 0 (public - circuit proves = Poseidon(sac_address))
    "amount", // 1 (public - deposited raw SAC units)
    "kyc_root", // 2
    "assets_root", // 3
    "auditor_pk", // 4 (TODO)
    "cm_out_0", // 5
    "new_root", // 6
    "fee", // 7 (0 in demo)
    "old_frontier", // 8 .. 8+D-1
    "new_frontier", // .. +D
    "c_auditor", // .. +K_a
    "c_recipient", // .. +K_r
  ],
  // docs/PUBLIC_IO.md → unshield.circom (shielded → transparent)
  unshield: [
    "anchor_root", // 0
    "kyc_root", // 1 (transparent recipient compliance)
    "sanction_root", // 2
    "assets_root", // 3
    "frozen_root", // 4
    "auditor_pk", // 5 (TODO)
    "nf_in_0", // 6
    "asset_id", // 7 (public - for the SAC transfer)
    "amount", // 8 (public - raw SAC units leaving)
    "recipient", // 9 (public - transparent Stellar address)
    "cm_change_0", // 10 (optional change note; 0/null if none)
    "new_root", // 11
    "fee", // 12
    "old_frontier", // 13 .. 13+D-1
    "new_frontier", // .. +D
    "c_auditor", // .. +K_a (for the change note, if any)
  ],
  // docs/PUBLIC_IO.md → dvp.circom (atomic two-asset; demo single combined proof)
  dvp: [
    "anchor_root", // 0
    "kyc_root", // 1
    "sanction_root", // 2
    "assets_root", // 3
    "frozen_root", // 4
    "auditor_pk", // 5 (TODO)
    "nf_legX_0", // 6
    "nf_legY_0", // 7
    "cm_out_X", // 8 (asset X → B)
    "cm_out_Y", // 9 (asset Y → A)
    "new_root", // 10
    "fee_X", // 11
    "fee_Y", // 12
    "old_frontier", // 13 .. 13+D-1
    "new_frontier", // .. +D
    "c_auditor_X", // .. +K_a
    "c_auditor_Y", // .. +K_a
    "c_recipient_X", // .. +K_r
    "c_recipient_Y", // .. +K_r
  ],
} as const;

/** Inputs common to every spend (anchor + compliance roots, auditor key). */
export interface CommonPublicInputs {
  anchor_root: FieldElement;
  kyc_root: FieldElement;
  sanction_root: FieldElement;
  assets_root: FieldElement;
  frozen_root: FieldElement;
  /** `auditor_pk = Poseidon(k_view)` - single field (LOCKED FIN-001). */
  auditor_pk: FieldElement;
}

// --- shield -----------------------------------------------------------------

export interface ShieldWitnessInput {
  /** Public deposited asset/amount (raw SAC units). */
  asset_id: FieldElement;
  amount: FieldElement;
  kyc_root: FieldElement;
  assets_root: FieldElement;
  auditor_pk: FieldElement;
  /** Output note opening (the freshly-minted shielded note). SECRET. */
  outNote: Note;
  /** Owner spending key. SECRET - derives owner_pk = Poseidon(owner_sk). */
  owner_sk: FieldElement;
  /** Merkle frontier before insertion (D filled-subtree elements). */
  old_frontier: FieldElement[];
  /** Depositor KYC membership path against kyc_root. */
  kycPath: MerklePath;
  /** Authorized-assets registry membership path against assets_root. */
  assetsPath: MerklePath;
  /** Per-asset limit from the registry leaf (witness, never public). SECRET-ish. */
  per_tx_limit_raw: FieldElement;
  /** Encryption randomness for c_auditor / c_recipient. SECRET. */
  encRandomness: FieldElement;
  fee?: FieldElement;
}

/**
 * Assemble the shield witness.
 *
 * Invariant #18: the output cm must open to the PUBLIC (asset_id, amount) without
 * a full opening (owner/rho/r stay private). That binding is enforced in-circuit;
 * here we only feed the opening as private signals.
 *
 * TODO(circuit): exact private signal names depend on shield.circom internals
 * (note-commitment gadget I/O, enc_check signal names). Fill once finalised.
 */
export function assembleShieldWitness(input: ShieldWitnessInput): Witness {
  // NOTE: do NOT log `input` - it contains owner_sk, rho, r_note, value, randomness.
  const witness: Witness = {
    // Public signals (PUBLIC_IO_ORDER.shield):
    asset_id: input.asset_id,
    amount: input.amount,
    kyc_root: input.kyc_root,
    assets_root: input.assets_root,
    auditor_pk: input.auditor_pk,
    fee: input.fee ?? "0",
    old_frontier: input.old_frontier,
    // Private witness:
    owner_sk: input.owner_sk,
    out_value: input.outNote.value,
    out_rho: input.outNote.rho,
    out_r_note: input.outNote.r_note,
    out_owner_pk: input.outNote.owner_pk,
    per_tx_limit_raw: input.per_tx_limit_raw,
    kyc_path_siblings: input.kycPath.siblings,
    kyc_path_indices: input.kycPath.pathIndices,
    assets_path_siblings: input.assetsPath.siblings,
    assets_path_indices: input.assetsPath.pathIndices,
    enc_randomness: input.encRandomness,
    // TODO(circuit): cm_out_0 / new_root / new_frontier / c_auditor / c_recipient
    // are circuit OUTPUTS (computed by the witness generator), not inputs. No
    // assignment needed here, but the names above must match shield.circom.
  };
  return witness;
}

// --- transfer ---------------------------------------------------------------

export interface TransferWitnessInput {
  common: CommonPublicInputs;
  /** Two input notes being spent. SECRET. */
  inNotes: [Note, Note];
  /** Spender spending key. SECRET. */
  owner_sk: FieldElement;
  /** Two output notes minted. SECRET. */
  outNotes: [Note, Note];
  old_frontier: FieldElement[];
  /** Merkle inclusion paths for the two input notes. */
  inInclusionPaths: [MerklePath, MerklePath];
  /** KYC membership path (recipient). */
  kycPath: MerklePath;
  /** Sanctions non-membership path. */
  sanctionPath: MerklePath;
  /** Frozen-set non-membership path (per spent note). */
  frozenPaths: [MerklePath, MerklePath];
  /** Authorized-assets registry membership path. */
  assetsPath: MerklePath;
  /** Per-asset limit from the registry leaf (witness, never public). */
  per_tx_limit_raw: FieldElement;
  encRandomness: FieldElement;
  fee?: FieldElement;
}

/**
 * Assemble the transfer (2-in / 2-out, single asset) witness.
 *
 * Invariants enforced in-circuit (not here): per-asset conservation
 * Σin == Σout + fee (#3), 64-bit range checks (#2), KYC membership, sanctions +
 * frozen non-membership (#6, #14), assets membership + value ≤ per_tx_limit_raw
 * (#17), auditor-encryption well-formedness (#5), tree transition (#12).
 *
 * TODO(circuit): private signal names depend on transfer.circom internals.
 */
export function assembleTransferWitness(input: TransferWitnessInput): Witness {
  // NOTE: do NOT log `input`.
  const c = input.common;
  const witness: Witness = {
    // Public signals (PUBLIC_IO_ORDER.transfer), order documented in PUBLIC_IO.md:
    anchor_root: c.anchor_root,
    kyc_root: c.kyc_root,
    sanction_root: c.sanction_root,
    assets_root: c.assets_root,
    frozen_root: c.frozen_root,
    auditor_pk: c.auditor_pk,
    fee: input.fee ?? "0",
    old_frontier: input.old_frontier,
    // Private witness:
    owner_sk: input.owner_sk,
    in_asset_id: [input.inNotes[0].asset_id, input.inNotes[1].asset_id],
    in_value: [input.inNotes[0].value, input.inNotes[1].value],
    in_owner_pk: [input.inNotes[0].owner_pk, input.inNotes[1].owner_pk],
    in_rho: [input.inNotes[0].rho, input.inNotes[1].rho],
    in_r_note: [input.inNotes[0].r_note, input.inNotes[1].r_note],
    out_asset_id: [input.outNotes[0].asset_id, input.outNotes[1].asset_id],
    out_value: [input.outNotes[0].value, input.outNotes[1].value],
    out_owner_pk: [input.outNotes[0].owner_pk, input.outNotes[1].owner_pk],
    out_rho: [input.outNotes[0].rho, input.outNotes[1].rho],
    out_r_note: [input.outNotes[0].r_note, input.outNotes[1].r_note],
    per_tx_limit_raw: input.per_tx_limit_raw,
    in0_path_siblings: input.inInclusionPaths[0].siblings,
    in0_path_indices: input.inInclusionPaths[0].pathIndices,
    in1_path_siblings: input.inInclusionPaths[1].siblings,
    in1_path_indices: input.inInclusionPaths[1].pathIndices,
    kyc_path_siblings: input.kycPath.siblings,
    kyc_path_indices: input.kycPath.pathIndices,
    sanction_path_siblings: input.sanctionPath.siblings,
    sanction_path_indices: input.sanctionPath.pathIndices,
    frozen0_path_siblings: input.frozenPaths[0].siblings,
    frozen0_path_indices: input.frozenPaths[0].pathIndices,
    frozen1_path_siblings: input.frozenPaths[1].siblings,
    frozen1_path_indices: input.frozenPaths[1].pathIndices,
    assets_path_siblings: input.assetsPath.siblings,
    assets_path_indices: input.assetsPath.pathIndices,
    enc_randomness: input.encRandomness,
    // TODO(circuit): nf_in_*, cm_out_*, new_root, new_frontier, c_auditor,
    // c_recipient are circuit OUTPUTS.
  };
  return witness;
}

// --- unshield ---------------------------------------------------------------

export interface UnshieldWitnessInput {
  common: CommonPublicInputs;
  /** Public transparent-exit fields. */
  asset_id: FieldElement;
  amount: FieldElement;
  /** Transparent Stellar recipient address (field-encoded). */
  recipient: FieldElement;
  /** Input note(s) being spent. SECRET. (Scaffold: single input.) */
  inNote: Note;
  owner_sk: FieldElement;
  /** Optional change note; omit if exact-spend (cm_change_0 = 0/null). SECRET. */
  changeNote?: Note;
  old_frontier: FieldElement[];
  inInclusionPath: MerklePath;
  kycPath: MerklePath;
  sanctionPath: MerklePath;
  /** Frozen-set non-membership path - MANDATORY (invariant #19, escape-hatch closure). */
  frozenPath: MerklePath;
  assetsPath: MerklePath;
  per_tx_limit_raw: FieldElement;
  encRandomness: FieldElement;
  fee?: FieldElement;
}

/**
 * Assemble the unshield (shielded → transparent) witness.
 *
 * Invariant #19: unshield MUST prove (a) transparent recipient KYC/non-sanctioned
 * and (b) frozen-set non-membership of the spent commitment. Both are enforced
 * in-circuit; here we supply the recipient + the frozen non-membership path.
 *
 * TODO(circuit): private signal names depend on unshield.circom internals, and
 * the change-note handling (cm_change_0 = 0/null when none).
 */
export function assembleUnshieldWitness(input: UnshieldWitnessInput): Witness {
  // NOTE: do NOT log `input`.
  const c = input.common;
  const witness: Witness = {
    // Public signals (PUBLIC_IO_ORDER.unshield):
    anchor_root: c.anchor_root,
    kyc_root: c.kyc_root,
    sanction_root: c.sanction_root,
    assets_root: c.assets_root,
    frozen_root: c.frozen_root,
    auditor_pk: c.auditor_pk,
    asset_id: input.asset_id,
    amount: input.amount,
    recipient: input.recipient,
    fee: input.fee ?? "0",
    old_frontier: input.old_frontier,
    // Private witness:
    owner_sk: input.owner_sk,
    in_value: input.inNote.value,
    in_rho: input.inNote.rho,
    in_r_note: input.inNote.r_note,
    in_owner_pk: input.inNote.owner_pk,
    // Change note opening; "0" sentinel when no change (TODO: confirm null encoding).
    change_value: input.changeNote?.value ?? "0",
    change_rho: input.changeNote?.rho ?? "0",
    change_r_note: input.changeNote?.r_note ?? "0",
    change_owner_pk: input.changeNote?.owner_pk ?? "0",
    per_tx_limit_raw: input.per_tx_limit_raw,
    in_path_siblings: input.inInclusionPath.siblings,
    in_path_indices: input.inInclusionPath.pathIndices,
    kyc_path_siblings: input.kycPath.siblings,
    kyc_path_indices: input.kycPath.pathIndices,
    sanction_path_siblings: input.sanctionPath.siblings,
    sanction_path_indices: input.sanctionPath.pathIndices,
    frozen_path_siblings: input.frozenPath.siblings,
    frozen_path_indices: input.frozenPath.pathIndices,
    assets_path_siblings: input.assetsPath.siblings,
    assets_path_indices: input.assetsPath.pathIndices,
    enc_randomness: input.encRandomness,
    // TODO(circuit): nf_in_0, cm_change_0, new_root, new_frontier, c_auditor are outputs.
  };
  return witness;
}

// --- dvp --------------------------------------------------------------------

export interface DvpLeg {
  /** Input note for this leg. SECRET. */
  inNote: Note;
  /** Output note minted for the counterparty. SECRET. */
  outNote: Note;
  /** Owner spending key for this leg's input. SECRET. */
  owner_sk: FieldElement;
  inInclusionPath: MerklePath;
  frozenPath: MerklePath;
  kycPath: MerklePath; // recipient KYC for this leg
  sanctionPath: MerklePath;
  assetsPath: MerklePath;
  per_tx_limit_raw: FieldElement;
  fee?: FieldElement;
}

export interface DvpWitnessInput {
  common: CommonPublicInputs;
  /** Leg X: asset X moves A → B. */
  legX: DvpLeg;
  /** Leg Y: asset Y moves B → A. */
  legY: DvpLeg;
  old_frontier: FieldElement[];
  encRandomness: FieldElement;
}

/**
 * Assemble the DvP witness (atomic two-asset).
 *
 * DEMO-ONLY combined proof: this single witness holds BOTH parties' secrets
 * (owner_sk for legX and legY). Per ARCHITECTURE.md "Settlement (DvP)" and
 * CLAUDE.md invariant #15, this is acceptable ONLY because a test harness controls
 * both keypairs; it does NOT demonstrate the no-key-sharing property and is NOT
 * the production model (production = escrow / two-phase). Label as non-production
 * wherever shown. Counterparty consent is on-chain via require_auth, never an
 * in-circuit signature.
 *
 * TODO(circuit): private signal names depend on dvp.circom internals.
 */
export function assembleDvpWitness(input: DvpWitnessInput): Witness {
  // NOTE: do NOT log `input` - holds BOTH parties' spending keys.
  const c = input.common;
  const witness: Witness = {
    // Public signals (PUBLIC_IO_ORDER.dvp):
    anchor_root: c.anchor_root,
    kyc_root: c.kyc_root,
    sanction_root: c.sanction_root,
    assets_root: c.assets_root,
    frozen_root: c.frozen_root,
    auditor_pk: c.auditor_pk,
    fee_X: input.legX.fee ?? "0",
    fee_Y: input.legY.fee ?? "0",
    old_frontier: input.old_frontier,
    // Private witness - leg X:
    legX_owner_sk: input.legX.owner_sk,
    legX_in_asset_id: input.legX.inNote.asset_id,
    legX_in_value: input.legX.inNote.value,
    legX_in_owner_pk: input.legX.inNote.owner_pk,
    legX_in_rho: input.legX.inNote.rho,
    legX_in_r_note: input.legX.inNote.r_note,
    legX_out_value: input.legX.outNote.value,
    legX_out_owner_pk: input.legX.outNote.owner_pk,
    legX_out_rho: input.legX.outNote.rho,
    legX_out_r_note: input.legX.outNote.r_note,
    legX_per_tx_limit_raw: input.legX.per_tx_limit_raw,
    legX_in_path_siblings: input.legX.inInclusionPath.siblings,
    legX_in_path_indices: input.legX.inInclusionPath.pathIndices,
    legX_frozen_path_siblings: input.legX.frozenPath.siblings,
    legX_frozen_path_indices: input.legX.frozenPath.pathIndices,
    legX_kyc_path_siblings: input.legX.kycPath.siblings,
    legX_kyc_path_indices: input.legX.kycPath.pathIndices,
    legX_sanction_path_siblings: input.legX.sanctionPath.siblings,
    legX_sanction_path_indices: input.legX.sanctionPath.pathIndices,
    legX_assets_path_siblings: input.legX.assetsPath.siblings,
    legX_assets_path_indices: input.legX.assetsPath.pathIndices,
    // Private witness - leg Y:
    legY_owner_sk: input.legY.owner_sk,
    legY_in_asset_id: input.legY.inNote.asset_id,
    legY_in_value: input.legY.inNote.value,
    legY_in_owner_pk: input.legY.inNote.owner_pk,
    legY_in_rho: input.legY.inNote.rho,
    legY_in_r_note: input.legY.inNote.r_note,
    legY_out_value: input.legY.outNote.value,
    legY_out_owner_pk: input.legY.outNote.owner_pk,
    legY_out_rho: input.legY.outNote.rho,
    legY_out_r_note: input.legY.outNote.r_note,
    legY_per_tx_limit_raw: input.legY.per_tx_limit_raw,
    legY_in_path_siblings: input.legY.inInclusionPath.siblings,
    legY_in_path_indices: input.legY.inInclusionPath.pathIndices,
    legY_frozen_path_siblings: input.legY.frozenPath.siblings,
    legY_frozen_path_indices: input.legY.frozenPath.pathIndices,
    legY_kyc_path_siblings: input.legY.kycPath.siblings,
    legY_kyc_path_indices: input.legY.kycPath.pathIndices,
    legY_sanction_path_siblings: input.legY.sanctionPath.siblings,
    legY_sanction_path_indices: input.legY.sanctionPath.pathIndices,
    legY_assets_path_siblings: input.legY.assetsPath.siblings,
    legY_assets_path_indices: input.legY.assetsPath.pathIndices,
    enc_randomness: input.encRandomness,
    // TODO(circuit): nf_legX_0, nf_legY_0, cm_out_X, cm_out_Y, new_root,
    // new_frontier, c_auditor_X/Y, c_recipient_X/Y are circuit OUTPUTS.
  };
  return witness;
}
