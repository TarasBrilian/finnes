pragma circom 2.1.6;

// =============================================================================
// unshield.circom — shielded -> transparent (1+ shielded inputs, transparent out)
// =============================================================================
//
// SCAFFOLD. Composition & public-signal ordering are concrete and normative;
// crypto bodies delegate to TODO-stub lib gadgets.
//
// COMPILE WITH:  circom unshield.circom --prime bls12381 --r1cs --wasm --sym
//   (`--prime bls12381` is a COMPILER flag, not a pragma.)
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER — COPIED VERBATIM FROM docs/PUBLIC_IO.md
// -----------------------------------------------------------------------------
//  0  anchor_root
//  1  kyc_root            (transparent recipient compliance)
//  2  sanction_root
//  3  assets_root
//  4  frozen_root
//  5  auditor_pk          (TODO)
//  6  nf_in_0
//  7  asset_id            (public — for the SAC transfer)
//  8  amount              (public — raw SAC units leaving)
//  9  recipient           (public — transparent Stellar address)
// 10  cm_change_0         (optional change note; 0/null if none)
// 11  new_root
// 12  fee
// 13 .. 13+D-1            old_frontier[0..D-1]
//    .. +D                new_frontier[0..D-1]
//    .. +K_a              c_auditor   (for the change note, if any)
// -----------------------------------------------------------------------------
//
// MUST ENFORCE (Security invariant #19): input inclusion + nullifier, FROZEN-SET
// NON-MEMBERSHIP of the spent commitment (escape-hatch closure), transparent
// `recipient` KYC/non-sanctioned, conservation `amount + change == input`.
//
// RAW SAC UNITS only — no rescaling (Security invariant #16).
// =============================================================================

include "lib/poseidon_bls.circom";
include "lib/note.circom";
include "lib/merkle.circom";
include "lib/assets.circom";
include "lib/enc_check.circom";
include "node_modules/circomlib/circuits/bitify.circom"; // Num2Bits

// Single shielded input + optional change note (demo: 1-in / 1-transparent-out
// + 1 change). K_r omitted: a transparent recipient has no shielded note to
// scan, so PUBLIC_IO.md carries only c_auditor (for the change note).
template Unshield(D, K_a) {
    // ---- public inputs ------------------------------------------------------
    signal input anchor_root;
    signal input kyc_root;
    signal input sanction_root;
    signal input assets_root;
    signal input frozen_root;
    signal input auditor_pk;
    signal input nf_in_0;
    signal input asset_id;
    signal input amount;
    signal input recipient;       // transparent Stellar address (public)
    signal input cm_change_0;     // optional change note commitment (0 if none)
    signal input new_root;
    signal input fee;
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor[K_a];

    // ---- private witness ----------------------------------------------------
    // single input note
    signal input in_asset_id;
    signal input in_value;
    signal input in_owner_pk;
    signal input in_rho;
    signal input in_r_note;
    signal input owner_sk;
    signal input in_path_elements[D];
    signal input in_path_indices[D];
    // frozen non-membership of the spent commitment (invariant #19b)
    signal input frozen_lo;
    signal input frozen_hi;
    signal input frozen_path_elements[D];
    signal input frozen_path_indices[D];
    // transparent recipient compliance
    signal input recipient_kyc_pk;            // KYC leaf for the transparent recipient
    signal input kyc_path_elements[D];
    signal input kyc_path_indices[D];
    signal input sanction_lo;
    signal input sanction_hi;
    signal input sanction_path_elements[D];
    signal input sanction_path_indices[D];
    // change note opening (owner = spender)
    signal input change_owner_pk;
    signal input change_value;
    signal input change_rho;
    signal input change_r_note;
    signal input has_change;                  // boolean: 1 if a change note exists
    // assets registry membership
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    signal input assets_path_elements[D];
    signal input assets_path_indices[D];
    // auditor encryption (for the change note)
    signal input enc_rand_auditor;
    // append index witness
    signal input nextIndex;

    // =========================================================================
    // 1. SPENT INPUT: range, opening, ownership, nullifier, inclusion, frozen NM
    // =========================================================================
    component inRange = Num2Bits(64);
    inRange.in <== in_value;

    component spent = SpentNote();
    spent.asset_id <== in_asset_id;
    spent.value    <== in_value;
    spent.owner_pk <== in_owner_pk;
    spent.rho      <== in_rho;
    spent.r_note   <== in_r_note;
    spent.owner_sk <== owner_sk;

    nf_in_0 === spent.nf;

    component incl = MerkleInclusion(D);
    incl.leaf <== spent.cm;
    for (var i = 0; i < D; i++) {
        incl.pathElements[i] <== in_path_elements[i];
        incl.pathIndices[i]  <== in_path_indices[i];
    }
    incl.root <== anchor_root;

    // FROZEN non-membership of the spent commitment — fund-critical (invariant #19).
    component frozenNM = MerkleNonMembership(D);
    frozenNM.target <== spent.cm;
    frozenNM.lo <== frozen_lo;
    frozenNM.hi <== frozen_hi;
    for (var i = 0; i < D; i++) {
        frozenNM.pathElements[i] <== frozen_path_elements[i];
        frozenNM.pathIndices[i]  <== frozen_path_indices[i];
    }
    frozenNM.root <== frozen_root;

    // =========================================================================
    // 2. PUBLIC asset binding + CONSERVATION: amount + change == input (+ fee)
    // =========================================================================
    // the spent note's asset must equal the publicly-revealed asset_id
    in_asset_id === asset_id;

    // amount range check (leaving the shielded domain)
    component amtRange = Num2Bits(64);
    amtRange.in <== amount;

    // has_change boolean
    has_change * (has_change - 1) === 0;

    // change note range check
    component changeRange = Num2Bits(64);
    changeRange.in <== change_value;

    // conservation: in_value == amount + change_value + fee
    in_value === amount + change_value + fee;

    // =========================================================================
    // 3. OPTIONAL CHANGE NOTE commitment, bound to cm_change_0.
    //    If has_change == 0, change_value must be 0 and cm_change_0 == 0/null.
    // =========================================================================
    component changeNote = OutputNote();
    changeNote.asset_id <== asset_id;            // change stays same asset
    changeNote.value    <== change_value;
    changeNote.owner_pk <== change_owner_pk;
    changeNote.rho      <== change_rho;
    changeNote.r_note   <== change_r_note;

    // cm_change_0 == has_change ? changeNote.cm : 0
    cm_change_0 === has_change * changeNote.cm;
    // and no value hidden when there is no change
    (1 - has_change) * change_value === 0;

    // =========================================================================
    // 4. ASSETS REGISTRY membership + per-tx limit (on the amount leaving).
    // =========================================================================
    component assets = AssetsMembership(D);
    assets.asset_id        <== asset_id;
    assets.value           <== amount;
    assets.sac_address     <== sac_address;
    assets.decimals        <== decimals;
    assets.per_tx_limit_raw <== per_tx_limit_raw;
    for (var i = 0; i < D; i++) {
        assets.pathElements[i] <== assets_path_elements[i];
        assets.pathIndices[i]  <== assets_path_indices[i];
    }
    assets.assets_root <== assets_root;

    // =========================================================================
    // 5. TRANSPARENT RECIPIENT compliance: KYC membership + sanctions NM.
    //    (Security invariant #19a)
    // =========================================================================
    // TODO: bind recipient_kyc_pk to the public `recipient` address (the mapping
    //       address -> KYC pk is a demo admin enrollment; pin the encoding so the
    //       proven KYC leaf provably corresponds to the revealed recipient).
    component kycIncl = MerkleInclusion(D);
    kycIncl.leaf <== recipient_kyc_pk;
    for (var i = 0; i < D; i++) {
        kycIncl.pathElements[i] <== kyc_path_elements[i];
        kycIncl.pathIndices[i]  <== kyc_path_indices[i];
    }
    kycIncl.root <== kyc_root;

    component sanctionNM = MerkleNonMembership(D);
    sanctionNM.target <== recipient_kyc_pk;
    sanctionNM.lo <== sanction_lo;
    sanctionNM.hi <== sanction_hi;
    for (var i = 0; i < D; i++) {
        sanctionNM.pathElements[i] <== sanction_path_elements[i];
        sanctionNM.pathIndices[i]  <== sanction_path_indices[i];
    }
    sanctionNM.root <== sanction_root;

    // =========================================================================
    // 6. MANDATORY auditor encryption — binds the CHANGE note plaintext.
    //    (The transparent leg is already public; the change note must still be
    //     auditable.) Security invariant #5.
    // =========================================================================
    component auditEnc = AuditorEncCheck(K_a);
    auditEnc.auditor_pk <== auditor_pk;
    for (var i = 0; i < K_a; i++) { auditEnc.c_auditor[i] <== c_auditor[i]; }
    auditEnc.asset_id <== asset_id;
    auditEnc.value    <== change_value;
    auditEnc.owner_pk <== change_owner_pk;
    auditEnc.rho      <== change_rho;
    auditEnc.enc_rand <== enc_rand_auditor;

    // =========================================================================
    // 7. TREE TRANSITION: insert change commitment (only if has_change).
    //    NOTE: a 0/null change leaf still needs a deterministic insertion rule.
    //    TODO: when has_change == 0, the transition must be a NO-OP (new_frontier
    //          == old_frontier, new_root unchanged). The current gadget always
    //          inserts; gate the insert on has_change in the real implementation.
    // =========================================================================
    component tt = FrontierTransition(D, 1);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_change_0;
    tt.nextIndex <== nextIndex;
    for (var i = 0; i < D; i++) { new_frontier[i] === tt.new_frontier[i]; }
    new_root === tt.new_root;
}

// -----------------------------------------------------------------------------
// main — order MUST match docs/PUBLIC_IO.md. D=32; K_a TODO placeholder (4).
// (No c_recipient for unshield — transparent recipient has no shielded note.)
// -----------------------------------------------------------------------------
component main { public [
    anchor_root,
    kyc_root,
    sanction_root,
    assets_root,
    frozen_root,
    auditor_pk,
    nf_in_0,
    asset_id,
    amount,
    recipient,
    cm_change_0,
    new_root,
    fee,
    old_frontier,
    new_frontier,
    c_auditor
] } = Unshield(32, 4);
