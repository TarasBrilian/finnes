pragma circom 2.1.6;

// =============================================================================
// dvp.circom - atomic two-asset settlement (DEMO: single combined proof)
// =============================================================================
//
// SCAFFOLD. Composition & public-signal ordering are concrete and normative;
// crypto bodies delegate to TODO-stub lib gadgets.
//
// COMPILE WITH:  circom dvp.circom --prime bls12381 --r1cs --wasm --sym
//   (`--prime bls12381` is a COMPILER flag, not a pragma.)
//
// -----------------------------------------------------------------------------
// !!! NON-PRODUCTION DEMO CIRCUIT (Security invariant #15) !!!
// This combined circuit holds BOTH parties' secrets in one witness (one
// pairing). That is acceptable ONLY because a test harness controls both
// keypairs; it does NOT demonstrate the no-key-sharing property. PRODUCTION DvP
// is the escrow / two-phase flow (ARCHITECTURE.md -> "Settlement (DvP)") built
// from transfer/shield variants - NOT this circuit. Counterparty consent is
// on-chain via require_auth (Ed25519), NEVER an in-circuit signature.
// -----------------------------------------------------------------------------
//
// Two legs: asset X (A -> B) and asset Y (B -> A).
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER - COPIED VERBATIM FROM docs/PUBLIC_IO.md
// -----------------------------------------------------------------------------
//  0  anchor_root
//  1  kyc_root
//  2  sanction_root
//  3  assets_root
//  4  frozen_root
//  5  auditor_pk          (TODO)
//  6  nf_legX_0
//  7  nf_legY_0
//  8  cm_out_X            (asset X -> B)
//  9  cm_out_Y            (asset Y -> A)
// 10  new_root
// 11  fee_X
// 12  fee_Y
// 13 .. 13+D-1            old_frontier[0..D-1]
//    .. +D                new_frontier[0..D-1]
//    .. +K_a              c_auditor_X
//    .. +K_a              c_auditor_Y
//    .. +K_r              c_recipient_X
//    .. +K_r              c_recipient_Y
// -----------------------------------------------------------------------------
//
// Per-leg: conservation per asset, per-leg per_tx_limit_raw, KYC of each
// recipient, frozen/sanctions non-membership. (Security invariants #3, #14,
// #17, #19.)
// =============================================================================

include "lib/poseidon_bls.circom";
include "lib/note.circom";
include "lib/merkle.circom";
include "lib/assets.circom";
include "lib/enc_check.circom";
include "node_modules/circomlib/circuits/bitify.circom"; // Num2Bits

template Dvp(D, K_a, K_r) {
    // ---- public inputs ------------------------------------------------------
    signal input anchor_root;
    signal input kyc_root;
    signal input sanction_root;
    signal input assets_root;
    signal input frozen_root;
    signal input auditor_pk;
    signal input nf_legX_0;
    signal input nf_legY_0;
    signal input cm_out_X;        // asset X -> B
    signal input cm_out_Y;        // asset Y -> A
    signal input new_root;
    signal input fee_X;
    signal input fee_Y;
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor_X[K_a];
    signal input c_auditor_Y[K_a];
    signal input c_recipient_X[K_r];
    signal input c_recipient_Y[K_r];

    // ---- private witness ----------------------------------------------------
    // Leg X: A spends an asset-X note -> B's output. owner_sk = A's key.
    signal input X_in_asset_id;
    signal input X_in_value;
    signal input X_in_owner_pk;
    signal input X_in_rho;
    signal input X_in_r_note;
    signal input A_owner_sk;
    signal input X_in_path_elements[D];
    signal input X_in_path_indices[D];
    signal input X_frozen_lo;
    signal input X_frozen_hi;
    signal input X_frozen_path_elements[D];
    signal input X_frozen_path_indices[D];
    // X output (to B)
    signal input X_out_value;
    signal input X_out_owner_pk;   // B's pk
    signal input X_out_rho;
    signal input X_out_r_note;
    // X assets-registry witness
    signal input X_sac_address;
    signal input X_decimals;
    signal input X_per_tx_limit_raw;
    signal input X_assets_path_elements[D];
    signal input X_assets_path_indices[D];
    // X recipient (B) compliance
    signal input X_kyc_path_elements[D];
    signal input X_kyc_path_indices[D];
    signal input X_sanction_lo;
    signal input X_sanction_hi;
    signal input X_sanction_path_elements[D];
    signal input X_sanction_path_indices[D];
    // X encryption randomness
    signal input X_enc_rand_auditor;
    signal input X_enc_rand_recipient;

    // Leg Y: B spends an asset-Y note -> A's output. owner_sk = B's key.
    signal input Y_in_asset_id;
    signal input Y_in_value;
    signal input Y_in_owner_pk;
    signal input Y_in_rho;
    signal input Y_in_r_note;
    signal input B_owner_sk;
    signal input Y_in_path_elements[D];
    signal input Y_in_path_indices[D];
    signal input Y_frozen_lo;
    signal input Y_frozen_hi;
    signal input Y_frozen_path_elements[D];
    signal input Y_frozen_path_indices[D];
    // Y output (to A)
    signal input Y_out_value;
    signal input Y_out_owner_pk;   // A's pk
    signal input Y_out_rho;
    signal input Y_out_r_note;
    // Y assets-registry witness
    signal input Y_sac_address;
    signal input Y_decimals;
    signal input Y_per_tx_limit_raw;
    signal input Y_assets_path_elements[D];
    signal input Y_assets_path_indices[D];
    // Y recipient (A) compliance
    signal input Y_kyc_path_elements[D];
    signal input Y_kyc_path_indices[D];
    signal input Y_sanction_lo;
    signal input Y_sanction_hi;
    signal input Y_sanction_path_elements[D];
    signal input Y_sanction_path_indices[D];
    // Y encryption randomness
    signal input Y_enc_rand_auditor;
    signal input Y_enc_rand_recipient;

    // append index witness
    signal input nextIndex;

    // =========================================================================
    // LEG X - A spends asset X to B
    // =========================================================================
    component X_inRange = Num2Bits(64);  X_inRange.in <== X_in_value;
    component X_outRange = Num2Bits(64); X_outRange.in <== X_out_value;

    component X_spent = SpentNote();
    X_spent.asset_id <== X_in_asset_id;
    X_spent.value    <== X_in_value;
    X_spent.owner_pk <== X_in_owner_pk;
    X_spent.rho      <== X_in_rho;
    X_spent.r_note   <== X_in_r_note;
    X_spent.owner_sk <== A_owner_sk;        // sound: A's own key
    nf_legX_0 === X_spent.nf;

    component X_incl = MerkleInclusion(D);
    X_incl.leaf <== X_spent.cm;
    for (var i = 0; i < D; i++) {
        X_incl.pathElements[i] <== X_in_path_elements[i];
        X_incl.pathIndices[i]  <== X_in_path_indices[i];
    }
    X_incl.root <== anchor_root;

    component X_frozenNM = MerkleNonMembership(D);
    X_frozenNM.target <== X_spent.cm;
    X_frozenNM.lo <== X_frozen_lo;
    X_frozenNM.hi <== X_frozen_hi;
    for (var i = 0; i < D; i++) {
        X_frozenNM.pathElements[i] <== X_frozen_path_elements[i];
        X_frozenNM.pathIndices[i]  <== X_frozen_path_indices[i];
    }
    X_frozenNM.root <== frozen_root;

    component X_out = OutputNote();
    X_out.asset_id <== X_in_asset_id;       // same asset within leg X
    X_out.value    <== X_out_value;
    X_out.owner_pk <== X_out_owner_pk;
    X_out.rho      <== X_out_rho;
    X_out.r_note   <== X_out_r_note;
    cm_out_X === X_out.cm;

    // per-asset conservation for leg X (no cross-asset sum - invariant #3)
    X_in_value === X_out_value + fee_X;

    component X_assets = AssetsMembership(D);
    X_assets.asset_id        <== X_in_asset_id;
    X_assets.value           <== X_out_value;
    X_assets.sac_address     <== X_sac_address;
    X_assets.decimals        <== X_decimals;
    X_assets.per_tx_limit_raw <== X_per_tx_limit_raw;
    for (var i = 0; i < D; i++) {
        X_assets.pathElements[i] <== X_assets_path_elements[i];
        X_assets.pathIndices[i]  <== X_assets_path_indices[i];
    }
    X_assets.assets_root <== assets_root;

    // recipient B KYC + sanctions NM (TODO: bind to B's pk == X_out_owner_pk)
    component X_kyc = MerkleInclusion(D);
    X_kyc.leaf <== X_out_owner_pk;
    for (var i = 0; i < D; i++) {
        X_kyc.pathElements[i] <== X_kyc_path_elements[i];
        X_kyc.pathIndices[i]  <== X_kyc_path_indices[i];
    }
    X_kyc.root <== kyc_root;

    component X_sanctionNM = MerkleNonMembership(D);
    X_sanctionNM.target <== X_out_owner_pk;
    X_sanctionNM.lo <== X_sanction_lo;
    X_sanctionNM.hi <== X_sanction_hi;
    for (var i = 0; i < D; i++) {
        X_sanctionNM.pathElements[i] <== X_sanction_path_elements[i];
        X_sanctionNM.pathIndices[i]  <== X_sanction_path_indices[i];
    }
    X_sanctionNM.root <== sanction_root;

    component X_auditEnc = AuditorEncCheck(K_a);
    X_auditEnc.auditor_pk <== auditor_pk;
    for (var i = 0; i < K_a; i++) { X_auditEnc.c_auditor[i] <== c_auditor_X[i]; }
    X_auditEnc.asset_id <== X_in_asset_id;
    X_auditEnc.value    <== X_out_value;
    X_auditEnc.owner_pk <== X_out_owner_pk;
    X_auditEnc.rho      <== X_out_rho;
    X_auditEnc.enc_rand <== X_enc_rand_auditor;

    component X_recipEnc = RecipientEncCheck(K_r);
    X_recipEnc.recipient_pk <== X_out_owner_pk;
    for (var i = 0; i < K_r; i++) { X_recipEnc.c_recipient[i] <== c_recipient_X[i]; }
    X_recipEnc.asset_id <== X_in_asset_id;
    X_recipEnc.value    <== X_out_value;
    X_recipEnc.owner_pk <== X_out_owner_pk;
    X_recipEnc.rho      <== X_out_rho;
    X_recipEnc.enc_rand <== X_enc_rand_recipient;

    // =========================================================================
    // LEG Y - B spends asset Y to A
    // =========================================================================
    component Y_inRange = Num2Bits(64);  Y_inRange.in <== Y_in_value;
    component Y_outRange = Num2Bits(64); Y_outRange.in <== Y_out_value;

    component Y_spent = SpentNote();
    Y_spent.asset_id <== Y_in_asset_id;
    Y_spent.value    <== Y_in_value;
    Y_spent.owner_pk <== Y_in_owner_pk;
    Y_spent.rho      <== Y_in_rho;
    Y_spent.r_note   <== Y_in_r_note;
    Y_spent.owner_sk <== B_owner_sk;        // sound: B's own key
    nf_legY_0 === Y_spent.nf;

    component Y_incl = MerkleInclusion(D);
    Y_incl.leaf <== Y_spent.cm;
    for (var i = 0; i < D; i++) {
        Y_incl.pathElements[i] <== Y_in_path_elements[i];
        Y_incl.pathIndices[i]  <== Y_in_path_indices[i];
    }
    Y_incl.root <== anchor_root;

    component Y_frozenNM = MerkleNonMembership(D);
    Y_frozenNM.target <== Y_spent.cm;
    Y_frozenNM.lo <== Y_frozen_lo;
    Y_frozenNM.hi <== Y_frozen_hi;
    for (var i = 0; i < D; i++) {
        Y_frozenNM.pathElements[i] <== Y_frozen_path_elements[i];
        Y_frozenNM.pathIndices[i]  <== Y_frozen_path_indices[i];
    }
    Y_frozenNM.root <== frozen_root;

    component Y_out = OutputNote();
    Y_out.asset_id <== Y_in_asset_id;
    Y_out.value    <== Y_out_value;
    Y_out.owner_pk <== Y_out_owner_pk;
    Y_out.rho      <== Y_out_rho;
    Y_out.r_note   <== Y_out_r_note;
    cm_out_Y === Y_out.cm;

    Y_in_value === Y_out_value + fee_Y;

    component Y_assets = AssetsMembership(D);
    Y_assets.asset_id        <== Y_in_asset_id;
    Y_assets.value           <== Y_out_value;
    Y_assets.sac_address     <== Y_sac_address;
    Y_assets.decimals        <== Y_decimals;
    Y_assets.per_tx_limit_raw <== Y_per_tx_limit_raw;
    for (var i = 0; i < D; i++) {
        Y_assets.pathElements[i] <== Y_assets_path_elements[i];
        Y_assets.pathIndices[i]  <== Y_assets_path_indices[i];
    }
    Y_assets.assets_root <== assets_root;

    component Y_kyc = MerkleInclusion(D);
    Y_kyc.leaf <== Y_out_owner_pk;
    for (var i = 0; i < D; i++) {
        Y_kyc.pathElements[i] <== Y_kyc_path_elements[i];
        Y_kyc.pathIndices[i]  <== Y_kyc_path_indices[i];
    }
    Y_kyc.root <== kyc_root;

    component Y_sanctionNM = MerkleNonMembership(D);
    Y_sanctionNM.target <== Y_out_owner_pk;
    Y_sanctionNM.lo <== Y_sanction_lo;
    Y_sanctionNM.hi <== Y_sanction_hi;
    for (var i = 0; i < D; i++) {
        Y_sanctionNM.pathElements[i] <== Y_sanction_path_elements[i];
        Y_sanctionNM.pathIndices[i]  <== Y_sanction_path_indices[i];
    }
    Y_sanctionNM.root <== sanction_root;

    component Y_auditEnc = AuditorEncCheck(K_a);
    Y_auditEnc.auditor_pk <== auditor_pk;
    for (var i = 0; i < K_a; i++) { Y_auditEnc.c_auditor[i] <== c_auditor_Y[i]; }
    Y_auditEnc.asset_id <== Y_in_asset_id;
    Y_auditEnc.value    <== Y_out_value;
    Y_auditEnc.owner_pk <== Y_out_owner_pk;
    Y_auditEnc.rho      <== Y_out_rho;
    Y_auditEnc.enc_rand <== Y_enc_rand_auditor;

    component Y_recipEnc = RecipientEncCheck(K_r);
    Y_recipEnc.recipient_pk <== Y_out_owner_pk;
    for (var i = 0; i < K_r; i++) { Y_recipEnc.c_recipient[i] <== c_recipient_Y[i]; }
    Y_recipEnc.asset_id <== Y_in_asset_id;
    Y_recipEnc.value    <== Y_out_value;
    Y_recipEnc.owner_pk <== Y_out_owner_pk;
    Y_recipEnc.rho      <== Y_out_rho;
    Y_recipEnc.enc_rand <== Y_enc_rand_recipient;

    // =========================================================================
    // TREE TRANSITION: insert both output commitments (X then Y).
    // =========================================================================
    component tt = FrontierTransition(D, 2);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_out_X;
    tt.leaves[1] <== cm_out_Y;
    tt.nextIndex <== nextIndex;
    for (var i = 0; i < D; i++) { new_frontier[i] === tt.new_frontier[i]; }
    new_root === tt.new_root;
}

// -----------------------------------------------------------------------------
// main - order MUST match docs/PUBLIC_IO.md. D=32; K_a/K_r TODO placeholders (4).
// -----------------------------------------------------------------------------
component main { public [
    anchor_root,
    kyc_root,
    sanction_root,
    assets_root,
    frozen_root,
    auditor_pk,
    nf_legX_0,
    nf_legY_0,
    cm_out_X,
    cm_out_Y,
    new_root,
    fee_X,
    fee_Y,
    old_frontier,
    new_frontier,
    c_auditor_X,
    c_auditor_Y,
    c_recipient_X,
    c_recipient_Y
] } = Dvp(32, 4, 4);
