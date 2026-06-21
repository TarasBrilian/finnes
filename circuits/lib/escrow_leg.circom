pragma circom 2.1.6;

// =============================================================================
// lib/escrow_leg.circom - the EscrowLeg(D, K_a, K_r, CHECK_RECIPIENT) template
// (FIN-017, production escrow DvP — see docs/DVP_ESCROW.md)
// =============================================================================
//
// A single-input / single-output single-asset shielded spend with the same
// FIN-003/004/005 gadgets as transfer/dvp, plus a single-insert tree transition.
// Used for the two escrow boundary ops (the contract picks which tree each root
// refers to — the circuit is tree-agnostic):
//
//   escrow_deposit  (CHECK_RECIPIENT = 0): spend the depositor's MAIN-tree note
//       (owner_sk = depositor) -> mint an ESCROW note owned by pk_intent. The
//       output owner is the intent, NOT a KYC'd party, so recipient compliance is
//       OFF (it is enforced later on the settle swap outputs). Frozen-set
//       non-membership of the SPENT note IS checked (a frozen note can't escrow).
//
//   escrow_refund   (CHECK_RECIPIENT = 1): spend an ESCROW note (owner_sk =
//       sk_intent) -> mint a MAIN-tree note to the depositor's refund_pk, which is
//       a real party, so recipient KYC membership + sanctions non-membership ARE
//       enforced (like transfer's recipient).
//
// settle = the existing dvp.circom (2 escrow inputs both owned by sk_intent,
// anchored to the escrow root) — no new circuit (docs/DVP_ESCROW.md).
//
// Compile with `--prime bls12381` (invariant #1). All gadgets are BLS-native; no
// embedded curve, no new primitive.
// =============================================================================

include "poseidon_bls.circom";
include "note.circom";
include "merkle.circom";
include "assets.circom";
include "enc_check.circom";
include "bits.circom"; // VENDORED Num2Bits (NO circomlib - invariant #1)

template EscrowLeg(D, K_a, K_r, CHECK_RECIPIENT) {
    // ---- public inputs (uniform across deposit/refund) ----
    signal input anchor_root;     // tree the SPENT note is included in
    signal input kyc_root;        // recipient KYC (only constrained if CHECK_RECIPIENT)
    signal input sanction_root;   // recipient sanctions (only constrained if CHECK_RECIPIENT)
    signal input assets_root;
    signal input frozen_root;     // frozen non-membership of the SPENT note
    signal input auditor_pk;
    signal input nf_in_0;
    signal input cm_out_0;        // the minted note's commitment
    signal input new_root;        // tree the MINTED note is inserted into (new root)
    signal input fee;
    signal input next_index;      // leaf count of the insert tree (pinned to state)
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor[K_a];
    signal input c_recipient[K_r];

    // ---- private witness ----
    signal input in_asset_id;
    signal input in_value;
    signal input in_owner_pk;
    signal input in_rho;
    signal input in_r_note;
    signal input owner_sk;        // depositor (deposit) or sk_intent (refund)
    signal input in_path_elements[D];
    signal input in_path_indices[D];
    signal input frozen_low_value;
    signal input frozen_low_next_index;
    signal input frozen_low_next_value;
    signal input frozen_path_elements[D];
    signal input frozen_path_indices[D];
    signal input out_value;
    signal input out_owner_pk;    // pk_intent (deposit) or refund_pk (refund)
    signal input out_rho;
    signal input out_r_note;
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    signal input assets_path_elements[D];
    signal input assets_path_indices[D];
    // recipient compliance witnesses (used only when CHECK_RECIPIENT == 1)
    signal input kyc_path_elements[D];
    signal input kyc_path_indices[D];
    signal input sanction_low_value;
    signal input sanction_low_next_index;
    signal input sanction_low_next_value;
    signal input sanction_path_elements[D];
    signal input sanction_path_indices[D];
    // encryption keying
    signal input k_view;
    signal input k_pair;
    signal input rho_enc_auditor;
    signal input rho_enc_recipient;

    // --- spent note: range, opening+ownership+nullifier, inclusion, frozen NM ---
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

    component frozenNM = MerkleNonMembership(D);
    frozenNM.target <== spent.cm;
    frozenNM.low_value      <== frozen_low_value;
    frozenNM.low_next_index <== frozen_low_next_index;
    frozenNM.low_next_value <== frozen_low_next_value;
    for (var i = 0; i < D; i++) {
        frozenNM.pathElements[i] <== frozen_path_elements[i];
        frozenNM.pathIndices[i]  <== frozen_path_indices[i];
    }
    frozenNM.root <== frozen_root;

    // --- minted note: range + commitment (same asset) ---
    component outRange = Num2Bits(64);
    outRange.in <== out_value;

    component outNote = OutputNote();
    outNote.asset_id <== in_asset_id;
    outNote.value    <== out_value;
    outNote.owner_pk <== out_owner_pk;
    outNote.rho      <== out_rho;
    outNote.r_note   <== out_r_note;
    cm_out_0 === outNote.cm;

    // --- per-asset conservation ---
    in_value === out_value + fee;

    // --- assets-registry membership + per-tx limit ---
    component assets = AssetsMembership(D);
    assets.asset_id        <== in_asset_id;
    assets.value           <== out_value;
    assets.sac_address     <== sac_address;
    assets.decimals        <== decimals;
    assets.per_tx_limit_raw <== per_tx_limit_raw;
    for (var i = 0; i < D; i++) {
        assets.pathElements[i] <== assets_path_elements[i];
        assets.pathIndices[i]  <== assets_path_indices[i];
    }
    assets.assets_root <== assets_root;

    // --- recipient compliance (ONLY for refund; the deposit recipient is the
    //     intent, which is not a KYC'd party) ---
    if (CHECK_RECIPIENT == 1) {
        component kycIncl = MerkleInclusion(D);
        kycIncl.leaf <== out_owner_pk;
        for (var i = 0; i < D; i++) {
            kycIncl.pathElements[i] <== kyc_path_elements[i];
            kycIncl.pathIndices[i]  <== kyc_path_indices[i];
        }
        kycIncl.root <== kyc_root;

        component sanctionNM = MerkleNonMembership(D);
        sanctionNM.target <== out_owner_pk;
        sanctionNM.low_value      <== sanction_low_value;
        sanctionNM.low_next_index <== sanction_low_next_index;
        sanctionNM.low_next_value <== sanction_low_next_value;
        for (var i = 0; i < D; i++) {
            sanctionNM.pathElements[i] <== sanction_path_elements[i];
            sanctionNM.pathIndices[i]  <== sanction_path_indices[i];
        }
        sanctionNM.root <== sanction_root;
    }

    // --- mandatory auditor ciphertext + recipient ciphertext (invariant #5) ---
    component auditEnc = AuditorEncCheck();
    auditEnc.auditor_pk <== auditor_pk;
    for (var i = 0; i < K_a; i++) { auditEnc.c_auditor[i] <== c_auditor[i]; }
    auditEnc.value    <== out_value;
    auditEnc.asset_id <== in_asset_id;
    auditEnc.owner_pk <== out_owner_pk;
    auditEnc.rho      <== out_rho;
    auditEnc.k_view   <== k_view;
    auditEnc.rho_enc  <== rho_enc_auditor;

    component recipEnc = RecipientEncCheck();
    for (var i = 0; i < K_r; i++) { recipEnc.c_recipient[i] <== c_recipient[i]; }
    recipEnc.value    <== out_value;
    recipEnc.asset_id <== in_asset_id;
    recipEnc.rho      <== out_rho;
    recipEnc.r_note   <== out_r_note;
    recipEnc.k_pair   <== k_pair;
    recipEnc.rho_enc  <== rho_enc_recipient;

    // --- single-insert tree transition (insert the minted note) ---
    component tt = FrontierTransition(D, 1);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_out_0;
    tt.nextIndex <== next_index;
    for (var i = 0; i < D; i++) { new_frontier[i] === tt.new_frontier[i]; }
    new_root === tt.new_root;
}
