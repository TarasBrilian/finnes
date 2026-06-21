pragma circom 2.1.6;

// =============================================================================
// lib/dvp.circom - the Dvp(D, K_a, K_r) template (FIN-016)
// =============================================================================
//
// Atomic two-asset settlement as a SINGLE combined proof (one pairing). Two legs:
//   leg X: party A spends an asset-X note  -> output to B   (owner_sk = A)
//   leg Y: party B spends an asset-Y note  -> output to A   (owner_sk = B)
// Each leg is a single-input / single-output transfer of ONE asset; the two legs
// use DIFFERENT assets and DIFFERENT spending keys. Both outputs land in the same
// tree-transition. Reuses the EXACT FIN-003/004/005 gadgets that transfer.circom
// composes (note, Merkle inclusion + IMT non-membership, FrontierTransition,
// assets membership + per-tx limit, mandatory auditor / recipient encryption).
//
// Compile with `--prime bls12381` (compiler flag, not pragma) - without it every
// Poseidon-BLS hash is the wrong field (Security invariant #1).
//
// -----------------------------------------------------------------------------
// !!! NON-PRODUCTION DEMO CIRCUIT (Security invariant #15) !!!
// One witness holds BOTH parties' secrets. Acceptable ONLY because a test harness
// controls both keypairs; it does NOT demonstrate the no-key-sharing property.
// PRODUCTION DvP is the escrow / two-phase flow (ARCHITECTURE.md -> "Settlement
// (DvP)"), built from transfer/shield variants, NOT this circuit. Counterparty
// consent is on-chain via require_auth (Ed25519), NEVER an in-circuit signature.
// -----------------------------------------------------------------------------
//
// Per-leg (NEVER cross-leg): per-asset conservation `in == out + fee`, 64-bit
// range checks, per-asset per_tx_limit_raw, recipient KYC + sanctions/frozen
// non-membership (Security invariants #3, #14, #17, #19).
// =============================================================================

include "poseidon_bls.circom";
include "note.circom";
include "merkle.circom";
include "assets.circom";
include "enc_check.circom";
include "bits.circom"; // VENDORED Num2Bits (NO circomlib - invariant #1)

// -----------------------------------------------------------------------------
// DvpLeg - one settlement leg: spend a single note of ONE asset to one output,
// proving inclusion / ownership / nullifier / frozen non-membership / per-asset
// conservation / assets-registry limit / recipient KYC + sanctions / encryption.
// Emits the nullifier and the output commitment to the parent.
// -----------------------------------------------------------------------------
template DvpLeg(D, K_a, K_r) {
    // shared state (wired from the parent's public inputs)
    signal input anchor_root;
    signal input kyc_root;
    signal input sanction_root;
    signal input assets_root;
    signal input frozen_root;
    signal input auditor_pk;
    // per-leg public
    signal input fee;
    signal input c_auditor[K_a];
    signal input c_recipient[K_r];
    // emitted to parent (bound to the leg's public nf / cm_out there)
    signal output nf;
    signal output cm_out;

    // input note (the spent note) + its spender's key
    signal input in_asset_id;
    signal input in_value;
    signal input in_owner_pk;
    signal input in_rho;
    signal input in_r_note;
    signal input owner_sk;                  // this leg's own spender (no key sharing)
    signal input in_path_elements[D];
    signal input in_path_indices[D];
    // frozen non-membership of the spent commitment (invariant #14)
    signal input frozen_low_value;
    signal input frozen_low_next_index;
    signal input frozen_low_next_value;
    signal input frozen_path_elements[D];
    signal input frozen_path_indices[D];
    // output note (same asset as input; recipient = out_owner_pk)
    signal input out_value;
    signal input out_owner_pk;
    signal input out_rho;
    signal input out_r_note;
    // assets-registry witness (this leg's asset)
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    signal input assets_path_elements[D];
    signal input assets_path_indices[D];
    // recipient compliance: KYC membership + sanctions non-membership
    signal input kyc_path_elements[D];
    signal input kyc_path_indices[D];
    signal input sanction_low_value;
    signal input sanction_low_next_index;
    signal input sanction_low_next_value;
    signal input sanction_path_elements[D];
    signal input sanction_path_indices[D];
    // encryption keying (invariant #5)
    signal input k_view;                    // auditor_pk = Poseidon(k_view)
    signal input k_pair;                    // sender<->recipient pairwise secret
    signal input rho_enc_auditor;
    signal input rho_enc_recipient;

    // --- input note: range, opening+ownership+nullifier, inclusion, frozen NM ---
    component inRange = Num2Bits(64);
    inRange.in <== in_value;

    component spent = SpentNote();
    spent.asset_id <== in_asset_id;
    spent.value    <== in_value;
    spent.owner_pk <== in_owner_pk;
    spent.rho      <== in_rho;
    spent.r_note   <== in_r_note;
    spent.owner_sk <== owner_sk;
    nf <== spent.nf;

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

    // --- output note: range + commitment (same asset within the leg) ---
    component outRange = Num2Bits(64);
    outRange.in <== out_value;

    component outNote = OutputNote();
    outNote.asset_id <== in_asset_id;
    outNote.value    <== out_value;
    outNote.owner_pk <== out_owner_pk;
    outNote.rho      <== out_rho;
    outNote.r_note   <== out_r_note;
    cm_out <== outNote.cm;

    // --- per-asset conservation (NEVER summed across the other leg, #3) ---
    in_value === out_value + fee;

    // --- assets-registry membership + per-tx limit on the output value ---
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

    // --- recipient compliance: KYC membership + sanctions non-membership ---
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
}

// -----------------------------------------------------------------------------
// Dvp - two legs + one combined tree transition. Public-signal ORDER lives on
// `main` in circuits/dvp.circom (the normative one, docs/PUBLIC_IO.md).
// Private leg witness is indexed [0]=X, [1]=Y.
// -----------------------------------------------------------------------------
template Dvp(D, K_a, K_r) {
    // ---- public inputs (canonical order) ----
    signal input anchor_root;
    signal input kyc_root;
    signal input sanction_root;
    signal input assets_root;
    signal input frozen_root;
    signal input auditor_pk;
    signal input nf_legX_0;
    signal input nf_legY_0;
    signal input cm_out_X;
    signal input cm_out_Y;
    signal input new_root;
    signal input fee_X;
    signal input fee_Y;
    signal input next_index;                // current leaf count (pinned to state)
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor_X[K_a];
    signal input c_auditor_Y[K_a];
    signal input c_recipient_X[K_r];
    signal input c_recipient_Y[K_r];

    // ---- private witness, per leg [0]=X, [1]=Y ----
    signal input in_asset_id[2];
    signal input in_value[2];
    signal input in_owner_pk[2];
    signal input in_rho[2];
    signal input in_r_note[2];
    signal input owner_sk[2];
    signal input in_path_elements[2][D];
    signal input in_path_indices[2][D];
    signal input frozen_low_value[2];
    signal input frozen_low_next_index[2];
    signal input frozen_low_next_value[2];
    signal input frozen_path_elements[2][D];
    signal input frozen_path_indices[2][D];
    signal input out_value[2];
    signal input out_owner_pk[2];
    signal input out_rho[2];
    signal input out_r_note[2];
    signal input sac_address[2];
    signal input decimals[2];
    signal input per_tx_limit_raw[2];
    signal input assets_path_elements[2][D];
    signal input assets_path_indices[2][D];
    signal input kyc_path_elements[2][D];
    signal input kyc_path_indices[2][D];
    signal input sanction_low_value[2];
    signal input sanction_low_next_index[2];
    signal input sanction_low_next_value[2];
    signal input sanction_path_elements[2][D];
    signal input sanction_path_indices[2][D];
    signal input k_view;                    // single shared auditor key (both legs)
    signal input k_pair[2];
    signal input rho_enc_auditor[2];
    signal input rho_enc_recipient[2];

    // ---- two legs ----
    component leg[2];
    for (var L = 0; L < 2; L++) {
        leg[L] = DvpLeg(D, K_a, K_r);
        leg[L].anchor_root  <== anchor_root;
        leg[L].kyc_root      <== kyc_root;
        leg[L].sanction_root <== sanction_root;
        leg[L].assets_root   <== assets_root;
        leg[L].frozen_root   <== frozen_root;
        leg[L].auditor_pk    <== auditor_pk;
        leg[L].k_view        <== k_view;

        leg[L].in_asset_id <== in_asset_id[L];
        leg[L].in_value    <== in_value[L];
        leg[L].in_owner_pk <== in_owner_pk[L];
        leg[L].in_rho      <== in_rho[L];
        leg[L].in_r_note   <== in_r_note[L];
        leg[L].owner_sk    <== owner_sk[L];
        leg[L].frozen_low_value      <== frozen_low_value[L];
        leg[L].frozen_low_next_index <== frozen_low_next_index[L];
        leg[L].frozen_low_next_value <== frozen_low_next_value[L];
        leg[L].out_value    <== out_value[L];
        leg[L].out_owner_pk <== out_owner_pk[L];
        leg[L].out_rho      <== out_rho[L];
        leg[L].out_r_note   <== out_r_note[L];
        leg[L].sac_address     <== sac_address[L];
        leg[L].decimals        <== decimals[L];
        leg[L].per_tx_limit_raw <== per_tx_limit_raw[L];
        leg[L].sanction_low_value      <== sanction_low_value[L];
        leg[L].sanction_low_next_index <== sanction_low_next_index[L];
        leg[L].sanction_low_next_value <== sanction_low_next_value[L];
        leg[L].k_pair           <== k_pair[L];
        leg[L].rho_enc_auditor  <== rho_enc_auditor[L];
        leg[L].rho_enc_recipient <== rho_enc_recipient[L];
        for (var i = 0; i < D; i++) {
            leg[L].in_path_elements[i]      <== in_path_elements[L][i];
            leg[L].in_path_indices[i]       <== in_path_indices[L][i];
            leg[L].frozen_path_elements[i]  <== frozen_path_elements[L][i];
            leg[L].frozen_path_indices[i]   <== frozen_path_indices[L][i];
            leg[L].assets_path_elements[i]  <== assets_path_elements[L][i];
            leg[L].assets_path_indices[i]   <== assets_path_indices[L][i];
            leg[L].kyc_path_elements[i]     <== kyc_path_elements[L][i];
            leg[L].kyc_path_indices[i]      <== kyc_path_indices[L][i];
            leg[L].sanction_path_elements[i] <== sanction_path_elements[L][i];
            leg[L].sanction_path_indices[i]  <== sanction_path_indices[L][i];
        }
    }

    // per-leg public fee + ciphertexts (X = leg 0, Y = leg 1)
    leg[0].fee <== fee_X;
    leg[1].fee <== fee_Y;
    for (var i = 0; i < K_a; i++) {
        leg[0].c_auditor[i] <== c_auditor_X[i];
        leg[1].c_auditor[i] <== c_auditor_Y[i];
    }
    for (var i = 0; i < K_r; i++) {
        leg[0].c_recipient[i] <== c_recipient_X[i];
        leg[1].c_recipient[i] <== c_recipient_Y[i];
    }

    // bind nullifiers + output commitments to the public inputs
    nf_legX_0 === leg[0].nf;
    nf_legY_0 === leg[1].nf;
    cm_out_X  === leg[0].cm_out;
    cm_out_Y  === leg[1].cm_out;

    // ---- combined tree transition: insert [cm_out_X, cm_out_Y] (#12) ----
    component tt = FrontierTransition(D, 2);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_out_X;
    tt.leaves[1] <== cm_out_Y;
    // next_index is a PUBLIC INPUT the contract pins to state.leaf_count (#11/#12).
    tt.nextIndex <== next_index;
    for (var i = 0; i < D; i++) { new_frontier[i] === tt.new_frontier[i]; }
    new_root === tt.new_root;
}
