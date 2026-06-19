pragma circom 2.1.6;

// =============================================================================
// transfer.circom - confidential transfer, 2-in / 2-out, single asset
// =============================================================================
//
// FIN-006 SCAFFOLD. Template composition & public-signal ordering are concrete
// and normative, and all lib gadgets it calls (Poseidon, note, Merkle/IMT,
// frontier transition, assets, enc-check) are now IMPLEMENTED and parity-tested
// (FIN-002/003/004/005). What remains for FIN-006 is the final wiring, NOT new
// crypto: (a) the second output note's mandatory c_auditor/c_recipient (the
// PUBLIC_IO layout carries 2·K_a + 2·K_r - only output 0 is bound below);
// (b) `nextIndex` as a constrained witness pinned to the contract's leaf count
// (FrontierTransition placeholder below); (c) binding `kyc_leaf` to the real
// recipient. Each is marked TODO(FIN-006). The depth/packing constants and all
// gadget interfaces are de-drifted to the libs (D=20, K_a=K_r=5).
//
// COMPILE WITH:  circom transfer.circom --prime bls12381 --r1cs --wasm --sym
//   `--prime bls12381` is a COMPILER FLAG, not a pragma. Without it the field is
//   BN254 and every Poseidon-BLS hash is wrong (Security invariant #1).
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER - COPIED VERBATIM FROM docs/PUBLIC_IO.md
// (THE canonical ordering. Must match contracts/finnes/src/types.rs
//  PublicInputs::to_vec(), prover/src/witness.ts, and sdk/src/.)
// -----------------------------------------------------------------------------
//  0  anchor_root
//  1  kyc_root
//  2  sanction_root
//  3  assets_root
//  4  frozen_root
//  5  auditor_pk          (= Poseidon(k_view); single field, LOCKED FIN-001)
//  6  nf_in_0
//  7  nf_in_1
//  8  cm_out_0
//  9  cm_out_1
// 10  new_root
// 11  fee                 (per-asset; 0 in demo)
// 12 .. 12+D-1            old_frontier[0..D-1]    (D = 20)
//    .. +D                new_frontier[0..D-1]
//    .. +K_a              c_auditor   (K_a = 5 packed field elements)
//    .. +K_r              c_recipient (K_r = 5 packed field elements)
// -----------------------------------------------------------------------------

include "lib/poseidon_bls.circom";
include "lib/note.circom";
include "lib/merkle.circom";
include "lib/assets.circom";
include "lib/enc_check.circom";
include "lib/bits.circom"; // VENDORED Num2Bits (NO circomlib - invariant #1)

// D = commitment-tree depth (D = 20, LOCKED FIN-001).
// K_a / K_r = packed ciphertext element counts (K_a = K_r = 5, LOCKED FIN-001).
template Transfer(D, K_a, K_r) {
    // ---- public inputs (declared on `main` in the order above) --------------
    signal input anchor_root;
    signal input kyc_root;
    signal input sanction_root;
    signal input assets_root;
    signal input frozen_root;
    signal input auditor_pk;
    signal input nf_in_0;
    signal input nf_in_1;
    signal input cm_out_0;
    signal input cm_out_1;
    signal input new_root;
    signal input fee;
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor[K_a];
    signal input c_recipient[K_r];

    // ---- private witness ----------------------------------------------------
    // input notes (asset_id, value, owner_pk, rho, r_note) x2
    signal input in_asset_id[2];
    signal input in_value[2];
    signal input in_owner_pk[2];
    signal input in_rho[2];
    signal input in_r_note[2];
    signal input owner_sk;                 // single spender owns both inputs
    // inclusion paths for the two input commitments (anchor tree)
    signal input in_path_elements[2][D];
    signal input in_path_indices[2][D];
    // output notes x2
    signal input out_asset_id[2];
    signal input out_value[2];
    signal input out_owner_pk[2];
    signal input out_rho[2];
    signal input out_r_note[2];
    // KYC membership (recipient) - demo: one recipient pk
    signal input kyc_path_elements[D];
    signal input kyc_path_indices[D];
    signal input kyc_leaf;                 // the recipient pk being proved KYC'd
    // sanctions non-membership (recipient) - IMT low-leaf witness
    signal input sanction_low_value;
    signal input sanction_low_next_index;
    signal input sanction_low_next_value;
    signal input sanction_path_elements[D];
    signal input sanction_path_indices[D];
    // frozen non-membership of EACH spent commitment (Security invariant #14)
    signal input frozen_low_value[2];
    signal input frozen_low_next_index[2];
    signal input frozen_low_next_value[2];
    signal input frozen_path_elements[2][D];
    signal input frozen_path_indices[2][D];
    // assets registry membership witness (single asset)
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    signal input assets_path_elements[D];
    signal input assets_path_indices[D];
    // auditor/recipient encryption keying (Security invariant #5; FIN-004)
    signal input k_view;                   // sender↔auditor shared key; auditor_pk = Poseidon(k_view)
    signal input k_pair;                   // sender↔recipient pairwise secret (OOB demo)
    signal input rho_enc_auditor;          // published nonce -> c_auditor[0]
    signal input rho_enc_recipient;        // published nonce -> c_recipient[0]

    // =========================================================================
    // 1. INPUT NOTES: opening, ownership, nullifier, inclusion, range, frozen
    // =========================================================================
    component spent[2];
    component inRange[2];
    component inIncl[2];
    component frozenNM[2];

    for (var k = 0; k < 2; k++) {
        // 64-bit range check on every input value (Security invariant #2)
        inRange[k] = Num2Bits(64);
        inRange[k].in <== in_value[k];

        spent[k] = SpentNote();
        spent[k].asset_id <== in_asset_id[k];
        spent[k].value    <== in_value[k];
        spent[k].owner_pk <== in_owner_pk[k];
        spent[k].rho      <== in_rho[k];
        spent[k].r_note   <== in_r_note[k];
        spent[k].owner_sk <== owner_sk;

        // inclusion under anchor_root
        inIncl[k] = MerkleInclusion(D);
        inIncl[k].leaf <== spent[k].cm;
        for (var i = 0; i < D; i++) {
            inIncl[k].pathElements[i] <== in_path_elements[k][i];
            inIncl[k].pathIndices[i]  <== in_path_indices[k][i];
        }
        inIncl[k].root <== anchor_root;

        // frozen-set non-membership of the spent commitment
        frozenNM[k] = MerkleNonMembership(D);
        frozenNM[k].target <== spent[k].cm;
        frozenNM[k].low_value      <== frozen_low_value[k];
        frozenNM[k].low_next_index <== frozen_low_next_index[k];
        frozenNM[k].low_next_value <== frozen_low_next_value[k];
        for (var i = 0; i < D; i++) {
            frozenNM[k].pathElements[i] <== frozen_path_elements[k][i];
            frozenNM[k].pathIndices[i]  <== frozen_path_indices[k][i];
        }
        frozenNM[k].root <== frozen_root;
    }

    // bind nullifiers to public inputs
    nf_in_0 === spent[0].nf;
    nf_in_1 === spent[1].nf;

    // =========================================================================
    // 2. OUTPUT NOTES: range check + commitment, bind to public cm_out_*
    // =========================================================================
    component outNote[2];
    component outRange[2];
    for (var k = 0; k < 2; k++) {
        outRange[k] = Num2Bits(64);
        outRange[k].in <== out_value[k];

        outNote[k] = OutputNote();
        outNote[k].asset_id <== out_asset_id[k];
        outNote[k].value    <== out_value[k];
        outNote[k].owner_pk <== out_owner_pk[k];
        outNote[k].rho      <== out_rho[k];
        outNote[k].r_note   <== out_r_note[k];
    }
    cm_out_0 === outNote[0].cm;
    cm_out_1 === outNote[1].cm;

    // =========================================================================
    // 3. SINGLE-ASSET binding + per-asset CONSERVATION (Security invariant #3)
    //    Σ inputs == Σ outputs + fee, NEVER summed across asset_id.
    // =========================================================================
    // all four notes share one asset_id
    in_asset_id[0] === in_asset_id[1];
    out_asset_id[0] === in_asset_id[0];
    out_asset_id[1] === in_asset_id[0];

    // conservation (values are 64-bit ranged so no field wraparound)
    in_value[0] + in_value[1] === out_value[0] + out_value[1] + fee;

    // =========================================================================
    // 4. ASSETS REGISTRY membership + per-tx limit (value <= per_tx_limit_raw)
    //    Checked per output value against the shared asset's limit.
    // =========================================================================
    component assetsOut[2];
    for (var k = 0; k < 2; k++) {
        assetsOut[k] = AssetsMembership(D);
        assetsOut[k].asset_id        <== in_asset_id[0];
        assetsOut[k].value           <== out_value[k];
        assetsOut[k].sac_address     <== sac_address;
        assetsOut[k].decimals        <== decimals;
        assetsOut[k].per_tx_limit_raw <== per_tx_limit_raw;
        for (var i = 0; i < D; i++) {
            assetsOut[k].pathElements[i] <== assets_path_elements[i];
            assetsOut[k].pathIndices[i]  <== assets_path_indices[i];
        }
        assetsOut[k].assets_root <== assets_root;
    }

    // =========================================================================
    // 5. RECIPIENT COMPLIANCE: KYC membership + sanctions non-membership
    //    (demo: recipient pk == out_owner_pk[0]; KYC privacy deferred.)
    // =========================================================================
    // TODO: bind kyc_leaf to the actual recipient pk(s). Demo enrolls all demo
    //       accounts; here we constrain the proven KYC leaf == output 0 owner.
    kyc_leaf === out_owner_pk[0];

    component kycIncl = MerkleInclusion(D);
    kycIncl.leaf <== kyc_leaf;
    for (var i = 0; i < D; i++) {
        kycIncl.pathElements[i] <== kyc_path_elements[i];
        kycIncl.pathIndices[i]  <== kyc_path_indices[i];
    }
    kycIncl.root <== kyc_root;

    component sanctionNM = MerkleNonMembership(D);
    sanctionNM.target <== kyc_leaf;
    sanctionNM.low_value      <== sanction_low_value;
    sanctionNM.low_next_index <== sanction_low_next_index;
    sanctionNM.low_next_value <== sanction_low_next_value;
    for (var i = 0; i < D; i++) {
        sanctionNM.pathElements[i] <== sanction_path_elements[i];
        sanctionNM.pathIndices[i]  <== sanction_path_indices[i];
    }
    sanctionNM.root <== sanction_root;

    // =========================================================================
    // 6. AUDITOR ENCRYPTION (mandatory) + recipient ciphertext (optional)
    //    Bound to public c_auditor / c_recipient. (Security invariant #5)
    //    Demo binds output note 0 (the recipient's note) to both ciphertexts.
    // =========================================================================
    component auditEnc = AuditorEncCheck();
    auditEnc.auditor_pk <== auditor_pk;
    for (var i = 0; i < K_a; i++) { auditEnc.c_auditor[i] <== c_auditor[i]; }
    auditEnc.value    <== out_value[0];
    auditEnc.asset_id <== out_asset_id[0];
    auditEnc.owner_pk <== out_owner_pk[0];
    auditEnc.rho      <== out_rho[0];
    auditEnc.k_view   <== k_view;
    auditEnc.rho_enc  <== rho_enc_auditor;

    component recipEnc = RecipientEncCheck();
    for (var i = 0; i < K_r; i++) { recipEnc.c_recipient[i] <== c_recipient[i]; }
    recipEnc.value    <== out_value[0];
    recipEnc.asset_id <== out_asset_id[0];
    recipEnc.rho      <== out_rho[0];
    recipEnc.r_note   <== out_r_note[0];
    recipEnc.k_pair   <== k_pair;
    recipEnc.rho_enc  <== rho_enc_recipient;
    // TODO(FIN-006): bind the SECOND output note (change) to its own mandatory
    //       c_auditor + c_recipient - PUBLIC_IO carries 2·K_a + 2·K_r (72 signals
    //       total). Only output 0 is bound here; wiring out-note-1 + expanding the
    //       c_auditor/c_recipient signal arrays to [2][5] is the remaining work.

    // =========================================================================
    // 7. TREE TRANSITION: old_frontier -> (new_frontier, new_root)
    //    (Security invariant #12) - contract stores outputs verbatim.
    // =========================================================================
    component tt = FrontierTransition(D, 2);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_out_0;
    tt.leaves[1] <== cm_out_1;
    // TODO: nextIndex must be a constrained witness equal to the contract's
    //       current leaf count (the contract checks old_frontier == state, which
    //       pins the index). Supply via witness; here we leave it as an input of
    //       the gadget - wire a dedicated signal in the real implementation.
    tt.nextIndex <== 0; // PLACEHOLDER - wire real append index witness.

    for (var i = 0; i < D; i++) { new_frontier[i] === tt.new_frontier[i]; }
    new_root === tt.new_root;
}

// -----------------------------------------------------------------------------
// main - public signal order MUST match docs/PUBLIC_IO.md (see header).
// D=20, K_a=K_r=5 (LOCKED FIN-001). Changing D / K_a / K_r requires a fresh
// phase-2 ceremony + new VK.
// -----------------------------------------------------------------------------
component main { public [
    anchor_root,
    kyc_root,
    sanction_root,
    assets_root,
    frozen_root,
    auditor_pk,
    nf_in_0,
    nf_in_1,
    cm_out_0,
    cm_out_1,
    new_root,
    fee,
    old_frontier,
    new_frontier,
    c_auditor,
    c_recipient
] } = Transfer(20, 5, 5);
