pragma circom 2.1.6;

// =============================================================================
// lib/unshield.circom - the Unshield(D, K_a, K_r) template (FIN-013)
// =============================================================================
//
// Shielded -> transparent: 1 shielded input, a transparent payout, and an
// OPTIONAL change note back to the sender. The reusable template body, kept
// separate from the top-level `circuits/unshield.circom` (which fixes D=20,
// K_a=K_r=5 and declares the public-signal `main`), so the same template can be
// instantiated at a small depth by the circuit-test harness
// (`circuits/test/unshield/unshield_test.circom`). Public-signal ORDER lives on
// `main` (docs/PUBLIC_IO.md § unshield.circom).
//
// Compile with `--prime bls12381` (compiler flag, not pragma). Without it the
// field is BN254 and every Poseidon-BLS hash is wrong (Security invariant #1).
//
// MUST ENFORCE (Security invariant #19 - the top compliance checkpoint, value
// leaving the shielded domain):
//   (a) the transparent `recipient` is KYC-approved AND non-sanctioned, and
//   (b) FROZEN-SET NON-MEMBERSHIP of the spent commitment (escape-hatch closure).
// Plus the usual input inclusion + nullifier, per-asset conservation
// `in_value == amount + change + fee`, 64-bit ranges, assets membership + per-tx
// limit, and the tree transition.
//
// CHANGE-NOTE SENTINEL (LOCKED, docs/PUBLIC_IO.md): `cm_change_0 == 0` means "no
// change". The change-note commitment and BOTH change ciphertexts are gated on
// `has_change = (cm_change_0 != 0)`; when there is no change, `amount == in_value`
// and `c_auditor`/`c_recipient` are all-zero. `0` is a safe sentinel because a
// real Poseidon commitment is never 0. The frontier transition then inserts the
// gated `cm_change_0`: when it is 0 the insert at `next_index` reproduces the
// CURRENT tree root (an empty leaf folds as `zeros[0]`), so `new_root` is correct
// for both the change and no-change cases; `new_frontier` is MUX'd back to
// `old_frontier` when there is no change (no filled subtree advances).
//
// RAW SAC UNITS only - no rescaling (Security invariant #16).
// =============================================================================

include "poseidon_bls.circom";
include "note.circom";
include "merkle.circom";
include "assets.circom";
include "bits.circom"; // VENDORED Num2Bits (NO circomlib - invariant #1)

// D = commitment-tree depth (production D = 20, LOCKED FIN-001).
// K_a / K_r = packed ciphertext element counts (K_a = K_r = 5, LOCKED FIN-001).
// The single output is the (optional) change note back to the sender.
template Unshield(D, K_a, K_r) {
    // ---- public inputs (declared on `main` in the canonical order) ----------
    signal input anchor_root;
    signal input kyc_root;                 // transparent recipient compliance
    signal input sanction_root;
    signal input assets_root;
    signal input frozen_root;
    signal input auditor_pk;               // = Poseidon(k_view); single field
    signal input nf_in_0;
    signal input asset_id;                 // public - for the SAC transfer
    signal input amount;                   // public - raw SAC units leaving
    signal input recipient;                // public - transparent Stellar address (field)
    signal input cm_change_0;              // change note (0 SENTINEL = no change)
    signal input new_root;
    signal input fee;
    signal input next_index;               // current leaf count (pinned to state)
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor[K_a];           // change-note auditor ct (all-zero if no change)
    signal input c_recipient[K_r];         // change-note recipient ct (all-zero if no change)

    // ---- private witness ----------------------------------------------------
    // single spent input note
    signal input in_asset_id;
    signal input in_value;
    signal input in_owner_pk;
    signal input in_rho;
    signal input in_r_note;
    signal input owner_sk;
    signal input in_path_elements[D];
    signal input in_path_indices[D];
    // frozen-set non-membership of the spent commitment (invariant #19b)
    signal input frozen_low_value;
    signal input frozen_low_next_index;
    signal input frozen_low_next_value;
    signal input frozen_path_elements[D];
    signal input frozen_path_indices[D];
    // transparent recipient compliance (KYC membership + sanctions non-membership)
    signal input kyc_path_elements[D];
    signal input kyc_path_indices[D];
    signal input sanction_low_value;
    signal input sanction_low_next_index;
    signal input sanction_low_next_value;
    signal input sanction_path_elements[D];
    signal input sanction_path_indices[D];
    // change-note opening (owner = spender) + the has_change selector
    signal input change_owner_pk;
    signal input change_value;
    signal input change_rho;
    signal input change_r_note;
    signal input has_change;               // boolean: 1 iff a change note exists
    // assets registry membership witness
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    signal input assets_path_elements[D];
    signal input assets_path_indices[D];
    // encryption keying for the change note (FIN-004 scheme)
    signal input k_view;                   // auditor_pk = Poseidon(k_view)
    signal input k_pair;                   // sender↔self pairwise secret (OOB demo)
    signal input rho_enc_auditor;          // published nonce -> c_auditor[0]
    signal input rho_enc_recipient;        // published nonce -> c_recipient[0]

    // =========================================================================
    // 1. SPENT INPUT: range, opening, ownership, nullifier, inclusion, frozen NM.
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

    // FROZEN non-membership of the spent commitment - fund-critical (#19b).
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

    // =========================================================================
    // 2. PUBLIC asset binding + CONSERVATION: in_value == amount + change + fee.
    // =========================================================================
    in_asset_id === asset_id;              // spent note's asset == revealed asset_id

    component amtRange = Num2Bits(64);
    amtRange.in <== amount;

    has_change * (has_change - 1) === 0;   // boolean

    component changeRange = Num2Bits(64);
    changeRange.in <== change_value;

    in_value === amount + change_value + fee;
    // no hidden value when there is no change note
    (1 - has_change) * change_value === 0;

    // =========================================================================
    // 3. OPTIONAL CHANGE NOTE commitment, gated to the public cm_change_0.
    //    cm_change_0 == has_change ? Poseidon(asset_id, change_value, ...) : 0.
    // =========================================================================
    component changeNote = OutputNote();
    changeNote.asset_id <== asset_id;      // change stays the same asset
    changeNote.value    <== change_value;
    changeNote.owner_pk <== change_owner_pk;
    changeNote.rho      <== change_rho;
    changeNote.r_note   <== change_r_note;
    cm_change_0 === has_change * changeNote.cm;

    // =========================================================================
    // 4. ASSETS REGISTRY membership + per-tx limit (on the amount leaving).
    // =========================================================================
    component assets = AssetsMembership(D);
    assets.asset_id         <== asset_id;
    assets.value            <== amount;
    assets.sac_address      <== sac_address;
    assets.decimals         <== decimals;
    assets.per_tx_limit_raw <== per_tx_limit_raw;
    for (var i = 0; i < D; i++) {
        assets.pathElements[i] <== assets_path_elements[i];
        assets.pathIndices[i]  <== assets_path_indices[i];
    }
    assets.assets_root <== assets_root;

    // =========================================================================
    // 5. TRANSPARENT RECIPIENT compliance (invariant #19a): the public recipient
    //    field IS the KYC-enrolled identity - prove kyc-membership AND
    //    sanctions-non-membership of `recipient` directly (demo enrollment keys
    //    KYC/sanctions sets by the recipient's address-field).
    // =========================================================================
    component kycIncl = MerkleInclusion(D);
    kycIncl.leaf <== recipient;
    for (var i = 0; i < D; i++) {
        kycIncl.pathElements[i] <== kyc_path_elements[i];
        kycIncl.pathIndices[i]  <== kyc_path_indices[i];
    }
    kycIncl.root <== kyc_root;

    component sanctionNM = MerkleNonMembership(D);
    sanctionNM.target <== recipient;
    sanctionNM.low_value      <== sanction_low_value;
    sanctionNM.low_next_index <== sanction_low_next_index;
    sanctionNM.low_next_value <== sanction_low_next_value;
    for (var i = 0; i < D; i++) {
        sanctionNM.pathElements[i] <== sanction_path_elements[i];
        sanctionNM.pathIndices[i]  <== sanction_path_indices[i];
    }
    sanctionNM.root <== sanction_root;

    // =========================================================================
    // 6. CHANGE-NOTE encryption (gated on has_change). The transparent leg is
    //    already public; the change note must still be auditor-decryptable
    //    (invariant #5) and sender-discoverable. Mirrors enc_check.circom EXACTLY
    //    (additive Poseidon keystream), but every published slot is multiplied by
    //    has_change so a no-change note publishes all-zero ciphertexts.
    //
    //    auditor plaintext   = [change_value, asset_id, change_owner_pk, change_rho]
    //    recipient plaintext = [change_value, asset_id, change_rho, change_r_note]
    // =========================================================================
    // (a) bind the auditor key (always): auditor_pk == Poseidon(k_view).
    component pk = PoseidonBLS(1);
    pk.in[0] <== k_view;
    auditor_pk === pk.out;

    // (b) auditor keystream + gated ciphertext slots.
    component shA = PoseidonBLS(2);
    shA.in[0] <== k_view;
    shA.in[1] <== rho_enc_auditor;
    signal ptA[4];
    ptA[0] <== change_value;
    ptA[1] <== asset_id;
    ptA[2] <== change_owner_pk;
    ptA[3] <== change_rho;
    c_auditor[0] === has_change * rho_enc_auditor;
    component ksA[4];
    signal tmpA[4];
    for (var i = 0; i < 4; i++) {
        ksA[i] = PoseidonBLS(2);
        ksA[i].in[0] <== shA.out;
        ksA[i].in[1] <== i + 1;
        tmpA[i] <== ptA[i] + ksA[i].out;
        c_auditor[i + 1] === has_change * tmpA[i];
    }

    // (c) recipient keystream + gated ciphertext slots (no key binding; OOB key).
    component shR = PoseidonBLS(2);
    shR.in[0] <== k_pair;
    shR.in[1] <== rho_enc_recipient;
    signal ptR[4];
    ptR[0] <== change_value;
    ptR[1] <== asset_id;
    ptR[2] <== change_rho;
    ptR[3] <== change_r_note;
    c_recipient[0] === has_change * rho_enc_recipient;
    component ksR[4];
    signal tmpR[4];
    for (var i = 0; i < 4; i++) {
        ksR[i] = PoseidonBLS(2);
        ksR[i].in[0] <== shR.out;
        ksR[i].in[1] <== i + 1;
        tmpR[i] <== ptR[i] + ksR[i].out;
        c_recipient[i + 1] === has_change * tmpR[i];
    }

    // =========================================================================
    // 7. TREE TRANSITION (Security invariants #11/#12). Insert the gated
    //    cm_change_0 at `next_index` (a PUBLIC INPUT pinned to the contract leaf
    //    count). When cm_change_0 == 0 (no change) the insert reproduces the
    //    CURRENT root (an empty leaf folds as zeros), so `new_root` is correct in
    //    both cases; `new_frontier` is MUX'd back to `old_frontier` when there is
    //    no change (no filled subtree advances). The contract advances leaf_count
    //    by 0 or 1 from the same cm_change_0 == 0 test.
    // =========================================================================
    component tt = FrontierTransition(D, 1);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_change_0;
    tt.nextIndex <== next_index;
    new_root === tt.new_root;
    for (var i = 0; i < D; i++) {
        // new_frontier[i] = has_change ? tt.new_frontier[i] : old_frontier[i]
        new_frontier[i] === old_frontier[i] + has_change * (tt.new_frontier[i] - old_frontier[i]);
    }
}
