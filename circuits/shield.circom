pragma circom 2.1.6;

// =============================================================================
// shield.circom - transparent -> shielded (0 shielded inputs, 1 transparent in)
// =============================================================================
//
// SCAFFOLD. Composition & public-signal ordering are concrete and normative;
// crypto bodies delegate to TODO-stub lib gadgets. Does NOT yet compile to a
// sound relation.
//
// COMPILE WITH:  circom shield.circom --prime bls12381 --r1cs --wasm --sym
//   (`--prime bls12381` is a COMPILER flag, not a pragma.)
//
// -----------------------------------------------------------------------------
// PUBLIC INPUT ORDER - COPIED VERBATIM FROM docs/PUBLIC_IO.md
// -----------------------------------------------------------------------------
//  0  asset_id            (public - derived from deposited SAC; circuit proves = Poseidon(sac_address))
//  1  amount              (public - deposited raw SAC units)
//  2  kyc_root            (depositor/owner KYC membership)
//  3  assets_root
//  4  auditor_pk          (TODO)
//  5  cm_out_0
//  6  new_root
//  7  fee                 (0 in demo)
//  8 .. 8+D-1             old_frontier[0..D-1]
//    .. +D                new_frontier[0..D-1]
//    .. +K_a              c_auditor
//    .. +K_r              c_recipient
// -----------------------------------------------------------------------------
//
// KEY CONSTRAINT (Security invariant #18): the output cm opens to the PUBLIC
// (asset_id, amount) WITHOUT revealing (owner_pk, rho, r_note). Never a full
// opening - that would de-anonymize the note at birth and a depositor could
// otherwise mint a note labelled as a different/more-valuable asset.
//
// RAW SAC UNITS only - no rescaling (Security invariant #16).
// =============================================================================

include "lib/poseidon_bls.circom";
include "lib/note.circom";
include "lib/merkle.circom";
include "lib/assets.circom";
include "lib/enc_check.circom";
include "node_modules/circomlib/circuits/bitify.circom"; // Num2Bits

template Shield(D, K_a, K_r) {
    // ---- public inputs ------------------------------------------------------
    signal input asset_id;
    signal input amount;
    signal input kyc_root;
    signal input assets_root;
    signal input auditor_pk;
    signal input cm_out_0;
    signal input new_root;
    signal input fee;
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor[K_a];
    signal input c_recipient[K_r];

    // ---- private witness ----------------------------------------------------
    // output note opening (owner_pk/rho/r_note stay hidden; asset_id/amount public)
    signal input out_owner_pk;
    signal input out_rho;
    signal input out_r_note;
    // assets registry membership witness
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    signal input assets_path_elements[D];
    signal input assets_path_indices[D];
    // depositor/owner KYC membership
    signal input kyc_path_elements[D];
    signal input kyc_path_indices[D];
    // encryption randomness
    signal input enc_rand_auditor;
    signal input enc_rand_recipient;
    // append index witness for the tree transition
    signal input nextIndex;

    // =========================================================================
    // 1. RANGE CHECK on the deposited amount (Security invariant #2)
    // =========================================================================
    component amtRange = Num2Bits(64);
    amtRange.in <== amount;

    // =========================================================================
    // 2. OUTPUT NOTE binds to PUBLIC (asset_id, amount) - invariant #18.
    //    cm = Poseidon(asset_id, amount, owner_pk, rho, r_note); only owner/rho/r
    //    are hidden.
    // =========================================================================
    component outNote = OutputNote();
    outNote.asset_id <== asset_id;
    outNote.value    <== amount;
    outNote.owner_pk <== out_owner_pk;
    outNote.rho      <== out_rho;
    outNote.r_note   <== out_r_note;
    cm_out_0 === outNote.cm;

    // (no shielded inputs => no nullifiers, no frozen non-membership here;
    //  no value enters from the shielded side, so conservation is trivially the
    //  deposited amount = the minted note value, already enforced by reusing
    //  `amount` as the note value above. fee is reserved (0 in demo).)
    // TODO: if a non-zero relayer fee is ever charged on shield, the minted note
    //       value must equal amount - fee; add that constraint then.

    // =========================================================================
    // 3. ASSETS REGISTRY membership + self-binding asset_id + per-tx limit
    //    Prevents minting a note labelled as a different/more-valuable asset.
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
    // 4. DEPOSITOR/OWNER KYC membership (no sanctions/frozen on shield-in;
    //    PUBLIC_IO.md lists only kyc_root for shield).
    // =========================================================================
    component kycIncl = MerkleInclusion(D);
    kycIncl.leaf <== out_owner_pk;   // owner must be KYC-approved to shield
    for (var i = 0; i < D; i++) {
        kycIncl.pathElements[i] <== kyc_path_elements[i];
        kycIncl.pathIndices[i]  <== kyc_path_indices[i];
    }
    kycIncl.root <== kyc_root;

    // =========================================================================
    // 5. MANDATORY auditor encryption + optional recipient ciphertext.
    // =========================================================================
    component auditEnc = AuditorEncCheck(K_a);
    auditEnc.auditor_pk <== auditor_pk;
    for (var i = 0; i < K_a; i++) { auditEnc.c_auditor[i] <== c_auditor[i]; }
    auditEnc.asset_id <== asset_id;
    auditEnc.value    <== amount;
    auditEnc.owner_pk <== out_owner_pk;
    auditEnc.rho      <== out_rho;
    auditEnc.enc_rand <== enc_rand_auditor;

    component recipEnc = RecipientEncCheck(K_r);
    recipEnc.recipient_pk <== out_owner_pk;
    for (var i = 0; i < K_r; i++) { recipEnc.c_recipient[i] <== c_recipient[i]; }
    recipEnc.asset_id <== asset_id;
    recipEnc.value    <== amount;
    recipEnc.owner_pk <== out_owner_pk;
    recipEnc.rho      <== out_rho;
    recipEnc.enc_rand <== enc_rand_recipient;

    // =========================================================================
    // 6. TREE TRANSITION: insert cm_out_0.
    // =========================================================================
    component tt = FrontierTransition(D, 1);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_out_0;
    tt.nextIndex <== nextIndex;
    for (var i = 0; i < D; i++) { new_frontier[i] === tt.new_frontier[i]; }
    new_root === tt.new_root;
}

// -----------------------------------------------------------------------------
// main - order MUST match docs/PUBLIC_IO.md. D=32; K_a/K_r TODO placeholders (4).
// -----------------------------------------------------------------------------
component main { public [
    asset_id,
    amount,
    kyc_root,
    assets_root,
    auditor_pk,
    cm_out_0,
    new_root,
    fee,
    old_frontier,
    new_frontier,
    c_auditor,
    c_recipient
] } = Shield(32, 4, 4);
