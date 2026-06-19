pragma circom 2.1.6;

// =============================================================================
// lib/shield.circom - the Shield(D, K_a, K_r) template (FIN-012)
// =============================================================================
//
// Transparent -> shielded: 0 shielded inputs, 1 transparent input, 1 output note.
// The reusable template body, kept separate from the top-level
// `circuits/shield.circom` (which fixes the production parameters D=20, K_a=K_r=5
// and declares the public-signal `main`), so the SAME template can be instantiated
// at a small depth by the circuit-test harness
// (`circuits/test/shield/shield_test.circom`) without a second `main`. The
// normative public-signal ORDER lives on `main` in `circuits/shield.circom`
// (docs/PUBLIC_IO.md § shield.circom).
//
// Compile with `--prime bls12381` (compiler flag, not pragma). Without it the
// field is BN254 and every Poseidon-BLS hash is wrong (Security invariant #1).
//
// KEY CONSTRAINT (Security invariant #18): the output cm opens to the PUBLIC
// `(asset_id, amount)` WITHOUT revealing `(owner_pk, rho, r_note)` - never a full
// opening (that would de-anonymise the note at birth). The self-binding
// `asset_id == Poseidon(sac_address)` (via AssetsMembership) plus the assets-root
// membership prevents minting a note labelled as a different / more-valuable asset.
//
// RAW SAC UNITS only - no rescaling (Security invariant #16).
//
// All gadgets it composes are implemented and parity-tested (FIN-002/003/004/005):
// note commitment, Merkle inclusion, FrontierTransition, assets-registry
// membership + per-tx limit, and the mandatory auditor / optional recipient
// encryption well-formedness.
// =============================================================================

include "poseidon_bls.circom";
include "note.circom";
include "merkle.circom";
include "assets.circom";
include "enc_check.circom";
include "bits.circom"; // VENDORED Num2Bits (NO circomlib - invariant #1)

// D = commitment-tree depth (production D = 20, LOCKED FIN-001).
// K_a / K_r = packed ciphertext element counts (K_a = K_r = 5, LOCKED FIN-001).
template Shield(D, K_a, K_r) {
    // ---- public inputs (declared on `main` in the canonical order) ----------
    signal input asset_id;                 // public - the deposited SAC's id
    signal input amount;                   // public - deposited raw SAC units
    signal input kyc_root;                 // depositor/owner KYC membership
    signal input assets_root;
    signal input auditor_pk;               // = Poseidon(k_view); single field
    signal input cm_out_0;
    signal input new_root;
    signal input fee;                      // per-asset; 0 in demo
    signal input next_index;               // current leaf count (pinned to state)
    signal input old_frontier[D];
    signal input new_frontier[D];
    signal input c_auditor[K_a];           // MANDATORY auditor ct (invariant #5)
    signal input c_recipient[K_r];         // recipient ct (note discovery)

    // ---- private witness ----------------------------------------------------
    // output note opening (owner_pk/rho/r_note stay hidden; asset_id/amount public)
    signal input out_owner_pk;
    signal input out_rho;
    signal input out_r_note;
    // assets registry membership witness (single asset)
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    signal input assets_path_elements[D];
    signal input assets_path_indices[D];
    // depositor/owner KYC membership
    signal input kyc_path_elements[D];
    signal input kyc_path_indices[D];
    // auditor/recipient encryption keying (Security invariant #5; FIN-004)
    signal input k_view;                   // sender↔auditor shared key; auditor_pk = Poseidon(k_view)
    signal input k_pair;                   // sender↔recipient pairwise secret (OOB demo)
    signal input rho_enc_auditor;          // published nonce -> c_auditor[0]
    signal input rho_enc_recipient;        // published nonce -> c_recipient[0]

    // =========================================================================
    // 1. RANGE CHECK on the deposited amount (Security invariant #2).
    // =========================================================================
    component amtRange = Num2Bits(64);
    amtRange.in <== amount;

    // =========================================================================
    // 2. OUTPUT NOTE binds to the PUBLIC (asset_id, amount) (invariant #18).
    //    cm = Poseidon(asset_id, amount, owner_pk, rho, r_note); only
    //    owner_pk/rho/r_note are hidden. The minted note value IS the deposited
    //    `amount` (fee is reserved, 0 in demo - see note below).
    // =========================================================================
    component outNote = OutputNote();
    outNote.asset_id <== asset_id;
    outNote.value    <== amount;
    outNote.owner_pk <== out_owner_pk;
    outNote.rho      <== out_rho;
    outNote.r_note   <== out_r_note;
    cm_out_0 === outNote.cm;

    // No shielded inputs => no nullifiers, no anchor inclusion, no frozen/sanction
    // non-membership here (PUBLIC_IO.md lists only kyc_root + assets_root for
    // shield). The minted note value equals the publicly-deposited `amount`, so
    // conservation is trivial. `fee` is carried in the public-IO for forward
    // compatibility (0 in demo); if a non-zero relayer fee is ever charged on
    // shield, the minted value must equal `amount - fee` - add that constraint
    // then (and revisit invariant #18, which binds the note to the deposited
    // amount).

    // =========================================================================
    // 3. ASSETS REGISTRY membership + self-binding asset_id + per-tx limit.
    //    Self-binding `asset_id == Poseidon(sac_address)` + membership under
    //    `assets_root` is what prevents minting a note labelled as a
    //    different / more-valuable asset (invariant #18). value <= limit (#17).
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
    // 4. DEPOSITOR/OWNER KYC membership. The owner of the minted note must be
    //    KYC-approved to shield (invariant #6). No sanctions/frozen on shield-in.
    // =========================================================================
    component kycIncl = MerkleInclusion(D);
    kycIncl.leaf <== out_owner_pk;
    for (var i = 0; i < D; i++) {
        kycIncl.pathElements[i] <== kyc_path_elements[i];
        kycIncl.pathIndices[i]  <== kyc_path_indices[i];
    }
    kycIncl.root <== kyc_root;

    // =========================================================================
    // 5. MANDATORY auditor encryption (invariant #5) + optional recipient ct.
    //    Each binds THIS note's plaintext (the same signals fed into the
    //    commitment), so the ciphertext cannot disagree with the minted note;
    //    the auditor ct also re-binds auditor_pk == Poseidon(k_view).
    // =========================================================================
    component auditEnc = AuditorEncCheck();
    auditEnc.auditor_pk <== auditor_pk;
    for (var i = 0; i < K_a; i++) { auditEnc.c_auditor[i] <== c_auditor[i]; }
    auditEnc.value    <== amount;
    auditEnc.asset_id <== asset_id;
    auditEnc.owner_pk <== out_owner_pk;
    auditEnc.rho      <== out_rho;
    auditEnc.k_view   <== k_view;
    auditEnc.rho_enc  <== rho_enc_auditor;

    component recipEnc = RecipientEncCheck();
    for (var i = 0; i < K_r; i++) { recipEnc.c_recipient[i] <== c_recipient[i]; }
    recipEnc.value    <== amount;
    recipEnc.asset_id <== asset_id;
    recipEnc.rho      <== out_rho;
    recipEnc.r_note   <== out_r_note;
    recipEnc.k_pair   <== k_pair;
    recipEnc.rho_enc  <== rho_enc_recipient;

    // =========================================================================
    // 6. TREE TRANSITION: insert cm_out_0 (Security invariant #12).
    //    `next_index` is a PUBLIC INPUT the contract supplies from its stored
    //    leaf count (pi.next_index == state.leaf_count), so the single insert
    //    lands at the true append position; old_frontier == state pins the tree
    //    shape. Without this a prover could compute a self-consistent transition
    //    for a wrong index and corrupt the verbatim-stored tree (#11/#12).
    //    FrontierTransition range-bounds next_index via Num2Bits(D).
    // =========================================================================
    component tt = FrontierTransition(D, 1);
    for (var i = 0; i < D; i++) { tt.old_frontier[i] <== old_frontier[i]; }
    tt.leaves[0] <== cm_out_0;
    tt.nextIndex <== next_index;
    for (var i = 0; i < D; i++) { new_frontier[i] === tt.new_frontier[i]; }
    new_root === tt.new_root;
}
