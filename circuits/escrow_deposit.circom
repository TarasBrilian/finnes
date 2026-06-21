pragma circom 2.1.6;
// escrow_deposit.circom (FIN-017) — spend a MAIN-tree note -> mint an ESCROW note
// owned by the intent. CHECK_RECIPIENT=0 (the intent is not a KYC'd party).
// Compile: circom escrow_deposit.circom --prime bls12381. See docs/DVP_ESCROW.md.
include "lib/escrow_leg.circom";
component main { public [
    anchor_root, kyc_root, sanction_root, assets_root, frozen_root, auditor_pk,
    nf_in_0, cm_out_0, new_root, fee, next_index,
    old_frontier, new_frontier, c_auditor, c_recipient
] } = EscrowLeg(20, 5, 5, 0);
