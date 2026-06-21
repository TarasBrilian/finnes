pragma circom 2.1.6;
// escrow_refund.circom (FIN-017) — after the deadline, spend an ESCROW note
// (owner = sk_intent) -> mint a MAIN-tree note to the depositor's refund_pk.
// CHECK_RECIPIENT=1 (the depositor is a real KYC'd party).
// Compile: circom escrow_refund.circom --prime bls12381. See docs/DVP_ESCROW.md.
include "lib/escrow_leg.circom";
component main { public [
    anchor_root, kyc_root, sanction_root, assets_root, frozen_root, auditor_pk,
    nf_in_0, cm_out_0, new_root, fee, next_index,
    old_frontier, new_frontier, c_auditor, c_recipient
] } = EscrowLeg(20, 5, 5, 1);
