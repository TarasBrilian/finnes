// Depth-4 transfer harness for a lighter, runnable demo trusted setup
// (FIN-007/008). Same gadgets and public-IO STRUCTURE as the production
// `Transfer(20,5,5)` main - only the tree depth differs (4 vs 20), so the full
// witness -> setup -> prove -> verify pipeline is exercised end-to-end at a depth
// whose ~115k-constraint setup fits a 2^18 Powers-of-Tau (the D=20 production
// ceremony is identical but needs 2^20; see scripts/setup-ceremony.sh).
// Public signals: 13 + 2*D + 2*K_a + 2*K_r = 13 + 8 + 10 + 10 = 41.
pragma circom 2.1.6;
include "../../lib/transfer.circom";
component main { public [
    anchor_root, kyc_root, sanction_root, assets_root, frozen_root, auditor_pk,
    nf_in_0, nf_in_1, cm_out_0, cm_out_1, new_root, fee, next_index,
    old_frontier, new_frontier, c_auditor, c_recipient
] } = Transfer(4, 5, 5);
