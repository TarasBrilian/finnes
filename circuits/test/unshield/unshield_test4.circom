// Depth-4 unshield harness for a lighter, runnable demo trusted setup (FIN-013,
// mirrors shield_test4 / transfer_test4). Same gadgets and public-IO STRUCTURE as
// the production `Unshield(20,5,5)` main - only the tree depth differs (4 vs 20),
// so the full witness -> setup -> prove -> verify pipeline is exercised end-to-end
// at a depth whose setup fits a small Powers-of-Tau (the D=20 production ceremony
// is identical; setup-ceremony.sh already iterates `unshield`).
// Public signals: 14 + 2*D + K_a + K_r = 14 + 8 + 5 + 5 = 32.
pragma circom 2.1.6;
include "../../lib/unshield.circom";
component main { public [
    anchor_root, kyc_root, sanction_root, assets_root, frozen_root, auditor_pk,
    nf_in_0, asset_id, amount, recipient, cm_change_0, new_root, fee, next_index,
    old_frontier, new_frontier, c_auditor, c_recipient
] } = Unshield(4, 5, 5);
