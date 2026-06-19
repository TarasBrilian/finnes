// Depth-4 shield harness for a lighter, runnable demo trusted setup (FIN-012,
// mirrors transfer_test4 from FIN-007/008). Same gadgets and public-IO STRUCTURE
// as the production `Shield(20,5,5)` main - only the tree depth differs (4 vs 20),
// so the full witness -> setup -> prove -> verify pipeline is exercised end-to-end
// at a depth whose setup fits a small Powers-of-Tau (the D=20 production ceremony
// is identical; see scripts/setup-ceremony.sh, which already iterates `shield`).
// Public signals: 9 + 2*D + K_a + K_r = 9 + 8 + 5 + 5 = 27.
pragma circom 2.1.6;
include "../../lib/shield.circom";
component main { public [
    asset_id, amount, kyc_root, assets_root, auditor_pk, cm_out_0, new_root, fee,
    next_index, old_frontier, new_frontier, c_auditor, c_recipient
] } = Shield(4, 5, 5);
