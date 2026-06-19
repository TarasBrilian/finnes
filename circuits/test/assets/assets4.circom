// Parity/acceptance harness: authorized-assets registry membership, depth 4
// (FIN-005). Compile --prime bls12381. Witness calculation succeeds iff asset_id
// self-binds, the leaf is included under assets_root, and value <= per_tx_limit_raw.
pragma circom 2.1.6;
include "../../lib/assets.circom";
component main = AssetsMembership(4);
