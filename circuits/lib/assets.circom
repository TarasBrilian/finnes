pragma circom 2.1.6;

// =============================================================================
// assets.circom — authorized-assets registry membership + per-tx limit check
// =============================================================================
//
// SCAFFOLD. Composition is concrete; hashing & range bounds delegate to stubs.
//
// Compile with `--prime bls12381`.
//
// Single source of truth for what may move and on what terms (Security
// invariant #17). Registry leaf:
//
//      (asset_id, sac_address, decimals, per_tx_limit_raw)
//
// committed as `assets_root`. asset_id = Poseidon(sac_address) (self-binding,
// computed in-circuit, never on-chain). Per-asset limits flow through MEMBERSHIP
// and are checked as `value <= per_tx_limit_raw`. The limit is a WITNESS, never
// a per-asset public input — exposing it would fingerprint the otherwise-hidden
// asset (Security invariant #17).
//
// RAW UNITS ONLY — `decimals` is carried in the leaf for binding/parity but the
// circuit NEVER rescales by it (Security invariant #16). It exists only so the
// leaf hash matches the registry; display scaling lives in the SDK.
// =============================================================================

include "poseidon_bls.circom";
include "merkle.circom";
include "note.circom";
include "../node_modules/circomlib/circuits/comparators.circom"; // LessThan / LessEqThan (field-agnostic)

// -----------------------------------------------------------------------------
// AssetsMembership(depth)
//   Proves:
//     (1) asset_id == Poseidon(sac_address)        (self-binding identity)
//     (2) leaf = Poseidon(asset_id, sac_address, decimals, per_tx_limit_raw)
//         is included under `assets_root`
//     (3) value <= per_tx_limit_raw                (per-asset limit)
//
//   `per_tx_limit_raw` and `decimals` arrive as private witness.
//   `value` is expected to already be 64-bit range-checked by the caller.
// -----------------------------------------------------------------------------
template AssetsMembership(depth) {
    signal input asset_id;
    signal input value;               // raw SAC units, already 64-bit ranged upstream
    // registry leaf witness
    signal input sac_address;
    signal input decimals;
    signal input per_tx_limit_raw;
    // inclusion path
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input assets_root;

    // (1) self-binding asset identity
    component aid = AssetId();
    aid.sac_address <== sac_address;
    asset_id === aid.asset_id;

    // (2) leaf = Poseidon(asset_id, sac_address, decimals, per_tx_limit_raw)
    component leafH = PoseidonBLS(4);
    leafH.in[0] <== asset_id;
    leafH.in[1] <== sac_address;
    leafH.in[2] <== decimals;
    leafH.in[3] <== per_tx_limit_raw;

    component incl = MerkleInclusion(depth);
    incl.leaf <== leafH.out;
    for (var i = 0; i < depth; i++) {
        incl.pathElements[i] <== pathElements[i];
        incl.pathIndices[i]  <== pathIndices[i];
    }
    incl.root <== assets_root;

    // (3) value <= per_tx_limit_raw
    // Both operands fit in 64 bits (value is 64-bit ranged; limit_raw should be
    // too — TODO: range-check per_tx_limit_raw to 64 bits here for soundness so
    // LessEqThan(64) cannot be gamed by an out-of-range limit witness).
    component le = LessEqThan(64);
    le.in[0] <== value;
    le.in[1] <== per_tx_limit_raw;
    le.out === 1;
}
