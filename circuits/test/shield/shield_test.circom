// Acceptance harness: shield (transparent -> shielded), depth 6 (FIN-012).
// Compile --prime bls12381. Witness calculation succeeds iff the SDK-built
// witness satisfies EVERY constraint class: 64-bit range on amount, output
// commitment opening to the public (asset_id, amount), assets membership +
// self-binding asset_id + per-tx limit, depositor KYC membership, mandatory
// auditor encryption, and the frontier transition (insert at next_index).
//
// Depth 6 (not the production D=20) keeps witness generation fast; the Shield
// template is depth-agnostic, so the same gadgets are exercised. Driven by
// scripts/test-shield-witness.ts.
pragma circom 2.1.6;
include "../../lib/shield.circom";
component main = Shield(6, 5, 5);
