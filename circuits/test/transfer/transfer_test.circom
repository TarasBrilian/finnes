// Acceptance harness: full confidential transfer (2-in / 2-out), depth 6
// (FIN-006). Compile --prime bls12381. Witness calculation succeeds iff the
// SDK-built witness satisfies EVERY constraint class: input inclusion +
// ownership + nullifier, output commitments, per-asset conservation, 64-bit
// ranges, assets membership + per-tx limit, KYC membership, sanctions + frozen
// non-membership, mandatory auditor encryption, and the frontier transition.
//
// Depth 6 (not the production D=20) keeps witness generation fast; the Transfer
// template is depth-agnostic, so the same gadgets are exercised. Driven by
// scripts/test-transfer-witness.ts.
pragma circom 2.1.6;
include "../../lib/transfer.circom";
component main = Transfer(6, 5, 5);
