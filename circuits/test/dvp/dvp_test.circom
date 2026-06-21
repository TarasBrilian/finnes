// Acceptance harness: full two-leg DvP settlement, depth 6 (FIN-016). Compile
// --prime bls12381. Witness calculation succeeds iff the SDK-built witness
// satisfies EVERY constraint class for BOTH legs: input inclusion + ownership +
// nullifier, output commitments, per-asset conservation (per leg, never crossed),
// 64-bit ranges, assets membership + per-tx limit, recipient KYC membership,
// sanctions + frozen non-membership, mandatory auditor encryption, and the
// combined frontier transition (insert both outputs). Depth 6 keeps witness
// generation fast; Dvp is depth-agnostic. Driven by scripts/test-dvp-witness.ts.
pragma circom 2.1.6;
include "../../lib/dvp.circom";
component main = Dvp(6, 5, 5);
