// Acceptance harness: unshield (shielded -> transparent), depth 6 (FIN-013).
// Compile --prime bls12381. Witness calculation succeeds iff the SDK-built
// witness satisfies EVERY constraint class: input range/opening/ownership/
// nullifier/inclusion, frozen-set non-membership (#19b), conservation, change-note
// gating, assets membership + per-tx limit, recipient KYC membership + sanctions
// non-membership (#19a), gated change-note encryption, and the (conditional)
// frontier transition. Depth 6 keeps witness generation fast; the Unshield
// template is depth-agnostic. Driven by scripts/test-unshield-witness.ts.
pragma circom 2.1.6;
include "../../lib/unshield.circom";
component main = Unshield(6, 5, 5);
