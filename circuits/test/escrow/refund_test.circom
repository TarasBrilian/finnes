// escrow_refund acceptance harness, depth 6 (FIN-017). EscrowLeg(...,1): recipient
// KYC + sanctions enforced (refund to a real party). Driven by test-escrow-witness.ts.
pragma circom 2.1.6;
include "../../lib/escrow_leg.circom";
component main = EscrowLeg(6, 5, 5, 1);
