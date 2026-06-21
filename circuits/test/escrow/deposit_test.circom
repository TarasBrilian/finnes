// escrow_deposit acceptance harness, depth 6 (FIN-017). EscrowLeg(...,0): no
// recipient compliance (intent-owned output). Driven by scripts/test-escrow-witness.ts.
pragma circom 2.1.6;
include "../../lib/escrow_leg.circom";
component main = EscrowLeg(6, 5, 5, 0);
