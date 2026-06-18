// Parity harness: frontier transition, depth 6, 2 inserts. Compile --prime bls12381.
pragma circom 2.1.6;
include "../../lib/merkle.circom";
component main = FrontierTransition(6, 2);
