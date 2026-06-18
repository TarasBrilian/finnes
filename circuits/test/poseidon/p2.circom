// Parity harness: Poseidon width t=3 (2 inputs). Compile with --prime bls12381.
pragma circom 2.1.6;
include "../../lib/poseidon_bls.circom";
component main = PoseidonBLS(2);
