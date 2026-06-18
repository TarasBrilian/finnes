// Parity harness: Poseidon width t=2 (1 input). Compile with --prime bls12381.
pragma circom 2.1.6;
include "../../lib/poseidon_bls.circom";
component main = PoseidonBLS(1);
