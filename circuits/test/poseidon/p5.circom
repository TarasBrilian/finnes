// Parity harness: Poseidon width t=6 (5 inputs, the commitment arity).
// Compile with --prime bls12381.
pragma circom 2.1.6;
include "../../lib/poseidon_bls.circom";
component main = PoseidonBLS(5);
