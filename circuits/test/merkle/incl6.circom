// Parity harness: Merkle inclusion, depth 6. Compile with --prime bls12381.
pragma circom 2.1.6;
include "../../lib/merkle.circom";
component main = MerkleInclusion(6);
