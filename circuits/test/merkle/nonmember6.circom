// Parity harness: IMT non-membership, depth 6. Compile --prime bls12381.
pragma circom 2.1.6;
include "../../lib/merkle.circom";
component main = MerkleNonMembership(6);
