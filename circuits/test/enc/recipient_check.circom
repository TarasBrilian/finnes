// Parity harness: optional recipient-encryption well-formedness (FIN-004).
// Compile --prime bls12381.
pragma circom 2.1.6;
include "../../lib/enc_check.circom";
component main = RecipientEncCheck();
