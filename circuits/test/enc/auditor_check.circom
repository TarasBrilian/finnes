// Parity harness: mandatory auditor-encryption well-formedness (FIN-004).
// Compile --prime bls12381. Witness calculation succeeds iff the supplied
// c_auditor is the correct keystream encryption of the plaintext under k_view.
pragma circom 2.1.6;
include "../../lib/enc_check.circom";
component main = AuditorEncCheck();
