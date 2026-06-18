pragma circom 2.1.6;

// =============================================================================
// poseidon_bls.circom — Poseidon over the BLS12-381 scalar field `r`
// =============================================================================
//
// SCAFFOLD. This is NOT a working Poseidon instance yet. It declares the
// template interface and the parameter-loading shape; the round logic is a
// TODO stub.
//
// -----------------------------------------------------------------------------
// CRITICAL — CURVE / FIELD WARNING (Security invariant #1, #13)
// -----------------------------------------------------------------------------
// Finnes runs on BLS12-381. The circuit field is the BLS12-381 SCALAR field:
//
//   r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
//     = 52435875175126190479447740508185965837690552500527637822603658699938581184513
//
// Circom must be invoked with the `--prime bls12381` flag (a COMPILER flag, NOT
// a pragma) so that field arithmetic is performed modulo `r`. There is no
// `pragma` that selects the field; `pragma circom 2.1.6;` only pins the language
// version.
//
//   circom transfer.circom --prime bls12381 --r1cs --wasm --sym
//
// DO NOT use circomlib / circomlibjs Poseidon here. circomlib's Poseidon ships
// constants generated for the BN254 (alt_bn128) scalar field. Re-interpreting
// those constants modulo BLS12-381's `r` does NOT yield a valid, secure Poseidon
// instance — the round constants and MDS matrix must be GENERATED for the target
// field's modulus and the chosen (t, full/partial round) profile. Using BN254
// constants on BLS12-381 is a silent cryptographic break, not a portability
// quirk.
//
// -----------------------------------------------------------------------------
// PARAMETER SET (TODO: generate & vendor)
// -----------------------------------------------------------------------------
// Use a parameter set generated specifically for the BLS12-381 scalar field `r`,
// following the neptune / Filecoin lineage (and matching SDF's Privacy Pools work
// on Soroban). Concretely the generator (e.g. the `poseidon` / neptune param
// scripts, or `circomlibjs`-style generators re-run with the BLS modulus) must
// produce, per arity:
//
//   - field modulus:        r (BLS12-381 scalar field, above)
//   - sbox:                 x^5  (alpha = 5; gcd(5, r-1) == 1 holds for r)
//   - width t:              nInputs + 1  (rate = nInputs, capacity = 1)
//   - R_F (full rounds):    8        (TODO: confirm for chosen security level)
//   - R_P (partial rounds): per-t    (TODO: from param generator, depends on t)
//   - round constants C[]:  TODO     (generated for r; vendor as a circom include)
//   - MDS matrix M[][]:     TODO     (generated for r; vendor as a circom include)
//
// PARITY (Security invariant #13): the EXACT same parameter set (constants, MDS,
// R_F, R_P, alpha) MUST be mirrored byte-for-byte in `sdk/src/poseidon.ts`. A
// cross-implementation test vector (same inputs -> same digest in circuit and JS)
// is a required CI gate. If you regenerate params here, regenerate there too.
//
// The constants are intentionally NOT inlined in this scaffold to avoid shipping
// a placeholder set that could be mistaken for real, audited parameters. They
// should live in a generated include, e.g. `lib/poseidon_bls_params.circom`,
// produced by the param generator and committed alongside its provenance notes.
// =============================================================================

// -----------------------------------------------------------------------------
// PoseidonBLS(nInputs)
//   in[nInputs] -> out  (single field-element digest)
//
// Permutation width is t = nInputs + 1 (sponge with rate=nInputs, capacity=1,
// single-call absorb/squeeze — sufficient for our fixed-arity hashes since every
// call site hashes a fixed small tuple).
// -----------------------------------------------------------------------------
template PoseidonBLS(nInputs) {
    signal input in[nInputs];
    signal output out;

    // t = state width.
    var t = nInputs + 1;

    // --- state initialization -------------------------------------------------
    // state[0] = capacity (0 for fixed-length input, no padding needed),
    // state[1..t-1] = the nInputs absorbed.
    signal state[t];
    // TODO: state[0] <== 0;  state[i+1] <== in[i];
    // (left unwired in scaffold; wiring belongs with the real round logic so the
    //  intermediate-signal layout matches the constant schedule.)

    // --- rounds ---------------------------------------------------------------
    // TODO: implement the Poseidon permutation using BLS12-381 params:
    //   for each of R_F/2 initial full rounds:
    //       add round constants C[k]; sbox ALL t lanes (x^5); MDS mix M
    //   for each of R_P partial rounds:
    //       add round constants C[k]; sbox lane 0 ONLY (x^5); MDS mix M
    //   for each of R_F/2 final full rounds:
    //       add round constants C[k]; sbox ALL t lanes (x^5); MDS mix M
    //   out <== state[1]  (squeeze a single element)
    //
    // x^5 sbox must be expressed as constraints, e.g.:
    //   x2 <== x*x;  x4 <== x2*x2;  y <== x4*x;   (3 constraints per sbox)
    //
    // PLACEHOLDER so the circuit type-checks during scaffolding. This is NOT a
    // hash and MUST be replaced before any proving/ceremony. It is deliberately
    // an under-constrained linear combination so it cannot be mistaken for a
    // sound commitment.
    var acc = 0;
    for (var i = 0; i < nInputs; i++) {
        acc += in[i];
    }
    out <== acc; // TODO: replace with Poseidon permutation squeeze (state[1]).
}
