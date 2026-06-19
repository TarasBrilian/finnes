//! Groth16 verifier over the native BLS12-381 host functions.
//!
//! Based on `stellar/soroban-examples/groth16_verifier` (CLAUDE.md →
//! "Base the Soroban verifier on …"). This is the **only** module that touches
//! the crypto host functions - `env.crypto().bls12_381()` (Conventions: keep
//! host-fn calls in verifier.rs).
//!
//! ## What Groth16 verification is
//!
//! Given a verifying key `vk`, a proof `(A, B, C)`, and public inputs
//! `x_1..x_n`, accept iff the pairing equation holds:
//!
//! ```text
//!   e(A, B) == e(alpha, beta) · e(vk_x, gamma) · e(C, delta)
//! ```
//!
//! where `vk_x = IC_0 + Σ_i x_i · IC_i` (one G1 scalar-mul per public input -
//! this is why PUBLIC_IO keeps the input set tight). Rearranged into a single
//! multi-pairing product that must equal the identity in `GT`, which the host
//! `pairing_check` evaluates:
//!
//! ```text
//!   e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1_GT
//! ```
//!
//! ## Point encoding (snarkjs → host)
//!
//! VK and proof points arrive already in the host's **uncompressed** big-endian
//! serialization, produced off-chain by `scripts/gen-verifier-fixture.mjs`
//! (and, at deploy time, by the VK/proof converter in the prover/SDK):
//!   - G1 (96 bytes): `be(X) ‖ be(Y)`, each coordinate a 48-byte `Fp`.
//!   - G2 (192 bytes): `be(X_c1) ‖ be(X_c0) ‖ be(Y_c1) ‖ be(Y_c0)` - note the
//!     `c1`-before-`c0` ordering the host mandates (snarkjs stores `[c0, c1]`,
//!     so the converter swaps the limbs).
//!   - Public inputs: 32-byte big-endian `Fr` scalars (the `to_scalars` vector).
//!
//! Keeping the curve-specific encoding in the off-chain converter lets this
//! module stay a thin, auditable wrapper over the host functions.
//!
//! Invariants honoured here:
//!   - #1: BLS12-381 only (host fns are BLS12-381-native; never BN254).
//!   - #5: public inputs (incl. ciphertext field elements) are bound by the
//!     verify; the contract never hashes ciphertext blobs.
//!   - #7: exactly one `pairing_check` per transaction.
//!   - No `unwrap()` on untrusted bytes - a wrong-length proof/VK point returns
//!     a typed `Error`, never a panic. (Points that are well-formed length-wise
//!     but off-curve / not in the subgroup are rejected by the host itself; that
//!     surfaces as a trapped, reverted transaction with no state mutation, since
//!     verification runs strictly before any effect - invariant #9.)

use soroban_sdk::crypto::bls12_381::{Fr, G1Affine, G2Affine};
use soroban_sdk::{Bytes, BytesN, Env, Vec};

use crate::errors::Error;
use crate::types::{Proof, Scalar, VerifyingKey};

/// Host serialized size of a G1 point (uncompressed: `be(X) ‖ be(Y)`).
const G1_SIZE: u32 = 96;
/// Host serialized size of a G2 point (uncompressed: `be(X_c1)‖be(X_c0)‖be(Y_c1)‖be(Y_c0)`).
const G2_SIZE: u32 = 192;

/// Decode a 96-byte blob into a host `G1Affine`. Length is validated here (no
/// `unwrap` on untrusted bytes); curve/subgroup validity is enforced by the host
/// when the point is consumed by a group op or the pairing check.
fn decode_g1(b: &Bytes) -> Result<G1Affine, Error> {
    if b.len() != G1_SIZE {
        return Err(Error::MalformedProof);
    }
    let n: BytesN<96> = b.try_into().map_err(|_| Error::MalformedProof)?;
    Ok(G1Affine::from_bytes(n))
}

/// Decode a 192-byte blob into a host `G2Affine`. Same contract as `decode_g1`.
fn decode_g2(b: &Bytes) -> Result<G2Affine, Error> {
    if b.len() != G2_SIZE {
        return Err(Error::MalformedProof);
    }
    let n: BytesN<192> = b.try_into().map_err(|_| Error::MalformedProof)?;
    Ok(G2Affine::from_bytes(n))
}

/// Verify a Groth16 proof against `vk` and the ordered public-input scalars.
///
/// `public_inputs` MUST already be in canonical order (see
/// `types::*PublicInputs::to_scalars` / docs/PUBLIC_IO.md). The verifier pairs
/// `public_inputs[i]` with `vk.ic[i + 1]`; `vk.ic[0]` is the constant term.
///
/// Returns `Ok(())` on a valid proof, `Err(Error::InvalidProof)` on a sound but
/// failing proof, and a structural `Error` on malformed inputs/keys.
pub fn verify_groth16(
    env: &Env,
    vk: &VerifyingKey,
    proof: &Proof,
    public_inputs: &Vec<Scalar>,
) -> Result<(), Error> {
    // --- arity check: ic must have exactly num_public + 1 points ---
    // Defends against a VK/public-IO drift that would otherwise read past the
    // intended IC points or silently ignore an input (invariant #12 / layout).
    let n_pub = public_inputs.len();
    if vk.ic.len() != n_pub + 1 {
        return Err(Error::VerifyingKeyArityMismatch);
    }
    if vk.ic.is_empty() {
        return Err(Error::VerifyingKeyMissing);
    }

    // --- BLS12-381 host module handle ---
    // The single entry point to the curve host functions. All point
    // (de)serialisation, scalar-muls, and the pairing-check go through here.
    let bls = env.crypto().bls12_381();

    // --- 1. Decode VK and proof point bytes into host curve points. ---
    // VK/ic decode failures are MalformedPublicInputs; proof decode failures are
    // MalformedProof. DO NOT `unwrap()` - these bytes are untrusted.
    let a = decode_g1(&proof.a)?;
    let b = decode_g2(&proof.b)?;
    let c = decode_g1(&proof.c)?;

    let alpha_g1 = decode_g1(&vk.alpha_g1).map_err(|_| Error::MalformedPublicInputs)?;
    let beta_g2 = decode_g2(&vk.beta_g2).map_err(|_| Error::MalformedPublicInputs)?;
    let gamma_g2 = decode_g2(&vk.gamma_g2).map_err(|_| Error::MalformedPublicInputs)?;
    let delta_g2 = decode_g2(&vk.delta_g2).map_err(|_| Error::MalformedPublicInputs)?;

    // --- 2. Accumulate the public-input linear combination vk_x. ---
    //   vk_x = IC_0 + Σ_{i=1..n} public_inputs[i-1] · IC_i
    // Build the MSM argument over IC[1..] and the public scalars, then fold in
    // the constant IC[0] with a single add. One host MSM call instead of n
    // separate `g1_mul`/`g1_add`s (cheaper, fewer host crossings).
    let ic0_bytes = vk.ic.get(0).ok_or(Error::MalformedPublicInputs)?;
    let ic0 = decode_g1(&ic0_bytes).map_err(|_| Error::MalformedPublicInputs)?;

    let mut points: Vec<G1Affine> = Vec::new(env);
    let mut scalars: Vec<Fr> = Vec::new(env);
    for i in 0..n_pub {
        let ic_bytes = vk.ic.get(i + 1).ok_or(Error::MalformedPublicInputs)?;
        let ic = decode_g1(&ic_bytes).map_err(|_| Error::MalformedPublicInputs)?;
        let x = public_inputs.get(i).ok_or(Error::MalformedPublicInputs)?;
        points.push_back(ic);
        scalars.push_back(Fr::from_bytes(x));
    }
    // n_pub >= 1 here (arity check guarantees ic.len() == n_pub + 1 >= 1, and a
    // 0-public-input circuit is not used), so the MSM argument is non-empty.
    let lincomb = bls.g1_msm(points, scalars);
    let vk_x = bls.g1_add(&ic0, &lincomb);

    // --- 3. Build the multi-pairing argument and run the single check. ---
    //   e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1_GT
    // Negate A in G1 (host-native `Neg`) so the whole product equals the GT
    // identity. `pairing_check` returns true iff the product is the identity.
    //
    // IMPORTANT (invariant #7): this is the ONE and ONLY pairing-check per tx.
    let neg_a = -a;

    let mut g1_points: Vec<G1Affine> = Vec::new(env);
    g1_points.push_back(neg_a);
    g1_points.push_back(alpha_g1);
    g1_points.push_back(vk_x);
    g1_points.push_back(c);

    let mut g2_points: Vec<G2Affine> = Vec::new(env);
    g2_points.push_back(b);
    g2_points.push_back(beta_g2);
    g2_points.push_back(gamma_g2);
    g2_points.push_back(delta_g2);

    if bls.pairing_check(g1_points, g2_points) {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}
