pragma circom 2.1.6;

// =============================================================================
// enc_check.circom — auditor-encryption well-formedness (MANDATORY)
// =============================================================================
//
// SCAFFOLD. The encryption SCHEME is a TODO (see PUBLIC_IO.md "Ciphertext
// binding (TODO: scheme)"). This file fixes the INTERFACE and the invariant that
// the auditor ciphertext is mandatory and circuit-constrained, not the concrete
// AEAD/KEM math.
//
// Compile with `--prime bls12381`.
//
// -----------------------------------------------------------------------------
// WHY THIS EXISTS (Security invariant #5)
// -----------------------------------------------------------------------------
// Every output note MUST be encrypted to the regulator view key, and that
// ciphertext MUST be bound to the proof as a PUBLIC INPUT. Groth16 binds public
// inputs inherently, so the contract stores the ciphertext VERBATIM and never
// hashes it. The prover must NOT be able to supply an unconstrained ciphertext:
// this gadget proves the public `c_auditor` field elements are a correct
// encryption of THIS note's plaintext (at minimum its `value`, and per the
// chosen scheme also asset_id/owner/rho) under `auditor_pk`.
//
// -----------------------------------------------------------------------------
// CHOSEN APPROACH: HYBRID — prove value-equality (CLAUDE.md "What to do when
// unsure" + Security invariant #5). The intended MVP path is NOT a full
// in-circuit AEAD. Instead:
//   - The note is symmetrically encrypted off-circuit (or the symmetric part is
//     opaque to the circuit), and
//   - the circuit proves that the committed ciphertext fields encode the SAME
//     `value` (and binding fields) that the note commitment opens to — i.e. the
//     plaintext the auditor will recover equals the real note plaintext.
// This prevents a prover from committing to a valid note while shipping an
// auditor ciphertext that decrypts to a different (e.g. zero) value.
//
// -----------------------------------------------------------------------------
// SCHEME — TODO (must be fixed before ceremony)
// -----------------------------------------------------------------------------
// Because there is NO embedded curve (Security invariant #1: no Baby Jubjub /
// Jubjub, no in-circuit signature), an in-circuit EC-DH/ElGamal KEM is OFF the
// table. Candidate hybrid schemes (decide & document):
//   (A) Poseidon-based KEM/commitment: derive a shared secret off-circuit; prove
//       in-circuit that c_value = value + Poseidon(shared_secret, domain) (a
//       one-time-pad / additive blinding over the field), binding `value` to the
//       public ciphertext field via a Poseidon keystream. auditor_pk then acts
//       as a Poseidon-based public key / KEM tag.
//   (B) Commit-and-prove: c_auditor carries a Poseidon commitment to the
//       plaintext plus an opaque symmetric blob; the circuit proves the
//       commitment opens to the note's (value, asset_id, owner_pk, rho).
// Either way the binding fields and the field-packing layout (K_a elements) must
// match PUBLIC_IO.md and `sdk/src/poseidon.ts` / the SDK encryptor.
//
// `auditor_pk` representation (single field vs _x/_y) is TODO until the scheme is
// fixed; PUBLIC_IO.md currently carries it as a single public input.
// =============================================================================

include "poseidon_bls.circom";

// -----------------------------------------------------------------------------
// AuditorEncCheck(nCipher)
//   Proves the public auditor ciphertext fields `c_auditor[nCipher]` are a
//   well-formed encryption, to `auditor_pk`, of the note plaintext described by
//   (asset_id, value, owner_pk, rho), using `enc_rand` as the encryption
//   randomness/ephemeral secret.
//
//   nCipher = K_a, the number of packed field elements (TODO: pin to scheme).
// -----------------------------------------------------------------------------
template AuditorEncCheck(nCipher) {
    // public
    signal input auditor_pk;
    signal input c_auditor[nCipher];
    // note plaintext being bound (private)
    signal input asset_id;
    signal input value;
    signal input owner_pk;
    signal input rho;
    // encryption randomness (private)
    signal input enc_rand;

    // ---- Hybrid value-equality binding (SCHEME = TODO) ----------------------
    // Sketch for candidate (A), additive Poseidon keystream:
    //   shared   = Poseidon(auditor_pk, enc_rand)          // KEM-ish derivation
    //   ks_value = Poseidon(shared, DOMAIN_VALUE)
    //   c_auditor[VALUE_SLOT] === value + ks_value
    //   ... and analogous bindings for asset_id / owner_pk / rho in their slots.
    //
    // The crucial soundness property: `value` here is the SAME signal fed into
    // the NoteCommitment upstream, so the ciphertext cannot disagree with the
    // committed note. Do NOT relax this to leave any plaintext field
    // unconstrained.
    //
    // PLACEHOLDER so the template type-checks. NOT a real encryption check; it
    // does NOT yet bind value to c_auditor. MUST be replaced before ceremony.
    component shared = PoseidonBLS(2);
    shared.in[0] <== auditor_pk;
    shared.in[1] <== enc_rand;

    // touch the plaintext signals so they are not dangling; this is NOT the real
    // binding constraint (TODO: bind each plaintext field to a ciphertext slot).
    signal plaintext_acc;
    plaintext_acc <== asset_id + value + owner_pk + rho;
    // TODO: replace with per-slot equality against c_auditor[...] derived from
    //       the Poseidon keystream above. Until then c_auditor is unconstrained
    //       — this is a SCAFFOLD and is explicitly insecure.
    signal cipher_acc;
    var acc = 0;
    for (var i = 0; i < nCipher; i++) {
        acc += c_auditor[i];
    }
    cipher_acc <== acc;
    // No constraint linking plaintext_acc/shared.out to cipher_acc yet (TODO).
}

// -----------------------------------------------------------------------------
// RecipientEncCheck(nCipher)
//   OPTIONAL recipient ciphertext (`c_recipient`). Same shape, encrypted to the
//   recipient's pk instead of auditor_pk. Not security-critical for compliance
//   (the recipient can always be told out-of-band), but kept so the recipient
//   can scan & discover the note. NOT mandatory (unlike c_auditor).
// -----------------------------------------------------------------------------
template RecipientEncCheck(nCipher) {
    signal input recipient_pk;
    signal input c_recipient[nCipher];
    signal input asset_id;
    signal input value;
    signal input owner_pk;
    signal input rho;
    signal input enc_rand;

    // TODO: same hybrid value-equality binding as AuditorEncCheck.
    signal acc_sig;
    var acc = 0;
    for (var i = 0; i < nCipher; i++) {
        acc += c_recipient[i];
    }
    acc_sig <== acc + recipient_pk + asset_id + value + owner_pk + rho + enc_rand;
    // PLACEHOLDER — no binding constraint yet (TODO).
}
