pragma circom 2.1.6;

// =============================================================================
// enc_check.circom — auditor/recipient encryption well-formedness (FIN-004)
// =============================================================================
//
// CONCRETE (FIN-001 scheme A, LOCKED in docs/PUBLIC_IO.md "Ciphertext binding").
// The auditor ciphertext is MANDATORY and bound to the proof as public inputs
// (Security invariant #5). This gadget proves the published ciphertext slots are
// the correct additive-Poseidon-keystream encryption of THIS note's plaintext —
// the prover cannot ship a value-correct commitment alongside an undecryptable or
// disagreeing ciphertext ("encrypt a zero" is impossible).
//
// Compile with `--prime bls12381`. Mirrors sdk/src/encrypt.ts EXACTLY (the
// keystream, the slot layout, and the domain separation). Any divergence is a
// parity break — guarded by scripts/test-enc-parity.ts.
//
// -----------------------------------------------------------------------------
// SCHEME (no embedded curve — invariant #1; asymmetry lives off-circuit):
// -----------------------------------------------------------------------------
//   auditor_pk = Poseidon(k_view)                         (bound in-circuit)
//   shared     = Poseidon(k_view, rho_enc)                (rho_enc published)
//   ks_i       = Poseidon(shared, i)   for slot i = 1..4  (domain-separated)
//   c[0]       = rho_enc                                  (published nonce)
//   c[i]       = pt[i-1] + ks_i   (mod r)                 (additive one-time pad)
//
// auditor ciphertext binds plaintext slots [value, asset_id, owner_pk, rho];
// recipient ciphertext binds [value, asset_id, rho, r_note]. Both K = 5.
//
// SOUNDNESS: the plaintext signals fed here are the SAME signals the note
// commitment opens to upstream (the caller wires `outNote.value` etc. into both),
// so the ciphertext cannot disagree with the committed note. For the auditor
// ciphertext the key is bound (`Poseidon(k_view) == auditor_pk`), so the prover
// must encrypt to a key the auditor authorized — no griefing gap. The recipient
// ciphertext is NON-mandatory (invariant #5 requires only the auditor one) and is
// keyed by a sender↔recipient pairwise secret (demo: out-of-band), so it carries
// no in-circuit key-authorization constraint — only well-formedness, for scanning.
// =============================================================================

include "poseidon_bls.circom";

// -----------------------------------------------------------------------------
// AuditorEncCheck — mandatory auditor ciphertext (K_a = 5).
//
//   c_auditor = [ rho_enc,
//                 value    + ks_1,
//                 asset_id + ks_2,
//                 owner_pk + ks_3,
//                 rho      + ks_4 ]
// -----------------------------------------------------------------------------
template AuditorEncCheck() {
    // public
    signal input auditor_pk;     // = Poseidon(k_view); checked against contract state
    signal input c_auditor[5];   // published field-packed ciphertext (public input)
    // note plaintext being bound (same signals as the note commitment upstream)
    signal input value;
    signal input asset_id;
    signal input owner_pk;
    signal input rho;
    // keying material (private witness)
    signal input k_view;         // sender↔auditor shared key; auditor_pk = Poseidon(k_view)
    signal input rho_enc;        // published nonce; equals c_auditor[0]

    // (1) bind the key: the prover may only use a key the auditor authorized.
    component pk = PoseidonBLS(1);
    pk.in[0] <== k_view;
    auditor_pk === pk.out;

    // (2) the published nonce occupies slot 0.
    c_auditor[0] === rho_enc;

    // (3) shared secret = Poseidon(k_view, rho_enc).
    component sh = PoseidonBLS(2);
    sh.in[0] <== k_view;
    sh.in[1] <== rho_enc;

    // (4) additive Poseidon keystream over Fr, domain-separated by slot index.
    signal pt[4];
    pt[0] <== value;
    pt[1] <== asset_id;
    pt[2] <== owner_pk;
    pt[3] <== rho;
    component ks[4];
    for (var i = 0; i < 4; i++) {
        ks[i] = PoseidonBLS(2);
        ks[i].in[0] <== sh.out;
        ks[i].in[1] <== i + 1;                 // slot index 1..4
        c_auditor[i + 1] === pt[i] + ks[i].out; // OTP binding (mod r)
    }
}

// -----------------------------------------------------------------------------
// RecipientEncCheck — optional recipient ciphertext (K_r = 5).
//
//   c_recipient = [ rho_enc,
//                   value    + ks_1,
//                   asset_id + ks_2,
//                   rho      + ks_3,
//                   r_note   + ks_4 ]
//
// Keyed by a sender↔recipient pairwise secret `k_pair` (demo: OOB). NOT mandatory
// (invariant #5 mandates only the auditor ciphertext) and carries no key-binding;
// it exists so the recipient can scan & discover the note (sdk/src/scan.ts). The
// recipient re-derives owner_pk from its own owner_sk, so owner_pk is not packed.
// -----------------------------------------------------------------------------
template RecipientEncCheck() {
    signal input c_recipient[5];
    signal input value;
    signal input asset_id;
    signal input rho;
    signal input r_note;
    signal input k_pair;         // sender↔recipient pairwise secret (private witness)
    signal input rho_enc;        // published nonce; equals c_recipient[0]

    c_recipient[0] === rho_enc;

    component sh = PoseidonBLS(2);
    sh.in[0] <== k_pair;
    sh.in[1] <== rho_enc;

    signal pt[4];
    pt[0] <== value;
    pt[1] <== asset_id;
    pt[2] <== rho;
    pt[3] <== r_note;
    component ks[4];
    for (var i = 0; i < 4; i++) {
        ks[i] = PoseidonBLS(2);
        ks[i].in[0] <== sh.out;
        ks[i].in[1] <== i + 1;
        c_recipient[i + 1] === pt[i] + ks[i].out;
    }
}
