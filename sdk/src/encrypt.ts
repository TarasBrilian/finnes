/**
 * Note encryption for the auditor (mandatory) and the recipient (optional).
 *
 * Every output note MUST carry a well-formed auditor ciphertext, bound to the
 * proof as a public input (invariants #5). The intended MVP scheme is the
 * HYBRID auditor-encryption check: instead of a full in-circuit AEAD, the
 * circuit proves VALUE-EQUALITY between the ciphertext's encrypted contents and
 * the note opening (CLAUDE.md → "What to do when unsure": prefer the hybrid
 * check). The exact scheme (KEM, symmetric layer, field packing of the blob,
 * and `auditor_pk` representation) is a SCAFFOLD TODO — see docs/PUBLIC_IO.md
 * §"Ciphertext binding (TODO: scheme)".
 *
 * SECURITY (invariant #8): plaintext note fields (`value`, `rho`, `r_note`) and
 * `auditor_sk` are secrets. NEVER log/persist/transmit them. These stubs throw
 * rather than producing a fake ciphertext, because an unconstrained or fake
 * auditor ciphertext would violate the mandatory-encryption invariant.
 */

import type { AuditorPublicKey, Ciphertext, Fr, Note, OwnerPk } from './types.js';

/** Randomness used to encrypt a note. SECRET — see invariant #8. */
export interface EncryptionRandomness {
  /** Ephemeral/KEM randomness in `[0, r)` (scheme-dependent). */
  readonly r: Fr;
}

/**
 * Encrypt a note to the auditor view key. MANDATORY for every output note
 * (invariant #5). Result is field-packed and bound by the proof.
 *
 * TODO(crypto): implement the hybrid scheme:
 *   1. KEM to `auditorPk` (curve/representation TODO — must be BLS-native;
 *      NO embedded curve such as Baby Jubjub, per invariant #1).
 *   2. Encrypt the note plaintext under the derived symmetric key.
 *   3. Pack into `Fr[]` (length `K_a`, TODO) matching docs/PUBLIC_IO.md.
 *   4. The circuit's `enc_check.circom` proves value-equality vs the opening.
 * Throws until the scheme is fixed.
 */
export function encryptToAuditor(
  _note: Note,
  _auditorPk: AuditorPublicKey,
  _randomness: EncryptionRandomness,
): Ciphertext {
  throw new Error(
    'TODO: encryptToAuditor scheme undefined (hybrid value-equality). ' +
      'Fix the KEM + packing to match circuits/lib/enc_check.circom. ' +
      'Auditor ciphertext is mandatory (invariant #5) — never fabricate one.',
  );
}

/**
 * Encrypt a note to the recipient so they can discover it during scanning.
 * Optional (the auditor ciphertext is the mandatory one).
 *
 * TODO(crypto): same hybrid scheme keyed to the recipient `owner_pk`
 * representation; pack to `Fr[]` (length `K_r`, TODO). Throws until fixed.
 */
export function encryptToRecipient(
  _note: Note,
  _recipientPk: OwnerPk,
  _randomness: EncryptionRandomness,
): Ciphertext {
  throw new Error(
    'TODO: encryptToRecipient scheme undefined (hybrid). Match the field ' +
      'packing in docs/PUBLIC_IO.md and the recipient-scan path in scan.ts.',
  );
}
