/**
 * Wallet scanning: trial-decrypt on-chain ciphertexts to discover owned notes
 * (ARCHITECTURE.md → Frontend "Local key & note management"). Runs only inside
 * the client/institution trust zone — it requires the viewing/spending secrets.
 *
 * SECURITY (invariant #8): the viewing key and any recovered plaintext
 * (`value`, `rho`, `r_note`) are secrets. NEVER log/persist them to shared
 * storage or transmit them to the backend. Discovered notes stay client-side.
 */

import type { Ciphertext, Commitment, Fr, Note, OwnerSk } from './types.js';

/** A ciphertext as observed on-chain, with the commitment it accompanies. */
export interface OnChainCiphertext {
  /** The output commitment recorded on-chain for this note. */
  readonly commitment: Commitment;
  /** Recipient-targeted ciphertext (field-packed); the scan target. */
  readonly cRecipient: Ciphertext;
}

/** A note the wallet successfully recovered, with bookkeeping for spending. */
export interface DiscoveredNote {
  readonly note: Note;
  /** On-chain commitment (re-derivable from the opening; checked for parity). */
  readonly commitment: Commitment;
  /** Leaf index in the commitment tree, if known (needed for inclusion paths). */
  readonly leafIndex?: number;
}

/** The secrets needed to trial-decrypt. SECRET — see invariant #8. */
export interface ViewingContext {
  /** Spending secret (used to derive the recipient decryption key). */
  readonly ownerSk: OwnerSk;
  /**
   * Optional separate viewing secret if the scheme splits view/spend.
   * Representation TODO with the encryption scheme.
   */
  readonly viewSk?: Fr;
}

/**
 * Attempt to decrypt a single on-chain ciphertext as ours.
 *
 * TODO(crypto): implement trial-decryption for the hybrid scheme (encrypt.ts):
 *   1. Derive the decryption key from `ctx` and the ciphertext's KEM part.
 *   2. Decrypt; if it parses into a valid note opening, recompute the
 *      commitment (note.ts `commitNote`) and CHECK it equals `obs.commitment`.
 *   3. Return the note only on commitment match; otherwise `undefined`.
 * Throws until the scheme is fixed (must not return fake/empty notes).
 */
export function tryDecryptNote(
  _obs: OnChainCiphertext,
  _ctx: ViewingContext,
): DiscoveredNote | undefined {
  throw new Error(
    'TODO: tryDecryptNote requires the encryption scheme (encrypt.ts) and ' +
      'commitment re-derivation parity (note.ts). Do not return fake notes.',
  );
}

/**
 * Trial-decrypt a batch of on-chain ciphertexts and return the owned notes.
 * Convenience loop over {@link tryDecryptNote}; inherits its TODO/throw.
 */
export function scanForOwnedNotes(
  observations: readonly OnChainCiphertext[],
  ctx: ViewingContext,
): DiscoveredNote[] {
  const found: DiscoveredNote[] = [];
  for (const obs of observations) {
    const note = tryDecryptNote(obs, ctx);
    if (note) found.push(note);
  }
  return found;
}
