/**
 * Wallet scanning: trial-decrypt on-chain recipient ciphertexts to discover
 * owned notes (ARCHITECTURE.md → Frontend "Local key & note management"). Runs
 * only inside the client/institution trust zone - it requires the spending and
 * pairwise-viewing secrets.
 *
 * Trial-decryption uses the recipient keystream (sdk/src/encrypt.ts), then
 * RE-DERIVES `owner_pk = Poseidon(owner_sk)` (the recipient ciphertext does not
 * carry owner_pk) and RE-COMPUTES the commitment to confirm a real match. A note
 * is accepted only when the recomputed commitment equals the on-chain one - a
 * ciphertext that is not ours decrypts to garbage and is rejected.
 *
 * SECURITY (invariant #8): the spending key, the pairwise key, and any recovered
 * plaintext (`value`, `rho`, `r_note`) are secrets. NEVER log/persist them to
 * shared storage or transmit them to the backend. Discovered notes stay client-side.
 */

import type { Ciphertext, Commitment, Fr, Note, OwnerSk } from './types.js';
import { decryptRecipient } from './encrypt.js';
import { commitNote, deriveOwnerPk, MAX_NOTE_VALUE } from './note.js';

/** A ciphertext as observed on-chain, with the commitment it accompanies. */
export interface OnChainCiphertext {
  /** The output commitment recorded on-chain for this note. */
  readonly commitment: Commitment;
  /** Recipient-targeted ciphertext (field-packed, K_r = 5); the scan target. */
  readonly cRecipient: Ciphertext;
}

/** A note the wallet successfully recovered, with bookkeeping for spending. */
export interface DiscoveredNote {
  readonly note: Note;
  /** On-chain commitment (re-derived from the opening and confirmed to match). */
  readonly commitment: Commitment;
  /** Leaf index in the commitment tree, if known (needed for inclusion paths). */
  readonly leafIndex?: number;
}

/** The secrets needed to trial-decrypt. SECRET - see invariant #8. */
export interface ViewingContext {
  /** Spending secret; `owner_pk = Poseidon(owner_sk)` is re-derived for matching. */
  readonly ownerSk: OwnerSk;
  /**
   * Sender↔recipient pairwise key used to key the recipient ciphertext (demo:
   * OOB-shared). Scanning tries this key against each observed ciphertext.
   */
  readonly recipientKey: Fr;
  /** Leaf index of this observation, if the caller tracks it. */
  readonly leafIndex?: number;
}

/**
 * Attempt to decrypt a single on-chain ciphertext as ours.
 *
 *   1. Decrypt `c_recipient` with the pairwise key → (value, asset_id, rho, r_note).
 *   2. Re-derive `owner_pk = Poseidon(owner_sk)` and reconstruct the note opening.
 *   3. Re-compute the commitment and CHECK it equals `obs.commitment`.
 *   4. Return the note only on commitment match; otherwise `undefined`.
 *
 * Never returns a note whose commitment does not re-derive - a foreign or garbled
 * ciphertext (recovered `value` out of 64-bit range, or commitment mismatch) is
 * silently skipped.
 */
export function tryDecryptNote(
  obs: OnChainCiphertext,
  ctx: ViewingContext,
): DiscoveredNote | undefined {
  let pt: ReturnType<typeof decryptRecipient>;
  try {
    pt = decryptRecipient(obs.cRecipient, ctx.recipientKey);
  } catch {
    return undefined;
  }

  // A foreign ciphertext decrypts to a random field element; reject anything that
  // cannot be a real 64-bit note value before re-deriving the commitment.
  if (pt.value < 0n || pt.value > MAX_NOTE_VALUE) return undefined;

  const ownerPk = deriveOwnerPk(ctx.ownerSk);
  const note: Note = {
    assetId: pt.assetId,
    value: pt.value,
    ownerPk,
    rho: pt.rho,
    rNote: pt.rNote,
  };

  let commitment: Commitment;
  try {
    commitment = commitNote(note);
  } catch {
    return undefined;
  }
  if (commitment !== obs.commitment) return undefined;

  return ctx.leafIndex === undefined
    ? { note, commitment }
    : { note, commitment, leafIndex: ctx.leafIndex };
}

/**
 * Trial-decrypt a batch of on-chain ciphertexts and return the owned notes.
 * Convenience loop over {@link tryDecryptNote}.
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
