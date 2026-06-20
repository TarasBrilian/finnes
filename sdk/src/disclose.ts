/**
 * Auditor (regulator) disclosure: decrypt a transaction's MANDATORY auditor
 * ciphertexts to full plaintext (amount, asset, parties) for audit. This powers
 * the regulator view (ARCHITECTURE.md → "Regulator / auditor view"; the climax
 * of the demo: "the regulator sees everything").
 *
 * Runs only in the AUDITOR trust zone — it requires the auditor's shared view
 * key `k_view`. The auditor ciphertext (invariant #5) binds, per output note,
 * `[value, asset_id, owner_pk, rho]`; decrypting it reveals the amount, the asset
 * identity, and the receiving party (`owner_pk`) of every minted note.
 *
 * BINDING NOTE: unlike the recipient ciphertext (sdk/src/scan.ts), the auditor
 * ciphertext does NOT carry `r_note`, so the auditor CANNOT recompute the
 * on-chain commitment to cross-check. It does not need to: invariant #5 binds the
 * SAME `value`/`asset_id`/`owner_pk`/`rho` signals into both the commitment and
 * the auditor keystream in-circuit, so a value-correct proof cannot ship a
 * disagreeing auditor ciphertext ("encrypt a zero" is impossible). The decrypted
 * plaintext is therefore authoritative by the Groth16 verification, not by an
 * off-chain re-derivation.
 *
 * SECURITY (invariant #8): `k_view` and all recovered plaintext (`value`, `rho`)
 * are secrets of the auditor zone. NEVER log/persist/transmit them.
 */

import type {
  AssetId,
  Ciphertext,
  CircuitId,
  Commitment,
  Fr,
  Nullifier,
  OwnerPk,
  RawAmount,
} from './types.js';
import { decryptAuditor } from './encrypt.js';
import { MAX_NOTE_VALUE } from './note.js';

/** An output note as observed on-chain by the auditor: commitment + its `c_auditor`. */
export interface AuditorObservedNote {
  /** The output commitment recorded on-chain. */
  readonly commitment: Commitment;
  /** The MANDATORY auditor ciphertext for this note (field-packed, K_a = 5). */
  readonly cAuditor: Ciphertext;
}

/**
 * A transaction as observed on-chain by the auditor: the published nullifiers
 * (spent inputs) and the output notes' commitments + auditor ciphertexts.
 *
 * For `unshield`, the (optional) change note may be the "no change" sentinel
 * (`commitment === 0n`, all-zero `c_auditor` — docs/PUBLIC_IO.md); such outputs
 * are skipped by {@link discloseTransaction}.
 */
export interface AuditorObservedTx {
  readonly circuit: CircuitId;
  /** Nullifiers of the spent inputs (opaque: they reveal nothing about which note). */
  readonly nullifiers: readonly Nullifier[];
  /** Output notes minted by this transaction. */
  readonly outputs: readonly AuditorObservedNote[];
}

/** A fully-decrypted output note, with optionally-resolved human labels. */
export interface DisclosedNote {
  /** The on-chain commitment this disclosure is for. */
  readonly commitment: Commitment;
  /** Raw SAC units (NEVER rescaled in the ZK layer; format with `decimals`). */
  readonly value: RawAmount;
  /** Self-binding asset identity `asset_id = Poseidon(sac_address)`. */
  readonly assetId: AssetId;
  /** The receiving party's spending public key `owner_pk = Poseidon(owner_sk)`. */
  readonly ownerPk: OwnerPk;
  /** Per-note serial/nonce recovered from the ciphertext. */
  readonly rho: Fr;
  /**
   * Position-derived role within the transaction, when known. For `transfer`,
   * output 0 is the recipient note and output 1 is the change note (back to the
   * sender); for `dvp`, output 0 is leg X and output 1 is leg Y.
   */
  readonly role?: 'recipient' | 'change' | 'leg_x' | 'leg_y' | 'output';
  /** Resolved asset label, if a resolver was supplied (e.g. "TBOND-2031"). */
  readonly assetLabel?: string;
  /** Asset display decimals, if resolved (registry/SDK only; never in-circuit). */
  readonly decimals?: number;
  /** Resolved party label, if a resolver mapped `ownerPk` to a known holder. */
  readonly party?: string;
  /**
   * False when the recovered `value` is outside the 64-bit range — a strong
   * signal the wrong `k_view` was used (a foreign ciphertext decrypts to a random
   * field element). `true` for any genuine note (range-checked in-circuit, #2).
   */
  readonly valueInRange: boolean;
}

/** A fully-disclosed transaction for the regulator view. */
export interface DisclosedTransaction {
  readonly circuit: CircuitId;
  readonly nullifiers: readonly Nullifier[];
  readonly outputs: readonly DisclosedNote[];
}

/** Optional label resolvers the auditor holds out-of-band (registry / KYC directory). */
export interface DisclosureResolvers {
  /** Map an `asset_id` to a display label + decimals (e.g. the assets registry). */
  readonly asset?: (assetId: AssetId) => { label: string; decimals: number } | undefined;
  /** Map an output note's `owner_pk` to a known party label. */
  readonly party?: (ownerPk: OwnerPk) => string | undefined;
}

/** True if a commitment is the all-zero "no change note" sentinel (docs/PUBLIC_IO.md). */
function isSentinel(commitment: Commitment): boolean {
  return commitment === 0n;
}

/** Role of output `index` within a `circuit`'s output list (docs/PUBLIC_IO.md ordering). */
function roleFor(circuit: CircuitId, index: number, total: number): DisclosedNote['role'] {
  if (circuit === 'transfer' && total === 2) return index === 0 ? 'recipient' : 'change';
  if (circuit === 'dvp' && total === 2) return index === 0 ? 'leg_x' : 'leg_y';
  if (circuit === 'unshield') return 'change';
  if (circuit === 'shield') return 'recipient';
  return 'output';
}

/**
 * Disclose a single output note: decrypt its auditor ciphertext with `k_view`
 * and attach any resolver labels. Used by {@link discloseTransaction}; exposed
 * for callers that hold a single observed note.
 */
export function discloseNote(
  obs: AuditorObservedNote,
  kView: Fr,
  resolvers?: DisclosureResolvers,
  role: DisclosedNote['role'] = 'output',
): DisclosedNote {
  const pt = decryptAuditor(obs.cAuditor, kView);
  const valueInRange = pt.value >= 0n && pt.value <= MAX_NOTE_VALUE;
  const asset = resolvers?.asset?.(pt.assetId);
  const party = resolvers?.party?.(pt.ownerPk);

  return {
    commitment: obs.commitment,
    value: pt.value,
    assetId: pt.assetId,
    ownerPk: pt.ownerPk,
    rho: pt.rho,
    role,
    valueInRange,
    ...(asset ? { assetLabel: asset.label, decimals: asset.decimals } : {}),
    ...(party !== undefined ? { party } : {}),
  };
}

/**
 * Disclose a whole transaction to the auditor: decrypt every (non-sentinel)
 * output note's mandatory auditor ciphertext to full plaintext (amount, asset,
 * party). The spent nullifiers are passed through opaquely — they prevent
 * double-spend but reveal nothing about which note was consumed; identifying the
 * spent notes is the indexer's job (cross-referencing prior outputs), not the
 * per-tx ciphertext's.
 *
 * Sentinel outputs (`commitment === 0n`, the `unshield` "no change" case) are
 * skipped: their auditor ciphertext is all-zero and carries no note.
 */
export function discloseTransaction(
  tx: AuditorObservedTx,
  kView: Fr,
  resolvers?: DisclosureResolvers,
): DisclosedTransaction {
  // Role is derived from the ORIGINAL output position + the original output
  // count (docs/PUBLIC_IO.md ordering), NOT a post-filter index — otherwise a
  // dropped leading sentinel would re-index the survivors and shift the
  // recipient/change (or leg_x/leg_y) roles the regulator relies on.
  const total = tx.outputs.length;
  const outputs = tx.outputs
    .map((o, idx) => ({ o, idx }))
    .filter(({ o }) => !isSentinel(o.commitment))
    .map(({ o, idx }) => discloseNote(o, kView, resolvers, roleFor(tx.circuit, idx, total)));
  return { circuit: tx.circuit, nullifiers: tx.nullifiers, outputs };
}

/**
 * Format a raw SAC amount for display using the asset's decimals. Display-layer
 * only (invariant #16: the ZK layer never rescales). Mirrors the frontend's
 * `formatRawAmount` so the regulator view and the institution view agree.
 */
export function formatRawAmount(value: RawAmount, decimals = 7): string {
  // Logic kept byte-for-byte identical to frontend/lib/finnes-client.ts so the
  // regulator and institution views render the same string (FIN-015 should
  // de-duplicate by having the frontend re-export this).
  const neg = value < 0n;
  const abs = neg ? -value : value;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = abs % base;
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '');
  const s = fracStr ? `${whole}.${fracStr}` : `${whole}`;
  return neg ? `-${s}` : s;
}
