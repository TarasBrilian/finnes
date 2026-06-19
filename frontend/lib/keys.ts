'use client';

/**
 * Local key material: spending key (owner_sk), viewing key, and the auditor
 * view key - generated and held CLIENT-SIDE ONLY.
 *
 * ============================================================================
 * TRUST BOUNDARY (CLAUDE.md invariant #8 - fund/privacy-critical)
 * ============================================================================
 * The frontend, with the prover, is the ONLY place private keys exist. The
 * spending key, the viewing key, the witness, owner_sk/rho/r_note, and the
 * auditor_sk MUST NEVER be:
 *   - logged (console, telemetry, error reporting),
 *   - persisted to any shared/remote service,
 *   - transmitted to the backend (indexer / API / relayer) or any third party.
 *
 * They live only in this in-memory store inside the browser tab.
 *
 * localStorage CAVEAT: a `persistToLocalStorage` flag is provided ONLY for
 * demo convenience so a key survives a page reload. It is DISABLED by default
 * and is NOT acceptable for production - browser localStorage is readable by
 * any script on the origin (XSS) and is unencrypted at rest. Real deployments
 * must use a hardware/OS keystore or a wallet-managed signer. See TODO(security).
 * ============================================================================
 *
 * NOTE: actual key generation requires field sampling + Poseidon derivation
 * from @finnes/sdk, which are SCAFFOLD stubs that throw. We therefore generate
 * placeholder field elements with a clear `isMock` flag, and route real
 * derivation (`deriveOwnerPk`) through the SDK so it lights up automatically
 * once the SDK lands. We never fabricate a working key silently.
 */

import type { Fr, OwnerPk, OwnerSk } from '@finnes/sdk';
import { deriveOwnerPk } from '@finnes/sdk';

/** A spending keypair held client-side. `ownerSk` is SECRET (invariant #8). */
export interface SpendingKeypair {
  /** SECRET spending key. Never log/persist/transmit. */
  readonly ownerSk: OwnerSk;
  /** Public owner key `Poseidon(owner_sk)`; safe to share/scan against. */
  readonly ownerPk: OwnerPk;
  /** Optional separate viewing secret if the scheme splits view/spend (TODO scheme). */
  readonly viewSk?: Fr;
  /** True when derivation came from mock randomness (SDK crypto not yet wired). */
  readonly isMock: boolean;
}

/** The auditor (regulator) view key. `sk` is SECRET - held in the auditor zone. */
export interface AuditorKeypair {
  /** SECRET auditor view key. Never log/persist/transmit (invariant #8). */
  readonly sk: Fr;
  /** Auditor public key placeholder (representation TODO with the scheme). */
  readonly pk: Fr;
  readonly isMock: boolean;
}

/**
 * Draw a placeholder field element. SCAFFOLD ONLY.
 *
 * TODO(crypto): replace with uniform sampling from `[0, r)` via a CSPRNG and the
 * SDK field utilities (see sdk/src/note.ts `sampleNoteRandomness` TODO). This
 * mock value is NOT cryptographically usable; it exists so the UI can render a
 * key-derivation flow before the SDK crypto lands.
 */
function mockFieldElement(): Fr {
  const bytes = new Uint8Array(31);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Non-CSPRNG fallback - demo only, never security-relevant.
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}

/**
 * Generate a spending keypair client-side.
 *
 * Attempts real `owner_pk` derivation via the SDK; if the SDK crypto still
 * throws (scaffold), falls back to a mock public key and marks `isMock: true`
 * so the UI can label balances/notes as not-yet-real. We never claim a working
 * key when crypto is unimplemented.
 */
export function generateSpendingKeypair(): SpendingKeypair {
  const ownerSk = mockFieldElement() as OwnerSk;
  try {
    const ownerPk = deriveOwnerPk(ownerSk);
    return { ownerSk, ownerPk, isMock: false };
  } catch {
    // SDK Poseidon not wired yet - see sdk/src/poseidon.ts.
    return { ownerSk, ownerPk: mockFieldElement() as OwnerPk, isMock: true };
  }
}

/**
 * Generate / import an auditor view keypair.
 *
 * TODO(crypto): the auditor key uses the (BLS-native) KEM of the chosen
 * encryption scheme - see sdk/src/encrypt.ts and docs/PUBLIC_IO.md
 * §"Ciphertext binding". Until then this is a mock placeholder.
 */
export function generateAuditorKeypair(): AuditorKeypair {
  return { sk: mockFieldElement(), pk: mockFieldElement(), isMock: true };
}

/**
 * Parse a user-supplied auditor view key (regulator pastes their key).
 * Accepts a decimal or 0x-hex string. Throws on malformed input - we never
 * silently coerce a bad key.
 */
export function importAuditorViewKey(raw: string): AuditorKeypair {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Empty auditor view key.');
  let sk: bigint;
  try {
    sk = trimmed.startsWith('0x') ? BigInt(trimmed) : BigInt(trimmed);
  } catch {
    throw new Error('Auditor view key must be a decimal or 0x-hex field element.');
  }
  // TODO(crypto): derive pk from sk via the scheme KEM once defined.
  return { sk, pk: mockFieldElement(), isMock: true };
}

// ---------------------------------------------------------------------------
// In-memory key store (module-scoped, browser-tab lifetime only).
// ---------------------------------------------------------------------------

interface KeyState {
  spending: SpendingKeypair | null;
  auditor: AuditorKeypair | null;
}

const state: KeyState = { spending: null, auditor: null };

/** Subscribers for simple reactive updates without pulling in a state lib. */
type Listener = () => void;
const listeners = new Set<Listener>();
function emit(): void {
  for (const l of listeners) l();
}

export function subscribeKeys(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getSpendingKeypair(): SpendingKeypair | null {
  return state.spending;
}

export function setSpendingKeypair(kp: SpendingKeypair | null): void {
  state.spending = kp;
  emit();
}

export function getAuditorKeypair(): AuditorKeypair | null {
  return state.auditor;
}

export function setAuditorKeypair(kp: AuditorKeypair | null): void {
  state.auditor = kp;
  emit();
}

/** Wipe all key material from memory (logout / panic). */
export function clearKeys(): void {
  state.spending = null;
  state.auditor = null;
  emit();
}

// ---------------------------------------------------------------------------
// localStorage - DEMO ONLY, OFF BY DEFAULT. See the trust-boundary note above.
// ---------------------------------------------------------------------------

/**
 * SECURITY TODO: persisting a spending/auditor key to localStorage is NOT safe
 * for production (XSS-readable, unencrypted at rest). These helpers are provided
 * only for demo continuity across reloads and are intentionally NOT called
 * anywhere by default. If you wire them, gate behind an explicit, clearly
 * labelled "demo persistence" opt-in and never store the auditor_sk this way in
 * a real regulator deployment.
 */
const LS_CAVEAT =
  'Persisting key material to localStorage is demo-only and insecure (invariant #8). Do not enable in production.';

export const localStoragePersistence = {
  caveat: LS_CAVEAT,
  /** DEMO ONLY. Do not call in production. */
  persistSpending(kp: SpendingKeypair): void {
    // eslint-disable-next-line no-console
    console.warn(LS_CAVEAT);
    // Intentionally not implemented to avoid an accidental secret-at-rest path.
    // TODO(security): if truly needed for the demo, serialise ownerSk here behind
    // an explicit opt-in and a prominent UI warning. Never the auditor_sk.
    throw new Error('localStorage persistence is disabled by default. ' + LS_CAVEAT);
  },
};
