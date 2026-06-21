/**
 * Threshold / multi-auditor view keys (FIN-020) — "no single honeypot".
 *
 * The auditor view key `k_view` (which decrypts every mandatory auditor ciphertext,
 * invariant #5) is the regulator's single most sensitive secret. Holding it in one
 * place is a honeypot. This module splits it across N authorities with a Shamir
 * k-of-n threshold scheme over the BLS12-381 scalar field `r`, so:
 *   - no single authority holds `k_view` (each holds one share),
 *   - any `k` authorities can combine their shares to reconstruct `k_view` and
 *     disclose, but fewer than `k` learn NOTHING about it,
 *   - the reconstructed `k_view` yields the SAME `auditor_pk = Poseidon(k_view)`
 *     the contract is initialised with — so this is purely off-chain key custody:
 *     the circuit, the contract, and the trusted setup are UNCHANGED.
 *
 * Pure field arithmetic (polynomial evaluation + Lagrange interpolation over `r`) —
 * no embedded curve, no new in-circuit primitive (invariant #1). To disclose, a
 * quorum runs `combineShares(...)` to recover `k_view`, then the existing
 * `discloseTransaction` (sdk/src/disclose.ts) path.
 *
 * SCOPE — this is threshold *custody*, not threshold *decryption*: the shares
 * reconstruct the full `k_view` at the disclosing node, so that one node briefly
 * holds the key at use-time. It removes the AT-REST honeypot (no single party
 * stores `k_view`; a quorum is required even to form it). True
 * decrypt-without-reconstructing needs a threshold PRF over the additive keystream
 * — a new primitive, deliberately out of scope (it would break invariant #1's
 * "Poseidon-BLS only" surface). The quorum should reconstruct in an isolated zone.
 *
 * SECURITY (invariant #8): a share (`y`) and the reconstructed `k_view` are
 * secrets. NEVER log/persist/transmit them outside an authority's own zone.
 */

import type { Fr } from './types.js';
import { FR_MODULUS, toField } from './poseidon.js';
import { auditorPkFromKey } from './encrypt.js';
import type { AuditorPublicKey } from './types.js';

const R = FR_MODULUS;

/** Reduce into `[0, r)` (handles negatives). */
const mod = (x: bigint): Fr => (((x % R) + R) % R) as Fr;

/** Modular exponentiation `base^exp mod r`. */
function modPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result;
}

/** Modular inverse over the prime field `r` (Fermat: a^(r-2) mod r). Throws on 0. */
function modInverse(a: bigint): bigint {
  const x = mod(a);
  if (x === 0n) throw new Error('threshold: no modular inverse of 0 (duplicate share x?)');
  return modPow(x, R - 2n);
}

/** One authority's share of the view key: the point `(x, y) = (x, P(x))`. */
export interface KeyShare {
  /** Evaluation point (authority index, 1-based; never 0 — `P(0)` is the secret). */
  readonly x: Fr;
  /** Polynomial value `P(x) mod r` — this authority's secret share. */
  readonly y: Fr;
}

export interface SplitOptions {
  /** Quorum size `k`: any `k` shares reconstruct the key; `k-1` learn nothing. */
  readonly threshold: number;
  /** Total authorities `n` (`>= threshold`). One share each. */
  readonly total: number;
  /**
   * The `k-1` non-constant polynomial coefficients `[a_1, …, a_{k-1}]`. Optional —
   * supply for deterministic tests; otherwise pass `randomCoefficients(k)`. The
   * constant term is fixed to `k_view`, so it is NOT included here.
   */
  readonly coefficients?: readonly Fr[];
}

/**
 * Split `kView` into `total` Shamir shares with quorum `threshold`. The secret is
 * `P(0) = kView` of a degree-`(threshold-1)` polynomial; share `i` is `(i, P(i))`
 * for `i = 1..total`. Reconstruct with {@link combineShares}.
 */
export function splitViewKey(kView: Fr, opts: SplitOptions): KeyShare[] {
  const { threshold: k, total: n } = opts;
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 1 || n < k) {
    throw new Error(`threshold: require 1 <= threshold(${k}) <= total(${n})`);
  }
  const coeffs = opts.coefficients ?? randomCoefficients(k);
  if (coeffs.length !== k - 1) {
    throw new Error(`threshold: expected ${k - 1} coefficient(s), got ${coeffs.length}`);
  }
  // P(x) = kView + a_1·x + … + a_{k-1}·x^{k-1}  (mod r)
  const poly: Fr[] = [toField(kView), ...coeffs.map(toField)];
  const shares: KeyShare[] = [];
  for (let i = 1; i <= n; i++) {
    const x = BigInt(i);
    let y = 0n;
    let xp = 1n; // x^j
    for (const c of poly) {
      y = mod(y + c * xp);
      xp = mod(xp * x);
    }
    shares.push({ x: mod(x), y: mod(y) });
  }
  return shares;
}

/**
 * Reconstruct the secret `P(0) = k_view` from `>= threshold` shares via Lagrange
 * interpolation at `x = 0`. Uses ALL provided shares (pass exactly a quorum, or
 * more). Shares must have distinct `x`. Fewer than `threshold` valid shares yield
 * a wrong value (the scheme leaks nothing below quorum, by design).
 */
export function combineShares(shares: readonly KeyShare[]): Fr {
  if (shares.length === 0) throw new Error('threshold: no shares to combine');
  const xs = shares.map((s) => mod(s.x));
  if (new Set(xs.map(String)).size !== xs.length) {
    throw new Error('threshold: duplicate share x (shares must be distinct)');
  }
  if (xs.some((x) => x === 0n)) throw new Error('threshold: share x=0 is the secret, not a share');

  let secret = 0n;
  for (let i = 0; i < shares.length; i++) {
    // L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j) = Π_{j≠i} (-x_j) · (x_i - x_j)^{-1}
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < shares.length; j++) {
      if (j === i) continue;
      num = mod(num * mod(-xs[j]!));
      den = mod(den * mod(xs[i]! - xs[j]!));
    }
    const li0 = mod(num * modInverse(den));
    secret = mod(secret + mod(shares[i]!.y * li0));
  }
  return secret;
}

/**
 * The auditor public key the contract enforces, derived from a quorum of shares
 * (`Poseidon(reconstructed k_view)`). Equals `auditorPkFromKey(k_view)` for the
 * original key, so a threshold-custodied key is a drop-in for the single-key init.
 */
export function auditorPkFromShares(shares: readonly KeyShare[]): AuditorPublicKey {
  return auditorPkFromKey(combineShares(shares));
}

/** Cryptographically-random `k-1` field coefficients for a fresh split. */
export function randomCoefficients(threshold: number): Fr[] {
  const out: Fr[] = [];
  for (let i = 0; i < threshold - 1; i++) out.push(randomFr());
  return out;
}

/** A uniform-ish field element from 32 secure random bytes (reduced mod r). */
function randomFr(): Fr {
  // Web Crypto global (Node >= 18 and browsers). Typed structurally to avoid a
  // DOM-lib dependency in the SDK's node tsconfig.
  const c = (globalThis as { crypto?: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto;
  if (!c?.getRandomValues) {
    throw new Error('threshold: no secure RNG; pass explicit `coefficients` to splitViewKey');
  }
  const b = new Uint8Array(32);
  c.getRandomValues(b);
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return mod(x);
}
