/**
 * Deployment configuration for the live testnet wiring (FIN-027).
 *
 * Points the frontend at the DEPLOYED contract and the proving artifacts. The
 * contract id is the one recorded in setup/build/deploy.testnet.json (FIN-015);
 * override any value via NEXT_PUBLIC_* env vars for a different deployment.
 *
 * PUBLIC data only, a contract id, RPC URL, and artifact URLs are not secret.
 */

const env = (k: string, fallback: string): string =>
  (typeof process !== 'undefined' && process.env?.[k]) || fallback;

/** The deployed Finnes contract. REDEPLOYED FRESH 2026-06-28 (CBWSM7RW…) so the
 *  stateful indexer (FIN-029) tracks from genesis; the prior CD3AO6XD… tree aged out
 *  of RPC retention, which is what produced the `UnknownAnchorRoot` (#10) on transfer.
 *  Override per-deployment via NEXT_PUBLIC_FINNES_CONTRACT_ID. */
export const CONTRACT_ID = env(
  'NEXT_PUBLIC_FINNES_CONTRACT_ID',
  'CBWSM7RWD3OFCBNPPUSPA4QFFSF7FFRFO6HR3O52LN757AFUKCBZ7RFU',
);

/** Soroban RPC endpoint (Testnet). */
export const RPC_URL = env('NEXT_PUBLIC_SOROBAN_RPC_URL', 'https://soroban-testnet.stellar.org');

/**
 * Stateful indexer (FIN-029) base URL for the DRIFT-PROOF read path. When set,
 * the write-path reads the COMPLETE commitment tree + frozen set from it instead
 * of reconstructing from RPC `getEvents` — which only sees Testnet's event
 * retention window and silently drops aged-out leaves, producing the wrong
 * `anchor_root`/`old_frontier` and an `UnknownAnchorRoot` (#10) on transfer /
 * unshield. Empty → fall back to direct RPC reconstruction (fine for local dev
 * where all events are still in-window). Routes live under `${INDEXER_URL}/v1/…`.
 *
 * On Vercel set this to the same-origin proxy path `/indexer` (see the
 * `rewrites()` in next.config.mjs), so the HTTPS page never fetches the plain
 * HTTP indexer directly (mixed content). Read STATICALLY (not via the dynamic
 * `env()` helper) because this is consumed CLIENT-SIDE, and only literal
 * `process.env.NEXT_PUBLIC_*` reads are inlined into the browser bundle.
 */
export const INDEXER_URL = (process.env.NEXT_PUBLIC_INDEXER_URL || '').replace(/\/+$/, '');

/** Testnet network passphrase. */
export const NETWORK_PASSPHRASE = env(
  'NEXT_PUBLIC_NETWORK_PASSPHRASE',
  'Test SDF Network ; September 2015',
);

/** The demo TBOND Stellar Asset Contract (registered on-chain via register_asset). */
export const TBOND_SAC = env(
  'NEXT_PUBLIC_TBOND_SAC',
  'CBJMD3SAONL6X7CJO5SQPK42X5BWDKXBQBMUT5NBXI4SJAPZQZPPOZXM',
);

/** The underlying classic TBOND asset (the SAC wraps it 1:1). A trustline to this
 *  is what a wallet needs to hold TBOND; the SAC balance reads the same entry. */
export const TBOND_CODE = env('NEXT_PUBLIC_TBOND_CODE', 'TBOND');
export const TBOND_ISSUER = env(
  'NEXT_PUBLIC_TBOND_ISSUER',
  'GB66GONTENMTB5L5QXO7ARYR6HN7FAQG7MX6KCAJGHJIYUXE44JW37TD',
);

/** Horizon (classic) endpoint, for trustlines + the faucet payment. */
export const HORIZON_URL = env('NEXT_PUBLIC_HORIZON_URL', 'https://horizon-testnet.stellar.org');

/**
 * Base URL for the in-browser proving artifacts (option 2, client-side snarkjs).
 * Each circuit loads a `.wasm` (witness generator) and a `.zkey` (proving key).
 * They are served as STATIC files, but the two have very different size/limits, so
 * they are configured SEPARATELY:
 *
 * - **WASM** (small: shield 208KB / unshield 318KB / transfer 435KB) are COMMITTED
 *   under `frontend/public/artifacts/<c>/<c>.wasm`, so a git deploy (Vercel) serves
 *   them from ARTIFACT_BASE (`/artifacts`) with no extra setup.
 * - **ZKEY** (large: shield 31MB / unshield 64MB / transfer 105MB) are GITIGNORED
 *   (demo-only, invariant #10) AND exceed GitHub's 100MB file cap + Vercel's deploy
 *   limits, so they CANNOT ride a git deploy. On a deployed build, host them on
 *   external storage (Cloudflare R2 / S3 / a GitHub Release — CORS + HTTP range
 *   enabled) and point NEXT_PUBLIC_ZKEY_BASE there. Locally they live under
 *   `frontend/public/artifacts/<c>/` and ZKEY_BASE falls back to ARTIFACT_BASE, so
 *   `npm run dev` needs no env var.
 *
 * NOTE (Next.js inlining): only STATIC `process.env.NEXT_PUBLIC_*` reads are
 * inlined into the client bundle — the dynamic `env()` helper above resolves
 * server-side only, so its overrides do NOT reach the browser. The in-browser
 * prover runs client-side, so the ZKEY vars below are read STATICALLY on purpose.
 */
export const ARTIFACT_BASE = env('NEXT_PUBLIC_ARTIFACT_BASE', '/artifacts');

/** Where the large `.zkey` are served from (defaults to ARTIFACT_BASE for local dev). */
export const ZKEY_BASE = process.env.NEXT_PUBLIC_ZKEY_BASE || ARTIFACT_BASE;

export type CircuitName = 'shield' | 'transfer' | 'unshield';

/**
 * Optional per-circuit FULL `.zkey` URL overrides (win over ZKEY_BASE). Use these
 * for flat hosts that can't mirror the `<c>/<c>.zkey` layout — e.g. GitHub Release
 * assets, which are flat-named. Read statically so Next inlines them client-side.
 */
const ZKEY_URL_OVERRIDE: Record<CircuitName, string | undefined> = {
  shield: process.env.NEXT_PUBLIC_ZKEY_URL_SHIELD,
  transfer: process.env.NEXT_PUBLIC_ZKEY_URL_TRANSFER,
  unshield: process.env.NEXT_PUBLIC_ZKEY_URL_UNSHIELD,
};

/** Resolve the wasm + zkey URLs for a circuit's in-browser proof. */
export function artifactUrls(circuit: CircuitName): { wasmUrl: string; zkeyUrl: string } {
  return {
    wasmUrl: `${ARTIFACT_BASE}/${circuit}/${circuit}.wasm`,
    zkeyUrl: ZKEY_URL_OVERRIDE[circuit] || `${ZKEY_BASE}/${circuit}/${circuit}.zkey`,
  };
}
