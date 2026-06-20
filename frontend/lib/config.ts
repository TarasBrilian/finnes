/**
 * Deployment configuration for the live testnet wiring (FIN-027).
 *
 * Points the frontend at the DEPLOYED contract and the proving artifacts. The
 * contract id is the one recorded in setup/build/deploy.testnet.json (FIN-015);
 * override any value via NEXT_PUBLIC_* env vars for a different deployment.
 *
 * PUBLIC data only — a contract id, RPC URL, and artifact URLs are not secret.
 */

const env = (k: string, fallback: string): string =>
  (typeof process !== 'undefined' && process.env?.[k]) || fallback;

/** The deployed Finnes contract (FIN-015). */
export const CONTRACT_ID = env(
  'NEXT_PUBLIC_FINNES_CONTRACT_ID',
  'CDIWXQSWIP6GKJKCAZPFONDD7VZ2PR2AQVCBQ7WRNTL64M3DAP55G7IA',
);

/** Soroban RPC endpoint (Testnet). */
export const RPC_URL = env('NEXT_PUBLIC_SOROBAN_RPC_URL', 'https://soroban-testnet.stellar.org');

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

/** Horizon (classic) endpoint — for trustlines + the faucet payment. */
export const HORIZON_URL = env('NEXT_PUBLIC_HORIZON_URL', 'https://horizon-testnet.stellar.org');

/**
 * Base URL for the in-browser proving artifacts (option 2 — client-side snarkjs).
 * Each circuit loads `${ARTIFACT_BASE}/<circuit>/<circuit>.wasm` and
 * `${ARTIFACT_BASE}/<circuit>/<circuit>.zkey`. These are served as STATIC files
 * from `frontend/public/artifacts/` (gitignored — the operator copies the D=20
 * .wasm/.zkey there; the .zkey are large: shield 31MB / unshield 64MB /
 * transfer 110MB, and demo-only per invariant #10, so never committed).
 */
export const ARTIFACT_BASE = env('NEXT_PUBLIC_ARTIFACT_BASE', '/artifacts');

export type CircuitName = 'shield' | 'transfer' | 'unshield';

/** Resolve the wasm + zkey URLs for a circuit's in-browser proof. */
export function artifactUrls(circuit: CircuitName): { wasmUrl: string; zkeyUrl: string } {
  return {
    wasmUrl: `${ARTIFACT_BASE}/${circuit}/${circuit}.wasm`,
    zkeyUrl: `${ARTIFACT_BASE}/${circuit}/${circuit}.zkey`,
  };
}
