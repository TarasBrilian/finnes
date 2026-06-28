/**
 * Indexer configuration (FIN-029). All values are PUBLIC (a contract id, an RPC
 * URL, a DB connection string) — no secret is ever read here (invariant #8).
 */

const env = (k: string, fallback: string): string => process.env[k] ?? fallback;

/** The Finnes contract to index. Pair with a FRESH redeploy so the indexer can
 *  capture every leaf from genesis (the prior contract's early leaves aged out of
 *  RPC and cannot be recovered — see docs/INDEXER_IMPLEMENTATION.md §10). */
export const CONTRACT_ID = env(
  'CONTRACT_ID',
  'CD3AO6XDA632MC35OYHM6TLO4Q3GJZA67VSUUSTRGLSBD3OTKF2FOYCF',
);

export const RPC_URL = env('RPC_URL', 'https://soroban-testnet.stellar.org');
export const NETWORK_PASSPHRASE = env('NETWORK_PASSPHRASE', 'Test SDF Network ; September 2015');

/** Contract deploy ledger = genesis. If 0, the worker falls back to
 *  `latest - RETENTION_LEDGERS` (and logs a warning) — only correct for a contract
 *  whose whole history is still inside RPC retention. */
export const START_LEDGER = Number(env('START_LEDGER', '0'));

export const DATABASE_URL = env('DATABASE_URL', '');
export const PORT = Number(env('PORT', '8080'));

/** Tail poll cadence + how many ledgers to lag behind `latest` for finality. */
export const POLL_INTERVAL_MS = Number(env('POLL_INTERVAL_MS', '4000'));
export const FINALITY_LAG = Number(env('FINALITY_LAG', '0'));

/** getEvents page size and the RPC retention fallback window (~22h on Testnet). */
export const EVENT_PAGE_LIMIT = 200;
export const RETENTION_LEDGERS = 17000;

/** Tree selector values stored in the DB (`tree` column). */
export const TREE_MAIN = 0;
export const TREE_ESCROW = 1;
