/**
 * Soroban RPC adapter: paginated event fetch (ingestion) + read-only contract
 * simulation (the `current_root`/`leaf_count` cross-check). Mirrors the decode
 * pattern in `frontend/lib/indexer.ts`, server-side.
 */

import {
  rpc,
  scValToNative,
  Contract,
  TransactionBuilder,
  Account,
  BASE_FEE,
  Keypair,
} from '@stellar/stellar-sdk';
import { Buffer } from 'node:buffer';

import { CONTRACT_ID, RPC_URL, NETWORK_PASSPHRASE, EVENT_PAGE_LIMIT } from './config.js';

export interface RawEffect {
  topic: string;
  value: unknown;
  txHash: string;
  ledger: number;
  ledgerClosedAt: string;
}

const server = (): rpc.Server => new rpc.Server(RPC_URL);

export async function latestLedger(): Promise<number> {
  return (await server().getLatestLedger()).sequence;
}

/** One page of contract events, decoded to native objects. Follow `cursor` across
 *  pages (the caller terminates when the cursor stops advancing). */
export async function fetchEventsPage(opts: {
  startLedger?: number;
  cursor?: string;
}): Promise<{ effects: RawEffect[]; cursor: string | undefined }> {
  const s = server();
  const filters = [{ type: 'contract' as const, contractIds: [CONTRACT_ID] }];
  const req = opts.cursor
    ? { cursor: opts.cursor, filters, limit: EVENT_PAGE_LIMIT }
    : { startLedger: opts.startLedger ?? 1, filters, limit: EVENT_PAGE_LIMIT };
  const r = await s.getEvents(req as Parameters<typeof s.getEvents>[0]);
  const effects: RawEffect[] = r.events.map((ev) => ({
    topic: scValToNative(ev.topic[0]!) as string,
    value: scValToNative(ev.value),
    txHash: ev.txHash,
    ledger: ev.ledger,
    ledgerClosedAt: ev.ledgerClosedAt,
  }));
  return { effects, cursor: r.cursor };
}

/** Simulate a read-only contract call (no wallet, no fee). Best-effort: used only
 *  for the reconciliation cross-check, so callers guard failures. */
async function simulateRead(method: string): Promise<unknown> {
  const s = server();
  const source = Keypair.random().publicKey();
  const account = new Account(source, '0');
  const contract = new Contract(CONTRACT_ID);
  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: NETWORK_PASSPHRASE })
    .addOperation(contract.call(method))
    .setTimeout(30)
    .build();
  const sim = await s.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(sim.error);
  const retval = sim.result?.retval;
  return retval ? scValToNative(retval) : undefined;
}

/** Authoritative main-tree state from the contract, for the indexer cross-check. */
export async function chainState(): Promise<{ root: Buffer | null; leafCount: number }> {
  const root = (await simulateRead('current_root')) as Buffer | null | undefined;
  const leafCount = (await simulateRead('leaf_count')) as bigint | number | undefined;
  return { root: root ?? null, leafCount: Number(leafCount ?? 0) };
}
