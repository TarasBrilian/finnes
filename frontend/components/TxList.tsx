'use client';

import type { OnChainTxSummary } from '@/lib/finnes-client';
import { MockBadge } from './MockBadge';

function shortCm(c: bigint): string {
  const hex = c.toString(16);
  return hex.length <= 10 ? `0x${hex}` : `0x${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

/**
 * Lists on-chain transactions as the PUBLIC sees them: opaque commitments,
 * nullifiers, and ciphertext references — no amounts, no parties. Selecting a
 * row feeds the DisclosurePanel, which (with the view key) reveals everything.
 */
export function TxList({
  txs,
  selectedHash,
  onSelect,
}: {
  txs: OnChainTxSummary[];
  selectedHash?: string;
  onSelect: (tx: OnChainTxSummary) => void;
}) {
  return (
    <div className="card">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink">On-chain transactions (public view)</h3>
        {txs.some((t) => t.isMock) && <MockBadge />}
      </div>

      <ul className="divide-y divide-slate-100">
        {txs.map((tx) => {
          const active = tx.txHash === selectedHash;
          return (
            <li key={tx.txHash}>
              <button
                type="button"
                onClick={() => onSelect(tx)}
                className={[
                  'w-full rounded-lg px-3 py-3 text-left transition',
                  active ? 'bg-brand-50 ring-1 ring-brand-500' : 'hover:bg-slate-50',
                ].join(' ')}
              >
                <div className="flex items-center justify-between">
                  <span className="mono">{tx.txHash}</span>
                  <span className="badge bg-slate-100 text-slate-700">{tx.circuit}</span>
                </div>
                <div className="mt-1 text-[11px] text-ink-faint">{tx.timestamp}</div>
                <div className="mt-2 grid grid-cols-2 gap-2 text-[11px] text-ink-muted">
                  <div>
                    <span className="font-medium">nullifiers:</span>{' '}
                    {tx.nullifiers.length ? tx.nullifiers.join(', ') : '—'}
                  </div>
                  <div>
                    <span className="font-medium">commitments:</span>{' '}
                    {tx.outputCommitments.map(shortCm).join(', ')}
                  </div>
                </div>
              </button>
            </li>
          );
        })}
      </ul>

      <p className="mt-3 text-[11px] text-ink-faint">
        This is everything the public and competitors can see: opaque blobs. No amount, asset, or
        party is observable here.
      </p>
    </div>
  );
}
