'use client';

import type { OnChainTxSummary } from '@/lib/finnes-client';

function shortCm(c: bigint): string {
  const hex = c.toString(16);
  return hex.length <= 10 ? `0x${hex}` : `0x${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

/**
 * Lists on-chain transactions as the PUBLIC sees them: opaque commitments,
 * nullifiers, and ciphertext references - no amounts, no parties. Selecting a
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
      <div className="mb-1 flex items-center justify-between gap-3">
        <h3 className="text-base font-bold text-ink">On-chain ledger</h3>
      </div>
      <p className="mb-4 text-xs text-ink-muted">
        Exactly what the public and competitors can see - opaque blobs only.
      </p>

      <ul className="space-y-2">
        {txs.map((tx) => {
          const active = tx.txHash === selectedHash;
          return (
            <li key={tx.txHash}>
              <button
                type="button"
                onClick={() => onSelect(tx)}
                aria-current={active ? 'true' : undefined}
                className={[
                  'w-full rounded-xl border px-4 py-3 text-left transition',
                  active
                    ? 'border-blue-500 bg-blue-50 ring-1 ring-blue-500'
                    : 'border-blue-100 hover:border-blue-200 hover:bg-blue-50/50',
                ].join(' ')}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-medium text-ink">{tx.txHash}</span>
                  <span className="badge border border-blue-200 bg-white capitalize text-blue-700">
                    {tx.circuit}
                  </span>
                </div>
                <div className="mt-1 font-mono text-[11px] text-ink-faint">{tx.timestamp}</div>
                <dl className="mt-2.5 grid grid-cols-2 gap-2 text-[11px] text-ink-muted">
                  <div className="min-w-0">
                    <dt className="font-semibold uppercase tracking-wide text-ink-faint">
                      nullifiers
                    </dt>
                    <dd className="truncate font-mono">
                      {tx.nullifiers.length ? tx.nullifiers.join(', ') : '-'}
                    </dd>
                  </div>
                  <div className="min-w-0">
                    <dt className="font-semibold uppercase tracking-wide text-ink-faint">
                      commitments
                    </dt>
                    <dd className="truncate font-mono">
                      {tx.outputs.map((o) => shortCm(o.commitment)).join(', ')}
                    </dd>
                  </div>
                </dl>
              </button>
            </li>
          );
        })}
      </ul>

      <p className="mt-4 flex items-start gap-2 border-t border-blue-100 pt-3 text-[11px] leading-relaxed text-ink-faint">
        <span aria-hidden="true" className="mt-px">
          🔒
        </span>
        No amount, asset, or counterparty is observable here - only the regulator, holding the view
        key, can resolve it.
      </p>
    </div>
  );
}
