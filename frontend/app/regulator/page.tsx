'use client';

import { useEffect, useState } from 'react';
import { AuditorKeyInput } from '@/components/AuditorKeyInput';
import { TxList } from '@/components/TxList';
import { DisclosurePanel } from '@/components/DisclosurePanel';
import { FreezePanel } from '@/components/FreezePanel';
import { listOnChainTransactions, type OnChainTxSummary } from '@/lib/finnes-client';

/**
 * Regulator / Auditor view (ARCHITECTURE.md → Frontend): hold the auditor view
 * key, list on-chain transactions (the opaque public view), and decrypt the
 * mandatory auditor ciphertext for a selected tx to display the full
 * transaction. The regulator's read authority is the one that sees everything.
 */
export default function RegulatorPage() {
  const [txs, setTxs] = useState<OnChainTxSummary[]>([]);
  const [selected, setSelected] = useState<OnChainTxSummary | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    listOnChainTransactions().then((t) => {
      if (cancelled) return;
      setTxs(t);
      setLoaded(true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // The ledger is REAL on-chain data when the indexer returned live events
  // (FIN-019); it falls back to the deterministic demo fixture otherwise.
  const live = txs.length > 0 && !txs[0]!.isMock;

  return (
    <div className="mx-auto max-w-6xl space-y-8 px-6 py-10">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1.5">
          <span className="eyebrow">Regulator console</span>
          <h1 className="text-3xl font-extrabold tracking-tight text-ink">Regulator / Auditor</h1>
          <p className="text-sm text-ink-muted">
            The public sees opaque blobs. With the view key, you see everything.
          </p>
        </div>
        <a href="/institution" className="btn-ghost">
          ← Switch to Institution
        </a>
      </header>

      {loaded && (
        <p className="-mt-4 text-[11px] text-ink-faint">
          {live ? (
            <>
              <span className="chip chip-good mr-2">Live</span>
              On-chain ledger reconstructed from the deployed contract&apos;s events over Soroban RPC
              (FIN-019).
            </>
          ) : (
            <>
              <span className="chip mr-2">Demo</span>
              Showing the deterministic demo fixture, no live events in range (RPC unavailable or
              past Testnet&apos;s ~22h event retention). Crypto is still genuine.
            </>
          )}
        </p>
      )}

      {/* Step 1: the read authority. */}
      <AuditorKeyInput />

      {/* The reveal: opaque public ledger (left) → full disclosure (right). */}
      <div className="grid items-start gap-6 lg:grid-cols-2">
        <TxList txs={txs} selectedHash={selected?.txHash} onSelect={setSelected} />
        <DisclosurePanel tx={selected} />
      </div>

      {/* Clawback: the auditor (above) identifies cm_target; the issuer freezes it. */}
      <FreezePanel selected={selected} />
    </div>
  );
}
