'use client';

import { useEffect, useState } from 'react';
import { AuditorKeyInput } from '@/components/AuditorKeyInput';
import { TxList } from '@/components/TxList';
import { DisclosurePanel } from '@/components/DisclosurePanel';
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

  useEffect(() => {
    let cancelled = false;
    listOnChainTransactions().then((t) => !cancelled && setTxs(t));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-8">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">Regulator / Auditor</h1>
          <p className="text-sm text-ink-muted">
            The public sees opaque blobs. With the view key, you see everything.
          </p>
        </div>
        <a href="/institution" className="btn-ghost">
          ← Switch to Institution
        </a>
      </header>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-1">
          <AuditorKeyInput />
        </div>

        <div className="lg:col-span-1">
          <TxList txs={txs} selectedHash={selected?.txHash} onSelect={setSelected} />
        </div>

        <div className="lg:col-span-1">
          <DisclosurePanel tx={selected} />
        </div>
      </div>

      <p className="text-[11px] text-ink-faint">
        Clawback is a separate two-phase / two-key flow (auditor identifies cm_target via the view
        key; issuer_authority freezes it). Not part of this scaffold — see ARCHITECTURE.md → Clawback
        &amp; freeze.
      </p>
    </div>
  );
}
