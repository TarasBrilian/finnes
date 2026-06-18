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

      {/* Step 1: the read authority. */}
      <AuditorKeyInput />

      {/* The reveal: opaque public ledger (left) → full disclosure (right). */}
      <div className="grid items-start gap-6 lg:grid-cols-2">
        <TxList txs={txs} selectedHash={selected?.txHash} onSelect={setSelected} />
        <DisclosurePanel tx={selected} />
      </div>

      <p className="text-[11px] leading-relaxed text-ink-faint">
        Clawback is a separate two-phase / two-key flow (auditor identifies cm_target via the view
        key; issuer_authority freezes it). Not part of this scaffold — see ARCHITECTURE.md → Clawback
        &amp; freeze.
      </p>
    </div>
  );
}
