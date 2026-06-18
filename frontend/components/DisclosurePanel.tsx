'use client';

import { useState } from 'react';
import {
  decryptAuditorView,
  formatRawAmount,
  type DecryptedAuditView,
  type OnChainTxSummary,
} from '@/lib/finnes-client';
import { useAuditorKeypair } from '@/lib/use-keys';
import { MockBadge } from './MockBadge';

/**
 * The demo's climax: with the auditor view key, decrypt the mandatory auditor
 * ciphertext for the selected tx and reveal the FULL transaction — amount,
 * asset, parties — that the public cannot see.
 *
 * SECURITY: the view key and the decrypted plaintext stay in this tab; never
 * logged or sent to a backend (invariant #8).
 *
 * SCAFFOLD: sdk decryption throws (scheme not fixed), so decryptAuditorView
 * returns a clearly-labelled MOCK plaintext. We never claim real decryption.
 */
export function DisclosurePanel({ tx }: { tx: OnChainTxSummary | null }) {
  const auditor = useAuditorKeypair();
  const [view, setView] = useState<DecryptedAuditView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onDecrypt() {
    if (!tx || !auditor) return;
    setBusy(true);
    setError(null);
    setView(null);
    try {
      setView(await decryptAuditorView(tx, auditor));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Decryption failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-ink">Selective disclosure</h3>
      <p className="mt-0.5 text-xs text-ink-muted">
        Public sees nothing; the regulator sees everything.
      </p>

      {!tx && <p className="mt-4 text-sm text-ink-muted">Select a transaction to inspect.</p>}

      {tx && (
        <div className="mt-4 space-y-4">
          <div className="rounded-lg bg-slate-50 p-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="mono">{tx.txHash}</span>
              <span className="badge bg-slate-100 text-slate-700">{tx.circuit}</span>
            </div>
            <p className="mt-2 text-ink-muted">
              Auditor ciphertext (field-packed, {tx.cAuditor.fields.length} elements) bound to the
              proof as a public input (invariant #5).
            </p>
          </div>

          <button
            type="button"
            className="btn-primary w-full"
            onClick={onDecrypt}
            disabled={!auditor || busy}
          >
            {busy ? 'Decrypting…' : 'Decrypt with view key'}
          </button>
          {!auditor && (
            <p className="text-xs text-ink-faint">Load the auditor view key to decrypt.</p>
          )}
          {error && <p className="text-xs text-rose-700">{error}</p>}

          {view && (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4">
              <div className="mb-3 flex items-center justify-between">
                <h4 className="text-sm font-semibold text-emerald-900">Full transaction</h4>
                {view.isMock && <MockBadge label="mock decryption" />}
              </div>
              <dl className="space-y-2 text-sm text-emerald-900">
                <div className="flex justify-between gap-4">
                  <dt className="text-emerald-700">Asset</dt>
                  <dd className="text-right">{view.assetLabel}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-emerald-700">Amount</dt>
                  <dd className="text-right font-mono">{formatRawAmount(view.rawAmount)}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-emerald-700">Sender</dt>
                  <dd className="text-right font-mono break-all">{view.senderPk}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-emerald-700">Recipient</dt>
                  <dd className="text-right font-mono break-all">{view.recipientPk}</dd>
                </div>
              </dl>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
