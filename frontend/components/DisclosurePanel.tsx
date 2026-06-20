'use client';

import { useState } from 'react';
import {
  decryptAuditorView,
  formatRawAmount,
  type DecryptedAuditView,
  type OnChainTxSummary,
} from '@/lib/finnes-client';
import { useAuditorKeypair } from '@/lib/use-keys';

/**
 * The demo's climax: with the auditor view key, decrypt the mandatory auditor
 * ciphertext for the selected tx and reveal the FULL transaction - amount,
 * asset, parties - that the public cannot see.
 *
 * SECURITY: the view key and the decrypted plaintext stay in this tab; never
 * logged or sent to a backend (invariant #8).
 *
 * REAL (FIN-014/015): decryptAuditorView runs the SDK's discloseTransaction over
 * the demo ledger's genuine auditor ciphertexts. A non-matching view key fails to
 * decrypt and surfaces an honest error rather than a fabricated reveal.
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
    <div className="card lg:sticky lg:top-24">
      <h3 className="text-base font-bold text-ink">Selective disclosure</h3>
      <p className="mt-0.5 text-xs text-ink-muted">
        The public sees nothing. With the view key, you see everything.
      </p>

      {!tx && (
        <div className="mt-6 rounded-xl border border-dashed border-blue-200 bg-blue-50/40 p-6 text-center">
          <p className="text-sm text-ink-muted">
            Select a transaction from the ledger to inspect it.
          </p>
        </div>
      )}

      {tx && (
        <div className="mt-4 space-y-4">
          <div className="rounded-xl bg-blue-50/70 p-3.5 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-medium text-ink">{tx.txHash}</span>
              <span className="badge border border-blue-200 bg-white capitalize text-blue-700">
                {tx.circuit}
              </span>
            </div>
            <p className="mt-2 leading-relaxed text-ink-muted">
              {tx.outputs.length} output note{tx.outputs.length === 1 ? '' : 's'} ·{' '}
              {tx.outputs[0]?.cAuditor.fields.length ?? 0} field-packed auditor-ciphertext elements
              each, bound to the proof as public inputs (invariant #5).
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
            <p className="text-center text-xs text-ink-faint">
              Load the auditor view key above to decrypt.
            </p>
          )}
          {error && <p className="text-xs text-rose-700">{error}</p>}

          {view && (
            <div className="panel-navy animate-fade-up p-5">
              <div
                aria-hidden="true"
                className="pointer-events-none absolute -bottom-6 -right-6 h-32 w-1/2 bg-contain bg-right-bottom bg-no-repeat opacity-30"
                style={{ backgroundImage: 'url(/mega-mendung.svg)' }}
              />
              <div className="relative">
                <div className="flex items-center justify-between gap-2">
                  <span className="eyebrow-light">Full transaction · visible only to you</span>
                </div>

                <p className="mt-4 text-xs font-medium uppercase tracking-wide text-blue-200/80">
                  {view.assetLabel}
                </p>
                <p className="stat mt-1 text-white">{formatRawAmount(view.rawAmount)}</p>

                <dl className="mt-5 space-y-2.5 border-t border-white/10 pt-4 text-sm">
                  <div className="flex items-start justify-between gap-4">
                    <dt className="text-blue-200/70">Sender</dt>
                    <dd className="break-all text-right font-mono text-blue-50">{view.senderPk}</dd>
                  </div>
                  <div className="flex items-start justify-between gap-4">
                    <dt className="text-blue-200/70">Recipient</dt>
                    <dd className="break-all text-right font-mono text-blue-50">
                      {view.recipientPk}
                    </dd>
                  </div>
                </dl>

                {view.outputs.length > 1 && (
                  <ul className="mt-4 space-y-1.5 border-t border-white/10 pt-4 text-xs">
                    {view.outputs.map((o, i) => (
                      <li key={i} className="flex items-center justify-between gap-3">
                        <span className="capitalize text-blue-200/70">
                          {o.role} · {o.party}
                        </span>
                        <span className="font-mono text-blue-50">
                          {formatRawAmount(o.rawAmount, o.decimals)} {o.assetLabel.split(' ')[0]}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
