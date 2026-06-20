'use client';

import { useEffect, useState } from 'react';
import {
  formatRawAmount,
  scanConfidentialBalances,
  type ConfidentialBalance,
} from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';

/**
 * The institution's confidential position - discovered by scanning on-chain
 * ciphertexts with the viewing key (ARCHITECTURE.md → Frontend). Rendered as the
 * dashboard's primary anchor: a deep navy panel with large per-asset figures.
 * The institution sees only its OWN notes.
 *
 * REAL (FIN-014/015): balances come from the SDK's scanForOwnedNotes — a genuine
 * trial-decrypt + commitment re-derivation over a local demo ciphertext fixture
 * (indexer stand-in). Per-asset figures are NOT summed across assets (invariant
 * #3 spirit - no cross-asset total).
 */
export function ConfidentialBalances({ spending }: { spending: SpendingKeypair | null }) {
  const [balances, setBalances] = useState<ConfidentialBalance[] | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!spending) {
      setBalances(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    scanConfidentialBalances(spending)
      .then((b) => !cancelled && setBalances(b))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [spending]);

  return (
    <section className="panel-navy p-7 sm:p-8">
      {/* faint cloud watermark, bottom-right */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -bottom-8 -right-8 h-48 w-2/3 bg-contain bg-right-bottom bg-no-repeat opacity-40"
        style={{ backgroundImage: 'url(/mega-mendung.svg)' }}
      />
      <div className="relative">
        <div className="flex items-center justify-between">
          <span className="eyebrow-light">Confidential position</span>
        </div>

        {!spending && (
          <p className="mt-5 max-w-md text-sm text-blue-100/80">
            Generate a shielded key to scan on-chain ciphertexts and reveal the notes you own.
          </p>
        )}

        {spending && loading && (
          <p className="mt-5 text-sm text-blue-100/80">Scanning ciphertexts…</p>
        )}

        {spending && balances && balances.length === 0 && (
          <p className="mt-5 text-sm text-blue-100/80">No owned notes discovered.</p>
        )}

        {spending && balances && balances.length > 0 && (
          <div className="mt-6 grid gap-x-10 gap-y-7 sm:grid-cols-2">
            {balances.map((b, i) => (
              <div
                key={b.assetId.toString()}
                className="animate-fade-up"
                style={{ animationDelay: `${i * 70}ms` }}
              >
                <p className="text-xs font-medium uppercase tracking-wide text-blue-200/80">
                  {b.assetLabel}
                </p>
                <p className="stat mt-1.5 text-white">{formatRawAmount(b.rawAmount)}</p>
                <p className="mt-1 text-xs text-blue-200/60">
                  {b.noteCount} note{b.noteCount === 1 ? '' : 's'} · raw SAC units
                </p>
              </div>
            ))}
          </div>
        )}

        <p className="relative mt-7 max-w-2xl border-t border-white/10 pt-4 text-[11px] leading-relaxed text-blue-200/60">
          Discovered by trial-decrypting on-chain ciphertexts client-side. Amounts are raw SAC units
          formatted with display decimals; the ZK layer never rescales (invariant #16). Balances are
          per-asset and never summed across assets.
        </p>
      </div>
    </section>
  );
}
