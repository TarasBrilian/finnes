'use client';

import { useEffect, useState } from 'react';
import {
  formatRawAmount,
  scanConfidentialBalances,
  type ConfidentialBalance,
} from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';

/**
 * The institution's confidential position, its unspent notes on the live
 * commitment tree (ARCHITECTURE.md → Frontend). Rendered as the dashboard's
 * primary anchor: a deep navy panel with large per asset figures. The institution
 * sees only its OWN notes.
 *
 * REAL & LIVE (FIN-027/019): balances are the session identity's unspent on chain
 * notes, commitments present in the contract's event-reconstructed tree and not
 * yet nullified (read live), i.e. exactly what the Transfer/Unshield tabs can
 * spend. Per asset figures are NOT summed across assets (invariant #3/#16). Falls
 * back to a deterministic demo fixture (flagged "Demo") only if RPC is unavailable.
 */
export function ConfidentialBalances({ spending }: { spending: SpendingKeypair | null }) {
  const [balances, setBalances] = useState<ConfidentialBalance[] | null>(null);
  const [loading, setLoading] = useState(false);
  const isMock = balances?.some((b) => b.isMock) ?? false;

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

  const totalNotes = balances?.reduce((n, b) => n + b.noteCount, 0) ?? 0;

  return (
    <section className="panel-navy p-7 sm:p-9">
      {/* faint cloud watermark, bottom-right */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -bottom-8 -right-8 h-48 w-2/3 bg-contain bg-right-bottom bg-no-repeat opacity-40"
        style={{ backgroundImage: 'url(/mega-mendung.svg)' }}
      />
      {/* top hairline glow */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-accent/50 to-transparent"
      />
      <div className="relative">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="eyebrow-light">Confidential position</span>
          {spending && balances && balances.length > 0 && (
            <span className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-3 py-1 text-[11px] font-medium text-blue-100/80">
              <span
                aria-hidden="true"
                className={`inline-block h-1.5 w-1.5 rounded-full ${isMock ? 'bg-amber-300' : 'animate-glowpulse bg-accent'}`}
              />
              {balances.length} asset{balances.length === 1 ? '' : 's'} · {totalNotes} note
              {totalNotes === 1 ? '' : 's'} · {isMock ? 'demo fixture (RPC offline)' : 'live on chain'}
            </span>
          )}
        </div>

        {!spending && (
          <p className="mt-5 max-w-md text-sm text-blue-100/80">
            Generate a shielded key to load your unspent notes on the live commitment tree.
          </p>
        )}

        {spending && loading && (
          <p className="mt-5 flex items-center gap-2 text-sm text-blue-100/80">
            <span aria-hidden="true" className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-blue-200/40 border-t-accent" />
            Reading your on chain notes…
          </p>
        )}

        {spending && balances && balances.length === 0 && (
          <p className="mt-5 text-sm text-blue-100/80">
            No unspent notes on chain yet. Shield a deposit to mint your first confidential note.
          </p>
        )}

        {spending && balances && balances.length > 0 && (
          <div className="mt-7 grid gap-x-12 gap-y-7 sm:grid-cols-2">
            {balances.map((b, i) => (
              <div
                key={b.assetId.toString()}
                className="animate-fade-up border-l-2 border-accent/40 pl-4"
                style={{ animationDelay: `${i * 70}ms` }}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] font-semibold uppercase tracking-wide text-accent">
                    {b.assetLabel.split(' ')[0]}
                  </span>
                  <span className="text-xs text-blue-200/70">{b.assetLabel}</span>
                </div>
                <p className="stat mt-1.5 text-white">{formatRawAmount(b.rawAmount)}</p>
                <p className="mt-1 text-xs text-blue-200/60">
                  {b.noteCount} note{b.noteCount === 1 ? '' : 's'} · raw SAC units
                </p>
              </div>
            ))}
          </div>
        )}

        <p className="relative mt-7 max-w-2xl border-t border-white/10 pt-4 text-[11px] leading-relaxed text-blue-200/60">
          Your unspent notes on the live commitment tree, each commitment present on chain and not
          yet nullified, matched client side to a note you hold. Amounts are raw SAC units formatted
          with display decimals; the ZK layer never rescales. Balances are per asset
          and never summed across assets.
        </p>
      </div>
    </section>
  );
}
