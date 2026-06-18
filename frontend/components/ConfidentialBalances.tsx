'use client';

import { useEffect, useState } from 'react';
import {
  formatRawAmount,
  scanConfidentialBalances,
  type ConfidentialBalance,
} from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';
import { MockBadge } from './MockBadge';

/**
 * Shows confidential balances discovered by scanning on-chain ciphertexts with
 * the viewing key (ARCHITECTURE.md → Frontend). The institution sees only its
 * OWN notes — nothing about other parties.
 *
 * SCAFFOLD: sdk scanning throws (encryption scheme not fixed), so the data is
 * clearly labelled MOCK until @finnes/sdk decryption is wired.
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
    <div className="card">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink">Confidential balances</h3>
        {balances?.some((b) => b.isMock) && <MockBadge />}
      </div>

      {!spending && (
        <p className="text-sm text-ink-muted">Generate a shielded key to scan for owned notes.</p>
      )}

      {spending && loading && <p className="text-sm text-ink-muted">Scanning ciphertexts…</p>}

      {spending && balances && balances.length === 0 && (
        <p className="text-sm text-ink-muted">No owned notes discovered.</p>
      )}

      {spending && balances && balances.length > 0 && (
        <ul className="divide-y divide-slate-100">
          {balances.map((b) => (
            <li key={b.assetId.toString()} className="flex items-center justify-between py-3">
              <div>
                <p className="text-sm font-medium text-ink">{b.assetLabel}</p>
                <p className="text-xs text-ink-faint">{b.noteCount} note(s)</p>
              </div>
              <span className="font-mono text-sm text-ink">{formatRawAmount(b.rawAmount)}</span>
            </li>
          ))}
        </ul>
      )}

      <p className="mt-3 text-[11px] text-ink-faint">
        Discovered by trial-decrypting on-chain ciphertexts client-side. Amounts are raw SAC units
        formatted with display decimals; the ZK layer never rescales (invariant #16).
      </p>
    </div>
  );
}
