'use client';

import { useState } from 'react';
import {
  clearKeys,
  generateSpendingKeypair,
  setSpendingKeypair,
} from '@/lib/keys';
import { useSpendingKeypair } from '@/lib/use-keys';
import { MockBadge } from './MockBadge';

function shortFr(f: bigint): string {
  const hex = f.toString(16);
  return hex.length <= 12 ? `0x${hex}` : `0x${hex.slice(0, 6)}…${hex.slice(-6)}`;
}

/**
 * Generates and holds the institution's shielded spending/viewing key in memory
 * (lib/keys.ts). NEVER persisted to a server (invariant #8). The secret
 * `owner_sk` is intentionally NOT displayed in full — only a short public
 * fingerprint of `owner_pk`.
 */
export function KeyManager() {
  const kp = useSpendingKeypair();
  const [revealed, setRevealed] = useState(false);

  return (
    <div className="card">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-ink">Shielded key</h3>
          <p className="mt-0.5 text-xs text-ink-muted">
            Spending + viewing key for the ZK layer. In-memory only — never sent anywhere.
          </p>
        </div>
        {kp ? (
          <button type="button" className="btn-ghost" onClick={() => clearKeys()}>
            Wipe
          </button>
        ) : (
          <button
            type="button"
            className="btn-primary"
            onClick={() => setSpendingKeypair(generateSpendingKeypair())}
          >
            Generate key
          </button>
        )}
      </div>

      {kp && (
        <div className="mt-3 space-y-2 rounded-lg bg-slate-50 p-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-ink-muted">owner_pk</span>
            <span className="mono">{shortFr(kp.ownerPk)}</span>
            {kp.isMock && <MockBadge label="mock derivation" />}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-ink-muted">owner_sk</span>
            <span className="mono">{revealed ? shortFr(kp.ownerSk) : '•••••• (secret)'}</span>
            <button
              type="button"
              className="text-brand-600 hover:underline"
              onClick={() => setRevealed((v) => !v)}
            >
              {revealed ? 'hide' : 'reveal fingerprint'}
            </button>
          </div>
          <p className="text-[11px] text-ink-faint">
            The secret key never leaves this tab and is not logged. If derivation is mock,
            balances/notes below are placeholders until @finnes/sdk Poseidon is wired.
          </p>
        </div>
      )}
    </div>
  );
}
