'use client';

import { useState } from 'react';
import {
  clearKeys,
  generateSpendingKeypair,
  setSpendingKeypair,
} from '@/lib/keys';
import { useSpendingKeypair } from '@/lib/use-keys';

function shortFr(f: bigint): string {
  const hex = f.toString(16);
  return hex.length <= 12 ? `0x${hex}` : `0x${hex.slice(0, 6)}…${hex.slice(-6)}`;
}

/**
 * The recipient's shielded key as the sender pastes it into the transfer form.
 * Prefixed `zk` so it can never be mistaken for a transparent Stellar address
 * (G…) or an Ethereum-style 0x… address. The transfer form labels its field
 * "Recipient shielded key (owner_pk)" to match this exactly.
 */
function shieldedKeyString(f: bigint): string {
  return `zk${f.toString(16)}`;
}

function shortShieldedKey(f: bigint): string {
  const s = shieldedKeyString(f);
  return s.length <= 14 ? s : `${s.slice(0, 8)}…${s.slice(-6)}`;
}

/**
 * Generates and holds the institution's shielded spending/viewing key in memory
 * (lib/keys.ts). NEVER persisted to a server (invariant #8). The secret
 * `owner_sk` is intentionally NOT displayed in full - only a short public
 * fingerprint of `owner_pk`.
 */
export function KeyManager() {
  const kp = useSpendingKeypair();
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copyShieldedKey() {
    if (!kp) return;
    try {
      await navigator.clipboard.writeText(shieldedKeyString(kp.ownerPk));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable; user can still read the value */
    }
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-ink">Shielded key</h3>
          <p className="mt-0.5 text-xs text-ink-muted">
            Spending + viewing key. In-memory only - never sent anywhere.
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
        <div className="mt-3 space-y-2 rounded-xl bg-blue-50/70 p-3 text-xs">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-ink-muted">shielded key</span>
              <span className="mono">{shortShieldedKey(kp.ownerPk)}</span>
              <button
                type="button"
                className="ml-auto font-medium text-blue-600 hover:underline"
                onClick={copyShieldedKey}
              >
                {copied ? 'copied ✓' : 'copy'}
              </button>
            </div>
            <p className="mt-0.5 text-[11px] text-ink-faint">
              Share this with the sender (owner_pk) - this is what they paste into a confidential
              transfer. It is public; safe to share.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-ink-muted">owner_sk</span>
            <span className="mono">{revealed ? shortFr(kp.ownerSk) : '•••••• (secret)'}</span>
            <button
              type="button"
              className="font-medium text-blue-600 hover:underline"
              onClick={() => setRevealed((v) => !v)}
            >
              {revealed ? 'hide' : 'reveal fingerprint'}
            </button>
          </div>
          <p className="text-[11px] text-ink-faint">
            The secret key never leaves this tab and is not logged.
          </p>
        </div>
      )}
    </div>
  );
}
