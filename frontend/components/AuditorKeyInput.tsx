'use client';

import { useState } from 'react';
import { generateAuditorKeypair, importAuditorViewKey, setAuditorKeypair } from '@/lib/keys';
import { useAuditorKeypair } from '@/lib/use-keys';
import { MockBadge } from './MockBadge';

/**
 * Holds the auditor (regulator) view key. SECRET — lives in this tab only,
 * never logged/persisted/transmitted (invariant #8). This key is the "read
 * authority": it can decrypt every transaction's auditor ciphertext.
 */
export function AuditorKeyInput() {
  const kp = useAuditorKeypair();
  const [raw, setRaw] = useState('');
  const [error, setError] = useState<string | null>(null);

  function onImport() {
    setError(null);
    try {
      setAuditorKeypair(importAuditorViewKey(raw));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Invalid key.');
    }
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-base font-bold text-ink">Auditor view key</h3>
        {kp?.isMock && <MockBadge label="mock key" />}
      </div>
      <p className="mt-0.5 text-xs text-ink-muted">
        Read authority. Held only in this tab; never sent anywhere (invariant #8).
      </p>

      {kp ? (
        <div className="mt-3 flex items-center justify-between rounded-xl bg-blue-50/70 p-3 text-xs">
          <span className="chip chip-good">
            <span aria-hidden="true" className="inline-block h-1.5 w-1.5 rounded-full bg-blue-500" />
            view key loaded
          </span>
          <button
            type="button"
            className="font-medium text-blue-600 hover:underline"
            onClick={() => setAuditorKeypair(null)}
          >
            clear
          </button>
        </div>
      ) : (
        <div className="mt-3 space-y-2">
          <input
            className="input font-mono"
            placeholder="paste auditor view key (decimal or 0x-hex)"
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
          />
          <div className="flex gap-2">
            <button type="button" className="btn-primary flex-1" onClick={onImport} disabled={!raw}>
              Load key
            </button>
            <button
              type="button"
              className="btn-ghost"
              onClick={() => setAuditorKeypair(generateAuditorKeypair())}
              title="Generate a mock key for the demo"
            >
              Demo key
            </button>
          </div>
          {error && <p className="text-xs text-rose-700">{error}</p>}
        </div>
      )}
    </div>
  );
}
