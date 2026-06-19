'use client';

import { useState } from 'react';
import { generateAuditorKeypair, importAuditorViewKey, setAuditorKeypair } from '@/lib/keys';
import { useAuditorKeypair } from '@/lib/use-keys';

function hex(f: bigint): string {
  return `0x${f.toString(16)}`;
}

/**
 * Holds the auditor (regulator) view key. SECRET - lives in this tab only,
 * never logged/persisted/transmitted (invariant #8). This key is the "read
 * authority": it can decrypt every transaction's auditor ciphertext.
 */
export function AuditorKeyInput() {
  const kp = useAuditorKeypair();
  const [raw, setRaw] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  function onImport() {
    setError(null);
    try {
      setAuditorKeypair(importAuditorViewKey(raw));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Invalid key.');
    }
  }

  function onClear() {
    setRevealed(false);
    setCopied(false);
    setAuditorKeypair(null);
  }

  async function copyViewKey() {
    if (!kp) return;
    try {
      await navigator.clipboard.writeText(hex(kp.sk));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable; the value is shown for manual copy */
    }
  }

  return (
    <div className="card">
      <h3 className="text-base font-bold text-ink">Auditor view key</h3>
      <p className="mt-0.5 text-xs text-ink-muted">
        Read authority. Held only in this tab; never sent anywhere (invariant #8).
      </p>

      {kp ? (
        <div className="mt-3 space-y-2 rounded-xl bg-blue-50/70 p-3 text-xs">
          <div className="flex items-center justify-between gap-3">
            <span className="chip chip-good">
              <span aria-hidden="true" className="inline-block h-1.5 w-1.5 rounded-full bg-blue-500" />
              view key loaded
            </span>
            <div className="flex items-center gap-3">
              <button
                type="button"
                className="font-medium text-blue-600 hover:underline"
                onClick={() => setRevealed((v) => !v)}
              >
                {revealed ? 'hide' : 'view key'}
              </button>
              <button
                type="button"
                className="font-medium text-blue-600 hover:underline"
                onClick={onClear}
              >
                clear
              </button>
            </div>
          </div>

          {revealed && (
            <div className="space-y-1.5 border-t border-blue-100 pt-2">
              <div className="flex items-center gap-2">
                <span className="shrink-0 text-ink-muted">auditor_pk</span>
                <span className="mono break-all">{hex(kp.pk)}</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="shrink-0 text-ink-muted">view key (secret)</span>
                <span className="mono break-all">{hex(kp.sk)}</span>
                <button
                  type="button"
                  className="ml-auto shrink-0 font-medium text-blue-600 hover:underline"
                  onClick={copyViewKey}
                >
                  {copied ? 'copied ✓' : 'copy'}
                </button>
              </div>
              <p className="text-[11px] text-ink-faint">
                Secret read authority - never sent anywhere (invariant #8). Reveal only to verify or
                copy it.
              </p>
            </div>
          )}
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
              title="Generate a demo view key"
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
