'use client';

import { useState } from 'react';
import {
  shield,
  unshield,
  type OpResult,
  type ShieldIntent,
  type UnshieldIntent,
} from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';
import { OpResultPanel } from './OpResultPanel';

type Mode = 'shield' | 'unshield';

/**
 * Shield (transparent RWA → note) and Unshield (note → transparent) in one
 * card with a mode toggle.
 *
 * - Shield: `(asset_id, amount)` are public; the proof binds the new commitment
 *   to the deposited asset without a full opening (invariant #18).
 * - Unshield: reveals `(asset_id, amount, recipient)` for the SAC transfer and
 *   MUST prove frozen-set non-membership + recipient compliance (invariant #19).
 *
 * Both sign the transparent leg via Freighter (not wired yet) and would submit
 * a client-side proof. Unwired steps show honestly in the result panel.
 */
export function ShieldUnshieldForm({ spending }: { spending: SpendingKeypair | null }) {
  const [mode, setMode] = useState<Mode>('shield');
  const [assetLabel, setAssetLabel] = useState('TBOND-2031 (tokenized bond)');
  const [sacAddress, setSacAddress] = useState('');
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [result, setResult] = useState<OpResult | null>(null);
  const [busy, setBusy] = useState(false);

  const needsField = mode === 'shield' ? sacAddress : recipient;
  const disabled = !spending || !needsField || !amount || busy;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!spending) return;
    setBusy(true);
    setResult(null);
    try {
      if (mode === 'shield') {
        const intent: ShieldIntent = {
          sacAddress: sacAddress.trim(),
          assetLabel,
          rawAmount: BigInt(amount),
        };
        setResult(await shield(intent, spending));
      } else {
        const intent: UnshieldIntent = {
          assetId: 1n,
          assetLabel,
          recipient: recipient.trim(),
          rawAmount: BigInt(amount),
        };
        setResult(await unshield(intent, spending));
      }
    } catch (err) {
      setResult({
        status: 'error',
        steps: [
          {
            label: 'Build intent',
            status: 'error',
            detail: err instanceof Error ? err.message : 'Invalid input.',
          },
        ],
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-base font-bold text-ink">Shield / Unshield</h3>
        <div className="segment">
          {(['shield', 'unshield'] as Mode[]).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => {
                setMode(m);
                setResult(null);
              }}
              className={`segment-item ${mode === m ? 'segment-item-active' : ''}`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>
      <p className="mt-1 text-xs text-ink-muted">
        {mode === 'shield'
          ? 'Deposit a transparent RWA token → confidential note.'
          : 'Redeem a note → transparent RWA. Proves frozen non-membership + recipient KYC.'}
      </p>

      <form className="mt-4 space-y-3" onSubmit={onSubmit}>
        <div>
          <label className="label" htmlFor="su-asset">
            Asset
          </label>
          <select
            id="su-asset"
            className="input"
            value={assetLabel}
            onChange={(e) => setAssetLabel(e.target.value)}
          >
            <option>TBOND-2031 (tokenized bond)</option>
            <option>eUSD (confidential cash)</option>
          </select>
        </div>

        {mode === 'shield' ? (
          <div>
            <label className="label" htmlFor="su-sac">
              SAC contract address
            </label>
            <input
              id="su-sac"
              className="input font-mono"
              placeholder="C… Stellar Asset Contract"
              value={sacAddress}
              onChange={(e) => setSacAddress(e.target.value)}
            />
          </div>
        ) : (
          <div>
            <label className="label" htmlFor="su-recipient">
              Transparent recipient
            </label>
            <input
              id="su-recipient"
              className="input font-mono"
              placeholder="G… / C… Stellar address"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
            />
          </div>
        )}

        <div>
          <label className="label" htmlFor="su-amount">
            Amount (raw SAC units)
          </label>
          <input
            id="su-amount"
            className="input font-mono"
            inputMode="numeric"
            placeholder="e.g. 1000000"
            value={amount}
            onChange={(e) => setAmount(e.target.value.replace(/[^0-9]/g, ''))}
          />
        </div>

        <button type="submit" className="btn-primary w-full" disabled={disabled}>
          {busy ? 'Assembling…' : mode === 'shield' ? 'Shield' : 'Unshield'}
        </button>
        {!spending && <p className="text-xs text-ink-faint">Generate a shielded key first.</p>}
      </form>

      <OpResultPanel result={result} />
    </div>
  );
}
