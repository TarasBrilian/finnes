'use client';

import { useState } from 'react';
import { confidentialTransfer, type OpResult, type TransferIntent } from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';
import { OpResultPanel } from './OpResultPanel';

/**
 * Confidential transfer A → B (2-in / 2-out, single asset). Building the intent
 * assembles a witness from LOCAL notes, calls the client-side prover, and would
 * submit the proof + public inputs + ciphertexts to the contract. Where wiring
 * is missing, the result panel shows 'TODO · not wired' — never a fake success.
 */
export function TransferForm({ spending }: { spending: SpendingKeypair | null }) {
  const [assetLabel, setAssetLabel] = useState('TBOND-2031 (tokenized bond)');
  const [recipientPk, setRecipientPk] = useState('');
  const [amount, setAmount] = useState('');
  const [result, setResult] = useState<OpResult | null>(null);
  const [busy, setBusy] = useState(false);

  const disabled = !spending || !recipientPk || !amount || busy;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!spending) return;
    setBusy(true);
    setResult(null);
    try {
      const intent: TransferIntent = {
        assetId: 1n,
        assetLabel,
        recipientPk: recipientPk.trim(),
        rawAmount: BigInt(amount),
      };
      setResult(await confidentialTransfer(intent, spending));
    } catch (err) {
      setResult({
        status: 'error',
        steps: [
          {
            label: 'Build transfer intent',
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
      <h3 className="text-sm font-semibold text-ink">Confidential transfer (A → B)</h3>
      <p className="mt-0.5 text-xs text-ink-muted">
        Public sees only an opaque commitment, a nullifier, and ciphertexts.
      </p>

      <form className="mt-4 space-y-3" onSubmit={onSubmit}>
        <div>
          <label className="label" htmlFor="t-asset">
            Asset
          </label>
          <select
            id="t-asset"
            className="input"
            value={assetLabel}
            onChange={(e) => setAssetLabel(e.target.value)}
          >
            <option>TBOND-2031 (tokenized bond)</option>
            <option>eUSD (confidential cash)</option>
          </select>
        </div>
        <div>
          <label className="label" htmlFor="t-recipient">
            Recipient (owner_pk or address)
          </label>
          <input
            id="t-recipient"
            className="input font-mono"
            placeholder="0x… recipient owner public key"
            value={recipientPk}
            onChange={(e) => setRecipientPk(e.target.value)}
          />
        </div>
        <div>
          <label className="label" htmlFor="t-amount">
            Amount (raw SAC units)
          </label>
          <input
            id="t-amount"
            className="input font-mono"
            inputMode="numeric"
            placeholder="e.g. 1000000"
            value={amount}
            onChange={(e) => setAmount(e.target.value.replace(/[^0-9]/g, ''))}
          />
        </div>
        <button type="submit" className="btn-primary w-full" disabled={disabled}>
          {busy ? 'Assembling…' : 'Build, prove & submit'}
        </button>
        {!spending && (
          <p className="text-xs text-ink-faint">Generate a shielded key first.</p>
        )}
      </form>

      <OpResultPanel result={result} />
    </div>
  );
}
