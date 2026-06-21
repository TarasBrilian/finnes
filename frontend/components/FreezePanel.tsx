'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  freezeCommitment,
  listFrozen,
  type OnChainTxSummary,
  type OpResult,
} from '@/lib/finnes-client';
import { OpResultPanel } from './OpResultPanel';

const shortHex = (h: string): string => (h.length <= 16 ? h : `${h.slice(0, 8)}…${h.slice(-6)}`);
const cmHex = (c: bigint): string => c.toString(16).padStart(64, '0');

/**
 * Clawback / freeze panel (FIN-018, invariant #14), the regulator console's
 * write surface. Two phase, two key:
 *   Phase 1 (read, auditor): identify cm_target by decrypting a tx with the view
 *     key (the disclosure panel above). Its output commitments are pickable here.
 *   Phase 2 (write, issuer): freeze cm_target, compute the new frozen_root (IMT
 *     insert) and submit the real `freeze` tx (issuer Freighter). Every later spend
 *     proves non membership against frozen_root, so the note becomes unspendable.
 */
export function FreezePanel({ selected }: { selected: OnChainTxSummary | null }) {
  const [target, setTarget] = useState('');
  const [frozen, setFrozen] = useState<string[]>([]);
  const [frozenMock, setFrozenMock] = useState(false);
  const [result, setResult] = useState<OpResult | null>(null);
  const [busy, setBusy] = useState(false);

  const refreshFrozen = useCallback(() => {
    listFrozen()
      .then((f) => {
        setFrozen(f.frozen);
        setFrozenMock(f.isMock);
      })
      .catch(() => {
        setFrozen([]);
        setFrozenMock(true);
      });
  }, []);

  useEffect(refreshFrozen, [refreshFrozen]);

  const onFreeze = async () => {
    setBusy(true);
    setResult(null);
    try {
      const r = await freezeCommitment(target);
      setResult(r);
      if (r.status === 'ok') refreshFrozen();
    } finally {
      setBusy(false);
    }
  };

  const candidates = selected?.outputs ?? [];

  return (
    <section className="card p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <span className="eyebrow">Issuer console</span>
          <h2 className="text-lg font-bold text-ink">Clawback &amp; freeze</h2>
        </div>
        <span className="chip">two phase · two key</span>
      </div>

      <p className="mt-2 max-w-2xl text-sm text-ink-muted">
        The auditor (read authority) identifies a target commitment by decrypting a transaction with
        the view key; the issuer (write authority) freezes it. A frozen note is unspendable: every
        spend must prove non membership against <span className="mono">frozen_root</span> (invariant
        #14/#19). No authority can compute a note&apos;s nullifier, so clawback is freeze-based, not a
        forced spend.
      </p>

      {/* Phase 1, pick cm_target from the disclosed transaction's outputs. */}
      <div className="mt-5">
        <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">
          1 · Target commitment (auditor read)
        </p>
        {candidates.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-2">
            {candidates.map((o, i) => {
              const h = cmHex(o.commitment);
              const isSel = target.replace(/^0x/, '') === h;
              return (
                <button
                  key={i}
                  type="button"
                  onClick={() => setTarget(h)}
                  className={`mono rounded-md border px-2.5 py-1 text-xs transition ${
                    isSel
                      ? 'border-accent bg-accent/10 text-ink'
                      : 'border-slate-200 text-ink-muted hover:border-accent/50'
                  }`}
                  title={`output ${i} commitment`}
                >
                  cm[{i}] {shortHex(h)}
                </button>
              );
            })}
          </div>
        ) : (
          <p className="mt-1 text-xs text-ink-faint">
            Select a transaction in the ledger and load the view key to pick a target, or paste a
            commitment below.
          </p>
        )}
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="cm_target (32-byte hex)"
          spellCheck={false}
          className="mono mt-3 w-full rounded-md border border-slate-200 px-3 py-2 text-xs text-ink focus:border-accent focus:outline-none"
        />
      </div>

      {/* Phase 2, issuer freezes. */}
      <div className="mt-5 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={onFreeze}
          disabled={busy || !target.trim()}
          className="btn-primary disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? 'Freezing…' : '2 · Freeze (issuer write)'}
        </button>
        <span className="text-[11px] text-ink-faint">
          Needs the issuer Freighter (admin=issuer=deployer in the demo); it signs + pays.
        </span>
      </div>

      <OpResultPanel result={result} />

      {/* Live frozen set. */}
      <div className="mt-6 border-t border-slate-100 pt-4">
        <div className="flex items-center gap-2">
          <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">Frozen set</p>
          <span className={`chip ${frozenMock ? '' : 'chip-good'}`}>
            {frozenMock ? 'RPC offline' : 'live'}
          </span>
        </div>
        {frozen.length === 0 ? (
          <p className="mt-1 text-xs text-ink-faint">Empty, no commitments have been frozen.</p>
        ) : (
          <ul className="mt-2 space-y-1">
            {frozen.map((h) => (
              <li key={h} className="mono text-xs text-ink-muted">
                {shortHex(h)}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
