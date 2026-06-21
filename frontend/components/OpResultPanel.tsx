'use client';

import type { OpResult, OpStep } from '@/lib/finnes-client';

/**
 * Renders the honest step-by-step status of a REAL write (FIN-027): assemble
 * witness → prove in browser → submit the Soroban tx. Each step shows its genuine
 * outcome (done / error) as the pipeline runs, we NEVER render a fake success. A
 * step that needs an operator prerequisite (served .zkey, connected Freighter, or
 * enough spendable notes) fails with an actionable error.
 */
function StepRow({ step }: { step: OpStep }) {
  const styles: Record<OpStep['status'], string> = {
    ok: 'bg-emerald-100 text-emerald-800',
    todo: 'bg-slate-200 text-slate-700',
    error: 'bg-rose-100 text-rose-800',
  };
  const labels: Record<OpStep['status'], string> = {
    ok: 'done',
    todo: 'pending',
    error: 'error',
  };
  return (
    <li className="flex items-start gap-3 py-2">
      <span className={`badge mt-0.5 shrink-0 ${styles[step.status]}`}>{labels[step.status]}</span>
      <div>
        <p className="text-sm font-medium text-ink">{step.label}</p>
        <p className="text-xs text-ink-muted">{step.detail}</p>
      </div>
    </li>
  );
}

export function OpResultPanel({ result }: { result: OpResult | null }) {
  if (!result) return null;

  const banner =
    result.status === 'ok'
      ? { cls: 'bg-emerald-50 text-emerald-900', text: 'Submitted on chain.' }
      : result.status === 'error'
        ? { cls: 'bg-rose-50 text-rose-900', text: 'Stopped, see the failing step below.' }
        : { cls: 'bg-amber-50 text-amber-900', text: 'In progress.' };

  return (
    <div className="mt-4 rounded-lg border border-slate-200">
      <div className={`rounded-t-lg px-4 py-2 text-sm font-medium ${banner.cls}`}>
        {banner.text}
        {result.txHash && (
          <a
            className="mono ml-2 underline"
            href={`https://stellar.expert/explorer/testnet/tx/${result.txHash}`}
            target="_blank"
            rel="noreferrer"
          >
            {result.txHash.slice(0, 12)}…
          </a>
        )}
      </div>
      <ul className="divide-y divide-slate-100 px-4 py-1">
        {result.steps.map((s, i) => (
          <StepRow key={i} step={s} />
        ))}
      </ul>
    </div>
  );
}
