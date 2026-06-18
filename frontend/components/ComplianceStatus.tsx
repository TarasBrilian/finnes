'use client';

import { useEffect, useState } from 'react';
import { fetchComplianceState, formatRawAmount, type ComplianceState } from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';

/**
 * KYC / sanctions / per-asset limit status, as a slim inline chip strip. In the
 * demo, KYC enrollment is mocked (admin script enrolls all demo accounts into
 * `kyc_root`) — the in-circuit membership check still happens on every transfer;
 * only enrollment is mocked (CLAUDE.md → Out of scope / KYC).
 */
export function ComplianceStatus({ spending }: { spending: SpendingKeypair | null }) {
  const [state, setState] = useState<ComplianceState | null>(null);

  useEffect(() => {
    if (!spending) {
      setState(null);
      return;
    }
    let cancelled = false;
    fetchComplianceState(spending.ownerPk).then((s) => !cancelled && setState(s));
    return () => {
      cancelled = true;
    };
  }, [spending]);

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <span className="text-xs font-semibold uppercase tracking-wide text-ink-faint">
        Compliance
      </span>

      {!state && <span className="text-sm text-ink-muted">Generate a key to check status.</span>}

      {state && (
        <>
          <span className={state.kycApproved ? 'chip chip-good' : 'chip chip-bad'}>
            <Dot good={state.kycApproved} />
            KYC {state.kycApproved ? 'approved' : 'not approved'}
          </span>
          <span className={state.sanctioned ? 'chip chip-bad' : 'chip chip-good'}>
            <Dot good={!state.sanctioned} />
            Sanctions {state.sanctioned ? 'listed' : 'clear'}
          </span>
          {state.perTxLimitRaw !== undefined && (
            <span className="chip border-blue-200 bg-white text-ink-muted">
              Per-tx limit
              <span className="font-mono font-semibold text-ink">
                {formatRawAmount(state.perTxLimitRaw)}
              </span>
            </span>
          )}
          {state.isMock && (
            <span className="badge bg-amber-100 text-amber-800" title="Placeholder data">
              mock
            </span>
          )}
        </>
      )}
    </div>
  );
}

function Dot({ good }: { good: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block h-1.5 w-1.5 rounded-full ${good ? 'bg-blue-500' : 'bg-rose-500'}`}
    />
  );
}
