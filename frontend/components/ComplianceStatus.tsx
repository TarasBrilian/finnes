'use client';

import { useEffect, useState } from 'react';
import { fetchComplianceState, formatRawAmount, type ComplianceState } from '@/lib/finnes-client';
import type { SpendingKeypair } from '@/lib/keys';
import { MockBadge } from './MockBadge';

/**
 * KYC / sanctions / per-asset limit status. In the demo, KYC enrollment is
 * mocked (admin script enrolls all demo accounts into `kyc_root`) — the
 * in-circuit membership check still happens on every transfer; only enrollment
 * is mocked (CLAUDE.md → Out of scope / KYC).
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
    <div className="card">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink">Compliance status</h3>
        {state?.isMock && <MockBadge />}
      </div>

      {!state && <p className="text-sm text-ink-muted">Generate a key to check status.</p>}

      {state && (
        <dl className="space-y-2 text-sm">
          <div className="flex items-center justify-between">
            <dt className="text-ink-muted">KYC</dt>
            <dd>
              {state.kycApproved ? (
                <span className="badge bg-emerald-100 text-emerald-800">approved</span>
              ) : (
                <span className="badge bg-rose-100 text-rose-800">not approved</span>
              )}
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-ink-muted">Sanctions</dt>
            <dd>
              {state.sanctioned ? (
                <span className="badge bg-rose-100 text-rose-800">listed</span>
              ) : (
                <span className="badge bg-emerald-100 text-emerald-800">clear</span>
              )}
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-ink-muted">Per-tx limit</dt>
            <dd className="font-mono text-ink">
              {state.perTxLimitRaw !== undefined ? formatRawAmount(state.perTxLimitRaw) : '—'}
            </dd>
          </div>
        </dl>
      )}

      <p className="mt-3 text-[11px] text-ink-faint">
        Limits are per-asset, enforced in-circuit via assets-registry membership (value ≤
        per_tx_limit_raw). The limit is a witness, never a public input.
      </p>
    </div>
  );
}
