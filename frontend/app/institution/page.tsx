'use client';

import { KeyManager } from '@/components/KeyManager';
import { ConfidentialBalances } from '@/components/ConfidentialBalances';
import { ComplianceStatus } from '@/components/ComplianceStatus';
import { TransferForm } from '@/components/TransferForm';
import { ShieldUnshieldForm } from '@/components/ShieldUnshieldForm';
import { useSpendingKeypair } from '@/lib/use-keys';

/**
 * Institution console (ARCHITECTURE.md → Frontend). Composition: the confidential
 * position is the primary anchor (navy panel), a compliance strip sits beneath
 * it, then a two-column workspace - actions on the left, key/wallet setup in a
 * narrow inspector on the right. The institution sees only its OWN notes.
 */
export default function InstitutionPage() {
  const spending = useSpendingKeypair();

  return (
    <div className="mx-auto max-w-6xl space-y-8 px-6 py-10">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1.5">
          <span className="eyebrow">Institution console</span>
          <h1 className="text-3xl font-extrabold tracking-tight text-ink">Institution</h1>
          <p className="text-sm text-ink-muted">
            Hold notes, settle confidentially, stay provably compliant.
          </p>
        </div>
        <a href="/regulator" className="btn-ghost">
          Switch to Regulator →
        </a>
      </header>

      {/* Primary anchor: confidential position + compliance. */}
      <div className="space-y-4">
        <ConfidentialBalances spending={spending} />
        <ComplianceStatus spending={spending} />
      </div>

      {/* Workspace: actions (left) + setup inspector (right). */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <div className="space-y-1">
            <span className="eyebrow">Move value</span>
            <h2 className="text-lg font-bold tracking-tight text-ink">Settlement actions</h2>
          </div>
          <div className="grid gap-6 md:grid-cols-2">
            <TransferForm spending={spending} />
            <ShieldUnshieldForm spending={spending} />
          </div>
        </div>

        <aside className="space-y-6 lg:col-span-1">
          <div className="space-y-1">
            <span className="eyebrow">Setup</span>
            <h2 className="text-lg font-bold tracking-tight text-ink">Shielded key</h2>
          </div>
          <KeyManager />
          <p className="rounded-2xl border border-blue-100 bg-blue-50/60 p-4 text-[11px] leading-relaxed text-ink-muted">
            <span className="font-semibold text-ink">Trust boundary.</span> The shielded key and the
            witness live only in this tab. The prover runs client-side; nothing secret reaches a
            shared backend.
          </p>
        </aside>
      </div>

      <p className="text-[11px] leading-relaxed text-ink-faint">
        DvP (atomic two-asset settlement) is a stretch goal. The demo path uses a single combined
        proof holding both parties&apos; secrets and is non-production (ARCHITECTURE.md → Settlement);
        production DvP is escrow / two-phase.
      </p>
    </div>
  );
}
