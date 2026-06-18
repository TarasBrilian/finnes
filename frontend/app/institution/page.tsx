'use client';

import { WalletConnect } from '@/components/WalletConnect';
import { KeyManager } from '@/components/KeyManager';
import { ConfidentialBalances } from '@/components/ConfidentialBalances';
import { ComplianceStatus } from '@/components/ComplianceStatus';
import { TransferForm } from '@/components/TransferForm';
import { ShieldUnshieldForm } from '@/components/ShieldUnshieldForm';
import { useSpendingKeypair } from '@/lib/use-keys';

/**
 * Institution view (ARCHITECTURE.md → Frontend): connect Freighter (transparent
 * side), hold the shielded key, see confidential balances + KYC/limit status,
 * and run shield / confidential_transfer / unshield. The institution sees only
 * its OWN notes.
 */
export default function InstitutionPage() {
  const spending = useSpendingKeypair();

  return (
    <div className="space-y-8">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">Institution</h1>
          <p className="text-sm text-ink-muted">
            Hold notes, settle confidentially, stay provably compliant.
          </p>
        </div>
        <a href="/regulator" className="btn-ghost">
          Switch to Regulator →
        </a>
      </header>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-1">
          <WalletConnect />
          <KeyManager />
          <ComplianceStatus spending={spending} />
        </div>

        <div className="space-y-6 lg:col-span-2">
          <ConfidentialBalances spending={spending} />
          <div className="grid gap-6 md:grid-cols-2">
            <TransferForm spending={spending} />
            <ShieldUnshieldForm spending={spending} />
          </div>
        </div>
      </div>

      <p className="text-[11px] text-ink-faint">
        DvP (atomic two-asset settlement) is a stretch goal. The demo path uses a single combined
        proof holding both parties&apos; secrets and is non-production (ARCHITECTURE.md → Settlement);
        production DvP is escrow / two-phase. Not implemented in this scaffold.
      </p>
    </div>
  );
}
