'use client';

import { KeyManager } from '@/components/KeyManager';
import { ConfidentialBalances } from '@/components/ConfidentialBalances';
import { ComplianceStatus } from '@/components/ComplianceStatus';
import { SettlementConsole } from '@/components/SettlementConsole';
import { useSpendingKeypair } from '@/lib/use-keys';

/**
 * Institution console (ARCHITECTURE.md → Frontend). A lean desk: a text-only
 * title bar with live session + protocol facts, the confidential position as the
 * single brand anchor, a slim compliance strip, then the settlement console (the
 * working surface) beside a compact key inspector. The institution sees only its
 * OWN notes.
 */

/** Protocol facts surfaced inline in the title bar — true statements, never faked. */
const FACTS: readonly { k: string; v: string }[] = [
  { k: 'Network', v: 'Stellar Testnet' },
  { k: 'Prover', v: 'Client-side' },
  { k: 'Curve', v: 'BLS12-381' },
  { k: 'Proof', v: 'Groth16 · one pairing' },
];

export default function InstitutionPage() {
  const spending = useSpendingKeypair();

  return (
    <div className="mx-auto max-w-6xl space-y-7 px-6 py-10">
      {/* ---- Title bar (text only, no boxed banner) ----------------------- */}
      <header className="space-y-4 border-b border-blue-100 pb-5">
        <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-4">
          <div className="space-y-1.5">
            <span className="eyebrow">Institution console</span>
            <h1 className="font-display text-4xl font-extrabold tracking-tight text-ink">
              Institution desk
            </h1>
            <p className="max-w-lg text-sm text-ink-muted">
              Hold shielded notes, settle confidentially, and stay provably compliant.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span
              className={`chip ${spending ? 'chip-good' : 'border-blue-200 bg-white text-ink-faint'}`}
            >
              <span
                aria-hidden="true"
                className={`inline-block h-1.5 w-1.5 rounded-full ${
                  spending ? 'animate-glowpulse bg-blue-500' : 'bg-ink-faint/60'
                }`}
              />
              {spending ? 'Session active' : 'No key loaded'}
            </span>
            <a href="/regulator" className="btn-ghost">
              Switch to Regulator →
            </a>
          </div>
        </div>

        {/* Inline protocol facts. */}
        <dl className="flex flex-wrap items-center gap-x-2 gap-y-1.5 text-xs">
          {FACTS.map((f, i) => (
            <div key={f.k} className="flex items-center gap-2">
              {i > 0 && <span aria-hidden="true" className="text-blue-200">·</span>}
              <dt className="font-medium uppercase tracking-wide text-ink-faint">{f.k}</dt>
              <dd className="font-semibold text-ink">{f.v}</dd>
            </div>
          ))}
        </dl>
      </header>

      {/* ---- Confidential position (single brand anchor) ------------------ */}
      <ConfidentialBalances spending={spending} />

      {/* ---- Slim compliance strip ---------------------------------------- */}
      <ComplianceStatus spending={spending} />

      {/* ---- Working surface: console (left) + key inspector (right) ------ */}
      <div className="grid items-start gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <SettlementConsole spending={spending} />
        </div>

        <aside className="space-y-4 lg:col-span-1">
          <KeyManager />
          <p className="flex items-start gap-2 px-1 text-[11px] leading-relaxed text-ink-faint">
            <svg viewBox="0 0 24 24" className="mt-0.5 h-3.5 w-3.5 shrink-0 text-blue-500" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3l7 3v5c0 4.4-3 8.3-7 10-4-1.7-7-5.6-7-10V6l7-3Z" />
            </svg>
            <span>
              <span className="font-semibold text-ink-muted">Trust boundary.</span> Keys, the
              witness, and note plaintext stay in this tab. The prover runs client-side; nothing
              secret reaches a shared backend.
            </span>
          </p>
        </aside>
      </div>

      {/* ---- Footnote: DvP is a labelled stretch goal --------------------- */}
      <p className="border-t border-blue-100 pt-5 text-[11px] leading-relaxed text-ink-faint">
        DvP (atomic two-asset settlement) is a stretch goal. The demo path uses a single combined
        proof holding both parties&apos; secrets and is non-production (ARCHITECTURE.md → Settlement);
        production DvP is escrow / two-phase.
      </p>
    </div>
  );
}
