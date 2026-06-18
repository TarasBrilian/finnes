import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { TrustBoundaryBanner } from '@/components/TrustBoundaryBanner';

export const metadata: Metadata = {
  title: 'Finnes — Confidential RWA Settlement',
  description:
    'Institution- and regulator-facing UI for the Finnes confidential settlement layer on Stellar/Soroban. Private from the public, fully auditable by regulators.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <TrustBoundaryBanner />
        <header className="border-b border-slate-200 bg-white">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <a href="/" className="flex items-center gap-2">
              <span className="text-lg font-bold tracking-tight text-ink">Finnes</span>
              <span className="hidden text-sm text-ink-faint sm:inline">
                confidential RWA settlement
              </span>
            </a>
            <span className="badge bg-amber-100 text-amber-800" title="This is a scaffold UI">
              SCAFFOLD · demo
            </span>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
        <footer className="mx-auto max-w-6xl px-6 py-10 text-xs text-ink-faint">
          Finnes is not a mixer — auditability is enforced in-circuit by design. Secrets
          (spending/viewing keys, witness, note plaintext) never leave the client trust zone.
        </footer>
      </body>
    </html>
  );
}
