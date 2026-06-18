import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { TrustBoundaryBanner } from '@/components/TrustBoundaryBanner';
import { CloudDivider } from '@/components/Batik';

export const metadata: Metadata = {
  title: 'Finnes — Confidential RWA Settlement',
  description:
    'Institution- and regulator-facing UI for the Finnes confidential settlement layer on Stellar/Soroban. Private from the public, fully auditable by regulators.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        {/* Humanist sans (Plus Jakarta Sans). Loaded via <link> so an offline
            build degrades to the system-sans fallback instead of failing. */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-screen">
        <TrustBoundaryBanner />
        <header className="cloud-band">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <a href="/" className="group flex items-center gap-3">
              {/* Wordmark — a small layered-cloud glyph + the name. */}
              <span
                aria-hidden="true"
                className="grid h-9 w-9 place-items-center rounded-xl bg-mega-mendung text-white shadow-sm"
              >
                <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
                  <path d="M4 17a8 8 0 0 1 16 0" />
                  <path d="M8 17a4 4 0 0 1 8 0" />
                  <path d="M11 17a1 1 0 0 1 2 0" />
                </svg>
              </span>
              <span className="flex flex-col leading-tight">
                <span className="text-lg font-extrabold tracking-tight text-ink">
                  Finnes
                </span>
                <span className="hidden text-[11px] font-medium uppercase tracking-[0.16em] text-sogan-600 sm:inline">
                  confidential RWA settlement
                </span>
              </span>
            </a>
            <span
              className="badge border border-emas-400/40 bg-emas-300/20 text-sogan-700"
              title="This is a scaffold UI"
            >
              SCAFFOLD · demo
            </span>
          </div>
          {/* Scalloped Mega Mendung lower edge of the header band. */}
          <CloudDivider className="block w-full text-brand-600" units={16} opacity={0.4} />
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
        <footer className="mx-auto max-w-6xl px-6 pb-12 pt-6">
          <CloudDivider className="mb-4 block w-full" units={16} opacity={0.3} />
          <p className="text-xs text-ink-faint">
            Finnes is not a mixer — auditability is enforced in-circuit by design. Secrets
            (spending/viewing keys, witness, note plaintext) never leave the client trust zone.
          </p>
        </footer>
      </body>
    </html>
  );
}
