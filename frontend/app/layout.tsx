import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { HeaderWalletButton } from '@/components/HeaderWalletButton';

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
        <header className="sticky top-0 z-20 border-b border-blue-100 bg-white/80 backdrop-blur-md">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3.5">
            <a href="/" className="group flex items-center gap-3">
              {/* Wordmark — Mega Mendung seal (asset) + the name. */}
              <img src="/seal.svg" alt="" aria-hidden="true" className="h-9 w-9 shadow-sm" />
              <span className="flex flex-col leading-none">
                <span className="text-[17px] font-extrabold tracking-tight text-ink">Finnes</span>
                <span className="mt-1 hidden text-[10px] font-semibold uppercase tracking-[0.18em] text-blue-500 sm:inline">
                  confidential RWA settlement
                </span>
              </span>
            </a>
            <div className="flex items-center gap-2">
              <nav className="mr-2 hidden items-center gap-1 text-sm font-medium text-ink-muted sm:flex">
                <a href="/institution" className="rounded-lg px-3 py-1.5 transition hover:bg-blue-50 hover:text-blue-700">
                  Institution
                </a>
                <a href="/regulator" className="rounded-lg px-3 py-1.5 transition hover:bg-blue-50 hover:text-blue-700">
                  Regulator
                </a>
              </nav>
              <HeaderWalletButton />
            </div>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-10">{children}</main>
        <footer className="mx-auto max-w-6xl px-6 pb-12 pt-8">
          <div className="mb-4 h-px w-full bg-blue-100" />
          <p className="max-w-3xl text-xs leading-relaxed text-ink-faint">
            Finnes is not a mixer — auditability is enforced in-circuit by design. Secrets
            (spending/viewing keys, witness, note plaintext) never leave the client trust zone.
          </p>
        </footer>
      </body>
    </html>
  );
}
