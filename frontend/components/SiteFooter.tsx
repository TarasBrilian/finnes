'use client';

import { usePathname } from 'next/navigation';

/**
 * Site footer. Dark on the immersive landing, light on the consoles.
 */
export function SiteFooter() {
  const pathname = usePathname();
  const dark = pathname === '/';

  if (dark) {
    return (
      <footer className="full-bleed bg-midnight">
        <div className="mx-auto max-w-6xl px-6 pb-12 pt-10">
          <div className="mb-5 h-px w-full bg-white/10" />
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <p className="max-w-2xl text-xs leading-relaxed text-white/45">
              Finnes is not a mixer; auditability is enforced in circuit by design. Secrets
              (spending/viewing keys, witness, note plaintext) never leave the client trust zone.
            </p>
            <div className="flex items-center gap-4 text-xs font-medium text-white/55">
              <a href="/institution" className="transition hover:text-accent">Institution</a>
              <a href="/regulator" className="transition hover:text-accent">Regulator</a>
              <span className="text-white/30">Stellar · Soroban</span>
            </div>
          </div>
        </div>
      </footer>
    );
  }

  return (
    <footer className="mx-auto max-w-6xl px-6 pb-12 pt-8">
      <div className="mb-4 h-px w-full bg-blue-100" />
      <p className="max-w-3xl text-xs leading-relaxed text-ink-faint">
        Finnes is not a mixer; auditability is enforced in circuit by design. Secrets
        (spending/viewing keys, witness, note plaintext) never leave the client trust zone.
      </p>
    </footer>
  );
}
