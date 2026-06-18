'use client';

import { usePathname, useRouter } from 'next/navigation';

type Role = { href: string; label: string; blurb: string };

const ROLES: Role[] = [
  {
    href: '/institution',
    label: 'Institution',
    blurb: 'Hold notes, shield / transfer / unshield, see KYC & limits.',
  },
  {
    href: '/regulator',
    label: 'Regulator / Auditor',
    blurb: 'Hold the view key, decrypt and audit any transaction.',
  },
];

/**
 * Switches between the two role-based views (ARCHITECTURE.md → Frontend). Each
 * view shows the user only what they are entitled to see.
 */
export function RoleSwitcher() {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <nav aria-label="Role" className="grid gap-4 sm:grid-cols-2">
      {ROLES.map((r) => {
        const active = pathname?.startsWith(r.href);
        return (
          <button
            key={r.href}
            type="button"
            aria-current={active ? 'page' : undefined}
            onClick={() => router.push(r.href)}
            className={[
              'card card-hover overflow-hidden text-left',
              active ? 'border-brand-500 ring-1 ring-brand-500' : '',
            ].join(' ')}
          >
            {/* gold corner accent on the active role */}
            {active && (
              <span
                aria-hidden="true"
                className="absolute left-0 top-0 h-full w-1 bg-mega-mendung"
              />
            )}
            <div className="flex items-center justify-between">
              <span className="text-base font-semibold text-ink">{r.label}</span>
              {active && (
                <span className="badge border border-emas-400/40 bg-emas-300/20 text-sogan-700">
                  current
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-ink-muted">{r.blurb}</p>
          </button>
        );
      })}
    </nav>
  );
}
