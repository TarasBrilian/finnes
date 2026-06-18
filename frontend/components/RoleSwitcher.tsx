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
              'card text-left transition hover:shadow-md',
              active ? 'ring-2 ring-brand-500' : '',
            ].join(' ')}
          >
            <div className="flex items-center justify-between">
              <span className="text-base font-semibold text-ink">{r.label}</span>
              {active && <span className="badge bg-brand-100 text-brand-700">current</span>}
            </div>
            <p className="mt-1 text-sm text-ink-muted">{r.blurb}</p>
          </button>
        );
      })}
    </nav>
  );
}
