'use client';

import { usePathname, useRouter } from 'next/navigation';

type Role = { href: string; label: string; blurb: string; glyph: React.ReactNode };

const ROLES: Role[] = [
  {
    href: '/institution',
    label: 'Institution',
    blurb: 'Hold notes, shield / transfer / unshield, see KYC & limits.',
    glyph: (
      <path d="M4 20h16M6 20V8l6-4 6 4v12M10 12h4M10 16h4" />
    ),
  },
  {
    href: '/regulator',
    label: 'Regulator / Auditor',
    blurb: 'Hold the view key, decrypt and audit any transaction.',
    glyph: (
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />
    ),
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
              'card card-hover group flex items-center gap-4 overflow-hidden text-left',
              active ? 'border-blue-500 ring-1 ring-blue-500' : '',
            ].join(' ')}
          >
            <span
              aria-hidden="true"
              className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-blue-50 text-blue-600"
            >
              <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                {r.glyph}
              </svg>
            </span>
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2">
                <span className="text-base font-bold text-ink">{r.label}</span>
                {active && (
                  <span className="badge border border-blue-200 bg-blue-50 text-blue-700">current</span>
                )}
              </span>
              <span className="mt-0.5 block text-sm text-ink-muted">{r.blurb}</span>
            </span>
            <span
              aria-hidden="true"
              className="shrink-0 text-blue-400 transition group-hover:translate-x-0.5 group-hover:text-blue-600"
            >
              →
            </span>
          </button>
        );
      })}
    </nav>
  );
}
