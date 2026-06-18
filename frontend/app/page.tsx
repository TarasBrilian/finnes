import { RoleSwitcher } from '@/components/RoleSwitcher';
import { MegaMendungOrnament } from '@/components/Batik';

/**
 * Landing + role switcher (Institution / Regulator). Each role-based view shows
 * the user only what they are entitled to see (ARCHITECTURE.md → Roles).
 */
export default function HomePage() {
  return (
    <div className="space-y-12">
      {/* Hero — treated as a calm poster: text on the left, Mega Mendung clouds
          drifting into the lower-right corner (a calm area for the headline). */}
      <section className="relative overflow-hidden rounded-3xl border border-sogan-100 bg-cloud-soft px-6 py-10 shadow-card sm:px-10 sm:py-14">
        <MegaMendungOrnament className="pointer-events-none absolute -bottom-6 -right-6 h-44 w-80 opacity-90 sm:h-56 sm:w-[28rem]" />
        <div className="relative max-w-2xl animate-fade-up space-y-4">
          <span className="eyebrow">Stellar · Soroban · BLS12-381</span>
          <h1 className="text-balance text-4xl font-extrabold leading-[1.08] tracking-tight text-ink sm:text-5xl">
            Confidential settlement for{' '}
            <span className="bg-mega-mendung bg-clip-text text-transparent">regulated RWA</span>
          </h1>
          <p className="max-w-xl text-base text-ink-muted">
            Settle real-world-asset tokens on Stellar with hidden amounts and counterparties —
            atomically settled (DvP), provably compliant in-circuit, and selectively disclosable to
            regulators.
          </p>
          <p className="text-sm font-semibold text-sogan-700">
            Dark-pool-grade confidentiality, audit-grade transparency.
          </p>
        </div>
        <p className="relative mt-6 max-w-xl text-xs text-ink-faint">
          This is a scaffold UI. The ZK crypto (@finnes/sdk), the Groth16 prover (@finnes/prover),
          and the Soroban contract are not yet wired; data shown is clearly labelled as mock and no
          operation fakes success.
        </p>
      </section>

      <section className="space-y-4">
        <div className="space-y-1">
          <span className="eyebrow">Masuk sebagai</span>
          <h2 className="text-xl font-bold tracking-tight text-ink">Choose a role</h2>
        </div>
        <RoleSwitcher />
      </section>

      <section className="space-y-4">
        <span className="eyebrow">How it holds together</span>
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            {
              t: 'Confidential transfer',
              d: 'RWA moves via Poseidon commitments; nullifiers prevent double-spend. Amounts and parties stay hidden.',
            },
            {
              t: 'In-circuit compliance',
              d: 'KYC membership, sanctions non-membership, and per-asset limits proven without revealing identities.',
            },
            {
              t: 'Mandatory disclosure',
              d: 'Every note is encrypted to the regulator view key — enforced by the proof, not optional.',
            },
          ].map((f, i) => (
            <div
              key={f.t}
              className="card animate-fade-up"
              style={{ animationDelay: `${i * 80}ms` }}
            >
              <span aria-hidden="true" className="mb-3 block h-1 w-8 rounded-full bg-emas-400" />
              <h3 className="text-sm font-semibold text-ink">{f.t}</h3>
              <p className="mt-1 text-sm text-ink-muted">{f.d}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
