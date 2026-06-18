import { RoleSwitcher } from '@/components/RoleSwitcher';
import { MegaMendungBanner } from '@/components/Batik';

/**
 * Landing + role switcher (Institution / Regulator). Each role-based view shows
 * the user only what they are entitled to see (ARCHITECTURE.md → Roles).
 */
export default function HomePage() {
  return (
    <div className="space-y-16">
      {/* Hero — navy Mega Mendung banner, big confident headline on the left. */}
      <MegaMendungBanner className="px-7 py-14 sm:px-14 sm:py-20">
        <div className="max-w-2xl animate-fade-up space-y-6">
          <span className="eyebrow-light">Stellar · Soroban · BLS12-381</span>
          <h1 className="text-balance text-[2.6rem] font-extrabold leading-[1.05] tracking-tight text-white sm:text-[3.4rem]">
            Confidential settlement
            <br />
            for <span className="text-blue-300">regulated RWA</span>
          </h1>
          <p className="max-w-xl text-lg leading-relaxed text-blue-100/85">
            Move real-world-asset tokens on Stellar with hidden amounts and counterparties —
            atomically settled, provably compliant in-circuit, and selectively disclosable to
            regulators.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <a href="/institution" className="btn bg-white text-blue-800 hover:bg-blue-50">
              Open institution console →
            </a>
            <a href="/regulator" className="btn border border-white/25 text-white hover:bg-white/10">
              Regulator view
            </a>
          </div>
          <p className="flex items-center gap-2 pt-2 text-xs text-blue-200/70">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-blue-300" />
            Scaffold UI — ZK crypto, Groth16 prover, and the Soroban contract are not yet wired; all
            data is clearly labelled mock and no operation fakes success.
          </p>
        </div>
      </MegaMendungBanner>

      <section className="space-y-5">
        <div className="space-y-1.5">
          <span className="eyebrow">Get started</span>
          <h2 className="text-2xl font-bold tracking-tight text-ink">Choose your role</h2>
        </div>
        <RoleSwitcher />
      </section>

      <section className="space-y-6">
        <div className="space-y-1.5">
          <span className="eyebrow">How it holds together</span>
          <h2 className="text-2xl font-bold tracking-tight text-ink">
            Private from the public, fully auditable
          </h2>
        </div>
        <div className="grid gap-px overflow-hidden rounded-2xl border border-blue-100 bg-blue-100 sm:grid-cols-3">
          {[
            {
              n: '01',
              t: 'Confidential transfer',
              d: 'RWA moves via Poseidon commitments; nullifiers prevent double-spend. Amounts and parties stay hidden.',
            },
            {
              n: '02',
              t: 'In-circuit compliance',
              d: 'KYC membership, sanctions non-membership, and per-asset limits proven without revealing identities.',
            },
            {
              n: '03',
              t: 'Mandatory disclosure',
              d: 'Every note is encrypted to the regulator view key — enforced by the proof, not optional.',
            },
          ].map((f, i) => (
            <div
              key={f.t}
              className="animate-fade-up bg-white p-6"
              style={{ animationDelay: `${i * 80}ms` }}
            >
              <span className="font-mono text-xs font-semibold text-blue-400">{f.n}</span>
              <h3 className="mt-3 text-base font-bold text-ink">{f.t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-ink-muted">{f.d}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
