import { BatikBackdrop, BATIK_SRC } from '@/components/Batik';
import { Parallax, Reveal } from '@/components/Parallax';

/**
 * Immersive landing for Finnes. A dark "vault" experience: oversized editorial
 * headlines over parallax Mega Mendung batik, a ticker, numbered pillars that
 * reveal on scroll, a role gateway, and a closing call to action. The role-based
 * consoles (/institution, /regulator) keep the light institutional theme.
 */

const PILLARS = [
  {
    n: '01',
    t: 'Confidential transfer',
    d: 'RWA moves as Poseidon commitments that hide amount, asset, and owner; nullifiers prevent double-spend. A Groth16 proof attests validity without revealing a single value.',
  },
  {
    n: '02',
    t: 'In-circuit compliance',
    d: 'KYC membership, sanctions non-membership, and per-asset limits are proven inside the circuit — compliance without exposing identities to the public ledger.',
  },
  {
    n: '03',
    t: 'Mandatory disclosure',
    d: 'Every note is encrypted to the regulator view key, enforced by the proof itself. Auditability is not optional — it is a constraint the prover cannot skip.',
  },
];

const ROLES = [
  {
    href: '/institution',
    label: 'Institution',
    blurb: 'Hold shielded notes, settle confidentially, and stay provably compliant — KYC, limits, and disclosure handled in-circuit.',
    glyph: 'M4 20h16M6 20V8l6-4 6 4v12M10 12h4M10 16h4',
  },
  {
    href: '/regulator',
    label: 'Regulator / Auditor',
    blurb: 'Hold the view key and decrypt any transaction. The public sees opaque blobs; you see the full picture — amounts and parties.',
    glyph: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
  },
];

export default function HomePage() {
  return (
    <div className="-mt-20 bg-midnight text-white">
      {/* ---- Hero ----------------------------------------------------------- */}
      {/* pt-20 restores the space the negative margin pulled the hero under the
          sticky header, so the dark hero sits behind the transparent nav. */}
      <section className="relative flex min-h-[90vh] items-center overflow-hidden pt-20">
        <BatikBackdrop />
        <div className="relative z-10 mx-auto w-full max-w-6xl px-6 py-24">
          <div className="max-w-3xl">
            <span className="eyebrow-accent animate-fade-up">Stellar · Soroban · BLS12-381</span>
            <h1 className="mt-6 font-display text-[3.1rem] font-extrabold leading-[0.98] tracking-tight text-white animate-fade-up sm:text-[4.6rem]">
              Confidential
              <br />
              settlement for
              <br />
              <span className="text-accent">regulated RWA.</span>
            </h1>
            <p
              className="mt-7 max-w-xl text-lg leading-relaxed text-white/70 animate-fade-up"
              style={{ animationDelay: '120ms' }}
            >
              Move real-world-asset tokens on Stellar with hidden amounts and counterparties —
              atomically settled, provably compliant in-circuit, and selectively disclosable to
              regulators.
            </p>
            <div
              className="mt-9 flex flex-wrap items-center gap-3 animate-fade-up"
              style={{ animationDelay: '220ms' }}
            >
              <a href="/institution" className="btn-glow">Open institution console →</a>
              <a href="/regulator" className="btn-outline-light">Regulator view</a>
            </div>
            <div
              className="mt-12 flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-medium uppercase tracking-[0.18em] text-white/40 animate-fade-up"
              style={{ animationDelay: '320ms' }}
            >
              <span>Groth16</span>
              <span className="text-white/20">/</span>
              <span>Poseidon-BLS</span>
              <span className="text-white/20">/</span>
              <span>one pairing-check</span>
              <span className="text-white/20">/</span>
              <span>no mixer</span>
            </div>
          </div>
        </div>
      </section>

      {/* ---- Ticker --------------------------------------------------------- */}
      <div className="border-y border-white/10 bg-midnight-900/60 py-4">
        <div className="marquee-mask overflow-hidden">
          <div className="flex w-max animate-marquee whitespace-nowrap">
            {[0, 1].map((g) => (
              <div key={g} className="flex items-center gap-8 pr-8 font-display text-sm font-semibold uppercase tracking-[0.22em] text-white/55">
                {Array.from({ length: 6 }).map((_, i) => (
                  <span key={i} className="flex items-center gap-8">
                    Dark-pool-grade confidentiality
                    <span className="text-accent">◆</span>
                    Audit-grade transparency
                    <span className="text-accent">◆</span>
                  </span>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ---- Pillars -------------------------------------------------------- */}
      <section className="relative overflow-hidden">
        <Parallax speed={0.08} className="pointer-events-none absolute -right-40 top-0 h-[560px] w-[560px]" aria-hidden>
          <div
            className="h-full w-full rounded-full opacity-[0.14] [mask-image:radial-gradient(closest-side,#000_55%,transparent)]"
            style={{ backgroundImage: `url(${BATIK_SRC})`, backgroundSize: 'cover', backgroundRepeat: 'no-repeat' }}
          />
        </Parallax>

        <div className="relative mx-auto max-w-6xl px-6 py-28">
          <Reveal>
            <span className="eyebrow-accent">How it holds together</span>
            <h2 className="mt-4 max-w-2xl font-display text-3xl font-bold leading-tight tracking-tight text-white sm:text-5xl">
              Private from the public,
              <br />
              <span className="text-white/55">fully auditable.</span>
            </h2>
          </Reveal>

          <div className="mt-16 divide-y divide-white/10 border-t border-white/10">
            {PILLARS.map((p, i) => (
              <Reveal key={p.t} delay={i * 90}>
                <article className="group grid items-start gap-6 py-10 md:grid-cols-[7rem_1fr] md:gap-12">
                  <span className="font-display text-5xl font-extrabold tracking-tight text-accent/80 transition group-hover:text-accent">
                    {p.n}
                  </span>
                  <div className="max-w-2xl">
                    <h3 className="font-display text-2xl font-bold tracking-tight text-white">{p.t}</h3>
                    <p className="mt-3 text-base leading-relaxed text-white/65">{p.d}</p>
                  </div>
                </article>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ---- Roles ---------------------------------------------------------- */}
      <section className="relative border-t border-white/10 bg-midnight-900/50">
        <div className="mx-auto max-w-6xl px-6 py-28">
          <Reveal>
            <span className="eyebrow-accent">Get started</span>
            <h2 className="mt-4 font-display text-3xl font-bold tracking-tight text-white sm:text-5xl">
              Choose your role
            </h2>
            <p className="mt-3 max-w-xl text-base text-white/60">
              Each view shows only what that party is entitled to see.
            </p>
          </Reveal>

          <div className="mt-12 grid gap-5 sm:grid-cols-2">
            {ROLES.map((r, i) => (
              <Reveal key={r.href} delay={i * 100}>
                <a href={r.href} className="glass glass-hover group flex h-full flex-col gap-5 p-8">
                  <span className="grid h-12 w-12 place-items-center rounded-xl border border-accent/30 bg-accent/10 text-accent">
                    <svg viewBox="0 0 24 24" className="h-6 w-6" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                      <path d={r.glyph} />
                    </svg>
                  </span>
                  <div>
                    <h3 className="font-display text-xl font-bold tracking-tight text-white">{r.label}</h3>
                    <p className="mt-2 text-sm leading-relaxed text-white/60">{r.blurb}</p>
                  </div>
                  <span className="mt-auto inline-flex items-center gap-2 text-sm font-semibold text-accent transition group-hover:gap-3">
                    Enter console <span aria-hidden>→</span>
                  </span>
                </a>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ---- Final CTA ------------------------------------------------------ */}
      <section className="relative overflow-hidden border-t border-white/10">
        <BatikBackdrop focus="center" />
        <div className="relative z-10 mx-auto max-w-4xl px-6 py-32 text-center">
          <Reveal>
            <h2 className="font-display text-4xl font-extrabold leading-tight tracking-tight text-white sm:text-6xl">
              Settle in private.
              <br />
              <span className="text-accent">Prove it in public.</span>
            </h2>
            <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-white/70">
              A confidential settlement layer for regulated assets — where competitors see nothing,
              and the regulator sees everything.
            </p>
            <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
              <a href="/institution" className="btn-glow">Open institution console →</a>
              <a href="/regulator" className="btn-outline-light">Regulator view</a>
            </div>
          </Reveal>
        </div>
      </section>
    </div>
  );
}
