import { BatikBackdrop, BatikRibbon, BatikTexture, BATIK_SRC } from '@/components/Batik';
import { Parallax, Reveal } from '@/components/Parallax';
import { FlowSteps } from '@/components/FlowSteps';

/**
 * Immersive landing for Finnes. A dark "vault" experience over parallax Mega
 * Mendung batik: an editorial hero with a live confidential-record visual, a
 * ticker, a stat band, the problem it solves, the signature "two truths"
 * reveal (public blobs vs. regulator plaintext), capabilities, the end-to-end
 * flow, a role gateway, and a closing call to action. The role-based consoles
 * (/institution, /regulator) keep the light institutional theme.
 */

// --- Quick-credibility figures shown directly under the hero. ---------------
const STATS = [
  { v: '128-bit', k: 'BLS12-381 security' },
  { v: '1', k: 'pairing-check per tx' },
  { v: '~1.05M', k: 'notes per tree (depth 20)' },
  { v: '0', k: 'values revealed to the public' },
];

// --- What a transparent public ledger leaks for an institution. -------------
const LEAKS = [
  { t: 'Amount', d: 'A large tokenized-bond transfer broadcasts its exact size to every competitor.' },
  { t: 'Counterparties', d: 'Address clustering reveals who settled with whom, and how often.' },
  { t: 'Position & timing', d: 'Pending transfers expose holdings and trading strategy in real time.' },
  { t: 'Front-running', d: 'Visible large orders invite being traded ahead of before they settle.' },
];

// --- The same on-chain transaction, two views. ------------------------------
const PUBLIC_VIEW = [
  { k: 'commitment', v: '0x9f3c…a71e' },
  { k: 'nullifier', v: '0x44b8…02d9' },
  { k: 'ciphertext', v: '0x6e1d… (packed)' },
  { k: 'proof', v: '✓ verified' },
];
const REGULATOR_VIEW = [
  { k: 'asset', v: 'TBOND-2031' },
  { k: 'amount', v: '1,000,000' },
  { k: 'from', v: 'Meridian Capital' },
  { k: 'to', v: 'Cendrawasih Bank' },
  { k: 'compliance', v: 'KYC ✓ · sanctions ✓ · within limit' },
];

// --- Capabilities (richer than the original three pillars). -----------------
const CAPS = [
  {
    n: '01',
    t: 'Confidential transfer',
    d: 'RWA moves as Poseidon commitments that hide amount, asset, and owner; nullifiers prevent double-spend. A Groth16 proof attests validity without revealing a single value.',
  },
  {
    n: '02',
    t: 'In-circuit compliance',
    d: 'KYC membership, sanctions non-membership, and per-asset limits are proven inside the circuit: compliance without exposing identities to the public ledger.',
  },
  {
    n: '03',
    t: 'Mandatory disclosure',
    d: 'Every note is encrypted to the regulator view key, enforced by the proof itself. Auditability is not optional; it is a constraint the prover cannot skip.',
  },
  {
    n: '04',
    t: 'Atomic DvP',
    d: 'The asset leg and the payment leg settle together in a single Soroban invocation; production settlement is escrow-based and two-phase, with a timeout refund.',
  },
  {
    n: '05',
    t: 'Issuer freeze & clawback',
    d: 'A frozen-commitment set makes a note unspendable; every spend proves non-membership. Two-phase and two-key: the auditor identifies, the issuer freezes.',
  },
  {
    n: '06',
    t: 'Threshold view keys',
    d: 'The auditor view key can be split Shamir k-of-n across authorities, so disclosure needs a quorum and there is no single honeypot to compromise.',
  },
];

// --- End-to-end flow. -------------------------------------------------------
const FLOW = [
  { n: '1', t: 'Shield', d: 'Deposit a transparent RWA token. It becomes a Poseidon-committed shielded note, and only an opaque commitment ever lands on-chain.' },
  { n: '2', t: 'Prove', d: 'The client builds a Groth16 proof of a valid, compliant, fully-encrypted transfer, locally. Spending and view keys never leave the tab.' },
  { n: '3', t: 'Verify & settle', d: 'Soroban runs one BLS12-381 pairing-check, records the nullifiers, and appends the new commitments, all atomically.' },
  { n: '4', t: 'Disclose', d: 'The regulator decrypts the mandatory ciphertext with the view key and audits the full transaction: amounts and parties.' },
];

const ROLES = [
  {
    href: '/institution',
    label: 'Institution',
    blurb: 'Hold shielded notes, settle confidentially, and stay provably compliant. KYC, limits, and disclosure are handled in-circuit.',
    glyph: 'M4 20h16M6 20V8l6-4 6 4v12M10 12h4M10 16h4',
  },
  {
    href: '/regulator',
    label: 'Regulator / Auditor',
    blurb: 'Hold the view key and decrypt any transaction. The public sees opaque blobs; you see the full picture: amounts and parties.',
    glyph: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
  },
];

export default function HomePage() {
  return (
    <div className="-mt-20 bg-midnight text-white">
      {/* ---- Hero ----------------------------------------------------------- */}
      {/* pt-20 restores the space the negative margin pulled the hero under the
          sticky header, so the dark hero sits behind the transparent nav. */}
      <section className="relative flex min-h-[92vh] items-center overflow-hidden pt-20">
        <BatikBackdrop />
        <div className="relative z-10 mx-auto grid w-full max-w-6xl items-center gap-14 px-6 py-24 lg:grid-cols-[1.05fr_0.95fr]">
          <div className="max-w-2xl">
            <span className="inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-accent animate-fade-up">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent/70" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-accent" />
              </span>
              Live on Stellar testnet
            </span>
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
              Move real-world-asset tokens on Stellar with hidden amounts and counterparties:
              atomically settled, provably compliant in-circuit, and selectively disclosable to
              regulators. <span className="text-white/90">Dark-pool-grade confidentiality, audit-grade transparency.</span>
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

          {/* Hero visual: a single on-chain record, opaque to the public,
              with the regulator's decrypted truth folded underneath. */}
          <div className="relative hidden animate-fade-up lg:block" style={{ animationDelay: '260ms' }} aria-hidden="true">
            <div className="absolute -inset-6 rounded-[2rem] bg-aurora opacity-80 blur-2xl" />
            <div className="glass relative overflow-hidden p-7 shadow-glow">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/45">Public ledger</span>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 px-2.5 py-0.5 text-[11px] font-semibold text-accent">
                  <span className="h-1.5 w-1.5 rounded-full bg-accent" /> proof verified
                </span>
              </div>
              <dl className="mt-5 space-y-2.5 font-mono text-[13px]">
                {PUBLIC_VIEW.map((r) => (
                  <div key={r.k} className="flex items-center justify-between gap-4 border-b border-white/5 pb-2.5">
                    <dt className="text-white/40">{r.k}</dt>
                    <dd className={r.k === 'proof' ? 'text-accent' : 'truncate text-white/75'}>{r.v}</dd>
                  </div>
                ))}
              </dl>

              <div className="mt-6 rounded-2xl border border-accent/25 bg-accent/[0.07] p-5">
                <span className="text-[11px] font-semibold uppercase tracking-[0.22em] text-accent/90">
                  Regulator view · with view key
                </span>
                <dl className="mt-3 space-y-2 text-[13px]">
                  {REGULATOR_VIEW.slice(0, 4).map((r) => (
                    <div key={r.k} className="flex items-center justify-between gap-4">
                      <dt className="text-white/45">{r.k}</dt>
                      <dd className="font-medium text-white">{r.v}</dd>
                    </div>
                  ))}
                </dl>
              </div>
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

      {/* ---- Stat band ------------------------------------------------------ */}
      <section className="border-b border-white/10 bg-midnight-900/40">
        <div className="mx-auto grid max-w-6xl grid-cols-2 gap-px overflow-hidden px-6 py-4 md:grid-cols-4">
          {STATS.map((s, i) => (
            <Reveal key={s.k} delay={i * 70}>
              <div className="px-2 py-6 text-center md:px-6">
                <div className="font-display text-3xl font-extrabold tracking-tight text-accent sm:text-4xl">{s.v}</div>
                <div className="mt-2 text-xs font-medium uppercase tracking-[0.14em] text-white/50">{s.k}</div>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ---- The problem ---------------------------------------------------- */}
      <section className="relative overflow-hidden">
        <Parallax speed={0.08} className="pointer-events-none absolute -left-40 top-10 h-[480px] w-[480px]" aria-hidden>
          <div
            className="h-full w-full rounded-full opacity-[0.12] [mask-image:radial-gradient(closest-side,#000_55%,transparent)]"
            style={{ backgroundImage: `url(${BATIK_SRC})`, backgroundSize: 'cover', backgroundRepeat: 'no-repeat' }}
          />
        </Parallax>

        <div className="relative mx-auto max-w-6xl px-6 py-28">
          <Reveal>
            <span className="eyebrow-accent">The problem</span>
            <h2 className="mt-4 max-w-3xl font-display text-3xl font-bold leading-tight tracking-tight text-white sm:text-5xl">
              On a public ledger, every RWA transfer
              <br />
              <span className="text-white/55">is exposed to everyone.</span>
            </h2>
            <p className="mt-5 max-w-2xl text-base leading-relaxed text-white/65">
              For retail crypto that is fine. For institutions it is a dealbreaker, leaking strategy,
              breaching client confidentiality, and inviting front-running.
            </p>
          </Reveal>

          <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {LEAKS.map((l, i) => (
              <Reveal key={l.t} delay={i * 80}>
                <div className="h-full rounded-2xl border border-white/10 bg-white/[0.03] p-6">
                  <div className="mb-3 h-px w-8 bg-rose-300/60" />
                  <h3 className="font-display text-lg font-bold tracking-tight text-white">{l.t}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-white/55">{l.d}</p>
                </div>
              </Reveal>
            ))}
          </div>

          <Reveal delay={120}>
            <p className="mt-12 max-w-2xl text-base leading-relaxed text-white/70">
              Mixers remove the leak, but also the audit trail, so they are unusable for regulated
              institutions. <span className="font-semibold text-accent">Finnes keeps both:</span> nothing
              is visible to the public, everything is visible to the regulator.
            </p>
          </Reveal>
        </div>
      </section>

      {/* ---- Two truths (the signature reveal) ------------------------------ */}
      <section className="relative border-t border-white/10 bg-midnight-900/50">
        <div className="mx-auto max-w-6xl px-6 py-28">
          <Reveal>
            <span className="eyebrow-accent">The same transaction, two truths</span>
            <h2 className="mt-4 max-w-2xl font-display text-3xl font-bold leading-tight tracking-tight text-white sm:text-5xl">
              Opaque to competitors.
              <br />
              <span className="text-accent">Transparent to the regulator.</span>
            </h2>
          </Reveal>

          <div className="mt-14 grid items-stretch gap-5 md:grid-cols-2">
            <Reveal>
              <div className="flex h-full flex-col rounded-2xl border border-white/10 bg-white/[0.03] p-7">
                <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-white/45">
                  <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></svg>
                  What the public sees
                </div>
                <dl className="mt-6 space-y-3 font-mono text-sm">
                  {PUBLIC_VIEW.map((r) => (
                    <div key={r.k} className="flex items-center justify-between gap-4 border-b border-white/5 pb-3">
                      <dt className="text-white/40">{r.k}</dt>
                      <dd className={r.k === 'proof' ? 'text-accent' : 'text-white/70'}>{r.v}</dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-6 text-sm leading-relaxed text-white/50">
                  Opaque commitments, nullifiers, and ciphertexts. A valid, compliant transfer happened, while amount and parties stay hidden.
                </p>
              </div>
            </Reveal>

            <Reveal delay={100}>
              <div className="flex h-full flex-col rounded-2xl border border-accent/30 bg-accent/[0.06] p-7 shadow-glow">
                <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-accent/90">
                  <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M7 11V8a5 5 0 0 1 10 0v3" /><rect x="5" y="11" width="14" height="10" rx="2" /></svg>
                  What the regulator sees · with the view key
                </div>
                <dl className="mt-6 space-y-3 text-sm">
                  {REGULATOR_VIEW.map((r) => (
                    <div key={r.k} className="flex items-center justify-between gap-4 border-b border-white/10 pb-3">
                      <dt className="text-white/50">{r.k}</dt>
                      <dd className="text-right font-medium text-white">{r.v}</dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-6 text-sm leading-relaxed text-white/60">
                  Every note is mandatorily encrypted to the view key, enforced by the proof. The
                  regulator decrypts the full picture: auditability the prover cannot skip.
                </p>
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      {/* ---- Capabilities --------------------------------------------------- */}
      <section className="relative overflow-hidden border-t border-white/10">
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

          <div className="mt-16 grid gap-px overflow-hidden rounded-2xl border border-white/10 bg-white/5 sm:grid-cols-2 lg:grid-cols-3">
            {CAPS.map((c, i) => (
              <Reveal key={c.t} delay={(i % 3) * 80}>
                <article className="group h-full bg-midnight p-8 transition hover:bg-midnight-800">
                  <span className="font-display text-3xl font-extrabold tracking-tight text-accent/70 transition group-hover:text-accent">
                    {c.n}
                  </span>
                  <h3 className="mt-4 font-display text-xl font-bold tracking-tight text-white">{c.t}</h3>
                  <p className="mt-2.5 text-sm leading-relaxed text-white/60">{c.d}</p>
                </article>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ---- Batik ribbon (textile divider, asset #2) ----------------------- */}
      <BatikRibbon />

      {/* ---- How it works --------------------------------------------------- */}
      <section className="relative overflow-hidden border-t border-white/10 bg-midnight-900/50">
        <BatikTexture side="right" />
        <div className="relative mx-auto max-w-6xl px-6 py-28">
          <Reveal>
            <span className="eyebrow-accent">End to end</span>
            <h2 className="mt-4 font-display text-3xl font-bold tracking-tight text-white sm:text-5xl">
              From deposit to disclosure
            </h2>
            <p className="mt-3 max-w-xl text-base text-white/60">
              Four steps. Secrets stay client-side; the chain and backend only ever touch public data.
            </p>
          </Reveal>

          <FlowSteps steps={FLOW} />
        </div>
      </section>

      {/* ---- Roles ---------------------------------------------------------- */}
      <section className="relative border-t border-white/10">
        <div className="mx-auto max-w-6xl px-6 py-28">
          <Reveal>
            <span className="eyebrow-accent">Get started</span>
            <h2 className="mt-4 font-display text-3xl font-bold tracking-tight text-white sm:text-5xl">
              Choose your role
            </h2>
            <p className="mt-3 max-w-xl text-base text-white/60">
              Each view shows only what that party is entitled to see, nothing about other parties.
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
              A confidential settlement layer for regulated assets, where competitors see nothing,
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
