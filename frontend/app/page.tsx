import { RoleSwitcher } from '@/components/RoleSwitcher';

/**
 * Landing + role switcher (Institution / Regulator). Each role-based view shows
 * the user only what they are entitled to see (ARCHITECTURE.md → Roles).
 */
export default function HomePage() {
  return (
    <div className="space-y-10">
      <section className="space-y-3">
        <h1 className="text-3xl font-bold tracking-tight text-ink">
          Confidential settlement for regulated RWA
        </h1>
        <p className="max-w-2xl text-ink-muted">
          Settle real-world-asset tokens on Stellar with hidden amounts and counterparties —
          atomically settled (DvP), provably compliant in-circuit, and selectively disclosable to
          regulators. <span className="font-medium text-ink">Dark-pool-grade confidentiality,
          audit-grade transparency.</span>
        </p>
        <p className="max-w-2xl text-sm text-ink-faint">
          This is a scaffold UI. The ZK crypto (@finnes/sdk), the Groth16 prover (@finnes/prover),
          and the Soroban contract are not yet wired; data shown is clearly labelled as mock and no
          operation fakes success.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold text-ink">Choose a role</h2>
        <RoleSwitcher />
      </section>

      <section className="grid gap-4 sm:grid-cols-3">
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
        ].map((f) => (
          <div key={f.t} className="card">
            <h3 className="text-sm font-semibold text-ink">{f.t}</h3>
            <p className="mt-1 text-sm text-ink-muted">{f.d}</p>
          </div>
        ))}
      </section>
    </div>
  );
}
