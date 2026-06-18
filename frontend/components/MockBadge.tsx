/**
 * Small, unmissable label for clearly-marked mock/placeholder data. Honesty is a
 * hard constraint: anything not backed by real sdk/prover/contract wiring must
 * say so.
 */
export function MockBadge({ label = 'MOCK DATA' }: { label?: string }) {
  return (
    <span
      className="badge bg-amber-100 text-amber-800"
      title="Placeholder data — not backed by real chain/crypto wiring yet."
    >
      {label}
    </span>
  );
}

/** A 'not wired' status pill for operations that require unimplemented wiring. */
export function NotWiredBadge() {
  return (
    <span className="badge bg-slate-200 text-slate-700" title="Requires sdk/prover/contract wiring">
      TODO · not wired
    </span>
  );
}
