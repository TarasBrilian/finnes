/**
 * Visible trust-boundary note (CLAUDE.md invariant #8). Always on screen so the
 * security model is never out of sight: the frontend + prover are the ONLY place
 * private keys exist; nothing secret ever reaches a shared backend.
 */
export function TrustBoundaryBanner() {
  return (
    <div className="border-b border-emerald-200 bg-emerald-50">
      <div className="mx-auto max-w-6xl px-6 py-2 text-xs text-emerald-900">
        <span className="font-semibold">Trust boundary:</span> spending keys, viewing keys, the
        witness, and note plaintext stay in this browser tab. The prover runs client-side. Nothing
        secret is ever logged, persisted, or sent to a shared backend (invariant&nbsp;#8).
      </div>
    </div>
  );
}
