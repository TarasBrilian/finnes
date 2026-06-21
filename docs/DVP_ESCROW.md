# FIN-017 — Production DvP via escrow (scope / design)

Status: **SCOPE / DESIGN** (not yet implemented). This document specifies the
production escrow DvP that replaces the demo combined-proof `settle_dvp` (FIN-016),
per [`ARCHITECTURE.md`](./ARCHITECTURE.md) → "Settlement (DvP)" and CLAUDE.md
invariant #15. It is the basis for deciding how much to build.

---

## Goal

Atomically exchange two assets (e.g. tokenized security ↔ confidential cash)
between A and B **without either party revealing its spending key to the other**,
and **without one combined witness holding both secrets** (the demo's non-production
shortcut). Hidden amounts/parties are preserved; the only accepted leak is that
"an intent of some size exists."

## Why the demo model is not production

A sound nullifier is `Poseidon(rho, owner_sk)`. A single combined proof spending
A's and B's notes needs **both** `owner_sk` in one witness — i.e. shared key
material. The demo accepts this only because a harness owns both keypairs. Escrow
avoids it: each party spends **with its own key** in a first phase; settlement
spends notes owned by the **intent**, not by any party's long-term key.

---

## Model (three on-chain phases + refund)

```
 create_intent           escrow_deposit ×2            settle_intent
 (A & B consent)   →   (each party, own key)   →   (one proof, both escrows)
                              │                            │
                              └────── timeout ───────→ escrow_refund ×2
                                   (deadline passed, unsettled)
```

1. **create_intent** — A and B agree off-chain on the swap, then both
   `require_auth` (native Ed25519) over the concrete intent: the two expected
   escrow commitments, the two swap-output commitments, each party's refund pk, a
   nonce, and a `deadline` (ledger seq). The contract stores an `Intent` record.
   Consent is on-chain, never an in-circuit signature (invariant #15).
2. **escrow_deposit** (×2, independent) — each party single-party-spends its own
   shielded note (main tree, its own `owner_sk`) into an **escrow note** owned by
   `pk_intent = Poseidon(sk_intent)`, inserted into a **separate escrow tree**.
   Sound, no shared key (each uses only its own secret).
3. **settle_intent** — once both escrows are deposited and `now < deadline`, ONE
   proof spends BOTH escrow notes (authority = `sk_intent`, the intent's own key —
   not a party's long-term spending key) and mints the swapped main-tree outputs
   (asset X → B, asset Y → A), which must equal the commitments A & B consented to.
   One proof / one pairing → atomic (invariant #7).
4. **escrow_refund** (×2) — if `now >= deadline` and the intent is unsettled, each
   party reclaims its escrow note into a fresh main-tree note paid to its
   committed `refund_pk`. Atomic-via-escrow with timeout refund (HTLC / DvP-CCP).

### Key design decisions (the crux)

- **`sk_intent` is a fresh per-intent key shared by A and B** (agreed when they
  consent). "No shared key material" in ARCHITECTURE refers to the **deposit**
  phase (the unsound part if combined); settlement may use a shared *intent* key
  because both escrow notes have the **same** owner (the intent) — there is no
  cross-party soundness issue. Either party (or a relayer) can drive settle/refund.
- **Domain separation via a separate escrow tree.** Because A and B both know
  `sk_intent`, an escrow note must NOT be spendable by the ordinary
  `confidential_transfer` (which would let A drain it bypassing the escrow rules).
  Escrow notes live in their **own commitment tree** (root/frontier/leaf-count in
  contract state); `confidential_transfer` anchors only to the main tree, so it
  can never consume an escrow note. `settle_intent`/`escrow_refund` are the ONLY
  ops that anchor to the escrow tree, and the contract enforces their rules.
- **Timelock + fixed outputs prevent cheating.** Before `deadline` only
  `settle_intent` is allowed, and its outputs MUST equal the intent's consented
  swap commitments (so the only valid pre-deadline action is the agreed swap).
  After `deadline`, only `escrow_refund` is allowed, paying each escrow back to its
  committed `refund_pk` (so neither party can divert the other's escrow).
- **Auditor + compliance preserved.** Every minted note (escrow notes, swap
  outputs, refund notes) carries the mandatory `c_auditor` (invariant #5); swap
  outputs prove recipient KYC + sanctions/frozen non-membership (invariants
  #14/#19), exactly like `transfer`.

---

## Components & how much reuses existing work

The novelty is mostly **contract-side** (two trees + intent state + timelock); the
circuits are close variants of `transfer`/`dvp` (anchor root + output-owner
binding differ — same gadgets, BLS-native, no new crypto).

| Component | New? | Notes |
|---|---|---|
| `escrow_deposit.circom` | variant of `transfer` (1-in/1-out) | input anchors **main** tree; output owner = `pk_intent` (bound to the intent); inserts into the **escrow** tree |
| settle | **reuses `dvp.circom` as-is** (no new circuit) | both inputs anchor the **escrow** tree, both owned by `sk_intent`; mints the two **main**-tree swap outputs — confirmed in Phase B by `buildSettleScenario` driving the `dvp` harness |
| `escrow_refund.circom` | variant of `transfer` (1-in/1-out) | input anchors **escrow** tree (owned by `sk_intent`); output to the depositor's `refund_pk` in the **main** tree |
| Escrow commitment tree | NEW contract state | second `merkle` instance (root/frontier/leaf-count, recent-roots) |
| `Intent` record + status | NEW contract state | `{deadline, status, escrow_a/b_cm, out_a/b_cm, refund_a/b_pk, deposited_a/b}` |
| `create_intent` / `escrow_deposit` / `settle_intent` / `escrow_refund` | NEW entrypoints | dual `require_auth` on create; timelock + state machine; verify-before-effects (#9) |
| Per-circuit VKs (`vk_escrow_deposit`, `vk_settle`, `vk_refund`) | NEW | fresh phase-2 ceremony per circuit |
| SDK witness builders + intent helpers | NEW | reuse `buildTransferWitness`/`buildDvpWitness` shapes |
| Negative/positive witness gates + `cargo` tests | NEW | one rejection per constraint class (CLAUDE.md rule) |

This roughly equals the entire transfer subsystem again, and **re-touches the
deployed contract heavily** (new tree + state + entrypoints) → a full **redeploy +
re-ceremony** to go live. The current testnet contract (single tree) cannot host
it incrementally.

---

## Open questions (need decisions before/at build time)

1. **Atomicity guarantee for settle.** A single proof spending both escrow notes is
   atomic; confirm we keep one pairing (invariant #7) by spending both escrow notes
   in one `settle.circom` (a dvp-shaped 2-in/2-out across the escrow tree).
2. **Refund authority.** Refund pays the depositor's committed `refund_pk`; confirm
   the depositor proves with `sk_intent` (shared) but the OUTPUT is pinned by the
   intent, so a malicious party can't redirect. Alternative: refund proves the
   original deposit linkage (heavier). Recommend the pinned-output approach.
3. **Escrow-note auditor ciphertext.** Escrow notes are transient; still mandate
   `c_auditor` on them (recommended, invariant #5 uniformity) or exempt them
   (smaller, but a uniformity exception)? Recommend mandate.
4. **Deadline source.** Soroban ledger sequence vs timestamp; recommend
   `env.ledger().sequence()` with a ledger-count deadline (deterministic).
5. **Intent privacy.** The `Intent` record leaks "an intent of size ~ exists" + the
   two parties' on-chain accounts (via `require_auth`). Accepted per ARCHITECTURE.
   Confirm we are fine exposing the swap-output commitments on-chain at create time.

---

## Phasing (so we can stop at a verifiable milestone)

- **Phase A — design (this doc). DONE.** Model + decisions locked.
- **Phase B — circuits + witness gates (verifiable locally, no chain). DONE.**
  `circuits/lib/escrow_leg.circom` = `EscrowLeg(D,K_a,K_r,CHECK_RECIPIENT)`, a 1-in/
  1-out single-asset spend reusing the FIN-003/004/005 gadgets + a single-insert
  tree transition. Top-levels `escrow_deposit.circom` (`EscrowLeg(20,5,5,0)`, output
  to the intent, no recipient KYC) and `escrow_refund.circom` (`EscrowLeg(20,5,5,1)`,
  output to a KYC'd party) compile at D=20 (61 public signals each). **`settle` is
  the existing `dvp.circom`** (confirmed: `buildSettleScenario` drives it with both
  escrow inputs owned by `sk_intent`, anchored to the escrow root → the two swap
  outputs). SDK `buildEscrowLegWitness`; `scripts/lib/escrow-scenario.ts` +
  `scripts/test-escrow-witness.ts` (`npm run escrow:witness`, in CI): valid accepted
  + one rejection per constraint class (#3/#5/#12/#14/#19) — 9/9.
- **Phase C — contract.** Escrow tree + `Intent` state machine + 4 entrypoints +
  `cargo test` (state transitions, timelock, dual-auth, verify-before-effects).
- **Phase D — operator/Railway.** Per-circuit D=20 ceremony → VKs → redeploy +
  init → live escrow DvP on testnet. (Same Railway procedure as transfer/dvp.)

**Effort:** Phase B alone ≈ the FIN-016 effort ×~2–3 (three circuits). Phases B+C
are a multi-session build. Phase D needs a redeploy of a new contract.

## Recommendation

Build **Phase B** next (the cryptographic core, fully verifiable with the existing
circom/snarkjs toolchain and the witness-gate pattern), then decide on C/D. The
demo already shows DvP via the labeled non-production combined proof (FIN-016), so
escrow DvP is a credibility/production deliverable rather than a demo-blocker — a
verified circuit core + this spec is a strong, honest increment.
