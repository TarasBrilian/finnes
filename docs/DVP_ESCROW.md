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
6. **Settle input binding (Phase-D hardening).** `settle_intent` pins the OUTPUT
   commitments to the intent but NOT the spent INPUT escrow commitments (the reused
   `dvp` circuit exposes nullifiers, not spent cms). It is **theft-safe** — spending
   an escrow needs the intent's `sk_intent` (A&B-only) and minting the exact outputs
   needs their secret openings, so no outsider can settle; the only residual is
   intra-intent self-griefing (a party settling with foreign escrows it controls,
   burning its own value). A tighter design uses a settle-specific circuit that
   exposes the two spent escrow cms so the contract can check them ==
   `intent.escrow_a/b_cm`. Deferred to Phase D (a circuit change). Likewise, both
   trees share `cfg.initial_root` in their genesis recent-roots windows — harmless
   (both trees are empty at genesis; the first escrow note produces a distinct
   escrow root only in the escrow window).

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

## Phase C — contract design (detail)

The contract today has ONE commitment tree (`DataKey::{TreeRoot, LeafCount,
Frontier, RecentRoots}` + `merkle.rs` helpers) and a `Circuit` enum
`{Shield, Transfer, Unshield, Dvp}`. Phase C adds a second tree + an intent state
machine + 4 entrypoints. It is a NEW contract (redeploy in Phase D); changing the
storage layout is acceptable.

### Second commitment tree (the escrow tree)

Domain separation is what stops A/B (who both know `sk_intent`) from draining an
escrow via the ordinary `confidential_transfer`. Mechanism — **per-tree
recent-roots windows**: `confidential_transfer` checks `anchor_root` against the
MAIN window; `settle`/`escrow_refund` check it against the ESCROW window. An escrow
note exists only in the escrow tree, so any inclusion proof for it anchors to an
escrow root, which is NOT in the main window → `UnknownAnchorRoot`. Free isolation.

- **Approach (recommended): parameterise `merkle.rs` + the tree DataKeys by a
  `Tree {Main, Escrow}` selector** — `Frontier(Tree)`, `TreeRoot(Tree)`,
  `LeafCount(Tree)`, `RecentRoots(Tree)`; `check_old_frontier(env, tree, …)`,
  `apply_transition(env, tree, …)`, `is_recent_root(env, tree, …)`. Mechanical
  churn across the 4 existing callers (all pass `Tree::Main`), cleanly tested by
  `cargo test`. (Alternative: additive `Escrow*` DataKeys + duplicate helpers —
  less churn, more duplication. Recommend the selector.)

### Intent state machine

`DataKey::Intent(BytesN<32>)` → `IntentRecord` (persistent):

```
IntentRecord {
  deadline:      u32,        // ledger sequence; settle requires now < deadline, refund now >= deadline
  status:        Open | Settled,
  escrow_a_cm, escrow_b_cm:  BytesN<32>,  // expected escrow commitments (deposit targets)
  out_a_cm,   out_b_cm:      BytesN<32>,  // consented swap outputs (settle must mint exactly these)
  refund_a_cm, refund_b_cm:  BytesN<32>,  // consented refund notes (refund must mint exactly these)
  deposited_a, deposited_b:  bool,
  refunded_a,  refunded_b:   bool,
}
```

All six commitments are fixed at `create_intent` under BOTH parties'
`require_auth`, so neither party can later divert value (settle/refund outputs are
pinned to the consented commitments; invariant #15 consent-binds the concrete
intent).

### Entrypoints (verify-before-effects, invariant #9)

1. **`create_intent(env, party_a, party_b, intent_id, record)`** — `party_a` &
   `party_b` both `require_auth`; validate `deadline > ledger.sequence()`; reject if
   `intent_id` exists; store `record` (Open). Emits `intent_created`.
2. **`escrow_deposit(env, depositor, intent_id, leg, proof, pi: EscrowDepositPI)`** —
   init; `require_auth(depositor)`; intent Open + this leg not yet deposited; MAIN
   anchor window; `nf` unused; frozen-strict + assets/auditor roots; `pi.cm_out_0 ==
   record.escrow_{leg}_cm`; ESCROW `old_frontier` + `next_index`; `verify_groth16(vk
   = EscrowDeposit)`; → insert `nf`, apply ESCROW transition (+1), set
   `deposited_{leg}`. Emits `escrow_deposited`.
3. **`settle_intent(env, intent_id, proof, pi: DvpPublicInputs)`** — init; intent
   Open; both `deposited`; `now < deadline`; ESCROW anchor window; both escrow `nf`
   unused; frozen-strict + kyc/sanction/assets/auditor; `pi.cm_out_x ==
   record.out_b_cm` & `pi.cm_out_y == record.out_a_cm`; MAIN `old_frontier` +
   `next_index`; `verify_groth16(vk = Dvp)`; → insert both `nf`, apply MAIN
   transition (+2), status = Settled. Emits `intent_settled`. No extra auth (consent
   was at create; a relayer may trigger).
4. **`escrow_refund(env, refunder, intent_id, leg, proof, pi: EscrowRefundPI)`** —
   init; `require_auth(refunder)`; intent Open; `now >= deadline`; this leg
   `deposited` & not `refunded`; ESCROW anchor window; `nf` unused; recipient
   KYC/sanction + frozen-strict + assets/auditor; `pi.cm_out_0 ==
   record.refund_{leg}_cm`; MAIN `old_frontier` + `next_index`; `verify_groth16(vk =
   EscrowRefund)`; → insert `nf`, apply MAIN transition (+1), set `refunded_{leg}`.
   Emits `escrow_refunded`.

### Supporting changes

- `Circuit` += `EscrowDeposit`, `EscrowRefund` (settle reuses `Dvp`); `init` stores
  `vk_escrow_deposit` / `vk_escrow_refund` (empty placeholders until the Phase-D
  ceremony, as `vk_dvp` is today).
- `types.rs` += `EscrowDepositPublicInputs` / `EscrowRefundPublicInputs` (61 signals,
  matching the circuits) + `to_scalars`.
- `events.rs` += the 4 intent events; `errors.rs` += `IntentExists`,
  `IntentNotFound`, `IntentNotOpen`, `AlreadyDeposited`, `NotDeposited`,
  `DeadlineNotReached`, `DeadlinePassed`, `EscrowCmMismatch`, `SwapOutputMismatch`.

### Tests (`cargo test`, no ceremony needed for these)

State-machine + ordering coverage (the full verify path needs a D=20 proof = Phase
D, like the existing entrypoints): create dual-auth; deposit→deposit→settle happy
path gated to the verifier; refund-before-deadline → `DeadlineNotReached`;
settle-after-deadline → `DeadlinePassed`; double-deposit → `AlreadyDeposited`;
wrong escrow/swap/refund commitment → mismatch errors; **two-tree isolation**
(an escrow root is NOT in the main window, so `confidential_transfer` rejects an
escrow-anchored spend → `UnknownAnchorRoot`); verify-before-effects.

### Effort / risk

A substantial contract addition (~the size of the original transfer+dvp contract
work): the `Tree` refactor touches all 4 existing entrypoints (mechanical, cargo-
tested), plus ~4 entrypoints, 2 PI structs, intent state, events, errors, and
tests. No ceremony/redeploy (that is Phase D). Fully verifiable by `cargo test` +
`clippy` + wasm build.

## Status

- **Phase A (design): DONE** — this document.
- **Phase B (circuits + witness gates): DONE** — see the phasing section above.
- **Phase C (contract): DONE.** Implemented the `Tree{Main,Escrow}` selector
  (state.rs + merkle.rs, all existing entrypoints pass `Tree::Main`), the
  `IntentRecord` state machine, `EscrowLegPublicInputs`, the 4 entrypoints
  (`create_intent` / `escrow_deposit` / `settle_intent` / `escrow_refund`), the
  `Circuit::{EscrowDeposit,EscrowRefund}` VKs (init stores empty placeholders until
  Phase D), 4 events, and 9 errors. `cargo test` = **34 passed** (8 new: create
  past-deadline/duplicate, deposit wrong-cm/leg-a-reaches-verifier/unknown-anchor,
  settle not-fully-deposited/unknown-intent, refund-before-deadline); `clippy`
  clean; `cargo fmt` clean; `wasm32v1-none` release builds. The full verify path is
  gated to the verifier (`VerifyingKeyArityMismatch` with the dummy VK), like the
  other entrypoints — a real D=20 proof is Phase D.
- **Phase D (ceremony + on-chain): DEFERRED** — per-circuit ceremony (escrow_deposit
  / escrow_refund VKs; settle reuses vk_dvp), wire real VKs into `init`
  (gen-init-config already carries the placeholders), and a fresh redeploy + live
  escrow DvP on testnet. Same Railway procedure as transfer/dvp.

Escrow DvP is a credibility/production deliverable, not a demo-blocker (FIN-016's
labeled combined proof already demos DvP).
