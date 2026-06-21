# Finnes — Task board

Tickets to take the scaffold to a working **hackathon demo** (shield → confidential
transfer → regulator disclosure). Ordered by the critical path: each phase mostly
depends on the previous one. See [`PUBLIC_IO.md`](./PUBLIC_IO.md) for the canonical
layout and the project root `CLAUDE.md` for the binding security invariants.

**Status:** `[ ]` todo · `[~]` in progress · `[x]` done
**Priority:** P0 = blocks everything · P1 = on critical path · P2 = needed for demo · P3 = deferred/backlog

> **FIN-001 through FIN-006 are DONE.** FIN-001 locked D=20, the
> auditor-encryption scheme (A), K_a=K_r=5, recipient/sentinel encodings. FIN-002
> hashes identically circuit↔SDK. FIN-003 implemented the note + Merkle gadgets
> (incl. vendored r-aware comparator + IMT non-membership), all circuit↔SDK
> parity-verified. FIN-004 (`enc_check.circom` + `sdk/src/encrypt.ts`) and FIN-005
> (`assets.circom`) are implemented and parity-tested. **FIN-006**:
> `transfer.circom` binds BOTH output notes' mandatory ciphertexts (inv #5) and
> wires `next_index` as a public input the contract pins to its leaf count
> (closing the `nextIndex<==0` soundness hole, inv #11/#12); it compiles to **73
> public signals**. The `Transfer` template was hoisted to
> `circuits/lib/transfer.circom`; `sdk/src/witness.ts` builds the full witness and
> `npm run transfer:witness` machine-verifies a valid witness is accepted and one
> failing witness per constraint class is rejected. The contract gained
> `leaf_count` state + a `next_index` gate (`cargo test` green).
> **FIN-007 + FIN-008 are now DONE too.** A real BLS12-381 Groth16 setup runs via
> `npm run setup:demo` (depth-4 `transfer_test4`, ~115k constraints, 2^18) and
> `npm run transfer:prove` builds an SDK witness, `groth16.fullProve`s it, and
> verifies locally (41 public signals; tamper rejected) — circuit + setup + prover
> proven end-to-end off-chain. The prover now uses the SDK builder + SDK ordered
> public-IO (duplicated `PUBLIC_IO_ORDER` removed, closing FIN-022). The D=20
> production ceremony is identical but needs `PTAU_POWER=20` + more RAM (or the
> deferred Poseidon optimisation).
> **FIN-009 is now DONE too.** `verifier.rs` runs the real Groth16 pairing-check over
> the BLS12-381 host functions (single `g1_msm` for `vk_x` + one `pairing_check`); a
> real depth-4 demo proof verifies in `cargo test` and a tampered public signal is
> rejected (`scripts/gen-verifier-fixture.ts` → `contracts/finnes/src/test_vectors.rs`).
> clippy/fmt clean, wasm builds.
> **FIN-009 through FIN-014 are DONE. FIN-015 is now LIVE ON TESTNET (2026-06-20):**
> the contract is deployed + initialised and a **real D=20 shield proof verifies
> on-chain** (1000 TBOND moved depositor→contract via a registered test SAC), with the
> **regulator decrypting the on-chain note** to full plaintext — the core claim proven
> against a deployed Soroban contract. Fixed a deploy blocker: `#[contracttype]` structs
> used type aliases Soroban's spec macro doesn't define, so `init` failed at the CLI
> (`Missing Entry Root`) — aliases replaced with `BytesN<32>` in all spec-facing
> surfaces. **Next on the critical path:** **FIN-025** (transfer on-chain), **FIN-027**
> (frontend write-path), then **FIN-026** (unshield). See Phase 8.

---

## Phase 0 — Lock open decisions (cheap, but blocks circuit signal counts)

### [x] FIN-001 · P0 · Finalize PUBLIC_IO open decisions — DONE
Resolved the `TODO`s in `docs/PUBLIC_IO.md` so signal counts are fixed before circuits are written.
- **Done:** tree depth `D = 20` (2^20 ≈ 1.05M notes; demo-cheap, fresh-ceremony to raise).
- **Done:** auditor-encryption scheme = **(A) Poseidon additive keystream**, value-bound 100% in-circuit (BLS-native, no embedded curve). Auditor ct keyed by the **sender's** auditor-shared key `k_S`; `auditor_pk = Poseidon(k_S)` bound in-circuit. Demo = single `auditor_pk` scalar; production = `auditor_set_root` membership (reuses the KYC/assets Merkle gadget) for per-institution confidentiality — keystream core unchanged. Fully sound + confidential in both regimes (no griefing gap). Corrected the scaffold's non-confidential naive formula.
- **Done:** `K_a = K_r = 5` (1 nonce + 4 masked slots); `auditor_pk` single field; **every output note carries one mandatory `c_auditor` + one `c_recipient`**.
- **Done:** transparent `recipient` = single field (demo); "no change note" sentinel = `cm_change_0 == 0` (gated `has_change`).
- **Done:** concrete per-circuit totals — transfer 72, shield 58, unshield 63, dvp 73.
**Acceptance:** ✅ `docs/PUBLIC_IO.md` has no `TODO` left in the per-circuit signal tables; counts are concrete. Secret-model decided (sender-key keystream; demo scalar / prod set-root).
**Deps:** none.

---

## Phase 1 — Cryptographic foundation (THE gate)

### [x] FIN-002 · P0 · Poseidon-BLS parity (circuit ↔ SDK) — DONE
Without this every proof fails — commitments/nullifiers/Merkle must hash identically off-chain and in-circuit.
- **Done:** fresh self-consistent params (Grain LFSR round constants + Cauchy MDS, α=5, t∈{2,3,6}) generated by `scripts/gen-poseidon-params.mjs` into `sdk/src/poseidon-params.ts` + `circuits/lib/poseidon_constants.circom` (byte-identical).
- **Done:** permutation implemented in `sdk/src/poseidon.ts` and `circuits/lib/poseidon_bls.circom` (unoptimized HadesMiMC).
- **Done:** parity verified by `scripts/test-poseidon-parity.ts` (`npm run poseidon:parity`) — circom `--prime bls12381` witness == SDK across t=2/3/6; vectors locked in `sdk/test/poseidon.test.ts` (`npm test` green).
**Acceptance:** ✅ met and machine-verified.
**Follow-ups:** add the sparse-matrix partial-round optimization later (perf); wire parity into CI (FIN-024).

---

## Phase 2 — Core circuit + gadgets

### [x] FIN-003 · P1 · Implement note + Merkle gadgets — DONE
Filled `circuits/lib/note.circom`, `circuits/lib/merkle.circom`, vendored bit gadgets, and `sdk/src/merkle.ts`; all circuit↔SDK parity-verified.
- **Done:** `note.circom` de-scaffolded (commitment/nullifier/owner_pk/asset_id real); mirrors `sdk/src/note.ts`.
- **Done:** `circuits/lib/bits.circom` — VENDORED field-agnostic gadgets (Num2Bits/LessThan/LessEqThan/IsZero/IsEqual) + **r-aware** AliasCheckBLS / Num2BitsBLS / LessThanField (circomlib was never installed and is BN254-pinned; vendoring keeps the tree BN254-free, invariant #1).
- **Done:** `merkle.circom` — MerkleInclusion (hoisted loop signals; circom 2.2 fix), **IMT MerkleNonMembership** (full-field sound comparisons), **real FrontierTransition** (incremental filled-subtrees insert, zeros computed in-circuit).
- **Done:** `sdk/src/merkle.ts` — `IncrementalMerkleTree` (root/frontier/inclusionPath), `applyFrontierTransition`, `emptyTreeZeros`, `imtLeafHash`; D=20; mirrors the circuit exactly.
- **Done:** parity gates (all green) — `npm run poseidon|note|merkle|comparator|nonmembership:parity`. The comparator gate proves AliasCheckBLS rejects non-canonical (≥ r) witnesses; the non-membership gate proves a member / forged low-leaf cannot prove absence (fund-critical, invariants #14/#19).
**Acceptance:** ✅ gadget-level witness tests pass; SDK and circuit agree on commitment/nullifier/root.
**Heads-up for FIN-006:** `FrontierTransition` needs `nextIndex` (current leaf count). For soundness it must be a public input the **contract** supplies from state (not prover-controlled) — this adds one public signal per tree-transition circuit (a small FIN-001 layout amendment to make when wiring `transfer.circom`).
**Deps:** FIN-002.

### [x] FIN-004 · P1 · Implement `enc_check.circom` + SDK encryption — DONE
Implemented the auditor/recipient encryption well-formedness gadget (`circuits/lib/enc_check.circom`, additive Poseidon keystream per FIN-001 scheme A) and the matching `sdk/src/encrypt.ts` (`K_a=K_r=5`). Auditor ciphertext is **mandatory** and bound as a public input (invariant #5).
**Acceptance:** ✅ circuit binds the plaintext slots and the key (`auditor_pk == Poseidon(k_view)`); SDK round-trips; parity gate `npm run enc:parity`.
**Deps:** FIN-001, FIN-002.

### [x] FIN-005 · P1 · Implement `assets.circom` registry membership — DONE
Filled `circuits/lib/assets.circom`: membership of `(asset_id, sac_address, decimals, per_tx_limit_raw)` against `assets_root`, self-binding `asset_id = Poseidon(sac_address)`, and `value ≤ per_tx_limit_raw` (both operands 64-bit ranged). Raw units only (inv #16/#17).
**Acceptance:** ✅ limit comes from the leaf (witness, not a public input); parity gate `npm run assets:parity`.
**Deps:** FIN-002.

### [x] FIN-006 · P1 · Complete `transfer.circom` (2-in/2-out) — DONE
Wired FIN-003/004/005 into `transfer.circom`: inclusion + ownership, nullifier derivation, **per-asset conservation** `Σin = Σout + fee`, 64-bit range checks, KYC membership, sanctions + **frozen** non-membership, assets membership, tree transition.
- **Done:** BOTH output notes carry a mandatory `c_auditor` + a `c_recipient` (inv #5; the scaffold under-bound output 1 — fixed). `next_index` is now a **public input** wired to `FrontierTransition` (was `<==0`, a soundness hole); the contract pins it to `leaf_count` (new state) and gates it in `confidential_transfer` (inv #11/#12). Compiles to **73 public signals**; `PUBLIC_IO.md` + `types.rs` + `publicInputs.ts` + `witness.ts` de-drifted. `init` bundled into `InitConfig` (Soroban 10-arg cap — the contract previously did not compile). `cargo test` green incl. `next_index` accept/reject tests.
- **Done (witness builder + fixtures):** the `Transfer(D,K_a,K_r)` template was extracted to `circuits/lib/transfer.circom` so it can be instantiated at a small depth for tests (the D=20 `main` in `circuits/transfer.circom` is unchanged: 73 public signals). `sdk/src/witness.ts` `buildTransferWitness()` does the full commitment/nullifier/ciphertext/frontier computation and emits the complete circom signal record (depth-parametric; reused by FIN-008). `scripts/test-transfer-witness.ts` (`npm run transfer:witness`) drives `circuits/test/transfer/transfer_test.circom` (`Transfer(6,5,5)`): a valid witness is **accepted**, and one failing witness per constraint class is **rejected** — unbalanced value (#3), bad Merkle path, missing auditor ct (#5), frozen note (#14), over-limit (#17), tampered `new_root` (#12), wrong spending key (#4). Gate green; `npm run typecheck` + SDK tests green.
**Acceptance:** ✅ valid witness produces a satisfying R1CS; ≥1 failing witness per constraint class is rejected (CLAUDE.md test rule), machine-verified by `npm run transfer:witness`.
**Deps:** FIN-003, FIN-004, FIN-005.

---

## Phase 3 — Trusted setup (demo)

### [x] FIN-007 · P1 · Demo ceremony + VK export — DONE (production D=20 VKs now exported + real proof verified)
Real **BLS12-381** Groth16 trusted setup, machine-verified end-to-end with FIN-008.
- **Curve/flag confirmed:** `snarkjs powersoftau new bls12381 …` works (snarkjs 0.7.5); the exported VK reports `protocol: groth16, curve: bls12381`.
- **PTAU sizing corrected (twice):** snarkjs needs `2^PTAU_POWER ≥ 2·nConstraints`. The earlier "~295k constraints → 2^20" estimate was WRONG: the actual compiled `transfer` at **D=20 is 73,740 constraints** (shield 18,233; unshield 44,520) — measured via `snarkjs r1cs info`. So `2·73,740 ≈ 147k` → **2^18 (262,144) suffices**, not 2^20. The "needs a big machine" blocker was an artifact of the bad estimate.
- **Production D=20 ceremony DONE:** the full 2^18 BLS12-381 ceremony for shield/transfer/unshield ran in **~13 minutes** on a 22GB Railway Pro container (`setup/ceremony.Dockerfile` — circom + snarkjs, driven over `railway ssh`). Exported the real **production verifying keys** `setup/build/{shield,transfer,unshield}/vk_*.json` (curve bls12381; nPublic **59 / 73 / 64** — the exact contract layouts). `.zkey`/`.ptau` stay gitignored (invariant #10); the ceremony is single-party DEMO-ONLY (not mainnet-secure), fine for a real testnet proof.
- **Real D=20 proof verified (capstone):** `scripts/test-prove-transfer-d20.ts` (`npm run transfer:prove:d20`) builds a real `Transfer(20,5,5)` witness via the SDK, `groth16.fullProve`s it against the production `transfer.zkey`, and verifies it against `vk_transfer.json`: **73 public signals, verify accepts, a tampered signal is rejected**. This is the genuine (non-simulated) proof the deployed contract verifies.
- **dvp excluded:** `dvp.circom` does not yet compile (FIN-016 backlog); the ceremony covers the 3 ready circuits.
**Acceptance:** ✅ real production-D=20 BLS12-381 VKs produced (59/73/64), `.zkey`/`.ptau` gitignored; a real D=20 transfer proof verifies + tamper-rejects. This **unblocks the on-chain half** of FIN-009/010/011/015 (a production proof now exists to verify on-chain).
**Deps:** FIN-006.

---

## Phase 4 — Prover (off-chain proof works end-to-end)

### [x] FIN-008 · P1 · Wire `prover/` witness + proving — DONE
The prover now produces a real Groth16 proof that verifies locally.
- **Witness via SDK:** `prover/src/witness.ts` no longer hand-rolls the transfer witness; the prover re-exports `buildTransferWitness` from `@finnes/sdk` (the full commitment/nullifier/ciphertext/frontier builder from FIN-006). shield/unshield/dvp stay as scaffolds until their circom lands.
- **Ordered public-IO de-duplicated (also closes FIN-022):** the duplicated `PUBLIC_IO_ORDER` constant is removed; `prover/src/index.ts` re-exports the SDK's `buildTransferPublicInputs` / `buildShieldPublicInputs` / … so the order lives once in `@finnes/sdk` (docs/PUBLIC_IO.md).
- **Artifacts wired:** `defaultArtifacts` fixed — WASM from `circuits/build/<c>/<c>_js/`, `.zkey`/VK from `setup/build/<c>/`. `Witness` widened for the 2-D ciphertext signals (`c_auditor[2][5]`).
- **End-to-end gate:** `scripts/test-prove-transfer.ts` (`npm run transfer:prove`) builds a depth-4 witness via the SDK, runs `groth16.fullProve` against the FIN-007 demo `.zkey`, and asserts: 41 public signals, `groth16.verify` accepts, and a **tampered public signal is rejected**. Never logs the witness (invariant #8).
**Acceptance:** ✅ `groth16.fullProve` → `groth16.verify` returns true locally; tamper rejected. Circuit + setup + prover proven before touching chain (depth-4 demo instance; D=20 awaits the heavier FIN-007 production ceremony).
**Deps:** FIN-007.

---

## Phase 5 — Contract verifier + state

### [x] FIN-009 · P1 · Implement `verifier.rs` (Groth16 over BLS12-381 host fns) — DONE
Replaced the `return false` placeholder with the real pairing math over `env.crypto().bls12_381()`: decode VK/proof points, `vk_x = IC₀ + Σ xᵢ·ICᵢ` via a single `g1_msm` + `g1_add`, and the one multi-`pairing_check` of `e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) == 1` (invariant #7 — exactly one pairing per tx).
- **Encoding:** VK/proof points arrive already in the host's **uncompressed** big-endian serialization (G1 96B `be(X)‖be(Y)`; G2 192B `be(X_c1)‖be(X_c0)‖be(Y_c1)‖be(Y_c0)` — note the host's `c1`-before-`c0` order vs snarkjs `[c0,c1]`). The curve-specific snarkjs→host conversion lives off-chain in `scripts/gen-verifier-fixture.ts` (`npm run verifier:fixture`), keeping `verifier.rs` a thin, auditable host-fn wrapper. No `unwrap` on untrusted bytes — a wrong-length point returns `MalformedProof`; arity drift returns `VerifyingKeyArityMismatch`.
- **Test vectors:** the fixture script proves the depth-4 `transfer_test4` demo (41 public signals), then emits `contracts/finnes/src/test_vectors.rs` (PUBLIC vk/proof/signals as host bytes). `cargo test` exercises `verifier::verify_groth16` directly: a REAL proof is **accepted**, a tampered public signal → `InvalidProof`, an arity mismatch and a malformed point are rejected structurally. (Tested at the `verify_groth16` boundary, not through `confidential_transfer`, because that entrypoint is hard-wired to the D=20 layout — 73 signals — and a production proof for it awaits the heavier D=20 ceremony per the FIN-007 note; the pairing math under test is identical.) Verify cost exceeds the test env's default budget, so the tests `reset_unlimited()`; on-chain cost is bounded by the protocol budget and dominated by the single pairing — measure via `simulateTransaction` at deploy.
- **Green:** `cargo test` (10 passed), `cargo clippy` clean, `cargo fmt`, and `cargo build --target wasm32-unknown-unknown` all pass.
**Acceptance:** ✅ `verify_groth16` accepts the FIN-008 proof and rejects a tampered one in `cargo test`.
**Deps:** FIN-008.

### [x] FIN-010 · P1 · SAC token movement on shield/unshield — DONE
`shield` transfers the real SAC `depositor → contract`; `unshield`/`mint_recovery` transfer `contract → recipient`. Resolve the SAC address from the assets-registry leaf for `asset_id`.
- **Done (resolution, invariant #11):** the contract performs no on-chain hashing, so it cannot recompute `asset_id = Poseidon(sac_address)`. New admin-managed mirror of the assets registry maps `asset_id → SAC Address` (`register_asset`) and `recipient_field → Address` (`register_transparent`, the demo account registry). New `sac.rs` resolves the SAC and moves the token; a caller-supplied SAC is rejected by construction (the on-chain half of invariant #18 — can't shield a worthless token while minting a valuable-asset note).
- **Done (movement, verify-before-effects):** `shield` pulls the SAC `depositor → contract` and `unshield` pays `contract → recipient`, both **after** `verify_groth16` (invariant #9). `amount` (big-endian `Fr`) decodes to `i128` with the high 24 bytes asserted zero (64-bit ranged in-circuit). The transfers are atomic with the state mutation. `unshield`'s recipient is now resolved via the demo account registry (replacing the bare zero-recipient check) → `RecipientNotAuthorised` if unregistered.
- **Note (`mint_recovery`):** mints a *shielded* recovery note (value originates from the frozen note, not a transparent payout per ARCHITECTURE.md → "Clawback"), so it moves no SAC; left as-is.
- **Done (tests):** `cargo test` (17 passed) covers `scalar_to_i128` decode + oversized-amount rejection; a real test SAC moved **in and out** via `sac::pull_deposit`/`pay_out` through the registry (`register_stellar_asset_contract_v2` + balances asserted); verify-before-effects atomicity (`shield` with an invalid proof reverts and moves **no** SAC); and the unshield recipient-registry gate (unregistered → `RecipientNotAuthorised`; registered → proceeds to the verifier). clippy/fmt clean, wasm builds.
- **Scope note:** the full positive path *through* the `shield`/`unshield` entrypoints (valid proof → SAC moves) needs a real D=20 proof (same ceremony friction as FIN-009); the helper + atomicity tests cover the SAC movement and its gating without one.
**Acceptance:** ✅ integration test moves a test SAC in/out, and proves the movement is gated by the proof check (invalid proof → no movement). `cargo test` green.
**Deps:** FIN-009.

### [x] FIN-011 · P2 · Contract state polish — DONE
Wire windowed compliance roots (kyc/sanction/assets) vs strict `frozen_root`; emit indexer events at every effect (commitments, nullifiers, ciphertext refs); set real TTL bump params; pin `soroban-sdk` to the deployed protocol.
- **Done (windowed roots, invariant #6):** `state.rs` keeps a per-root recent-roots window (`KycWindow`/`SanctionWindow`/`AssetsWindow`, `COMPLIANCE_WINDOW_CAPACITY = 16`) seeded at `init`, appended on every admin update (single chokepoint in `set_*_root`), de-duping against membership **anywhere** in the window (not just the tail — adversarial-review fix, so a toggling A→B→A update can't fill the window with duplicates and evict still-valid distinct roots). `lib.rs` `check_kyc/sanction/assets_root` accept any root in the window; `frozen_root` stays STRICT. Out-of-window roots are still rejected; the windows are per-key independent.
- **Done (events, indexer):** new `events.rs` publishes a typed `#[contracttype]` payload (stable schema) at every effect — `shield`/`transfer`/`unshield`/`dvp` (nullifiers + output commitments + `new_root` + field-packed ciphertexts), `freeze` (cm_target + new frozen_root), `mint_recovery`, admin `root_updated` (kyc/sanction/assets), and the FIN-010 registries `asset_registered` / `transparent_registered` (so the indexer can link a field-encoded `asset_id`/`recipient` to its concrete SAC/Stellar address — adversarial-review gap). All data is PUBLIC; no secret emitted (#8); emitted AFTER the mutation on the verify-before-effects path (#9).
- **Done (TTL params):** `state.rs` reframes the bump targets in day-derived ledgers (`LEDGERS_PER_DAY`): persistent + instance **7d threshold / 30d extend** (lowered from a 90d extend after review — 30d sits safely under the standard Soroban network `max_entry_ttl` ≈ 6 months, so it won't trap `extend_ttl`/brick mutations on testnet/futurenet; a smaller custom network must lower these, ideally promoting them to validated `InitConfig` params in production). Liveness/cost tuning only — Protocol 23 auto-restores archived persistent entries (#4).
- **Done (SDK pin):** `Cargo.toml` pins `soroban-sdk = "=22.0.11"` (runtime + dev) so a transitive bump can't silently change host-fn semantics or the storage/event layout.
- **Done (mint_recovery parity, review fix):** `mint_recovery`/`clawback` now also `check_kyc_root` — it reuses the shield circuit/VK (which binds `kyc_root`), so it is held to the same windowed freshness check as `shield`, closing a check asymmetry.
- **Done (tests):** `cargo test` (26 passed) — ordered pre-proof checks (unknown anchor → `UnknownAnchorRoot`; seeded double-spend → `NullifierAlreadyUsed`; stale `frozen_root` → `StaleFrozenRoot` strict; windowed kyc accepts the prior + new root, rejects a never-published one → `StaleKycRoot`); **per-key window independence** (rotating kyc doesn't touch the assets window; out-of-window assets → `StaleAssetsRoot`); **membership-dedup + eviction** (a non-consecutive repeat doesn't evict the oldest, but the 17th distinct root does); plus event-emission assertions (`freeze`, `update_kyc_root`, `register_asset` — topic + typed payload). clippy clean, `cargo fmt`, wasm builds.
- **Known gap (out of FIN-011 scope):** `settle_dvp` still omits the `next_index` leaf-count pin (#11/#12) because `dvp.circom` does not yet expose that public input — tracked under **FIN-016** (its existing `TODO`); the demo DvP entrypoint is already labelled non-production (#15).
**Acceptance:** ✅ events emitted (asserted in `cargo test`); the ordered checks (anchor window → nullifier unused → roots match → verify) are covered pre-proof; the verify→mutate composition through the entrypoint still awaits the D=20 ceremony (FIN-007 note), as for FIN-009/010.
**Deps:** FIN-009.

---

## Phase 6 — Boundary circuits

### [x] FIN-012 · P1 · `shield.circom` + VK — DONE
Transfer variant: 0 shielded inputs, 1 transparent input; prove output `cm` opens to the **public** `(asset_id, amount)` without revealing `(owner, rho, r)` (anti-counterfeit, invariant #18). Run phase-2, export `vk_shield.json`.
- **Done:** the scaffold (broken: circomlib `Num2Bits` include, wrong `AuditorEncCheck`/`RecipientEncCheck` signatures, `D=32`/`K=4`) was rewritten. The `Shield(D,K_a,K_r)` template was hoisted to `circuits/lib/shield.circom` (mirrors `lib/transfer.circom`) and wired to the real FIN-003/004/005 gadgets; the top-level `circuits/shield.circom` fixes `D=20, K_a=K_r=5` and compiles to **59 public signals**.
- **Done (soundness, inv #11/#12):** added `next_index` as a public input the contract pins to its leaf count (the scaffold's private `nextIndex` let a prover insert at index 0 every time — the same hole FIN-006 closed for transfer). De-drifted across all four surfaces: `docs/PUBLIC_IO.md` (58→**59**), `contracts/finnes/src/types.rs` `ShieldPublicInputs` + `to_scalars()`, `sdk/src/publicInputs.ts` `buildShieldPublicInputs`, and the `shield` + `mint_recovery` entrypoints (`check_next_index`).
- **Done (witness builder + gates):** `sdk/src/witness.ts` `buildShieldWitness()` does the full commitment/ciphertext/frontier computation. `scripts/test-shield-witness.ts` (`npm run shield:witness`) drives `circuits/test/shield/shield_test.circom` (`Shield(6,5,5)`): a valid witness is **accepted**, and one failing witness per constraint class is **rejected** — tampered `cm_out_0` (#18), bad KYC path (#6), missing auditor ct (#5), over-limit (#17), wrong asset binding / self-binding (#18), tampered `new_root` (#12).
- **Done (VK + end-to-end proof):** `scripts/setup-ceremony.sh` already iterates `shield`, so `npm run circuits:build` + `npm run setup:ceremony` export `setup/build/shield/vk_shield.json` (shield D=20 is ~99k constraints → fits 2^18, lighter than transfer). A real depth-4 demo VK (`vk_shield_test4.json`, groth16/bls12381/nPublic 27) was produced reusing the FIN-007 ptau, and `scripts/test-prove-shield.ts` (`npm run shield:prove`) builds an SDK witness, `groth16.fullProve`s it, and asserts 27 public signals, `groth16.verify` accepts, and a **tampered public signal is rejected** (anti-counterfeit, #18). `cargo test`/clippy/fmt + wasm build + `npm run typecheck` + SDK tests all green; `.zkey`/`.ptau` stay gitignored (inv #10).
**Acceptance:** ✅ valid shield proof verifies; a tampered/counterfeit public input is rejected, machine-verified by `npm run shield:witness` + `npm run shield:prove`. (Demo at depth 4; production D=20 procedure identical — same `npm run setup:ceremony`.)
**Deps:** FIN-006, FIN-007.

### [x] FIN-013 · P1 · `unshield.circom` + VK — DONE
Transfer variant revealing `(asset_id, amount, recipient)`; MUST enforce **frozen-set non-membership** (escape-hatch closure) + transparent-recipient KYC/non-sanction (invariant #19). Export `vk_unshield.json`.
- **Done:** rewrote the broken scaffold (circomlib include, wrong `MerkleNonMembership`/enc-check signatures, missing `c_recipient`, `D=32`/`K=4`). `Unshield(D,K_a,K_r)` hoisted to `circuits/lib/unshield.circom`; top-level `circuits/unshield.circom` fixes `D=20, K_a=K_r=5` → **64 public signals**.
- **Done (invariant #19):** the spent commitment proves **frozen-set non-membership** (#19b, escape-hatch closure) and the public transparent `recipient` proves **KYC membership + sanctions non-membership** (#19a). Plus input inclusion/nullifier/ownership, per-asset conservation `in == amount + change + fee`, 64-bit ranges, assets membership + per-tx limit.
- **Done (change-note sentinel + conditional transition):** the change note carries a MANDATORY `c_auditor` + a `c_recipient` (PUBLIC_IO carries K_a + K_r; the scaffold dropped `c_recipient`), both gated on `has_change = (cm_change_0 != 0)` (all-zero when no change). The frontier transition inserts the gated `cm_change_0`: a `0` leaf reproduces the CURRENT root (no-op), and `new_frontier` is MUX'd to `old_frontier`; the contract advances `leaf_count` by 0/1 from the same `cm_change_0 == 0` test. `next_index` added as a public input pinned to state (#11/#12). De-drifted across `docs/PUBLIC_IO.md` (63→**64**), `types.rs` (`UnshieldPublicInputs` + `c_recipient` + `next_index`), `publicInputs.ts`, and the `unshield` entrypoint.
- **Done (witness builder + gates):** SDK `buildUnshieldWitness()` (handles both change and exact-spend). `scripts/test-unshield-witness.ts` (`npm run unshield:witness`) drives `Unshield(6,5,5)`: **two** valid witnesses accepted (with change AND exact spend), and one failing witness per constraint class rejected — frozen note (#19b), sanctioned recipient (#19a), bad input path, unbalanced value (#3), over-limit (#17), missing auditor ct (#5), wrong spending key (#4), tampered `new_root` (#12).
- **Done (VK + end-to-end proof):** `scripts/setup-ceremony.sh` already iterates `unshield`. A real depth-4 demo VK (`vk_unshield_test4.json`, groth16/bls12381/nPublic 32) was produced reusing the FIN-007 ptau, and `scripts/test-prove-unshield.ts` (`npm run unshield:prove`) builds an SDK witness, `groth16.fullProve`s it, and asserts 32 public signals, `groth16.verify` accepts, and a **tampered `frozen_root` is rejected**. `cargo test`/clippy/fmt + wasm + `npm run typecheck` + SDK tests all green; `.zkey`/`.ptau` stay gitignored (inv #10).
**Acceptance:** ✅ valid unshield verifies; a frozen note cannot be unshielded (machine-verified by `npm run unshield:witness` + `npm run unshield:prove`). (Demo at depth 4; production D=20 procedure identical via `npm run setup:ceremony`.)
**Deps:** FIN-006, FIN-007.

---

## Phase 7 — Disclosure & client wiring

### [x] FIN-014 · P2 · SDK scanning + disclosure — DONE
Implemented the auditor (regulator) disclosure path and finalized the SAC-address encoding; recipient scanning (`sdk/src/scan.ts`) was already in place from FIN-004 and is now backed by the unblocked `deriveAssetId`.
- **Done (SAC encoding):** `sdk/src/note.ts` `sacAddressToField()` encodes a field-element literal (decimal/`0x`-hex, the `scripts/lib/*-scenario.ts` `777n` convention); `deriveAssetId('777') === Poseidon(777)` matches the scenarios. A real Stellar StrKey (`C…`/`G…`) THROWS by design (PRODUCTION GAP, mirrors the deferred `recipient` encoding): a naive 32-byte big-endian-mod-`r` map is non-injective at the top (two addresses could alias to one `asset_id`) and would skip StrKey version/CRC validation (a typo would silently mint a wrong `asset_id` that desyncs from the contract registry). Production binds the full address via two fields (hi/lo) or SHA-256 (invariant #11) — a fresh-ceremony change. Failing loudly beats encoding a possibly-wrong identity (adversarial-review hardening).
- **Done (auditor disclosure):** new `sdk/src/disclose.ts` — `discloseTransaction()` / `discloseNote()` decrypt every (non-sentinel) output note's MANDATORY `c_auditor` with `k_view` to full plaintext `(value, asset_id, owner_pk=party, rho)`, tag roles from the ORIGINAL output position + count (transfer: recipient/change; dvp: leg_x/leg_y) — NOT a post-filter index, so a dropped leading sentinel never shifts recipient↔change (adversarial-review fix) — skip the `unshield` `cm_change_0 == 0` sentinel, and attach optional asset/party resolver labels. Documented the binding asymmetry: the auditor ct omits `r_note` so the commitment can't be re-derived off-chain — the plaintext is authoritative by invariant #5 (same signals feed commitment + keystream in-circuit), not by re-derivation. Added `formatRawAmount` (display only, invariant #16).
- **Done (tests):** `sdk/test/disclose.test.ts` (11 tests, `npm test` → 26 green): auditor discloses a 2-output transfer to amount/asset/parties, resolver labels attach, **wrong `k_view` recovers garbage + out-of-64-bit-range** (wrong-key signal), the no-change sentinel is skipped, **roles derive from the ORIGINAL position so a leading sentinel keeps the survivor's role** (regression test for the re-index fix), the SAC encoding matches the scenario convention / **throws on a real StrKey** (production gap) / rejects junk, `formatRawAmount` whole/zero/decimals=0/negative edges, and — strongest parity — an **END-TO-END** case discloses the `c_auditor` AS EMITTED by `buildTransferWitness` (the exact public signals the Groth16 proof binds, consumed via the witness record's own names/shapes), recovering the output notes' value/asset/owner and matching `derived.cmOut`. Re-exported from `sdk/src/index.ts`; SDK + repo `tsc -b` clean. Never logs secrets (invariant #8).
- **Done (cleanup):** `formatRawAmount` is byte-for-byte identical to the frontend's (FIN-015 should de-dup); the stale "SCAFFOLD TODO" comments on `Ciphertext` / `AuditorPublicKey` in `sdk/src/types.ts` are corrected (scheme is LOCKED: `K_a=K_r=5`, single-field `auditor_pk = Poseidon(k_view)`).
- **Scope note:** wiring this into the frontend regulator view (replacing the `decryptAuditorView` mock in `frontend/lib/finnes-client.ts`) belongs to **FIN-015**; identifying the *spent* notes behind nullifiers is the indexer's job (FIN-019), not the per-tx ciphertext.
**Acceptance:** ✅ recipient discovers an incoming note (scan, parity-tested since FIN-004); auditor decrypts a tx to full plaintext (amount, asset, parties), machine-verified by `sdk/test/disclose.test.ts`.
**Deps:** FIN-004.

### [~] FIN-015 · P2 · Deploy testnet + wire frontend — DEPLOYED + INIT'D; SHIELD + DISCLOSURE LIVE ON TESTNET
Run `scripts/deploy.sh`, run the post-deploy `init` (auditor_pk, issuer_authority, roots, VKs). Replace mocks in `frontend/lib/finnes-client.ts` with real sdk/prover/contract calls; configure browser proving (snarkjs webpack fallbacks + load `.wasm`/`.zkey`). Mock KYC enrollment via an admin script (pre-enroll demo accounts; invariant: keep the in-circuit check).
- **Done (frontend READ paths, real crypto):** new `frontend/lib/demo-data.ts` builds a deterministic ledger of GENUINE Poseidon commitments + auditor/recipient ciphertexts (an indexer stand-in, FIN-019) keyed by a fixed demo view key. `scanConfidentialBalances` now runs the SDK's **`scanForOwnedNotes`** (real trial-decrypt + commitment re-derivation, per-asset aggregation, no cross-asset sum #3/#16) and `decryptAuditorView` runs **`discloseTransaction`** (real auditor decrypt to amount/asset/parties; recipient + change notes; a non-matching view key recovers out-of-range garbage and surfaces an honest error — never a faked reveal). `keys.ts` derives the real `auditor_pk = Poseidon(k_view)` (`auditorPkFromKey`) and the "Demo key" loads the ledger's matching view key. `OnChainTxSummary` reshaped to per-output `{commitment, cAuditor}`; `TxList`/`DisclosurePanel` updated (DisclosurePanel shows the per-note recipient/change breakdown). Stale "sdk … throws / MOCK" comments corrected across `finnes-client.ts`, `keys.ts`, `ConfidentialBalances.tsx`, `DisclosurePanel.tsx`. Verified: 10/10 wiring checks (real disclosure + scan over demo data, wrong-key reject, foreign-owner finds 0); `next build` compiles all 6 routes; frontend `tsc --noEmit` adds no new errors (only the 3 pre-existing prover↔snarkjs resolution ones).
- **Done (mock KYC enrollment + demo compliance state, offline):** `scripts/lib/demo-state.ts` + `scripts/enroll-demo.ts` (`npm run enroll:demo`) pre-enroll the demo institutions into `kyc_root` and build the four compliance roots (kyc membership / sanction + frozen empty-IMT non-membership / assets registry), `auditor_pk = Poseidon(k_view)`, and the empty commitment-tree seed (initial frontier/root) — all real SDK Poseidon/Merkle at the production `D = 20`, no ceremony or chain needed. Emits the PUBLIC state to `setup/build/demo-state.json` (gitignored, regenerable) that the post-deploy `init` / prover / frontend consume; writes NO secret (`owner_sk` / `k_view` stay in the script, invariant #8; the in-circuit KYC check is kept). Gate `scripts/test-demo-state.ts` (`npm run demo:state`, 17/17) asserts every enrolled account proves membership, a non-enrolled account neither is in the set nor verifies against `kyc_root` via any path, each asset proves assets-registry membership, `auditor_pk == Poseidon(k_view)`, and the serialized state leaks no secret (exhaustive key-allowlist on every JSON branch). Hardened after adversarial review: the gate now constructs an actual IMT **non-membership** proof for a real target against the empty sanctions+frozen sets (and fails it against a wrong root), and pins the empty commitment-tree seed value-equal to `emptyTreeZeros` (the genesis convention the contract `init`/first-transfer `old_frontier` mirror, #12) — not a length-only check. The assets leaf's `sac_address` field and `asset_id`'s preimage now share the single canonical `sacAddressToField` encoding. (Fixed an incremental-Merkle bug: asset/KYC inclusion paths are derived after ALL inserts.) Demo identity constants are kept in lockstep with `frontend/lib/demo-data.ts` (documented; a cross-file parity gate is deferred until the UI refactor settles).
- **Done (VK→contract conversion + init config, offline):** the **D=20 ceremony is now done (FIN-007)** — `scripts/lib/vk-host.ts` converts each snarkjs `vk_*.json` to the contract's host-byte `VerifyingKey` (G1 96B / G2 192B with the c1‖c0 swap / Fr 32B — the EXACT encoding `verifier.rs` decodes and the FIN-009 cargo tests pass). `scripts/gen-init-config.ts` (`npm run init:config`) assembles the full `InitConfig` from `demo-state.json` (roots + `auditor_pk` + empty-tree seed) + the 3 host VKs (+ an EMPTY `dvp` placeholder) into `setup/build/init-config.json`, validating every byte length (auditor_pk 32B, frontier 20×32B, vk_transfer alpha 96 / beta 192 / ic 74×96). `scripts/init.sh` (`npm run init`) invokes `init` via the stellar CLI (admin/issuer from env) and optionally wires `register_asset`/`register_transparent` from a registry mapping. Hardened after adversarial review: fixed a **blocker** in `init.sh` (a `VAR=x ( subshell )` env-prefix is a bash parse error — `bash -n` now clean); the host-byte encoders are **single-source** in `vk-host.ts` (imported by `gen-verifier-fixture.ts`, so the deployed VK and the cargo-validated test vectors can't drift); `vk_dvp`'s placeholder is a valid-length zero blob (not an empty `Bytes` string the CLI might reject); and the registry hex conversion guards against >32-byte values. (Runtime-confirm risk: the stellar CLI's `Bytes` JSON format — bare hex vs `0x` vs base64 — and empty-`ic` Vec acceptance are validated only on the first live `init`.)
- **Done (LIVE ON TESTNET, 2026-06-20):** contract deployed + initialised + a real **shield** verified on-chain + **regulator disclosure** of the on-chain note — the core "confidential yet auditable" claim proven against a deployed Soroban contract.
  - **Contract spec bug fixed (blocker):** the `#[contracttype]` structs used the type aliases `Root`/`Scalar`/`Nullifier`/`Commitment` (= `BytesN<32>`) as field/variant types; Soroban's spec macro does NOT define aliases, so the embedded contract spec carried dangling type refs and `init` failed at the CLI with `Missing Entry Root`. Replaced the aliases with `BytesN<32>` in every spec-facing surface (`types.rs` PublicInputs + `InitConfig`, `events.rs` event structs, `state.rs` `DataKey`, and `lib.rs` public-fn signatures); alias defs kept for internal/test use. Rebuilt clean (no more "not defined in the spec" warnings). **Any CLI/frontend invocation was blocked by this** — must stay fixed.
  - **Deploy:** deploy the `wasm32v1-none` artifact (`contracts/target/wasm32v1-none/release/finnes.wasm`) — the `wasm32-unknown-unknown` variant is rejected by the Soroban VM (`reference-types not enabled`). `scripts/deploy.sh` still points at the old `contracts/finnes/target/...` path (workspace puts it under `contracts/target/...`) — **FIN-028 below**. Deployed contract `CDIWXQSWIP6GKJKCAZPFONDD7VZ2PR2AQVCBQ7WRNTL64M3DAP55G7IA`; `setup/build/deploy.testnet.json` records it.
  - **Init:** `npm run init` (admin=issuer=`deployer`) succeeded; on-chain `current_root` equals `demo-state.json` `initialRoot` exactly.
  - **Proving on Railway:** `scripts/prove-shield-live.ts` builds a D=20 shield witness against the **live genesis** (`buildDemoComplianceState(20)` — same roots/auditor_pk/frontier `init` stored) and proves it with the production `shield.zkey` on the Railway `ceremony` service; the small proof JSON is exfiltrated.
  - **Submit:** `scripts/submit-shield-live.ts` converts the snarkjs proof + 59 public signals to the host-byte `Proof` + `ShieldPublicInputs` args (reusing `vk-host.ts`). Real `shield` tx moved **1000 TBOND** depositor→contract atomically (test SAC `CBJMD3SA…` registered via `register_asset`), minted cm `577c94d2…`, advanced the tree to root `70112c60…`. Verified: contract balance 1000, deployer 999000.
  - **Disclosure:** `scripts/disclose-shield-live.ts` — the auditor view key decrypts the **on-chain** `c_auditor` to (value 1000, TBOND-2031, Meridian Capital), invariant #5 proven end-to-end on live data.
- **Remaining (frontend write-path + full demo):** `confidential_transfer` / `unshield` on-chain (**FIN-025 / FIN-026**); wire `frontend/lib/finnes-client.ts` write paths to real prove + `submitToContract` against the deployed contract (**FIN-027**); browser proving needs `.zkey` served + snarkjs webpack fallbacks. `npm run demo` orchestration still a scaffold.
**Acceptance:** ✅ shield → regulator disclosure run end-to-end on testnet with a real proof. (Transfer + frontend write-path remain — see FIN-025/026/027.)
**Deps:** FIN-009, FIN-010, FIN-012, FIN-013, FIN-014.

---

## Phase 8 — On-chain end-to-end (live testnet, builds on FIN-015)

The deployed+init'd contract (`CDIWXQSWIP6GKJKCAZPFONDD7VZ2PR2AQVCBQ7WRNTL64M3DAP55G7IA`) and
the live shield+disclosure (FIN-015) are the base. These extend the same
prove-on-Railway → convert → submit-locally pipeline to the rest of the flow.

### [x] FIN-025 · P2 · `confidential_transfer` on-chain — LIVE ON TESTNET (2026-06-20)
- **Done (LIVE ON TESTNET, 2026-06-20):** a real 2-in/2-out confidential transfer
  verified on-chain end-to-end against the deployed contract
  `CDIWXQSWIP6G…AP55G7IA`. Proved on the Railway `ceremony` container with the
  production `shield.zkey`/`transfer.zkey` (VK hashes confirmed byte-equal to the
  deployed VKs before submitting), exfiltrated, locally re-verified
  (`groth16.verify` ACCEPT against `vk_*.json`), then submitted via `stellar`.
  - **Shield #2** (prerequisite; tx `d3b2e58c2e24e547241c14b68480b91f1be68fbe2bf2d83f603df3f084d5334a`):
    minted the 2nd note (1000 TBOND, Bank A) at index 1 → `new_root 38170760…`;
    on-chain `current_root` then equalled the transfer's `anchor_root` exactly.
  - **Transfer** (tx `bf6f54f0466772833541d101313da891336e08b52172b1250f25cfe695da945e`):
    spent [genesis 1000, shield2 1000] → recipient 1500 (Bank B) + change 500
    (Bank A). On-chain event = the EXACT values the offline gate derived:
    `nf_in_0 73bd4f2f…`, `nf_in_1 4b7d8246…`, `cm_out_0 283af76c…`,
    `cm_out_1 4340d50a…`, `new_root 069cbb56…`.
  - **Effects verified on-chain:** `current_root == 069cbb56…` (tree advanced by 2);
    both nullifiers `is_nullifier_used == true`; regulator `discloseTransaction`
    decrypted recipient 1500 → Cendrawasih (Bank B) + change 500 → Meridian (Bank A),
    Σ==2000, both in-range — invariant #5 proven on live transfer data.
- **Was (scripts + offline verification, retained):** SCRIPTS DONE + WITNESS-VERIFIED OFFLINE
Spend two shielded notes → recipient + change, verified on-chain. Unlike shield,
transfer needs a non-empty tree and a valid `anchor_root` in the recent-roots
window, so it must run **after** ≥2 on-chain shields:
1. Shield two notes owned by the same sender (reuse `scripts/prove-shield-live.ts`,
   but at the live `next_index` / `old_frontier` after each insert — the genesis
   shield used index 0; the 2nd needs index 1 and the post-1st frontier).
2. Reconstruct the off-chain commitment tree from the two on-chain `cm`s (an
   indexer stand-in) to get the input inclusion paths + the current `anchor_root`.
3. Build the `Transfer(20,5,5)` witness (`buildTransferWitness`) against the live
   roots (kyc/sanction/assets/frozen/auditor_pk from `buildDemoComplianceState`,
   `anchor_root` = current tree root, `next_index` = current leaf_count), prove
   with `transfer.zkey` on Railway, convert (73 signals) + submit
   `confidential_transfer`. Disclose both output notes with the view key.

- **Done (scripts, offline-verified):** the full pipeline is implemented and the
  witness/state wiring is machine-verified WITHOUT the Railway-only `transfer.zkey`.
  - `scripts/lib/live-notes.ts` — single source of truth (indexer stand-in) for the
    two on-chain input notes + the two transfer outputs. `GENESIS_NOTE` is pinned
    byte-equal to `prove-shield-live.ts`; the gate asserts
    `commitNote(GENESIS_NOTE)` equals the on-chain `cm_out_0`
    (`577c94d2…`) — closing the drift gotcha. `reconstructAnchorTree()` rebuilds the
    live tree from the two commitments → anchor_root / old_frontier / next_index.
  - `scripts/lib/transfer-live.ts` (`buildLiveTransferWitness`) — assembles the real
    `Transfer(20,5,5)` witness against `buildDemoComplianceState(20)`: spend
    [genesis 1000, shield2 1000] (Bank A) → [1500 → Bank B recipient, 500 change →
    Bank A]; recipient KYC membership, empty sanctions/frozen non-membership of each
    spent cm, TBOND assets membership, frozen_root STRICT-equal to state.
  - `scripts/test-transfer-live-witness.ts` + `npm run transfer:live:witness` — the
    OFFLINE GATE. Asserts indexer parity + conservation (Σin 2000 == Σout 2000) +
    bracketability, then runs `snarkjs wtns calculate` + `wtns check` on
    `transfer.r1cs`: **WITNESS IS CORRECT — all 295,206 constraints satisfied, 73
    public inputs, bls12381.** A proof from this witness WILL verify on-chain; the
    `.zkey` only affects proof *generation*, not satisfiability.
  - `scripts/test-transfer-live-anchor.ts` + `npm run transfer:live:anchor` — the
    ANCHOR-PARITY gate: proves the off-chain indexer stand-in reconstructs the SAME
    tree the contract stored — the 1-note reconstructed root EQUALS the on-chain
    genesis `new_root` (`70112c60…`), shield #2's `old_frontier` equals the on-chain
    post-genesis `new_frontier`, the empty seed equals the genesis `old_frontier`,
    and every witness compliance root equals the live init root (frozen STRICT). So
    anchor_root / old_frontier / next_index will pass the contract's checks.
  - `scripts/prove-shield2-live.ts` (`npm run shield2:live:prove`) — the ≥2-shield
    prerequisite: shields note #2 at index 1 / post-genesis frontier. Witness
    machine-verified CORRECT against `shield.r1cs`.
  - `scripts/prove-transfer-live.ts` (`transfer:live:prove`), `submit-transfer-live.ts`
    (`transfer:live:submit`, 73-signal → host-byte `TransferPublicInputs`; the
    field-by-field mapping smoke-tested: 96/192/96-byte proof, 20/20 frontiers,
    10/10 ciphertext vectors, exact order), `disclose-transfer-live.ts`
    (`transfer:live:disclose`, decrypts recipient + change). `submit-shield-live.ts`
    parameterized with optional `<in> <out>` argv so shield #2 reuses it.
  - **Ceremony-artifact note (operational, important):** the LOCAL
    `setup/build/shield/shield.zkey` is a DIFFERENT (older/local) ceremony than the
    production `vk_shield.json` — a locally-made shield proof REJECTS against the
    deployed VK, while the genesis proof (made on Railway) ACCEPTS. So shield #2 and
    transfer MUST be proved on the Railway `ceremony` container that holds the
    production `transfer.zkey` (as the script headers state). Do not submit a
    locally-generated proof.
- **Remaining (needs Railway prover + testnet deployer key):**
  1. `npm run shield2:live:prove` ON RAILWAY → `submit-shield-live.ts
     setup/build/shield2-proof-live.json setup/build/shield2-args.json` → invoke
     `shield` on testnet (tree advances to leaf_count 2).
  2. `npm run transfer:live:prove` ON RAILWAY → `npm run transfer:live:submit` →
     invoke `confidential_transfer` on testnet → `npm run transfer:live:disclose`.

**Acceptance:** a real transfer proof verifies on-chain; nullifiers recorded; tree
advances by 2; auditor decrypts recipient + change notes. *(MET on testnet — txs
`d3b2e58c…` (shield #2) + `bf6f54f0…` (transfer); see the Done block above.)*
**Deps:** FIN-015.

### [x] FIN-026 · P2 · `unshield` on-chain — LIVE ON TESTNET (2026-06-20)
Spend a shielded note → transparent recipient, moving the real SAC out. Requires a
`register_transparent(recipient_field → G-addr)` mapping and the frozen/sanction
non-membership + recipient-KYC witness (invariant #19). Build the `Unshield(20,5,5)`
witness (64 signals) against live state, prove on Railway, submit; assert the SAC
moves contract→recipient and the change-note sentinel path (0 vs 1 insert) is
exercised.

- **Done (LIVE ON TESTNET, 2026-06-20):** a real exact-spend unshield verified
  on-chain. Spent the FIN-025 change note (500 TBOND, Bank A, on-chain leaf 3) out
  to a transparent recipient, proved on the Railway `ceremony` container with the
  production `unshield.zkey` (VK hash confirmed byte-equal to the deployed VK),
  exfiltrated, locally re-verified (`groth16.verify` ACCEPT vs `vk_unshield.json`),
  then submitted via `stellar`.
  - `scripts/lib/unshield-live.ts` (`buildLiveUnshieldWitness`) builds the witness
    against `buildDemoComplianceState(20)` + the reconstructed post-transfer 4-leaf
    tree (`reconstructPostTransferTree` in `live-notes.ts`); spends an EXACT amount
    so `cm_change_0 == 0` (no-change sentinel → 0 inserts, the gated 0-leaf path).
  - `scripts/test-unshield-live-witness.ts` + `npm run unshield:live:witness` —
    offline gate: anchor parity (4-leaf root == on-chain `069cbb56…`), exact-spend +
    no-change sentinel + `new_root == anchor_root`, then `snarkjs wtns check` on
    `unshield.r1cs`: **WITNESS IS CORRECT — 182,072 constraints, 64 public inputs.**
  - `prove-unshield-live.ts` (`unshield:live:prove`) + `submit-unshield-live.ts`
    (`unshield:live:submit`, 64-signal → host-byte `UnshieldPublicInputs`; change
    ciphertexts are SINGLE-note K_a/K_r=5 vectors, all-zero for an exact spend).
  - **Registry:** `register_transparent(recipient=480b9681… → deployer G-addr)`
    (tx `431b948bd1168282e75666408b2c40a38402e1e523deaac8190b132dcfc9f227`).
  - **Unshield** (tx `f8e47f81c14af6ab199393fe5372c16ab8d6b33b3bb1a35804ef18626790549e`):
    on-chain event = the gate's derived values — `nf_in_0 126ef193…`, `amount 500`,
    `cm_change_0 0`, `new_root 069cbb56…` (unchanged), `recipient 480b9681…`,
    all-zero change ciphertexts.
  - **Effects verified on-chain:** real SAC moved contract→recipient (TBOND contract
    2000→1500, deployer 998000→998500); nullifier `126ef193…` `is_nullifier_used ==
    true`; `current_root` UNCHANGED `069cbb56…` (0 inserts — the no-change sentinel
    path exercised). Invariant #19 (frozen non-membership + recipient KYC) proven
    in-circuit and verified on-chain.
- **Done (1-insert sentinel branch — "0 vs 1 insert" completeness, 2026-06-20):** the
  acceptance requires BOTH change-note sentinel branches; the above covered 0-insert,
  this covers 1-insert (a PARTIAL unshield that mints a change note).
  - `scripts/lib/unshield-live.ts` `buildLivePartialUnshieldWitness` + gate
    `npm run unshield2:live:witness` (anchor parity, conservation 1000+500==1500,
    `cm_change_0 != 0`, `new_root != anchor_root`, mandatory change-note `c_auditor`
    non-zero; `snarkjs wtns check` → WITNESS IS CORRECT, 182k constraints). Prover
    `prove-partial-unshield-live.ts` (`unshield2:live:prove`); submit reuses
    `submit-unshield-live.ts <in> <out>`; disclosure `disclose-partial-unshield-live.ts`
    (`unshield2:live:disclose`).
  - **Registry:** `register_transparent(recipient=4c981b72… Bank B → deployer)`
    (tx `c0ecac3a356384673959d56f0c752bea6415663d5973d615b8a9ee218926181b`).
  - **Partial unshield** (tx `0da98de526dd8037fae8ffc611155d6d77207524a122082ad2f7906275e7a764`):
    spent the transfer recipient note (1500, Bank B, leaf 2) → 1000 transparent +
    500 change. On-chain event = the gate's values: `nf_in_0 07be65aa…`,
    `amount 1000`, `cm_change_0 46b002cf…` (non-zero), `new_root 542198b8…`, real
    change-note `c_auditor`.
  - **Effects verified on-chain:** SAC moved contract→recipient 1000 (TBOND contract
    1500→500, deployer 998500→999500); nullifier `07be65aa…` recorded;
    `current_root` ADVANCED to `542198b8…` (1 insert — the change-note sentinel
    branch exercised); regulator decrypted the change note (500 → Bank B) from the
    mandatory on-chain `c_auditor` (invariant #5). Both `(0 vs 1 insert)` branches
    now proven on live data.
**Deps:** FIN-015, FIN-025 (needs an on-chain note to spend).

### [~] FIN-027 · P2 · Frontend write-path wiring (real submit) — INFRA DONE + BUILD/RPC-VERIFIED; one-click write awaits indexer + served zkeys
Replace the honest `todo` step lists in `frontend/lib/finnes-client.ts`
(`shield` / `confidentialTransfer` / `unshield`) with the real flow: UTXO
selection → witness build → client-side prove (snarkjs in-browser: serve
`.wasm`/`.zkey`, add webpack fallbacks, **FIN-023**) → `submitToContract` invoking
the deployed contract via `@stellar/stellar-sdk` + Freighter (or the relayer
fee-bump). Point at contract `CDIWXQSWIP6G…AP55G7IA` (or read from
`setup/build/deploy.testnet.json`). The "Build, prove & submit" button then runs
for real. `fetchStateRoots` must read live contract/indexer state instead of MOCK.

- **Done (option 2 — in-browser proving; real infra, machine-verified):**
  - `frontend/lib/config.ts` — deployed contract id / RPC / network / SAC / artifact
    URLs (env-overridable). `frontend/lib/host-bytes.ts` — browser-safe port of
    `vk-host` (frToHex/g1ToHex/g2ToHex); **byte-identical to the cargo-verified
    converter** (parity-checked against `transfer-args.json`).
  - `frontend/lib/contract-spec.json` — the deployed contract's OWN spec (extracted
    via `stellar contract bindings`); `frontend/lib/soroban.ts` uses
    `Spec.funcArgsToScVals` to encode args. **Encoding validated against the LIVE
    contract**: a real `confidential_transfer` simulate decoded to contract logic
    (`Error(Contract,#11)` = nullifier used), not an encoding error.
  - `fetchStateRoots` now reads the LIVE `current_root` over Soroban RPC (verified
    returns `542198b8…`) + the four compliance roots from `demoComplianceRoots`
    (real SDK Poseidon/Merkle, **verified == the on-chain init roots**) — no MOCK.
  - `submitToContract` is REAL: spec-encode → `prepareTransaction` (RPC simulate +
    footprint) → Freighter sign → `sendTransaction` → poll. `proveInBrowser`
    (`frontend/lib/prove-browser.ts`) runs `groth16.fullProve` client-side; the
    witness never leaves the tab (invariant #8). `next.config.mjs` adds the snarkjs
    browser fallbacks; `snarkjs`+`buffer` added to the frontend. `next build` is
    GREEN (6/6 routes). The circuit `.wasm` are committed under
    `frontend/public/artifacts/<circuit>/`; the `.zkey` are gitignored (operator
    copies them there).
- **Done (buttons now EXECUTE the real pipeline, not a static TODO list):**
  `frontend/lib/write-flow.ts` wires `shield` / `confidentialTransfer` / `unshield`
  to: assemble a contract-acceptable witness from the live state → `proveInBrowser`
  → `submitInvocation`, reporting genuine per-step `ok`/`error` (the panel no longer
  shows "TODO · not wired"). `frontend/lib/demo-state.ts` (enrolled identities +
  KYC/assets paths) + `frontend/lib/live-notes.ts` (the on-chain note set + tree
  reconstruction — indexer stand-in) anchor the witness to the **current** chain
  state: verified `reconstructLiveTree().root == 542198b8…` (the live root), and the
  built **shield + unshield witnesses are `WITNESS IS CORRECT`** against the r1cs
  (so the proofs will be accepted). The session acts as an enrolled demo bank
  (Bank B) — a random key isn't in `kyc_root`. `is_nullifier_used` is read live to
  pick spendable notes; `unshield` spends the one remaining note, `transfer` errors
  honestly (`1 < 2` spendable). `next build` GREEN.
- **Done (institution balances now LIVE, not a fixture — honesty fix):** the
  `ConfidentialBalances` panel previously read a static demo ciphertext fixture yet
  reported `isMock: false` (misleading). `scanConfidentialBalances`
  (`frontend/lib/finnes-client.ts`) now returns the session identity's **unspent
  on-chain notes** — new `fetchLiveOwnedNotes()` (`write-flow.ts`) matches each
  locally-held opening (demo seeds + notes this wallet shielded/kept-as-change) to a
  live leaf in the contract's event-reconstructed tree (`buildChainTree`, FIN-019)
  and filters by live `is_nullifier_used`. So the balance shown == exactly what the
  Transfer/Unshield tabs can spend (no recipient-ciphertext key agreement needed; the
  wallet holds its own openings). Falls back to the deterministic fixture (real SDK
  `scanForOwnedNotes` trial-decrypt) ONLY when RPC is unavailable, flagged
  `isMock: true`; the panel shows a **live on-chain / demo fixture** source chip and
  honest copy ("Reading your on-chain notes…"). `tsc` adds no new errors (only the
  pre-existing snarkjs-resolution ones, FIN-023); `next build` GREEN (all routes).
- **Remaining = operator RUNTIME prerequisites only (no more code for the demo
  path):** (1) place the PRODUCTION D=20 `.zkey` under `public/artifacts/<circuit>/`
  (from the Railway ceremony — the LOCAL `shield.zkey` is a different ceremony and a
  proof from it is rejected on-chain; only the Railway zkeys match the deployed VK);
  (2) connect a funded Testnet Freighter (it signs + pays); (3) `transfer` needs ≥2
  spendable notes — shield twice first (each shield UI press mints one).
- **Known gap (not FIN-027 — needs a key-agreement scheme):** cross-party
  recipient-ciphertext **scan-from-chain** (discovering a note someone ELSE sent you,
  from only on-chain data) stays parked. The demo recipient ciphertext is keyed by an
  out-of-band pairwise key that the write-path throws away (`kPair: randFr()`), so an
  on-chain `c_recipient` is not recipient-recoverable without ECDH/note-encryption
  keys — a circuit-touching crypto change (RecipientEncCheck is bound in-circuit),
  tracked with FIN-019/production note encryption. The owned-notes balance path above
  does NOT depend on it.
**Deps:** FIN-015, FIN-019 (indexer for paths/roots/ciphertexts; can stub via RPC).

### [x] FIN-028 · P3 · Fix `scripts/deploy.sh` wasm path + record contract id — DONE
`deploy.sh` looked for `contracts/finnes/target/wasm32-unknown-unknown/release/finnes.wasm`,
but the cargo **workspace** emits to `contracts/target/`, and Soroban needs the
**`wasm32v1-none`** target (the `unknown-unknown` build trips
`reference-types not enabled`).
- **Done:** `WASM_PATH` now `${ROOT_DIR}/contracts/target/wasm32v1-none/release/finnes.wasm`
  (verified the artifact exists there, 43086 bytes). Build comment + not-found error
  message de-staled to point at the workspace target dir. `bash -n scripts/deploy.sh` clean.
**Deps:** none.

---

## Backlog — deferred (not needed for the core demo)

### [ ] FIN-016 · P3 · `dvp.circom` + `settle_dvp` (demo combined proof)
Two-leg combined circuit (demo single-witness, labelled non-production). Consent via on-chain `require_auth` for both parties, not in-circuit signature (invariant #15).

### [ ] FIN-017 · P3 · Production DvP via escrow
Escrow / two-phase settlement (each party single-party-spends into an intent-owned escrow note; settlement spends both and mints swapped outputs). Atomic-via-escrow with timeout refund.

### [ ] FIN-018 · P3 · Clawback / freeze flow + UI
Frozen-commitment set management; two-phase two-key (auditor identifies `cm_target`, issuer freezes + mints recovery note); optional dual-signature freeze tx (invariant #14). Frontend freeze/clawback panel.

### [~] FIN-019 · P3 · Backend tier (indexer / API / relayer) — INDEXER DONE + LIVE-VERIFIED; API/relayer deferred
Indexer (event subscription, off-chain tree reconstruction, ciphertext store), API (paths/roots/ciphertexts), relayer (fee-bump submission; per-asset `fee` term is 0 in demo). Replaces the frontend's mock/stubbed reads.
- **Done (indexer — event subscription + tree + ciphertext store, LIVE-VERIFIED):**
  `frontend/lib/indexer.ts` now does a full single-pass event replay over Soroban
  RPC and reconstructs, in on-chain order: the commitment leaves (the tree — already
  used by the write-path via `buildChainTree`), the per-output **auditor
  ciphertexts** (sliced `K_a`-wide from the `c_auditor` event vector: transfer = 2
  notes, shield/unshield = 1, exact-spend unshield = 0 via the `cm_change_0 == 0`
  sentinel), and the spent-input **nullifiers**. New `indexTransactions()` yields the
  regulator's ledger as REAL on-chain records.
- **Done (replaces a named stub):** `finnes-client.listOnChainTransactions()` now
  reads `indexTransactions()` (REAL chain data, `isMock: false`), falling back to the
  `demo-data.ts` fixture ONLY when no events are in range (RPC down / past Testnet's
  ~22h retention / empty contract), flagged honestly. The regulator page shows a
  Live/Demo source chip; an exact-spend unshield (no confidential output) reports
  "nothing to disclose" instead of a misleading wrong-key error.
- **Done (tree-reconstruction correctness — aged-out prefix, write-path fix):** a
  stateless RPC re-read only sees events within Testnet's ~22h retention, so the
  **genesis shield (leaf 0) had aged out** — `buildChainTree` was silently dropping
  it, mis-rooting the tree and shifting every leaf index (so the institution
  write-path would build wrong inclusion paths → on-chain proof failure). Fixed:
  `buildChainTree` now splices the confirmed aged-out prefix from the canonical demo
  seed (`liveSeedCommitments` in `live-notes.ts`) — but ONLY when continuity is
  provable (the first in-window leaf equals a known seed leaf at `p > 0`), so a
  fresh/redeployed contract is never wrongly seeded. (A production indexer is a
  stateful service that persists the tree and never re-reads from genesis; this seed
  is the demo stand-in.)
- **Verified on LIVE testnet (`npm run indexer:verify:live`,
  `scripts/verify-indexer-live.ts`):** indexed 12 events off the deployed contract
  `CDIWXQSWIP6G…AP55G7IA`; (a) the reconstructed tree (9 in-window + 1 aged-out
  genesis seed = **10 leaves**) roots to `1e98da06…`, **byte-equal to the contract's
  current `new_root`** (write-path anchor sound); and (b) the regulator view key
  decrypted **7 confidential txs** to full plaintext — e.g. transfer `bf6f54f0…` →
  recipient 1500 (Cendrawasih/Bank B) + change 500 (Meridian/Bank A), matching the
  FIN-025 on-chain record exactly. The 3-tx local fixture is now a fallback, not the
  source. `tsc` clean (only the pre-existing snarkjs-resolution errors), `next build`
  GREEN (8/8 routes).
- **Remaining (deferred, not blocking the demo):** a standalone API service
  (paths/roots/ciphertexts over HTTP) and the relayer (fee-bump submission; `fee` is
  0 in demo). The frontend reads RPC directly, so neither is needed for the demo
  path. The institution **balances** panel now reads the session's unspent on-chain
  notes live (FIN-027, owned-by-local-opening); the remaining gap is cross-party
  **recipient**-ciphertext scanning from chain (discovering a note someone else sent
  you), which needs an on-chain-recoverable `c_recipient` key (ECDH/note-encryption,
  not the demo's throwaway pairwise key) — a circuit-touching crypto change.

### [ ] FIN-020 · P3 · Threshold / multi-auditor view keys
No single auditor honeypot — split the view key across authorities.

### [ ] FIN-021 · P3 · Production trusted setup
Replace the single-party demo ceremony with a multi-party contribution + transcript verification (invariant #10).

---

## Cleanup (do alongside the above)

- [x] FIN-022 · P2 · Prover: import ordered public-input builders from `@finnes/sdk`; delete the duplicated `PUBLIC_IO_ORDER` constant. — DONE (folded into FIN-008).
- [ ] FIN-023 · P3 · Remove `typescript.ignoreBuildErrors` / `eslint.ignoreDuringBuilds` from `frontend/next.config.mjs` once sibling packages typecheck cleanly; rely on per-package `npm run typecheck`.
- [x] FIN-024 · P3 · Add CI: `npm test` (incl. the Poseidon parity gate), `cargo test`, `cargo clippy`, circuit pass/fail witnesses. — DONE
  `.github/workflows/ci.yml` (push to `main` + every PR, cancel-in-progress) runs
  three independent jobs, ALL verified green locally before commit:
  - **js** — `npm ci` → `npm run typecheck` (sdk+prover) → `npm test` (26 sdk tests
    incl. the locked **Poseidon-BLS parity vector**, invariant #13).
  - **contract** — `rustup` (from `rust-toolchain.toml`) → `cargo fmt --all --check`
    → `cargo clippy --all-targets --workspace -- -D warnings` (warnings = errors per
    CLAUDE.md) → `cargo test --workspace` (26 passed; real Groth16 verifier vectors).
  - **circuits** — installs the pinned **circom v2.2.3** linux binary (BLS12-381
    prime, invariant #1) + repo snarkjs, then runs the 7 circuit↔SDK parity gates
    (`poseidon|note|merkle|comparator|nonmembership|enc|assets`) and the 3 pass/fail
    witness gates (`transfer|shield|unshield:witness` — one rejection per constraint
    class). The gates compile their own small-depth test circuits, so no committed
    artifacts or ceremony are needed.
  - **Fixed pre-existing fmt drift** the new gate caught: `lib.rs` + the generated
    `test_vectors.rs` were not rustfmt-clean (`cargo fmt`); and
    `scripts/gen-verifier-fixture.ts` now `cargo fmt`s its output so a regeneration
    can't re-break the gate.
