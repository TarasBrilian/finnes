# CLAUDE.md

Operational guidance for AI coding agents (e.g. Claude Code) working in this
repository. Read this first. For the product overview see [`README.md`](./README.md);
for the full technical spec see [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## What this project is

**Finnes** is a confidential settlement layer for regulated RWA on Stellar/Soroban.
It moves RWA tokens with hidden amounts/parties, while staying atomic (DvP),
provably compliant, and auditable by regulators via view keys. It is **not** a
mixer — auditability is enforced in-circuit.

Stack: Circom + Groth16 + **BLS12-381**, Soroban (Rust/WASM) verifier, SnarkJS
proving, **Poseidon-BLS** commitments (no embedded curve), shielded-note (UTXO)
model.

---

## Security invariants — NEVER break these

These are fund-critical or privacy-critical. A violation is a serious bug even if
tests pass. If a change would touch any of these, stop and flag it explicitly.

1. **Curve is BLS12-381. Never BN254.** BN254 is ~100-bit and not natively
   supported by Soroban. All circuits, keys, and the verifier use BLS12-381.
   Every in-circuit gadget must be BLS-native: Poseidon is parameterized for the
   BLS12-381 **scalar field `r`** — never circomlib's BN254 constants reduced into
   the field (that is not a valid Poseidon instance). The protocol uses **no
   embedded curve** (no Baby Jubjub, no Jubjub) and **no in-circuit signature**;
   the only in-circuit primitive is Poseidon-BLS plus field-agnostic range/bit
   checks.
2. **Range-check every value.** Every note `value` (input and output) must pass a
   64-bit range check. Without it, field wraparound can mint value from negatives.
   Never remove or weaken a `Num2Bits(64)` / range constraint.
3. **Value conservation is per-asset.** `Σ inputs(asset) == Σ outputs(asset) + fee`.
   Never sum across different `asset_id`s. The `fee` term is per-asset and
   denominated in the shielded asset; it is **0 in the demo** but kept in the
   circuit/public-IO so a non-zero relayer fee can be added later without
   re-ceremony. The XLM network fee is separate and paid by the submitter — a
   relayer **fee-bump** in the demo, never the user's own account (which would link
   identity to a confidential transfer).
4. **Nullifiers are mandatory and single-use.** Every spent input must publish a
   nullifier; the contract must reject a tx if any nullifier already exists. Never
   short-circuit the nullifier check.
5. **Auditor encryption is mandatory and circuit-enforced.** Every output note must
   include a well-formed `C_auditor`, **bound to the proof as a public input** —
   Groth16 verification inherently binds public inputs, so the contract never
   hashes ciphertext blobs (it stores them verbatim). Never make the auditor
   ciphertext optional, and never let the prover supply it unconstrained.
6. **Compliance roots come from contract state, not the proof alone.** The contract
   must check that `kyc_root` / `sanction_root` / `assets_root` / `auditor_pk` /
   `frozen_root` in the public inputs match stored state. **Freshness policy is
   per-root:** `frozen_root` is **strict** (must equal current state — immediacy is
   the point of clawback), while `kyc_root` / `sanction_root` / `assets_root` may be
   validated against a recent-roots window (they change rarely and benignly). Never
   trust prover-supplied roots blindly, and never accept a stale `frozen_root`.
7. **One Groth16 proof per transaction.** A pairing-check is ~40M instructions;
   multiple proofs per tx risks exceeding the Soroban instruction budget.
8. **Never log or persist secrets.** `owner_sk`, `r`, `rho`, witness inputs,
   plaintext note values, and `auditor_sk` must never be logged, committed, or sent
   to any service. The off-chain prover runs where the data already lives.
9. **Verify before effects.** In every contract entrypoint: validate root → check
   nullifiers unused → check compliance roots → verify Groth16 → bind ciphertexts →
   only then mutate state (insert nullifiers/commitments, update root).
10. **Trusted-setup artifacts.** Never commit a `.zkey` produced from an undocumented
    or single-party ceremony as production. Treat phase-2 output as sensitive.
11. **No hashing on-chain.** The contract runs one BLS12-381 pairing-check plus
    storage writes — never Poseidon. All hashing (commitments, nullifiers, Merkle,
    ciphertext binding) happens in-circuit. Poseidon is mirrored across exactly
    **two surfaces** — the circuit and the JS/TS SDK/prover — never the Rust
    contract. Any unavoidable on-chain hash uses a host function (SHA-256), never
    Poseidon.
12. **Tree transition is proved in-circuit; the frontier is public-IO.** A transfer
    proves `old_frontier → (new_frontier, new_root)`. `old_frontier` (filled
    subtrees, ~depth elements) is a public input checked equal to state;
    `new_frontier` and `new_root` are public outputs the contract stores verbatim.
    Root alone is insufficient. Keep this layout identical across circuit /
    contract / prover.
13. **Poseidon parameter parity.** The Poseidon parameter set (for the BLS12-381
    scalar field `r`) must be byte-for-byte identical in the circuit and the SDK.
    Ship a cross-implementation test vector (same inputs → same hash in circuit and
    JS) as a CI gate. Never use circomlibjs' default (BN254) Poseidon.
14. **Clawback = frozen-set non-membership, two-phase / two-key.** Shielded clawback
    works via an issuer-managed frozen-commitment set: every spend must prove
    **non-membership** of each spent commitment against `frozen_root` (reusing the
    sanctions non-membership gadget), so a frozen note becomes unspendable.
    Clawback is two-phase: (1) the auditor decrypts with the view key to identify
    `cm_target` (read authority); (2) `issuer_authority` adds it to the frozen set
    and mints a recovery note (write authority). Never try to clawback by computing
    a note's nullifier — that needs the owner's spending key, which no authority
    holds. Keep `auditor_pk` (read) and `issuer_authority` (write) as distinct keys
    even when one operator holds both in a demo.
15. **Counterparty consent is on-chain, not in-circuit; production DvP is escrow.**
    DvP/settlement consent uses native Soroban `require_auth` (Ed25519) over a tx
    that commits to the concrete intent (output commitments, nonce) — never an
    in-circuit signature gadget. Production DvP is **escrow / two-phase** (each
    party single-party-spends its own note into an intent-owned escrow note; a
    settlement step spends both escrow notes and mints the swapped outputs —
    atomic-via-escrow with timeout refund). The **demo** may use one combined proof
    holding both parties' secrets (one pairing) **only** because a harness controls
    both keypairs; this is non-production and must be labeled.
16. **Notes hold raw SAC units; the circuit never rescales.** Every note stores the
    asset's raw Stellar Asset Contract amount. Circuits must never multiply/divide
    by decimals — decimals live only in the assets registry and the SDK (display).
    Rescaling in-circuit reintroduces cross-asset value confusion and breaks
    per-asset conservation.
17. **Authorized-assets registry is the single source of truth; limits flow through
    membership.** The registry leaf is `(asset_id, sac_address, decimals,
    per_tx_limit_raw)`, committed as `assets_root`. Per-tx limits are per-asset,
    taken from the leaf as a witness and enforced via membership against
    `assets_root` (`value ≤ per_tx_limit_raw`) — never exposed as a per-asset public
    input (a distinctive limit would fingerprint the otherwise-hidden asset).
    `asset_id = Poseidon(sac_address)` (computed in-circuit, never on-chain). For
    DvP the limit check is per-leg.
18. **Shield binds the note to the deposited asset.** `shield` must prove the new
    commitment opens to the publicly-deposited `(asset_id, amount)` without
    revealing `(owner, rho, r)` — never a full opening. Otherwise a depositor could
    shield asset X but mint a note labeled as a more valuable asset Y and unshield
    counterfeit value.
19. **`unshield` must prove frozen-set non-membership + recipient compliance.** Value
    leaving the shielded domain to a transparent address is the top compliance
    checkpoint: `unshield` must enforce (a) the transparent recipient is
    KYC/non-sanctioned, and (b) **non-membership of the spent commitment against
    `frozen_root`**. Skipping (b) is an escape hatch that lets a frozen note exit —
    treat it as fund-critical as the nullifier check.

---

## Repository map

```
circuits/        Circom circuits (transfer.circom, dvp.circom, lib/*.circom)
contracts/finnes/  Soroban contract (Rust): lib.rs, verifier.rs, merkle.rs, state.rs
prover/          Off-chain prover service (TypeScript) — generates proofs
sdk/             Client SDK: note management, ciphertext scanning, encryption
setup/           Trusted-setup ceremony artifacts (.zkey, verifying keys)
scripts/         build / deploy / demo scripts
```

When implementing a feature, the change usually spans: a circuit (`circuits/`), the
verifier/state in the contract (`contracts/finnes/src/`), and the prover/SDK glue
(`prover/`, `sdk/`). Keep public-input ordering identical across all three —
mismatched ordering is the most common integration bug.

---

## Common commands

```bash
# Circuits
npm run circuits:build         # compile Circom -> R1CS + WASM
npm run circuits:test          # circuit-level tests (witness assertions)
npm run setup:ceremony         # phase-2 setup, export .zkey + VK

# Contract (Soroban / Rust)
cd contracts/finnes
cargo test                     # unit + integration tests
cargo fmt && cargo clippy      # format + lint (clippy must be clean)
stellar contract build         # build WASM
stellar contract deploy --wasm <path> --network testnet

# Prover / SDK
npm test                       # TS tests
npm run demo                   # end-to-end: shield -> transfer -> disclosure
```

Run `cargo fmt`, `cargo clippy`, and the relevant tests before considering any
change complete. Treat clippy warnings as errors.

---

## Conventions

- **Rust**: standard `rustfmt`; no `unwrap()` in contract code paths that handle
  untrusted input — return contract errors. Keep host-function calls in
  `verifier.rs`.
- **Circom**: keep reusable templates in `circuits/lib/`. Document the public-input
  order in a comment at the top of each top-level circuit; it must match the
  contract's `PublicInputs::to_vec()` and the prover's input assembly.
- **Field encoding**: use decimal-string representation off-chain for readability,
  hex/bytes for contract integration. Be explicit and consistent at boundaries.
- **Tests**: every circuit needs both a passing witness and at least one failing
  witness (e.g. unbalanced values, bad Merkle path, missing auditor ciphertext) to
  prove the constraint actually constrains.

---

## When adding a new circuit or changing public inputs

1. Update the circuit and its top-of-file public-input comment.
2. Re-run the phase-2 ceremony for that circuit; export a fresh VK.
3. Update the contract's `VerifyingKey` and `PublicInputs` layout to match exactly
   (including the Merkle frontier transition and any ciphertext public inputs).
4. Update the prover's input assembly and the SDK.
5. Add a negative test that fails if any new constraint is removed.

A VK/public-input mismatch produces "invalid proof" errors that look like crypto
bugs but are usually ordering/layout drift. Check this first.

## What to do when unsure

- If a task asks you to weaken any item in "Security invariants", do not do it
  silently — surface the conflict and ask.
- Prefer the **hybrid** auditor-encryption check (prove value equality) over full
  in-circuit AEAD unless explicitly asked; it is the intended MVP path.
- Base the Soroban verifier on `stellar/soroban-examples/groth16_verifier` rather
  than writing pairing math by hand.
- Do not introduce browser storage, external network calls from the contract, or
  any dependency that pulls in BN254 by default.
- Counterparty consent for DvP goes through on-chain `require_auth`, never an
  in-circuit signature gadget; never add an embedded curve (Baby Jubjub / Jubjub).

---

## Out of scope / non-goals

- Finnes is not an anonymity tool. Do not add features that remove auditability or
  the issuer clawback path.
- No reliance on off-chain reserve attestations — all settlement legs are on-chain
  (this is a deliberate simplification versus a proof-of-backing design).
- Do not optimize the circuit by dropping range checks or conservation constraints.
- KYC is **mocked for the demo**: the in-circuit membership check against `kyc_root`
  stays (never drop it), but enrollment is a hand-run admin script over demo
  accounts — there is no real identity provider/oracle. Do not build one, and do not
  remove the in-circuit check. Recipient-KYC privacy is deferred to production.