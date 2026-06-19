# circuits/ — Finnes ZK circuits (Circom + Groth16 + BLS12-381)

> **STATUS: gadgets implemented; top-level wiring in progress.** The reusable
> `lib/` gadgets are now real and circuit↔SDK parity-tested: Poseidon-BLS
> (FIN-002), note commitment/nullifier + Merkle inclusion/IMT non-membership +
> frontier transition (FIN-003), auditor/recipient encryption binding (FIN-004),
> and authorized-assets membership + per-tx limit (FIN-005). What is NOT yet done:
> the top-level circuits (`shield`/`transfer`/`unshield`/`dvp`) are still being
> wired from these gadgets (FIN-006+), no ceremony has run, and no VK exists. Do
> **not** generate proving keys or claim end-to-end soundness from this tree yet.
> `D = 20`, `K_a = K_r = 5`, and the auditor-encryption scheme are LOCKED
> (FIN-001, docs/PUBLIC_IO.md).

Confidential RWA settlement circuits for Stellar/Soroban. Four top-level
circuits, each with its own verifying key:

| Circuit | Role | Public-IO source |
|---|---|---|
| `shield.circom`   | transparent → shielded (binds note to deposited asset) | `docs/PUBLIC_IO.md` |
| `transfer.circom` | confidential transfer, 2-in / 2-out, single asset      | `docs/PUBLIC_IO.md` |
| `unshield.circom` | shielded → transparent (frozen non-membership + KYC)   | `docs/PUBLIC_IO.md` |
| `dvp.circom`      | atomic two-asset DvP (**demo: single combined proof**) | `docs/PUBLIC_IO.md` |

Reusable gadgets live in `lib/`:

| File | Templates |
|---|---|
| `lib/poseidon_bls.circom` | `PoseidonBLS(nInputs)` — Poseidon over the BLS12-381 scalar field |
| `lib/note.circom`         | `AssetId`, `OwnerPk`, `NoteCommitment`, `Nullifier`, `SpentNote`, `OutputNote` |
| `lib/merkle.circom`       | `MerkleInclusion`, `MerkleNonMembership`, `FrontierTransition`, `HashLR` |
| `lib/enc_check.circom`    | `AuditorEncCheck` (mandatory), `RecipientEncCheck` (optional) |
| `lib/assets.circom`       | `AssetsMembership` — registry membership + `per_tx_limit_raw` check |

---

## Building (DO NOT run from this scaffold yet)

```bash
# The --prime flag is a COMPILER FLAG, not a pragma. There is NO pragma that
# selects the field. pragma circom 2.1.6; only pins the language version.
circom transfer.circom  --prime bls12381 --r1cs --wasm --sym
circom shield.circom    --prime bls12381 --r1cs --wasm --sym
circom unshield.circom  --prime bls12381 --r1cs --wasm --sym
circom dvp.circom       --prime bls12381 --r1cs --wasm --sym
```

`pragma circom 2.1.6;` is set in every file. The field is selected **only** by
`--prime bls12381` on the command line — omitting it silently compiles against
BN254 and every Poseidon-BLS hash is wrong.

### ⚠️ BN254-vs-BLS warning (read before touching any hash)

This is the single most dangerous footgun in the tree, and it is **Security
invariant #1**:

- The circuit field is the **BLS12-381 scalar field** `r`:

  ```
  r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    = 52435875175126190479447740508185965837690552500527637822603658699938581184513
  ```

- **Never** use `circomlib` / `circomlibjs` Poseidon. Its constants are
  generated for the **BN254** scalar field. Reducing those constants modulo
  BLS12-381's `r` does **not** produce a valid Poseidon instance — it is a silent
  cryptographic break. Round constants and the MDS matrix must be **generated for
  `r`** and the chosen `(t, R_F, R_P)` profile.
- circomlib is **NOT** installed and is never pulled in (it is BN254-pinned).
  The field-agnostic helpers we need (`Num2Bits`, `LessThan`, `LessEqThan`,
  `IsZero`, `IsEqual`) plus r-aware full-field comparators (`Num2BitsBLS`,
  `AliasCheckBLS`, `LessThanField`) are **VENDORED** in `lib/bits.circom`. All
  circuits include `bits.circom`, never `node_modules/circomlib/...`.
- There is **no embedded curve** (no Baby Jubjub / Jubjub) and **no in-circuit
  signature**. The only in-circuit cryptographic primitive is Poseidon-BLS plus
  field-agnostic range/bit checks. DvP/settlement consent is on-chain
  (`require_auth`), never an in-circuit signature gadget.

### Poseidon parameter set (`lib/poseidon_bls.circom`) — DONE (FIN-002)

`PoseidonBLS` implements the real permutation (unoptimized HadesMiMC, `alpha = 5`,
`R_F = 8`, `R_P` per width). The parameters are generated for the BLS12-381 scalar
field `r` by `scripts/gen-poseidon-params.mjs` into both
`lib/poseidon_constants.circom` and `sdk/src/poseidon-params.ts` (byte-identical,
invariant #13). The cross-implementation parity vector is a CI gate
(`scripts/test-poseidon-parity.ts`, `sdk/test/poseidon.test.ts`). Supported widths
are `t ∈ {2,3,6}` (arities 1, 2, 5) — a 4-field leaf is padded to arity 5
(see `assets.circom` / `imtLeafHash`).

---

## Public-IO is canonical and ordered

The single source of truth for public-signal ordering is **`docs/PUBLIC_IO.md`**.
Each top-level circuit copies its ordering verbatim into a header comment and
declares `main { public [...] }` in that exact order. The same order must be
mirrored in:

- `contracts/finnes/src/types.rs` → `PublicInputs::to_vec()`,
- `prover/src/witness.ts`,
- `sdk/src/`.

A mismatch surfaces as an "invalid proof" that looks like a crypto bug but is
almost always ordering/layout drift — **check `docs/PUBLIC_IO.md` first**.
Changing any ordering (or `D`, `K_a`, `K_r`) requires a fresh phase-2 ceremony
for that circuit and a new VK.

### Parameters (LOCKED, FIN-001)

- `D = 20` — commitment-tree depth (capacity 2^20 ≈ 1.05M notes; demo-cheap).
- `K_a = K_r = 5` — packed ciphertext element counts (1 nonce + 4 masked slots,
  additive Poseidon keystream; see `lib/enc_check.circom` / `sdk/src/encrypt.ts`).
- `auditor_pk` is a **single** public field, `= Poseidon(k_view)`.

Changing any of these requires a fresh phase-2 ceremony + new VK.

---

## Security invariants honoured by the structure (see CLAUDE.md)

These are wired into the gadgets (lib done; top-level wiring is FIN-006+):

- **#1 BLS12-381 only / no embedded curve / no in-circuit signature** — only
  `PoseidonBLS` + range/bit checks; `--prime bls12381`.
- **#2 64-bit range check on every value** — `Num2Bits(64)` on every input and
  output `value` (and `amount` / `change_value`).
- **#3 Per-asset conservation** — `Σin == Σout + fee`, single-asset binding
  enforced; **never** summed across `asset_id`. DvP conserves per leg.
- **#4 Nullifiers mandatory** — every spent input derives and publishes a
  nullifier bound to a public input.
- **#5 Auditor encryption mandatory** — `AuditorEncCheck` on every output note,
  bound to public `c_auditor` (additive Poseidon keystream, DONE FIN-004; the key
  is bound via `auditor_pk = Poseidon(k_view)`).
- **#12 Tree transition in-circuit** — `old_frontier` (public input) →
  (`new_frontier`, `new_root`) (public outputs); contract stores verbatim, no
  on-chain hashing.
- **#14 / #19 Frozen-set non-membership** — proved for every spent commitment on
  `transfer`, `unshield`, and `dvp` (reusing the sanctions non-membership
  gadget).
- **#16 Raw SAC units** — circuits never rescale by `decimals`; `decimals` is in
  the registry leaf only for hash binding.
- **#17 Assets registry is the limit source** — `AssetsMembership` proves
  `asset_id = Poseidon(sac_address)`, registry inclusion, and
  `value ≤ per_tx_limit_raw` (limit is a witness, never a public input).
- **#18 Shield binds to deposited asset** — `shield` proves the output `cm` opens
  to the public `(asset_id, amount)` without revealing `(owner, rho, r)`.

---

## Outstanding TODOs a human must resolve

DONE (lib gadgets, parity-tested): `PoseidonBLS` + params (FIN-002);
`NoteCommitment`/`Nullifier`, `MerkleInclusion`/`MerkleNonMembership` (IMT,
r-aware comparisons), `FrontierTransition` (FIN-003); `AuditorEncCheck` /
`RecipientEncCheck` (FIN-004); `AssetsMembership` + per-tx limit (FIN-005). `D`,
`K_a`, `K_r` are LOCKED (FIN-001).

Remaining:

1. **`transfer.circom` wiring (FIN-006)**: bind the SECOND output note's mandatory
   c_auditor/c_recipient (PUBLIC_IO carries 2·K_a + 2·K_r), supply `nextIndex` as a
   constrained witness pinned to the contract leaf count, and bind `kyc_leaf` to
   the real recipient. Then ≥1 failing witness per constraint class.
2. **Boundary circuits (FIN-012/013)**: `shield.circom` (asset-binding open) and
   `unshield.circom` (frozen non-membership + transparent-recipient KYC; no-change
   `cm_change_0 == 0` sentinel path).
3. **`dvp.circom` (FIN-016)**: non-production demo combined circuit — production
   DvP is the escrow/two-phase flow built from `transfer`/`shield` variants.
4. **`FrontierTransition` ↔ contract parity**: confirm `nextIndex` / no-change
   handling matches `contracts/finnes/src/merkle.rs` and the indexer bit-for-bit.
5. **Tests** (`circuits/test/`): per CLAUDE.md, each top-level circuit needs a
   passing witness and ≥1 failing witness (unbalanced values, bad path,
   missing/garbled auditor ciphertext, frozen note spend, over-limit).
