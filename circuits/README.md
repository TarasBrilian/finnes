# circuits/ — Finnes ZK circuits (Circom + Groth16 + BLS12-381)

> **STATUS: SCAFFOLD.** These circuits are **not** implemented, compiled,
> ceremony-ready, or verified. Template signatures, sub-circuit composition, and
> the public-signal ordering are concrete and intended to be correct. The actual
> cryptographic **constraint bodies** (Poseidon permutation, Merkle frontier
> transition, auditor-encryption binding, sorted-set non-membership ordering)
> are `// TODO:` stubs. Do **not** generate proving keys, run a ceremony, or
> claim soundness from this tree. Several gadgets are deliberately
> under-constrained placeholders so they cannot be mistaken for finished crypto.

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
- From `circomlib` we use **only field-agnostic helpers** — `Num2Bits`,
  `LessThan`, `LessEqThan`, `IsEqual`, `Mux1` — and never its Poseidon. The
  includes (`node_modules/circomlib/circuits/{bitify,comparators}.circom`) assume
  circomlib is installed at the repo root; repoint them if you vendor your own
  bit gadgets.
- There is **no embedded curve** (no Baby Jubjub / Jubjub) and **no in-circuit
  signature**. The only in-circuit cryptographic primitive is Poseidon-BLS plus
  field-agnostic range/bit checks. DvP/settlement consent is on-chain
  (`require_auth`), never an in-circuit signature gadget.

### Poseidon parameter set (`lib/poseidon_bls.circom`)

`PoseidonBLS` currently has a **placeholder body** (a linear accumulator, NOT a
hash). Before any real use:

1. Generate a Poseidon parameter set for the BLS12-381 scalar field `r`
   (neptune / Filecoin lineage; matching SDF's Privacy Pools work on Soroban):
   `alpha = 5` (x⁵ sbox), width `t = nInputs + 1`, `R_F = 8`, `R_P` per `t`,
   plus the round constants `C[]` and MDS matrix `M[][]`.
2. Vendor them as a generated include (e.g. `lib/poseidon_bls_params.circom`)
   with provenance notes, and implement the permutation in `PoseidonBLS`.
3. **Mirror the exact same parameter set byte-for-byte in `sdk/src/poseidon.ts`**
   (Security invariant #13). Ship a cross-implementation test vector (same inputs
   → same digest in circuit and JS) as a CI gate.

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

### Parameters pending resolution

- `D = 32` — commitment-tree depth (PUBLIC_IO.md; **TODO** confirm capacity vs
  proving cost).
- `K_a`, `K_r` — packed ciphertext element counts. Set to **`4` as placeholders**
  pending the auditor-encryption scheme; pin them in `docs/PUBLIC_IO.md` and the
  enc-check gadget together.
- `auditor_pk` is a single public field today; the encryption scheme may expand
  it to `_x/_y` (PUBLIC_IO.md TODO).

---

## Security invariants honoured by the structure (see CLAUDE.md)

These are wired into the template composition (bodies still TODO):

- **#1 BLS12-381 only / no embedded curve / no in-circuit signature** — only
  `PoseidonBLS` + range/bit checks; `--prime bls12381`.
- **#2 64-bit range check on every value** — `Num2Bits(64)` on every input and
  output `value` (and `amount` / `change_value`).
- **#3 Per-asset conservation** — `Σin == Σout + fee`, single-asset binding
  enforced; **never** summed across `asset_id`. DvP conserves per leg.
- **#4 Nullifiers mandatory** — every spent input derives and publishes a
  nullifier bound to a public input.
- **#5 Auditor encryption mandatory** — `AuditorEncCheck` on every output note,
  bound to public `c_auditor` (hybrid value-equality; **scheme TODO**).
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

1. **`PoseidonBLS` permutation + BLS12-381 params** (`lib/poseidon_bls.circom`)
   and SDK parity (`sdk/src/poseidon.ts`) + CI test vector.
2. **Auditor-encryption scheme** (`lib/enc_check.circom`): pick the hybrid
   value-equality construction (no embedded curve → no in-circuit EC-DH), bind
   each plaintext field to a ciphertext slot, fix `K_a` / `K_r` and `auditor_pk`
   representation. Currently the ciphertext is **unconstrained** (insecure
   placeholder).
3. **`FrontierTransition`** (`lib/merkle.circom`): real incremental-insert logic,
   empty-subtree constants, `nextIndex` wiring, and a no-op path for the
   no-change case in `unshield`. Must match `contracts/finnes/src/merkle.rs` and
   the indexer bit-for-bit. Currently a placeholder (under-constrained).
4. **`MerkleNonMembership`** (`lib/merkle.circom`): confirm the sorted-set leaf
   encoding with the indexer; add domain range-bounds so `LessThan` is sound.
5. **KYC/recipient binding**: bind the proven KYC leaf to the actual recipient
   identity (in `unshield`, to the public transparent `recipient`).
6. **Confirm `D = 32`**, and **pin `K_a` / `K_r`** in `docs/PUBLIC_IO.md`.
7. **Tests** (`circuits/test/`): per CLAUDE.md, each circuit needs a passing
   witness and ≥1 failing witness (unbalanced values, bad path, missing/garbled
   auditor ciphertext, frozen note spend).
8. **`dvp.circom` is the non-production demo combined circuit** — production DvP
   is the escrow/two-phase flow built from `transfer`/`shield` variants.
