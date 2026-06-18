# Canonical public-IO layout

**Single source of truth for ZK public-input / public-output ordering.** The order
defined here MUST be mirrored exactly in all four surfaces:

- each `circuits/*.circom` top-level `main` (public signal order),
- the contract's `PublicInputs::to_vec()` in `contracts/finnes/src/types.rs`,
- the prover's input assembly in `prover/src/witness.ts`,
- the SDK helpers in `sdk/src/`.

A mismatch surfaces as an "invalid proof" that looks like a crypto bug but is
almost always ordering/layout drift — **check this file first**. Changing any
ordering requires a fresh phase-2 ceremony for that circuit and a new VK
(see CLAUDE.md → "When adding a new circuit or changing public inputs").

> Status: SCAFFOLD. Field-packing of ciphertexts, the auditor-encryption scheme,
> and the exact tree depth are marked `TODO` below; the **logical signal order**
> is the part that is normative and must not be reordered casually.

---

## Field & curve

- Curve **BLS12-381**; the circuit field is its scalar field `r`. Never BN254.
- Hash: **Poseidon parameterized for `r`** — see `sdk/src/poseidon.ts` and
  `circuits/lib/poseidon_bls.circom`. Never circomlib/circomlibjs BN254 Poseidon.
- All amounts are **raw SAC units**; no rescaling in-circuit. Every `value` is
  64-bit range-checked (`Num2Bits(64)`).

## Primitives

```
asset_id      = Poseidon(sac_address)
owner_pk      = Poseidon(owner_sk)
commitment cm = Poseidon(asset_id, value, owner_pk, rho, r_note)
nullifier  nf = Poseidon(rho, owner_sk)
```

Note plaintext = `(asset_id, value, owner_pk, rho, r_note)`. Only `cm` is public
on-chain.

## Roots (state-matched public inputs)

| Root            | Freshness | Meaning                                                       |
|-----------------|-----------|---------------------------------------------------------------|
| `anchor_root`   | windowed  | a recent commitment-tree root the proof is anchored to        |
| `kyc_root`      | windowed  | KYC-approved set (membership)                                 |
| `sanction_root` | windowed  | sanctioned set (non-membership)                               |
| `assets_root`   | windowed  | authorized-assets registry; leaf `(asset_id, sac_address, decimals, per_tx_limit_raw)` |
| `frozen_root`   | **strict**| issuer-managed frozen-commitment set (non-membership)         |

## Tree

- Depth `D = 32` (TODO: confirm capacity vs cost).
- Frontier = filled-subtrees, `D` field elements.
- Transition proved in-circuit: `old_frontier` (in) → (`new_frontier`, `new_root`) (out).
- Contract stores `new_frontier` / `new_root` verbatim — it performs **no hashing**.

## Ciphertext binding (TODO: scheme)

- `c_auditor` (mandatory) and `c_recipient` are carried as **public inputs**
  (field-packed); Groth16 binds them inherently — the contract never hashes them.
- Encryption scheme: hybrid (prove value-equality), curve/representation `TODO`.
- `auditor_pk` representation (`auditor_pk_*`) `TODO` once the scheme is fixed.

---

## transfer.circom — 2-in / 2-out, single asset

Public signals, in order (`i` = index):

```
 0  anchor_root
 1  kyc_root
 2  sanction_root
 3  assets_root
 4  frozen_root
 5  auditor_pk          (TODO: may expand to _x/_y once scheme fixed)
 6  nf_in_0
 7  nf_in_1
 8  cm_out_0
 9  cm_out_1
10  new_root
11  fee                 (per-asset; 0 in demo)
12 .. 12+D-1            old_frontier[0..D-1]
   .. +D                new_frontier[0..D-1]
   .. +K_a              c_auditor   (K_a packed field elements, TODO)
   .. +K_r              c_recipient (K_r packed field elements, TODO)
```

Private witness: input notes `(asset_id, value, owner_pk, rho, r_note)×2`,
`owner_sk`, Merkle paths for the two inputs, KYC path, sanctions non-membership
path, frozen non-membership path, assets-registry path (+ `per_tx_limit_raw`),
output note openings ×2, encryption randomness.

Constraints: input inclusion + ownership, `nf` derivation, **per-asset value
conservation** `Σin == Σout + fee` (never across `asset_id`), 64-bit range checks,
KYC membership, sanctions + frozen non-membership, assets membership +
`value ≤ per_tx_limit_raw`, auditor-encryption well-formedness, tree transition.

## shield.circom — transparent → shielded (0 shielded inputs, 1 transparent input)

```
 0  asset_id            (public — derived from deposited SAC; circuit proves = Poseidon(sac_address))
 1  amount              (public — deposited raw SAC units)
 2  kyc_root            (depositor/owner KYC membership)
 3  assets_root
 4  auditor_pk          (TODO)
 5  cm_out_0
 6  new_root
 7  fee                 (0 in demo)
 8 .. 8+D-1             old_frontier[0..D-1]
   .. +D                new_frontier[0..D-1]
   .. +K_a              c_auditor
   .. +K_r              c_recipient
```

Key constraint: the output `cm` opens to `(asset_id, amount, owner_pk, rho, r_note)`
for the **public** `(asset_id, amount)` without revealing `(owner_pk, rho, r_note)`.
Prevents minting a note labelled as a different/more-valuable asset.

## unshield.circom — shielded → transparent (1+ shielded inputs, transparent output)

```
 0  anchor_root
 1  kyc_root            (transparent recipient compliance)
 2  sanction_root
 3  assets_root
 4  frozen_root
 5  auditor_pk          (TODO)
 6  nf_in_0
 7  asset_id            (public — for the SAC transfer)
 8  amount              (public — raw SAC units leaving)
 9  recipient           (public — transparent Stellar address)
10  cm_change_0         (optional change note; 0/null if none)
11  new_root
12  fee
13 .. 13+D-1            old_frontier[0..D-1]
   .. +D                new_frontier[0..D-1]
   .. +K_a              c_auditor   (for the change note, if any)
```

MUST enforce: input inclusion + nullifier, **frozen-set non-membership** of the
spent commitment (escape-hatch closure), transparent `recipient` KYC/non-sanctioned,
conservation `amount + change == input`.

## dvp.circom — atomic two-asset settlement (demo: single combined proof)

Two legs (asset X: A→B, asset Y: B→A). Demo uses one combined witness holding both
parties' secrets (one pairing). Production uses the escrow / two-phase flow
(ARCHITECTURE.md → "Settlement (DvP)") built from `transfer`/`shield` variants, not
this combined circuit.

```
 0  anchor_root
 1  kyc_root
 2  sanction_root
 3  assets_root
 4  frozen_root
 5  auditor_pk          (TODO)
 6  nf_legX_0
 7  nf_legY_0
 8  cm_out_X            (asset X → B)
 9  cm_out_Y            (asset Y → A)
10  new_root
11  fee_X
12  fee_Y
13 .. 13+D-1            old_frontier[0..D-1]
   .. +D                new_frontier[0..D-1]
   .. +K_a              c_auditor_X
   .. +K_a              c_auditor_Y
   .. +K_r              c_recipient_X
   .. +K_r              c_recipient_Y
```

Per-leg: conservation per asset, per-leg `per_tx_limit_raw` check, KYC of each
recipient, frozen/sanctions non-membership. Consent is on-chain via `require_auth`
(both parties), never an in-circuit signature.
