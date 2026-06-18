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

> Status: DECISIONS LOCKED (FIN-001). Tree depth, the auditor-encryption scheme,
> ciphertext field-packing, the `auditor_pk` representation, the transparent
> `recipient` encoding, and the "no change note" sentinel are all fixed below
> (no `TODO` remains in the per-circuit signal tables). The **logical signal
> order** is normative and must not be reordered casually. Changing any locked
> count or ordering requires a fresh phase-2 ceremony + new VK for that circuit.

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

- Depth **`D = 20`** (LOCKED, FIN-001). Capacity `2^20 ≈ 1,048,576` notes —
  sufficient for the demo, and chosen to keep proving cheap (each input/KYC/
  sanctions/frozen/assets Merkle path is `D` Poseidon-`t=2` hashes, and the
  unoptimized HadesMiMC permutation makes per-level cost the dominant term).
  Production may raise `D` (e.g. 32) — that is a fresh-ceremony change, not a
  runtime parameter.
- Frontier = filled-subtrees, `D` field elements.
- Transition proved in-circuit: `old_frontier` (in) → (`new_frontier`, `new_root`) (out).
- Contract stores `new_frontier` / `new_root` verbatim — it performs **no hashing**.

## Ciphertext binding (LOCKED, FIN-001)

`c_auditor` (mandatory, invariant #5) and `c_recipient` (optional, for note
discovery) are carried as **public inputs** (field-packed); Groth16 binds them
inherently — the contract never hashes them, it stores them verbatim.

### Scheme: Poseidon additive keystream over a shared view-key (DEMO)

There is **no embedded curve** (invariant #1), so an in-circuit EC-DH/ElGamal KEM
is off the table — and Poseidon has no trapdoor, so a true public-key encryption
*verified in-circuit* is impossible BLS-natively. The resolution: keep the
value-binding **100% in-circuit (Poseidon)**, and put the asymmetry in the
**off-circuit key-distribution layer** (a one-time onboarding step, NOT per-tx).
The in-circuit gadget is **identical** in the demo and in production — only how the
keying secret is *authorized* changes (a scalar-equality in the demo becomes a
Merkle membership in production; that core does not change).

**Keying.** Each institution `I` shares a symmetric key `k_I` with the auditor,
established once at onboarding (e.g. over the auditor's X25519 key — off-circuit,
not security-critical to per-tx soundness). The **auditor ciphertext of a note is
keyed by its sender institution's** `k_S`:

```
auditor_pk    = Poseidon(k_S)     ← bound in-circuit so the prover must use a key
                                    the AUDITOR authorized:
   • DEMO (single institution): auditor_pk is a single scalar in contract state;
     the circuit proves auditor_pk == Poseidon(k_view) and the contract checks
     pi.auditor_pk == state.auditor_pk (exact).
   • PRODUCTION (multi-institution): contract stores auditor_set_root = Merkle root
     over { Poseidon(k_I) : I authorized }; the circuit proves Poseidon(k_S) ∈
     auditor_set_root, REUSING the KYC/assets Merkle-membership gadget. Institution
     B never holds k_A ⇒ cannot decrypt A's notes (confidential); the auditor holds
     every k_I ⇒ decrypts all (full audit). This is a fresh-ceremony swap of a
     scalar-equality for a membership check — the keystream below is unchanged.
```

Per **output note**, the prover samples a fresh nonce `ρ_enc` (published, so the
auditor can recompute the keystream) and masks the bound plaintext fields:

```
shared        = Poseidon(k_S, ρ_enc)
ks_i          = Poseidon(shared, i)              // domain-separated by slot index i
c[i]          = pt[i] + ks_i        (mod r)      // additive one-time pad over Fr
```

Decryption (auditor, holding `k_S`): `pt[i] = c[i] − Poseidon(Poseidon(k_S, ρ_enc), i)`.

**Soundness (full, both regimes).** `value`/`asset_id`/`owner_pk`/`rho` fed into the
keystream are the **same** signals fed into the note commitment, so the ciphertext
cannot disagree with the committed note ("encrypt a zero" is impossible), and the
key is bound (`Poseidon(k_S)` == `auditor_pk` / ∈ `auditor_set_root`) so the prover
cannot encrypt to a key the auditor lacks. There is **no griefing gap**: the prover
can only use its own authorized key, which the auditor can always read. (A pure
off-circuit X25519 transport with only an in-circuit value-commitment would NOT have
this property — the prover could publish a value-correct commitment alongside an
undecryptable blob; this scheme avoids that by binding the keystream itself.)

**Confidentiality.** Demo: single institution, so the single shared `k_view` never
leaks across parties. Production: per-institution `k_I` ⇒ genuine cross-institution
confidentiality, with a threshold/multi-auditor split of the auditor's keys
available as a further hardening (FIN-020).

> The recipient ciphertext (`c_recipient`) uses the same keystream construction but
> keyed by a sender↔recipient pairwise secret (demo: OOB); it is non-mandatory
> (invariant #5 requires only the auditor ciphertext) and exists for note discovery.

### Field-packing (LOCKED)

`auditor_pk` is a **single** field element (`Poseidon(k_view)`), not `_x`/`_y`.

```
K_a = 5  (c_auditor, per output note):
  [0] ρ_enc            (published nonce)
  [1] value    + ks_1
  [2] asset_id + ks_2
  [3] owner_pk + ks_3
  [4] rho      + ks_4

K_r = 5  (c_recipient, per output note):
  [0] ρ_enc            (published nonce; independent of the auditor nonce)
  [1] value    + ks_1
  [2] asset_id + ks_2
  [3] rho      + ks_3
  [4] r_note   + ks_4
```

`c_recipient` carries `r_note` instead of `owner_pk` (the recipient re-derives
`owner_pk` from its own `owner_sk`; it needs `r_note`+`rho` to later spend the
note). For the demo, the recipient keystream is keyed by an OOB-shared pairwise
secret (same construction); recipient discovery is **not** security-critical
(invariant #5 mandates only the auditor ciphertext).

**Every output note carries one mandatory `c_auditor` and one `c_recipient`.** A
2-out `transfer` therefore publishes `2·K_a + 2·K_r` ciphertext fields. For the
`unshield` change note and any "no change" case, see the per-circuit table and the
sentinel rule below.

---

## transfer.circom — 2-in / 2-out, single asset

`D = 20`, `K_a = K_r = 5`. Both output notes carry a mandatory `c_auditor` and a
`c_recipient` (cm_out_0 = recipient note, cm_out_1 = change note back to sender;
a zero-value change note is a normal commitment, so no sentinel is needed here).

Public signals, in order (`i` = absolute index):

```
 0       anchor_root
 1       kyc_root
 2       sanction_root
 3       assets_root
 4       frozen_root
 5       auditor_pk            (= Poseidon(k_view); single field)
 6       nf_in_0
 7       nf_in_1
 8       cm_out_0              (recipient note)
 9       cm_out_1              (change note → sender)
10       new_root
11       fee                   (per-asset; 0 in demo)
12 .. 31 old_frontier[0..19]   (D = 20)
32 .. 51 new_frontier[0..19]
52 .. 56 c_auditor_0[0..4]     (output note 0; mandatory)
57 .. 61 c_auditor_1[0..4]     (output note 1; mandatory)
62 .. 66 c_recipient_0[0..4]   (output note 0)
67 .. 71 c_recipient_1[0..4]   (output note 1)
```

Total: **72** public signals (`12 + 2·D + 2·K_a + 2·K_r` = `12 + 40 + 10 + 10`).

Private witness: input notes `(asset_id, value, owner_pk, rho, r_note)×2`,
`owner_sk`, Merkle paths for the two inputs, KYC path, sanctions non-membership
path, frozen non-membership path, assets-registry path (+ `per_tx_limit_raw`),
output note openings ×2, encryption randomness.

Constraints: input inclusion + ownership, `nf` derivation, **per-asset value
conservation** `Σin == Σout + fee` (never across `asset_id`), 64-bit range checks,
KYC membership, sanctions + frozen non-membership, assets membership +
`value ≤ per_tx_limit_raw`, auditor-encryption well-formedness, tree transition.

## shield.circom — transparent → shielded (0 shielded inputs, 1 transparent input)

`D = 20`, `K_a = K_r = 5`. One output note ⇒ one mandatory `c_auditor` + one
`c_recipient`.

```
 0       asset_id            (public — derived from deposited SAC; circuit proves = Poseidon(sac_address))
 1       amount              (public — deposited raw SAC units)
 2       kyc_root            (depositor/owner KYC membership)
 3       assets_root
 4       auditor_pk          (= Poseidon(k_view); single field)
 5       cm_out_0
 6       new_root
 7       fee                 (0 in demo)
 8 .. 27 old_frontier[0..19] (D = 20)
28 .. 47 new_frontier[0..19]
48 .. 52 c_auditor_0[0..4]   (mandatory)
53 .. 57 c_recipient_0[0..4]
```

Total: **58** public signals (`8 + 2·D + K_a + K_r` = `8 + 40 + 5 + 5`).

Key constraint: the output `cm` opens to `(asset_id, amount, owner_pk, rho, r_note)`
for the **public** `(asset_id, amount)` without revealing `(owner_pk, rho, r_note)`.
Prevents minting a note labelled as a different/more-valuable asset.

## unshield.circom — shielded → transparent (1+ shielded inputs, transparent output)

`D = 20`, `K_a = K_r = 5`. The single output is the (optional) change note.

```
 0       anchor_root
 1       kyc_root            (transparent recipient compliance)
 2       sanction_root
 3       assets_root
 4       frozen_root
 5       auditor_pk          (= Poseidon(k_view); single field)
 6       nf_in_0
 7       asset_id            (public — for the SAC transfer)
 8       amount              (public — raw SAC units leaving)
 9       recipient           (public — transparent Stellar address; see encoding below)
10       cm_change_0         (change note; 0 SENTINEL = no change, see below)
11       new_root
12       fee
13 .. 32 old_frontier[0..19] (D = 20)
33 .. 52 new_frontier[0..19]
53 .. 57 c_auditor_0[0..4]   (change note; all-zero when cm_change_0 == 0)
58 .. 62 c_recipient_0[0..4] (change note; all-zero when cm_change_0 == 0)
```

Total: **63** public signals (`13 + 2·D + K_a + K_r` = `13 + 40 + 5 + 5`).

**`recipient` encoding (LOCKED, demo):** a **single** field element. The demo's
transparent addresses are sampled to fit `< r`, and the contract maps
`pi.recipient` → the concrete Stellar `Address` for the SAC `transfer` via its
demo account registry. PRODUCTION GAP: a full 32-byte ed25519 / `C…` address can
exceed `r`; production splits `recipient` into two fields (hi/lo 16 bytes) or binds
it via the SHA-256 host function (the one on-chain hash invariant #11 permits) —
either is a fresh-ceremony change.

**"No change note" sentinel (LOCKED):** `cm_change_0 == 0`. The circuit gates the
change-note commitment and both change ciphertexts on `has_change = (cm_change_0 ≠
0)` (a constrained witness); when there is no change, `amount == input value`, and
`c_auditor_0` / `c_recipient_0` are all-zero. `0` is safe as a sentinel because a
real Poseidon commitment is never `0` (negligible probability over `Fr`).

MUST enforce: input inclusion + nullifier, **frozen-set non-membership** of the
spent commitment (escape-hatch closure), transparent `recipient` KYC/non-sanctioned,
conservation `amount + change == input`.

## dvp.circom — atomic two-asset settlement (demo: single combined proof)

Two legs (asset X: A→B, asset Y: B→A). Demo uses one combined witness holding both
parties' secrets (one pairing). Production uses the escrow / two-phase flow
(ARCHITECTURE.md → "Settlement (DvP)") built from `transfer`/`shield` variants, not
this combined circuit.

`D = 20`, `K_a = K_r = 5`. Two output notes (one per leg), each with a mandatory
`c_auditor` + a `c_recipient`.

```
 0       anchor_root
 1       kyc_root
 2       sanction_root
 3       assets_root
 4       frozen_root
 5       auditor_pk          (= Poseidon(k_view); single field)
 6       nf_leg_x_0
 7       nf_leg_y_0
 8       cm_out_X            (asset X → B)
 9       cm_out_Y            (asset Y → A)
10       new_root
11       fee_x
12       fee_y
13 .. 32 old_frontier[0..19] (D = 20)
33 .. 52 new_frontier[0..19]
53 .. 57 c_auditor_X[0..4]   (mandatory)
58 .. 62 c_auditor_Y[0..4]   (mandatory)
63 .. 67 c_recipient_X[0..4]
68 .. 72 c_recipient_Y[0..4]
```

Total: **73** public signals (`13 + 2·D + 2·K_a + 2·K_r` = `13 + 40 + 10 + 10`).
Signal names match `DvpPublicInputs` in `contracts/finnes/src/types.rs`
(`nf_leg_x_0` / `nf_leg_y_0` / `fee_x` / `fee_y`).

Per-leg: conservation per asset, per-leg `per_tx_limit_raw` check, KYC of each
recipient, frozen/sanctions non-membership. Consent is on-chain via `require_auth`
(both parties), never an in-circuit signature.
