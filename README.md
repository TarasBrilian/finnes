# Finnes

**Confidential settlement layer for regulated RWA on Stellar.**
Private from the public, fully auditable by regulators.

Finnes lets regulated institutions settle real world asset (RWA) tokens on Stellar
with **hidden amounts and counterparties**, while remaining **atomically settled
(DvP)**, **provably compliant**, and **selectively disclosable** to regulators.
It is built on Soroban's native BLS12-381 host functions (Protocol 22, CAP-0059)
and a Groth16 + Circom proving stack.

> Positioning in one line: *"Dark pool grade confidentiality, audit grade
> transparency."* Finnes is not a mixer. Auditability is enforced in circuit by
> design.

---

## The problem

On a public ledger like Stellar, every RWA transfer is exposed: amount,
counterparties (via address clustering), timing, and position size. For retail
crypto that is fine. For institutions it is a dealbreaker:

- An institution settling a large tokenized-bond transfer leaks its trading
  strategy to competitors.
- It breaches client confidentiality, banking secrecy, and data-protection rules.
- Large pending transfers are exposed to front running.

Stellar's compliance stack (clawback, transfer restrictions, identity) controls
*who may hold* a token, but does nothing to hide *amount and parties*. Existing
crypto privacy tools (mixers) are unusable for institutions because they offer
total anonymity with no audit trail. The result: institutions are stuck between a
transparent public ledger (no privacy) and off chain/permissioned settlement (no
composability, counterparty risk returns). **There is no "confidential yet
compliant" option for RWA settlement.** Finnes fills that gap.

This aligns directly with the broader industry priority of building compliant
privacy infrastructure for confidential transfers on public ledgers.

---

## The solution

A shielded-note (UTXO) settlement protocol on Soroban with three pillars:

1. **Confidential transfer**: RWA moves via Poseidon commitments that hide
   amount/asset/owner; nullifiers prevent double spend. A Groth16 circuit proves
   each transfer is valid without revealing values.
2. **Atomic DvP**: the asset leg and the payment leg settle together in a single
   Soroban invocation, so on chain settlement guarantees are preserved.
3. **Selective disclosure**: every note is mandatorily encrypted to a regulator
   *view key* (enforced inside the circuit), and compliance (KYC membership,
   sanctions non membership, limits) is proven in circuit without revealing
   identities to the public.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full technical design.

---

## How it works

Value is held as **shielded notes**. A note records an asset, an amount, and an
owner, but only its Poseidon **commitment** ever appears on chain. The amount and
parties stay hidden. Commitments are inserted as leaves into an on chain
incremental Merkle tree.

To spend a note, a prover publishes a **nullifier** (which prevents double spend
but reveals nothing about which note was spent) and a **Groth16 proof** that:

- the input notes exist in the tree and are owned by the spender,
- value is conserved per asset and no value is created (range-checked; a per asset
  fee term is reserved but zero in the demo),
- the recipient is KYC-approved and not sanctioned, within policy limits,
- each output note is correctly encrypted to the regulator's view key.

The Soroban contract verifies the proof using BLS12-381 host functions, records the
nullifiers, and appends the new commitments, all in one atomic transaction. The
public sees only opaque commitments, nullifiers, and ciphertexts; the regulator,
holding the view key, can decrypt and audit every transaction in full.

---

## Key features

- Hidden amounts and counterparties on a public ledger.
- In circuit compliance: KYC whitelist membership + sanctions non membership + per-tx limits.
- Mandatory regulator view-key encryption, enforced by the proof (cannot be skipped).
- Issuer freeze / clawback over shielded balances, enforced in circuit via a
  frozen-commitment set (non membership) as a two phase, two key (auditor + issuer) operation.
- Atomic two-asset DvP settlement (single-tx in the demo; escrow based in production).
- Optional threshold/multi-auditor view keys (no single honeypot).

---

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Curve | BLS12-381 | Native Soroban host functions (CAP-0059); 128-bit security |
| Proof system | Groth16 | Single pairing-check verification (~40M instructions on Soroban) |
| Circuits | Circom (`--prime bls12381`) | BLS-native gadgets; no embedded curve |
| Proving | SnarkJS | Standard Groth16 prover / setup / VK export |
| On chain | Soroban (Rust/WASM) | Verifier based on `stellar/soroban-examples/groth16_verifier` |
| Hashing | Poseidon-BLS | Parameterized for the BLS12-381 scalar field; in circuit only (never on chain) |

---

## Repository structure

```
finnes/
├── circuits/                 # Circom circuits
│   ├── shield.circom         # transparent → shielded (binds note to deposited asset)
│   ├── transfer.circom       # confidential transfer (2-in / 2-out)
│   ├── unshield.circom       # shielded → transparent (frozen non membership + KYC)
│   ├── dvp.circom            # atomic two-asset DvP
│   └── lib/
│       ├── note.circom       # note commitment / nullifier
│       ├── merkle.circom     # Merkle inclusion / non-inclusion
│       └── enc_check.circom  # auditor-encryption well-formedness
├── contracts/                # Soroban smart contracts (Rust)
│   └── finnes/
│       └── src/
│           ├── lib.rs        # entrypoints: shield / confidential_transfer / settle_dvp / unshield
│           ├── verifier.rs   # Groth16 verify via BLS12-381 host fns
│           ├── merkle.rs     # incremental Merkle tree + recent roots
│           └── state.rs      # storage layout
├── prover/                   # off chain prover service (TypeScript)
├── sdk/                      # client SDK: note management, scanning, encryption
├── frontend/                 # Next.js web UI (institution + regulator/auditor views)
├── setup/                    # trusted-setup ceremony artifacts (.zkey, VK)
├── scripts/                  # build / deploy / demo scripts
├── README.md
├── ARCHITECTURE.md
└── CLAUDE.md
```

> The **backend tier** (indexer / API / relayer) described in
> [`ARCHITECTURE.md`](./ARCHITECTURE.md) is not yet scaffolded; the frontend
> currently reads mock/indexer-stubbed data where it would call that tier.

---

## Prerequisites

- Node.js >= 20 and npm
- Rust + `cargo` with the `wasm32-unknown-unknown` target
- Stellar CLI (`stellar`) configured for Testnet
- Circom 2.x and SnarkJS (`npm i -g snarkjs`)

---

## Quickstart

```bash
# 1. Install dependencies
npm install

# 2. Compile circuits (R1CS + WASM witness generator)
npm run circuits:build

# 3. Run the trusted setup (phase-2 ceremony) and export the verifying key
npm run setup:ceremony

# 4. Build and test the Soroban contract
cd contracts/finnes
cargo test
stellar contract build

# 5. Deploy to Testnet
stellar contract deploy --wasm target/wasm32-unknown-unknown/release/finnes.wasm \
  --network testnet

# 6. Run the end-to-end demo
npm run demo
```

---

## Configuration

The contract is parameterized by a small set of governance values, set at
initialization and updatable through the admin entrypoints:

| Parameter | Meaning |
|---|---|
| `kyc_root` | Merkle root of KYC-approved shielded addresses (mock-enrolled for the demo) |
| `sanction_root` | Root of the sanctioned-address set (non membership) |
| `frozen_root` | Root of the issuer-managed frozen-commitment set (clawback; non membership) |
| `auditor_pk` | Regulator view-key public key (or a threshold set) |
| `issuer_authority` | Public key authorized to freeze / clawback |
| `assets_root` | Merkle root of the authorized-assets registry; each leaf = `(asset_id, sac_address, decimals, per_tx_limit_raw)`. Per asset limits live here, not as a global scalar |
| `vk_shield`, `vk_transfer`, `vk_unshield`, `vk_dvp` | Groth16 verifying keys per circuit |

`kyc_root`, `sanction_root`, `assets_root`, `auditor_pk`, and `frozen_root` are
passed as public inputs on every transfer and must match contract state, so a
prover cannot use stale sets. `frozen_root` is matched **strictly** (immediacy of
clawback), while `kyc_root` / `sanction_root` / `assets_root` may use a recent-roots
window.

---

## Demo flow

1. `shield`: deposit a transparent RWA token, creating a confidential note.
2. `confidential_transfer`: move value A → B; the public sees only an opaque
   commitment, a nullifier, and ciphertexts.
3. Regulator decrypts the mandatory auditor ciphertext with the view key and
   displays the full transaction (amount, parties).
4. (Stretch) `settle_dvp`: settle a security leg against a confidential cash leg
   atomically.

Closing narrative: *the public sees that a valid, compliant transfer happened;
competitors cannot see amounts or parties; the regulator sees everything; DvP
stays atomic.*

---

## Testing

```bash
npm run circuits:test     # circuit witness assertions (positive + negative cases)
cargo test                # contract unit + integration tests (in contracts/finnes)
npm test                  # prover / SDK tests
```

Every circuit ships with both a passing witness and at least one failing witness
(e.g. unbalanced values, bad Merkle path, missing auditor ciphertext) to prove each
constraint actually constrains.

---

## Status & roadmap

- [x] Architecture and threat model
- [ ] `transfer.circom` (2-in/2-out, single asset) + KYC membership + range checks
- [ ] Authorized-assets registry + `shield.circom` / `unshield.circom` (asset binding, per asset limits, frozen non membership on unshield)
- [ ] Hybrid auditor-encryption check
- [ ] Soroban verifier + state + tree
- [ ] End-to-end demo (shield → transfer → regulator disclosure)
- [ ] Atomic DvP (`dvp.circom` + `settle_dvp`)
- [x] Threshold/multi-auditor view keys (SDK Shamir k-of-n split of the view key,
      FIN-020: off chain key custody; the reconstructed key yields the same
      `auditor_pk`, so the circuit/contract are unchanged)

---

## Acknowledgments

- CAP-0059 BLS12-381 host functions (Protocol 22).
- `stellar/soroban-examples/groth16_verifier` as the on chain verifier reference.