# `setup/` — Trusted-setup artifacts

This directory holds the Groth16 **trusted-setup** outputs for Finnes: the
per-circuit proving keys (`.zkey`) and the public verifying keys
(`vk_<name>.json`). It is produced by [`scripts/setup-ceremony.sh`](../scripts/setup-ceremony.sh)
(wired to `npm run setup:ceremony`).

---

## ⚠️ DEMO-ONLY — not production-secure (invariant #10)

The ceremony script runs a **single-party, local** setup. The toxic waste from a
single party is not destroyed by independent contributors, so **anyone able to
reconstruct it can forge proofs**. The resulting `.zkey` files are suitable for
local development and demos **only**.

Per **CLAUDE.md invariant #10**: *never commit / ship a `.zkey` produced from an
undocumented or single-party ceremony as production. Treat phase-2 output as
sensitive.*

A production deployment requires a **documented, multi-party phase-2 ceremony**:
multiple independent participants each contribute randomness to every circuit's
`.zkey`, at least one honest participant destroys their secret, and the full
transcript is published and verifiable (`snarkjs zkey verify`). Until that exists,
do not deploy these keys to a network that secures real value.

---

## BLS12-381 requirement (invariant #1)

The whole stack is **BLS12-381**, never BN254:

- **Phase 1 (Powers of Tau)** must be generated for **BLS12-381**
  (`snarkjs powersoftau new bls12381 ...`). snarkjs defaults to `bn128` (BN254);
  using the default would silently break the entire proving stack and violate
  invariant #1.
- A generic BN254 `.ptau` downloaded from the usual public ceremonies **cannot**
  be used — the curve must match the circuits, which are compiled with
  `circom --prime bls12381`.
- The verifying keys exported here feed the Soroban verifier, which uses the
  BLS12-381 host functions (CAP-0059, Protocol 22/23).

---

## Two-phase ceremony

### Phase 1 — Powers of Tau (universal, circuit-independent)

```
powersoftau new bls12381 <power> pot_0000.ptau
powersoftau contribute     pot_0000.ptau pot_0001.ptau   # demo entropy
powersoftau prepare phase2 pot_0001.ptau pot_final.ptau
```

`<power>` sets capacity to `2^power` constraints. **TODO:** confirm it covers the
largest circuit (`transfer` / `dvp`, with tree depth `D = 20` per
[`docs/PUBLIC_IO.md`](../docs/PUBLIC_IO.md)). The script defaults to `2^16`
(override with `PTAU_POWER`).

### Phase 2 — per-circuit (binds phase-1 to each R1CS)

For each circuit in `[shield, transfer, unshield, dvp]`:

```
groth16 setup        circuits/build/<name>/<name>.r1cs  pot_final.ptau  <name>_0000.zkey
zkey contribute      <name>_0000.zkey  <name>.zkey        # demo: single contribution
zkey export verificationkey <name>.zkey  vk_<name>.json
```

**TODO (production):** replace the single `zkey contribute` with multiple
independent contributions (and/or a public-randomness beacon), then verify the
transcript.

---

## Layout

```
setup/
├── README.md            this file
├── .gitkeep
└── build/               generated; gitignored (see below)
    ├── ptau/            potNN_*.ptau                (SECRET-ish, demo-only)
    ├── shield/
    │   ├── shield.zkey                              (SECRET, demo-only)
    │   └── vk_shield.json                           (PUBLIC)
    ├── transfer/  …  transfer.zkey,  vk_transfer.json
    ├── unshield/  …  unshield.zkey,  vk_unshield.json
    └── dvp/       …  dvp.zkey,       vk_dvp.json
```

## What is and isn't committed

The repository `.gitignore` already enforces this:

- **Ignored (never commit):** `*.ptau`, `*.zkey`, and the whole `setup/build/`
  tree. These are sensitive (invariant #10) and/or large.
- **Kept (safe to commit):** the public verifying keys `vk_*.json` (the
  `.gitignore` has an explicit allow for `vk_*.json` / `verification_key.json`).
  The VK is public by design — it is embedded in the on-chain verifier.

If you ever need to share a `.zkey`, treat it as you would a secret: it is the
proving key, and (for a single-party setup) its provenance is not trustworthy.
