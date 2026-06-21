# @finnes/frontend

The institution- and regulator-facing web UI for **Finnes**, a confidential
settlement layer for regulated RWA on Stellar/Soroban (see the repo
[`README.md`](../README.md) and [`ARCHITECTURE.md`](../ARCHITECTURE.md)).

Next.js (App Router) + React + TypeScript + Tailwind.

> **Status: SCAFFOLD.** The UI is real and demo-credible, but the cryptographic
> layer is not wired. `@finnes/sdk` and `@finnes/prover` ship TODO stubs that
> throw, and the Soroban contract calls are placeholders. Everything not backed
> by real wiring is **clearly labelled MOCK** in the UI, and no operation ever
> fakes success, operations report `TODO · not wired` per step.

---

## Trust boundary (read this)

The frontend, **together with the prover, is the only place private keys exist**
(the client/institution trust zone). This is fund- and privacy-critical
(CLAUDE.md **invariant #8**):

The shielded **spending key**, **viewing key**, the **witness**,
  `owner_sk` / `rho` / `r_note`, note plaintext, and the **auditor view key**
  MUST NEVER be logged, persisted to a shared service, or transmitted to the
  backend (indexer / API / relayer) or any third party.
The **prover runs client-side** (browser WASM or a self-hosted node inside the
  institution's zone), never a shared multi-tenant service.
The frontend may fetch **public** data from the API (Merkle paths, roots,
  ciphertext blobs) and submits **only** public data on-chain (proof, public
  inputs, ciphertexts).
Key material lives in an **in-memory** store ([`lib/keys.ts`](./lib/keys.ts)).
  A `localStorage` path exists only as a documented, **disabled-by-default**
  demo caveat, it is not acceptable for production.

A visible trust-boundary banner is always on screen
([`components/TrustBoundaryBanner.tsx`](./components/TrustBoundaryBanner.tsx)).

---

## Run

> Dependencies may be absent and the sibling packages are scaffolds, `dev` /
> `build` are not expected to fully work yet.

```bash
# from repo root, with workspaces wired up
npm install
cd frontend
npm run dev        # http://localhost:3000
```

`next.config.mjs` uses `transpilePackages` for `@finnes/sdk` / `@finnes/prover`
so their TypeScript source can be imported directly during the scaffold phase.

---

## Routes & components

| Route            | View                                                         |
|------------------|--------------------------------------------------------------|
| `/`              | Landing + role switcher (Institution / Regulator)            |
| `/institution`   | Wallet, shielded key, balances, compliance, shield/transfer/unshield |
| `/regulator`     | Auditor view key, public tx list, selective-disclosure decrypt |

**Components** (`components/`):

`TrustBoundaryBanner`, always-on security note.
`RoleSwitcher`. Institution ↔ Regulator.
`WalletConnect`. Freighter (transparent side only).
`KeyManager`, generate/hold the shielded spending+viewing key (in-memory).
`ConfidentialBalances`, scan-discovered owned notes (mock until SDK wired).
`ComplianceStatus`. KYC / sanctions / per-asset limit.
`TransferForm`, confidential transfer A → B.
`ShieldUnshieldForm`, shield (transparent → note) / unshield (note → transparent).
`OpResultPanel`, honest per-step status (build → encrypt → witness → prove → submit).
`AuditorKeyInput`, load/hold the auditor view key (read authority).
`TxList`, the opaque public view of on-chain transactions.
`DisclosurePanel`, decrypt the auditor ciphertext → full transaction (the demo climax).
`MockBadge` / `NotWiredBadge`, unmissable mock/TODO labels.

**Lib** (`lib/`):

`keys.ts`, local key generation + in-memory store (never persisted to a server).
`use-keys.ts`, reactive hooks over the key store.
`finnes-client.ts`, thin wrapper over `@finnes/sdk` + `@finnes/prover` and
  placeholder contract invocations; builds intents, would assemble witnesses,
  call the prover, and submit only public data.

---

## TODO, what a human must finish

Every place below needs real `sdk` / `prover` / `contract` wiring. Search the
code for `TODO(`.

### Crypto / SDK (`@finnes/sdk` is stubbed and throws)
[ ] **Key generation** (`lib/keys.ts`): uniform field sampling from `[0, r)`
      via a CSPRNG; real `owner_pk = Poseidon(owner_sk)` derivation (currently
      falls back to a mock with `isMock: true`).
[ ] **Confidential balances** (`lib/finnes-client.ts` → `scanConfidentialBalances`):
      call `scanForOwnedNotes` / `tryDecryptNote` once the encryption scheme is
      fixed (`sdk/src/scan.ts`, `encrypt.ts` throw). Remove the mock balances.
[ ] **Note encryption** (shield/transfer/unshield): `encryptToAuditor`
      (mandatory, invariant #5) + `encryptToRecipient` once the hybrid
      value-equality scheme + field packing land.
[ ] **Asset binding**: `deriveAssetId` / `sacAddressToField` (the SAC-address
      → `Fr` encoding is undefined in the SDK).
[ ] **Auditor decryption** (`decryptAuditorView`): derive the decryption key
      from `auditor.sk` and decrypt `cAuditor`. Remove the mock plaintext.

### Prover (`@finnes/prover`, witness assembly + proving)
[ ] **Witness assembly**: `assembleShieldWitness` / `assembleTransferWitness` /
      `assembleUnshieldWitness` once circuit signal names + frontier/ciphertext
      packing are finalised.
[ ] **Proving in the browser**: load the BLS12-381 `.wasm` / `.zkey` artifacts
      from `circuits:build` + `setup:ceremony`; configure webpack fallbacks in
      `next.config.mjs` for snarkjs. The witness must never leave the tab.

### Contract (Soroban)
[ ] **Submission** (`finnes-client.ts` → `submitToContract`): build the Soroban
      operation invoking `shield` / `confidential_transfer` / `settle_dvp` /
      `unshield` with proof + public inputs + ciphertexts; sign via Freighter
      (transparent legs) or submit via the relayer fee-bump; await the result.
[ ] **Public inputs**: wire the real `buildShield/Transfer/UnshieldPublicInputs`
      calls with actual nullifiers, commitments, frontier, and ciphertext fields.

### Backend (public-data reads)
[ ] **State roots** (`fetchStateRoots`), **auditor pk** (`fetchAuditorPublicKey`),
      **compliance** (`fetchComplianceState`), and **tx list**
      (`listOnChainTransactions`): wire to the indexer/API. Remove mocks.

### Wallet
[ ] **Freighter API** (`WalletConnect`): pin to the installed `@stellar/freighter-api`
      version; the `requestAccess` / `getAddress` / `getNetwork` shape varies.

### Security (do not skip)
[ ] Keep all the above strictly client-side. Never add a code path that sends
      a key, witness, or note plaintext to a backend or logs it (invariant #8).
[ ] `localStorage` persistence in `lib/keys.ts` is disabled by default and must
      stay opt-in + clearly warned if ever enabled for the demo. Never persist
      the `auditor_sk`.

### Not in this scaffold
[ ] **DvP** (atomic two-asset settlement) UI, stretch goal.
[ ] **Clawback / freeze** UI (two-phase, two-key: auditor + issuer).
