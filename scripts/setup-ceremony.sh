#!/usr/bin/env bash
#
# setup-ceremony.sh — Groth16 trusted setup for Finnes (BLS12-381).
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                            !!!  DEMO ONLY  !!!                            ║
# ║                                                                          ║
# ║  This script runs a SINGLE-PARTY, LOCAL "ceremony". The resulting .zkey  ║
# ║  files are NOT SECURE and MUST NOT be used in production.                ║
# ║                                                                          ║
# ║  CLAUDE.md invariant #10: never commit / ship a .zkey produced from an   ║
# ║  undocumented or single-party ceremony as production. A real deployment  ║
# ║  needs a multi-party phase-2 contribution ceremony where at least one    ║
# ║  honest participant destroys their toxic waste.                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Two phases (see setup/README.md):
#   Phase 1 — Powers of Tau, universal / circuit-independent, over BLS12-381.
#   Phase 2 — per-circuit, binds phase-1 to each circuit's R1CS, emits .zkey.
#
# Exports the PUBLIC verifying key vk_<name>.json (safe to commit) and keeps the
# secret .zkey / .ptau out of git (already gitignored).
#
# Wired to: npm run setup:ceremony
set -euo pipefail

# --- paths ------------------------------------------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS_BUILD="${ROOT_DIR}/circuits/build"
SETUP_DIR="${ROOT_DIR}/setup"
SETUP_BUILD="${SETUP_DIR}/build"
PTAU_DIR="${SETUP_BUILD}/ptau"

CIRCUITS=(shield transfer unshield dvp)

# Powers of Tau size: 2^PTAU_POWER constraints. TODO: confirm against the largest
# circuit's constraint count once circuits are finalised (transfer/dvp dominate;
# tree depth D=32 per docs/PUBLIC_IO.md drives this). 16 is a placeholder.
PTAU_POWER="${PTAU_POWER:-16}"

# --- loud demo-only banner --------------------------------------------------
cat >&2 <<'BANNER'
================================================================================
  WARNING: DEMO-ONLY TRUSTED SETUP

  This generates a single-party Groth16 setup on your local machine. The toxic
  waste is NOT destroyed by independent parties, so anyone who can reconstruct
  it can FORGE PROOFS. Do NOT use the resulting .zkey in production.

  Per CLAUDE.md invariant #10, a production setup requires a documented,
  multi-party phase-2 ceremony. See setup/README.md.
================================================================================
BANNER

# --- tool checks ------------------------------------------------------------
if ! command -v snarkjs >/dev/null 2>&1; then
  echo "ERROR: 'snarkjs' not found on PATH." >&2
  echo "  Install: npm i -g snarkjs   (https://github.com/iden3/snarkjs)" >&2
  exit 1
fi

# A source of entropy for contributions. Non-secret here precisely because this
# is demo-only; a real ceremony uses independent, secret per-party entropy.
rand_entropy() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    date +%s%N
  fi
}

mkdir -p "${PTAU_DIR}" "${SETUP_BUILD}"

# ============================================================================
# PHASE 1 — Powers of Tau (universal, BLS12-381)
# ============================================================================
PTAU_NEW="${PTAU_DIR}/pot${PTAU_POWER}_0000.ptau"
PTAU_CONTRIB="${PTAU_DIR}/pot${PTAU_POWER}_0001.ptau"
PTAU_FINAL="${PTAU_DIR}/pot${PTAU_POWER}_final.ptau"

if [[ -f "${PTAU_FINAL}" ]]; then
  echo "==> Phase 1: reusing existing ${PTAU_FINAL}"
else
  echo "==> Phase 1: powers of tau over BLS12-381 (2^${PTAU_POWER})"

  # IMPORTANT: '-v ... bls12381' selects the BLS12-381 curve. snarkjs defaults to
  # bn128 (BN254) — using the default here would violate invariant #1.
  # TODO: verify the exact snarkjs flag/curve name for your snarkjs version
  #       (recent versions accept 'bls12381'; some builds use 'bls12-381').
  snarkjs powersoftau new bls12381 "${PTAU_POWER}" "${PTAU_NEW}" -v

  echo "    contributing (demo entropy, NOT secret)"
  snarkjs powersoftau contribute "${PTAU_NEW}" "${PTAU_CONTRIB}" \
    --name="finnes-demo-phase1" -v -e="$(rand_entropy)"

  echo "    preparing phase 2"
  snarkjs powersoftau prepare phase2 "${PTAU_CONTRIB}" "${PTAU_FINAL}" -v
fi

# ============================================================================
# PHASE 2 — per-circuit Groth16 setup
# ============================================================================
made=0
skipped=0
for name in "${CIRCUITS[@]}"; do
  r1cs="${CIRCUITS_BUILD}/${name}/${name}.r1cs"
  out_dir="${SETUP_BUILD}/${name}"

  if [[ ! -f "${r1cs}" ]]; then
    echo "WARN: ${r1cs} not found — skipping '${name}'. Run 'npm run circuits:build' first." >&2
    skipped=$((skipped + 1))
    continue
  fi

  echo "==> Phase 2: ${name}"
  mkdir -p "${out_dir}"

  zkey_0000="${out_dir}/${name}_0000.zkey"
  zkey_final="${out_dir}/${name}.zkey"
  vk_json="${out_dir}/vk_${name}.json"

  # Initial zkey from the circuit R1CS + final ptau.
  snarkjs groth16 setup "${r1cs}" "${PTAU_FINAL}" "${zkey_0000}"

  # Single demo contribution. TODO (production): replace with multiple
  # independent contributions (snarkjs zkey contribute / beacon) by separate
  # parties, then verify the full transcript with `snarkjs zkey verify`.
  snarkjs zkey contribute "${zkey_0000}" "${zkey_final}" \
    --name="finnes-demo-${name}-phase2" -v -e="$(rand_entropy)"

  # Export the PUBLIC verifying key. This is the only artifact safe to commit;
  # it is what gets translated into the Soroban verifier (vk_<name>.json).
  snarkjs zkey export verificationkey "${zkey_final}" "${vk_json}"

  echo "    -> ${zkey_final}            (SECRET — gitignored, demo-only)"
  echo "    -> ${vk_json}   (PUBLIC — safe to commit)"
  made=$((made + 1))
done

echo
echo "Done. Phase-2 setup for ${made} circuit(s), skipped ${skipped}."
echo "Reminder: the .zkey files are DEMO-ONLY and not production-secure (invariant #10)."
