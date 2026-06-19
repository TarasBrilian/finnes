#!/usr/bin/env bash
#
# setup-shield-ceremony.sh — shield-ONLY Groth16 setup (BLS12-381) at 2^18.
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                            !!!  DEMO ONLY  !!!                            ║
# ║  Single-party, local "ceremony". The .zkey is NOT secure (invariant #10).║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Why a shield-only variant: `npm run setup:ceremony` sizes Powers of Tau for the
# heaviest circuit (transfer/dvp at D=20, ~295k constraints → 2^20), whose
# `prepare phase2` step can exceed a 16GB laptop. The PRODUCTION shield circuit
# (`circuits/shield.circom`, D=20) has only ~99k constraints, so snarkjs's
# `2^power >= 2*nConstraints` rule is satisfied by 2^18 (2*99k = 198k <= 262144).
# This script therefore produces the REAL production-depth `vk_shield.json`
# WITHOUT being blocked by transfer's 2^20 requirement.
#
# It REUSES an existing prepared 2^18 ptau if present (the depth-4 demo ceremony's
# `setup/build/ptau_demo/p_f.ptau` qualifies), so Phase 1 is usually skipped
# entirely. Otherwise it runs a fresh 2^18 Phase 1 (far lighter than 2^20).
#
# Produces (gitignored .zkey, committable VK):
#   setup/build/shield/{shield.zkey, vk_shield.json}
#
# Wired to: npm run setup:shield
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PTAU_POWER="${PTAU_POWER:-18}"
CIRCUITS_DIR="circuits"
LIB_DIR="${CIRCUITS_DIR}/lib"
R1CS="circuits/build/shield/shield.r1cs"
OD="setup/build/shield"
PTAU_DIR="setup/build/ptau"
# Candidate prepared ptau files we can reuse, in priority order.
PTAU_OWN="${PTAU_DIR}/pot${PTAU_POWER}_final.ptau"
PTAU_DEMO="setup/build/ptau_demo/p_f.ptau"

cat >&2 <<'BANNER'
================================================================================
  WARNING: DEMO-ONLY SHIELD-ONLY TRUSTED SETUP (not production-secure, inv #10)
  Single-party local setup of the PRODUCTION shield circuit (D=20) at 2^18.
  For the demo only. A real deployment needs a multi-party phase-2 ceremony.
================================================================================
BANNER

command -v circom  >/dev/null || { echo "ERROR: circom not found." >&2; exit 1; }
command -v snarkjs >/dev/null || { echo "ERROR: snarkjs not found." >&2; exit 1; }

rand_entropy() { command -v openssl >/dev/null && openssl rand -hex 32 || date +%s%N; }

# 0. Compile the production shield circuit (D=20) if its R1CS is missing.
if [[ ! -f "${R1CS}" ]]; then
  echo "==> Compiling circuits/shield.circom (BLS12-381, D=20)"
  mkdir -p circuits/build/shield
  circom "${CIRCUITS_DIR}/shield.circom" \
    --prime bls12381 --r1cs --wasm --sym \
    -l "${LIB_DIR}" -o circuits/build/shield
fi

# Sanity: shield must fit the chosen ptau (2^power >= 2*nConstraints). snarkjs
# prints ANSI-coloured output, so strip escape codes (perl, portable on macOS)
# before pulling the integer. Best-effort: skip the check if it can't be parsed.
NC="$(snarkjs r1cs info "${R1CS}" 2>/dev/null \
  | perl -pe 's/\e\[[0-9;]*m//g' \
  | awk -F'Constraints:' '/# of Constraints/ {gsub(/[^0-9]/,"",$2); print $2; exit}')"
HAVE=$(( 1 << PTAU_POWER ))
if [[ "${NC}" =~ ^[0-9]+$ ]]; then
  NEED=$(( 2 * NC ))
  echo "==> shield has ${NC} constraints; need 2^power >= ${NEED}; 2^${PTAU_POWER} = ${HAVE}"
  if (( HAVE < NEED )); then
    echo "ERROR: 2^${PTAU_POWER} (${HAVE}) < 2*constraints (${NEED}). Raise PTAU_POWER." >&2
    exit 1
  fi
else
  echo "==> WARN: could not parse shield constraint count; skipping the 2^${PTAU_POWER} fit check." >&2
fi

mkdir -p "${OD}" "${PTAU_DIR}"

# 1. Phase 1 — reuse a prepared 2^18 ptau if we have one; else run a fresh one.
PTAU_FINAL=""
if [[ -f "${PTAU_OWN}" ]]; then
  PTAU_FINAL="${PTAU_OWN}"
  echo "==> Phase 1: reusing ${PTAU_FINAL}"
elif [[ -f "${PTAU_DEMO}" ]]; then
  PTAU_FINAL="${PTAU_DEMO}"
  echo "==> Phase 1: reusing the depth-4 demo ptau ${PTAU_FINAL} (2^${PTAU_POWER})"
else
  echo "==> Phase 1: fresh powers of tau over BLS12-381 (2^${PTAU_POWER})"
  snarkjs powersoftau new bls12381 "${PTAU_POWER}" "${PTAU_DIR}/pot${PTAU_POWER}_0000.ptau" -v
  snarkjs powersoftau contribute "${PTAU_DIR}/pot${PTAU_POWER}_0000.ptau" \
    "${PTAU_DIR}/pot${PTAU_POWER}_0001.ptau" --name=finnes-shield-phase1 -e="$(rand_entropy)" -v
  snarkjs powersoftau prepare phase2 "${PTAU_DIR}/pot${PTAU_POWER}_0001.ptau" "${PTAU_OWN}" -v
  PTAU_FINAL="${PTAU_OWN}"
fi

# 2. Phase 2 — per-circuit Groth16 setup for shield + export the PUBLIC VK.
echo "==> Phase 2: groth16 setup + contribute + export VK (shield)"
snarkjs groth16 setup "${R1CS}" "${PTAU_FINAL}" "${OD}/shield_0000.zkey"
snarkjs zkey contribute "${OD}/shield_0000.zkey" "${OD}/shield.zkey" \
  --name=finnes-demo-shield-phase2 -e="$(rand_entropy)" -v
snarkjs zkey export verificationkey "${OD}/shield.zkey" "${OD}/vk_shield.json"

echo
echo "Done. Shield artifacts (D=20, production depth):"
echo "  ${OD}/shield.zkey       (SECRET — gitignored, demo-only)"
echo "  ${OD}/vk_shield.json    (PUBLIC verifying key)"
echo "Reminder: DEMO-ONLY single-party setup, not production-secure (invariant #10)."
