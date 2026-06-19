#!/usr/bin/env bash
#
# setup-demo-ceremony.sh — lightweight, fully-runnable BLS12-381 Groth16 setup for
# the DEPTH-4 transfer harness (`transfer_test4`). Companion to FIN-007/FIN-008.
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                            !!!  DEMO ONLY  !!!                            ║
# ║  Single-party, local "ceremony". The .zkey is NOT secure (invariant #10).║
# ║  This is also a DEPTH-4 instance of the transfer circuit (same gadgets &  ║
# ║  public-IO STRUCTURE as production, only the tree depth differs), used to ║
# ║  exercise witness -> setup -> prove -> verify on a laptop. The production ║
# ║  D=20 ceremony is `npm run setup:ceremony` (PTAU_POWER=20; far heavier).  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# snarkjs requires 2^PTAU_POWER >= 2 * nConstraints. transfer_test4 has ~115k
# constraints, so 2*115k = 230k needs 2^18 = 262144.
#
# Produces (gitignored build artifacts):
#   circuits/build/transfer_test4/transfer_test4_js/transfer_test4.wasm
#   setup/build/transfer_test4/{transfer_test4.zkey, vk_transfer_test4.json}
#
# Then: `npm run transfer:prove` proves + verifies against these.
# Wired to: npm run setup:demo
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PTAU_POWER="${PTAU_POWER:-18}"
PD="setup/build/ptau_demo"
OD="setup/build/transfer_test4"
R1CS="circuits/build/transfer_test4/transfer_test4.r1cs"
HARNESS="circuits/test/transfer/transfer_test4.circom"

cat >&2 <<'BANNER'
================================================================================
  WARNING: DEMO-ONLY DEPTH-4 TRUSTED SETUP (not production-secure, invariant #10)
  A single-party local setup of a depth-4 transfer instance. For the pipeline
  demo only. Production = `npm run setup:ceremony` (D=20, PTAU_POWER=20).
================================================================================
BANNER

command -v circom  >/dev/null || { echo "ERROR: circom not found." >&2; exit 1; }
command -v snarkjs >/dev/null || { echo "ERROR: snarkjs not found." >&2; exit 1; }

rand_entropy() { command -v openssl >/dev/null && openssl rand -hex 32 || date +%s%N; }

# 0. Compile the depth-4 harness if needed.
if [[ ! -f "${R1CS}" ]]; then
  echo "==> Compiling ${HARNESS} (BLS12-381, depth 4)"
  mkdir -p circuits/build/transfer_test4
  circom "${HARNESS}" --r1cs --wasm --prime bls12381 -o circuits/build/transfer_test4 -l circuits/lib
fi

mkdir -p "${PD}" "${OD}"

# 1-3. Phase 1 (Powers of Tau, BLS12-381). Reuse a prepared ptau if present.
if [[ ! -f "${PD}/p_f.ptau" ]]; then
  echo "==> Phase 1: powers of tau over BLS12-381 (2^${PTAU_POWER})"
  snarkjs powersoftau new bls12381 "${PTAU_POWER}" "${PD}/p_0.ptau" -v
  snarkjs powersoftau contribute "${PD}/p_0.ptau" "${PD}/p_1.ptau" --name=finnes-demo -e="$(rand_entropy)" -v
  snarkjs powersoftau prepare phase2 "${PD}/p_1.ptau" "${PD}/p_f.ptau" -v
else
  echo "==> Phase 1: reusing ${PD}/p_f.ptau"
fi

# 4-6. Phase 2 (per-circuit Groth16 setup) + export VK.
echo "==> Phase 2: groth16 setup + contribute + export VK"
snarkjs groth16 setup "${R1CS}" "${PD}/p_f.ptau" "${OD}/transfer_test4_0000.zkey"
snarkjs zkey contribute "${OD}/transfer_test4_0000.zkey" "${OD}/transfer_test4.zkey" \
  --name=finnes-demo-phase2 -e="$(rand_entropy)" -v
snarkjs zkey export verificationkey "${OD}/transfer_test4.zkey" "${OD}/vk_transfer_test4.json"

echo
echo "Done. Demo artifacts:"
echo "  ${OD}/transfer_test4.zkey            (SECRET — gitignored, demo-only)"
echo "  ${OD}/vk_transfer_test4.json         (PUBLIC verifying key)"
echo "Next: npm run transfer:prove"
echo "Reminder: DEMO-ONLY, not production-secure (invariant #10)."
