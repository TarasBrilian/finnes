#!/usr/bin/env bash
#
# build-circuits.sh — compile every Finnes circuit to R1CS + WASM witness gen.
#
# SCAFFOLD. Compiles each top-level circuit with the BLS12-381 prime
# (invariant #1: curve is BLS12-381, never BN254) into circuits/build/<name>/.
#
# Wired to: npm run circuits:build
#
# NOTE: the top-level circuits (shield/transfer/unshield/dvp .circom) are not all
# present yet — this script skips any missing circuit with a warning rather than
# failing the whole build, so it is useful incrementally during development.
set -euo pipefail

# --- paths ------------------------------------------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS_DIR="${ROOT_DIR}/circuits"
BUILD_DIR="${CIRCUITS_DIR}/build"
LIB_DIR="${CIRCUITS_DIR}/lib"

# Canonical circuit list (see docs/PUBLIC_IO.md). escrow_deposit/escrow_refund are
# the production escrow-DvP boundary circuits (FIN-017); settle reuses dvp.
CIRCUITS=(shield transfer unshield dvp escrow_deposit escrow_refund)

# --- tool checks ------------------------------------------------------------
if ! command -v circom >/dev/null 2>&1; then
  echo "ERROR: 'circom' not found on PATH." >&2
  echo "  Install Circom 2.x: https://docs.circom.io/getting-started/installation/" >&2
  exit 1
fi

# circom must support the bls12381 prime (Circom 2.x). Surface the version.
echo "Using $(circom --version 2>/dev/null || echo 'circom (version unknown)')"

# --- build ------------------------------------------------------------------
mkdir -p "${BUILD_DIR}"

built=0
skipped=0
for name in "${CIRCUITS[@]}"; do
  src="${CIRCUITS_DIR}/${name}.circom"
  out="${BUILD_DIR}/${name}"

  if [[ ! -f "${src}" ]]; then
    echo "WARN: ${src} not found — skipping '${name}' (circuit not implemented yet)." >&2
    skipped=$((skipped + 1))
    continue
  fi

  echo "==> Compiling ${name} (BLS12-381)"
  mkdir -p "${out}"

  # --prime bls12381 : invariant #1 (BLS12-381 scalar field, never BN254).
  # --r1cs --wasm --sym : constraint system, witness generator, symbol map.
  # -l "${LIB_DIR}" : resolve circuits/lib/*.circom includes.
  circom "${src}" \
    --prime bls12381 \
    --r1cs \
    --wasm \
    --sym \
    -l "${LIB_DIR}" \
    -o "${out}"

  echo "    -> ${out}/${name}.r1cs, ${out}/${name}_js/, ${out}/${name}.sym"
  built=$((built + 1))
done

echo
echo "Done. Built ${built} circuit(s), skipped ${skipped}."
if [[ "${built}" -eq 0 ]]; then
  echo "No circuits compiled. Implement circuits/<name>.circom first." >&2
  # TODO: make this a hard failure once all four top-level circuits exist.
fi
