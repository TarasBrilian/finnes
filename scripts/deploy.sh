#!/usr/bin/env bash
#
# deploy.sh — build and deploy the Finnes Soroban contract to Stellar Testnet.
#
# SCAFFOLD. Builds the WASM, deploys it, and captures the resulting contract id.
# Does NOT initialise contract state (kyc_root, auditor_pk, VKs, etc.) — that is
# a follow-up `stellar contract invoke ... initialize` once the constructor and
# vk_<name>.json layout are finalised (see TODO below).
#
# Wired to: npm run deploy
set -euo pipefail

# --- config -----------------------------------------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_DIR="${ROOT_DIR}/contracts/finnes"

NETWORK="${STELLAR_NETWORK:-testnet}"
# Identity/source account used to pay deploy fees. TODO: confirm this matches a
# configured `stellar keys` identity (e.g. `stellar keys generate deployer`).
SOURCE_ACCOUNT="${STELLAR_SOURCE:-deployer}"

# WASM output path (cargo target dir, release profile).
WASM_PATH="${CONTRACT_DIR}/target/wasm32-unknown-unknown/release/finnes.wasm"

# Where to record the deployed contract id for downstream tooling (demo, SDK).
DEPLOY_OUT="${ROOT_DIR}/setup/build/deploy.testnet.json"

# --- tool checks ------------------------------------------------------------
if ! command -v stellar >/dev/null 2>&1; then
  echo "ERROR: 'stellar' CLI not found on PATH." >&2
  echo "  Install: https://developers.stellar.org/docs/tools/developer-tools/cli/stellar-cli" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: 'cargo' (Rust toolchain) not found on PATH." >&2
  exit 1
fi
if [[ ! -d "${CONTRACT_DIR}" ]]; then
  echo "ERROR: contract dir ${CONTRACT_DIR} not found." >&2
  exit 1
fi

echo "Network : ${NETWORK}"
echo "Source  : ${SOURCE_ACCOUNT}"

# --- build ------------------------------------------------------------------
echo "==> Building contract WASM"
# Build from within the crate. `stellar contract build` wraps cargo and produces
# an optimised wasm32-unknown-unknown release artifact.
( cd "${CONTRACT_DIR}" && stellar contract build )

if [[ ! -f "${WASM_PATH}" ]]; then
  echo "ERROR: expected WASM not found at ${WASM_PATH}" >&2
  echo "  TODO: confirm the crate name / output path (finnes.wasm) once Cargo.toml is final." >&2
  exit 1
fi
echo "    -> ${WASM_PATH}"

# --- deploy -----------------------------------------------------------------
echo "==> Deploying to ${NETWORK}"
# Capture the contract id printed by the CLI. `stellar contract deploy` prints the
# contract id to stdout on success.
CONTRACT_ID="$(stellar contract deploy \
  --wasm "${WASM_PATH}" \
  --source-account "${SOURCE_ACCOUNT}" \
  --network "${NETWORK}")"

if [[ -z "${CONTRACT_ID}" ]]; then
  echo "ERROR: deploy did not return a contract id." >&2
  exit 1
fi

echo "    contract id: ${CONTRACT_ID}"

# --- record -----------------------------------------------------------------
mkdir -p "$(dirname "${DEPLOY_OUT}")"
cat > "${DEPLOY_OUT}" <<JSON
{
  "network": "${NETWORK}",
  "contractId": "${CONTRACT_ID}",
  "wasm": "${WASM_PATH}",
  "deployedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
echo "    recorded -> ${DEPLOY_OUT}"

echo
echo "Done. Deployed finnes to ${NETWORK} as ${CONTRACT_ID}"
echo "TODO: initialise contract state (auditor_pk, issuer_authority, kyc_root,"
echo "      sanction_root, assets_root, frozen_root, vk_shield/transfer/unshield/dvp)"
echo "      via 'stellar contract invoke ${CONTRACT_ID} -- initialize ...'."
