#!/usr/bin/env bash
#
# init.sh — post-deploy initialisation of the Finnes contract (FIN-015).
#
# Invokes `init` with the generated InitConfig (roots + auditor_pk + empty-tree
# seed + the D=20 verifying keys), then optionally registers the demo assets
# (asset_id -> SAC address) and transparent recipients (recipient field -> G addr)
# so shield/unshield can move real Stellar Asset Contract tokens (FIN-010).
#
# Prereqs (you provide):
#   - a deployed contract (scripts/deploy.sh writes setup/build/deploy.testnet.json,
#     or set CONTRACT_ID),
#   - STELLAR_SOURCE  : a configured `stellar keys` identity that signs (the admin),
#   - ADMIN_ADDRESS / ISSUER_ADDRESS : the read/write authority G-addresses,
#   - the D=20 VKs (setup/build/<c>/vk_<c>.json) + demo-state.json (npm run enroll:demo).
#
# Wired to: npm run init
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT_DIR}/setup/build"
DEPLOY_OUT="${BUILD}/deploy.testnet.json"
CFG_JSON="${BUILD}/init-config.json"

NETWORK="${STELLAR_NETWORK:-testnet}"
SOURCE_ACCOUNT="${STELLAR_SOURCE:-deployer}"

# --- resolve contract id ----------------------------------------------------
CONTRACT_ID="${CONTRACT_ID:-}"
if [[ -z "${CONTRACT_ID}" && -f "${DEPLOY_OUT}" ]]; then
  CONTRACT_ID="$(grep -oE '"contractId"[[:space:]]*:[[:space:]]*"[^"]+"' "${DEPLOY_OUT}" | sed -E 's/.*"([^"]+)"$/\1/')"
fi
if [[ -z "${CONTRACT_ID}" ]]; then
  echo "ERROR: no contract id. Run scripts/deploy.sh first or set CONTRACT_ID=<C...>." >&2
  exit 1
fi

# --- tool / config checks ---------------------------------------------------
command -v stellar >/dev/null 2>&1 || { echo "ERROR: 'stellar' CLI not found on PATH." >&2; exit 1; }

if [[ "${ADMIN_ADDRESS:-}" == "" || "${ISSUER_ADDRESS:-}" == "" ]]; then
  echo "ERROR: set ADMIN_ADDRESS and ISSUER_ADDRESS (the read/write authority G-addresses)." >&2
  exit 1
fi

# (Re)generate the init config with the real admin/issuer baked in.
echo "==> Generating init config (admin=${ADMIN_ADDRESS}, issuer=${ISSUER_ADDRESS})"
ADMIN_ADDRESS="${ADMIN_ADDRESS}" ISSUER_ADDRESS="${ISSUER_ADDRESS}" \
  ( cd "${ROOT_DIR}" && npm run --silent init:config )

[[ -f "${CFG_JSON}" ]] || { echo "ERROR: ${CFG_JSON} not generated." >&2; exit 1; }

echo "Network    : ${NETWORK}"
echo "Source     : ${SOURCE_ACCOUNT}"
echo "Contract   : ${CONTRACT_ID}"

# --- invoke init ------------------------------------------------------------
# The contract takes a single `cfg: InitConfig` struct; the stellar CLI converts
# the JSON object (Bytes fields as hex strings, Address as G-strkey, Vec as JSON
# arrays) to ScVal via the contract spec.
#
# NOTE (first run): if the CLI rejects the byte encoding, the bytes are correct
# (G1=96B, G2=192B, Fr=32B — the same encoding verifier.rs decodes and the FIN-009
# cargo tests pass) but the CLI's expected JSON wrapping may differ by version
# (hex vs 0x-hex vs base64). Adjust frToHex/g1ToHex output in scripts/lib/vk-host.ts
# accordingly, or switch to `stellar contract bindings typescript` for a typed client.
CFG="$(node -e "process.stdout.write(JSON.stringify(require('${CFG_JSON}').cfg))")"

echo "==> Invoking init"
stellar contract invoke \
  --id "${CONTRACT_ID}" \
  --source-account "${SOURCE_ACCOUNT}" \
  --network "${NETWORK}" \
  -- init --cfg "${CFG}"

echo "    init OK."

# --- register assets + transparent recipients (optional) --------------------
# shield/unshield resolve the concrete SAC / payout address from an admin registry
# (FIN-010). Provide the mapping as setup/build/asset-registry.json:
#   { "assets": [ {"asset_id":"<decimal>", "sac":"C..."} ],
#     "recipients": [ {"recipient":"<decimal>", "addr":"G..."} ] }
REG="${BUILD}/asset-registry.json"
if [[ -f "${REG}" ]]; then
  echo "==> Registering assets / transparent recipients from ${REG}"
  node -e "
    const r = require('${REG}');
    for (const a of (r.assets||[])) console.log('asset', a.asset_id, a.sac);
    for (const t of (r.recipients||[])) console.log('recip', t.recipient, t.addr);
  " | while read -r kind a b; do
    if [[ "${kind}" == "asset" ]]; then
      # asset_id (decimal) -> 32-byte hex for the Scalar arg.
      HEX="$(node -e "process.stdout.write(BigInt('${a}').toString(16).padStart(64,'0'))")"
      stellar contract invoke --id "${CONTRACT_ID}" --source-account "${SOURCE_ACCOUNT}" --network "${NETWORK}" \
        -- register_asset --asset_id "${HEX}" --sac "${b}"
    elif [[ "${kind}" == "recip" ]]; then
      HEX="$(node -e "process.stdout.write(BigInt('${a}').toString(16).padStart(64,'0'))")"
      stellar contract invoke --id "${CONTRACT_ID}" --source-account "${SOURCE_ACCOUNT}" --network "${NETWORK}" \
        -- register_transparent --recipient "${HEX}" --addr "${b}"
    fi
  done
  echo "    registry wired."
else
  echo "NOTE: no ${REG} — skipping register_asset/register_transparent."
  echo "      Create it (asset_id->SAC, recipient->G addr) so shield/unshield can move real tokens."
fi

echo
echo "Done. Contract ${CONTRACT_ID} initialised on ${NETWORK}."
