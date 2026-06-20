# Railway ceremony runner (FIN-015 / FIN-007 production note).
#
# A one-off, RAM-heavy job image for the Groth16 trusted setup over BLS12-381.
# It installs circom (R1CS compile) + snarkjs (Powers of Tau + per-circuit
# phase-2) and then idles, so we `railway ssh` in and drive the ceremony manually
# and exfiltrate the artifacts (vk_*.json + .zkey) before tearing the service down.
#
# Used ONLY by a dedicated `ceremony` service via RAILWAY_DOCKERFILE_PATH; the main
# `finnes` service keeps its RailPack build (this file is not the root Dockerfile).
#
# IMPORTANT (memory): the 2^20 BLS12-381 `prepare phase2` step is heavy — set the
# ceremony service to ~32GB in the Railway dashboard before running the heavy step,
# and pass NODE_OPTIONS=--max-old-space-size=30000 (done in the run command).
#
# DEMO-ONLY ceremony (single-party); the .zkey is NOT production-secure (invariant
# #10). Fine for a real testnet proof; never for mainnet funds.

FROM node:20-bookworm

# circom 2.x prebuilt linux x86_64 binary (Railway runs amd64) + snarkjs global.
# circom 2.1.9 is backward-compatible with the repo's `pragma circom 2.1.6`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates time \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://github.com/iden3/circom/releases/download/v2.1.9/circom-linux-amd64 \
      -o /usr/local/bin/circom \
 && chmod +x /usr/local/bin/circom \
 && npm install -g snarkjs@0.7.5

WORKDIR /app
COPY . .

# `npm run circuits:build` / `setup:ceremony` only shell out to circom/snarkjs on
# PATH, so no `npm install` is needed for the ceremony itself.

# Keep the container alive: this is a manual one-off job, driven over `railway ssh`.
CMD ["sleep", "infinity"]
