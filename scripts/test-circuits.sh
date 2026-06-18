#!/usr/bin/env bash
#
# test-circuits.sh — witness-level tests for every Finnes circuit.
#
# SCAFFOLD. Per CLAUDE.md ("Tests") and README "Testing": every circuit ships
# with BOTH a passing witness AND at least one FAILING witness (e.g. unbalanced
# values, bad Merkle path, missing auditor ciphertext) — proving each constraint
# actually constrains.
#
# Convention (TODO: finalise inputs under circuits/test/):
#   circuits/test/<name>/pass.json    -> witness generation MUST succeed
#   circuits/test/<name>/fail_*.json  -> witness generation MUST fail (>=1 file)
#
# Witness generation uses the compiled WASM at:
#   circuits/build/<name>/<name>_js/generate_witness.js
#
# Wired to: npm run circuits:test
set -euo pipefail

# --- paths ------------------------------------------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS_BUILD="${ROOT_DIR}/circuits/build"
TEST_DIR="${ROOT_DIR}/circuits/test"

CIRCUITS=(shield transfer unshield dvp)

# --- tool checks ------------------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: 'node' (>=20) not found on PATH." >&2
  exit 1
fi

# Generate a witness. Returns 0 on success, non-zero on a failed constraint.
# Args: <name> <input.json>
gen_witness() {
  local name="$1" input="$2"
  local wasm_dir="${CIRCUITS_BUILD}/${name}/${name}_js"
  local wasm="${wasm_dir}/${name}.wasm"
  local gen="${wasm_dir}/generate_witness.js"
  local out
  out="$(mktemp -t "finnes_${name}_XXXXXX.wtns")"

  if [[ ! -f "${gen}" || ! -f "${wasm}" ]]; then
    echo "MISSING_WASM"
    return 2
  fi

  # Witness file is intermediate only; never persist (witness.json is gitignored
  # per invariant #8 anyway). Suppress snarkjs/wasm chatter.
  if node "${gen}" "${wasm}" "${input}" "${out}" >/dev/null 2>&1; then
    rm -f "${out}"
    return 0
  else
    rm -f "${out}"
    return 1
  fi
}

# --- run --------------------------------------------------------------------
total_pass=0
total_fail=0
total_err=0
ran_any=0

for name in "${CIRCUITS[@]}"; do
  ctest="${TEST_DIR}/${name}"
  pass_input="${ctest}/pass.json"

  echo "==> ${name}"

  if [[ ! -d "${ctest}" ]]; then
    echo "    WARN: no test dir ${ctest} — skipping (add pass.json + fail_*.json)." >&2
    continue
  fi

  # ---- positive case: MUST succeed ----
  if [[ -f "${pass_input}" ]]; then
    ran_any=1
    set +e
    gen_witness "${name}" "${pass_input}"
    rc=$?
    set -e
    case "${rc}" in
      0) echo "    PASS: pass.json generated a witness"; total_pass=$((total_pass + 1)) ;;
      2) echo "    ERROR: ${name} not compiled — run 'npm run circuits:build'." >&2; total_err=$((total_err + 1)) ;;
      *) echo "    FAIL: pass.json should have produced a valid witness but did not" >&2; total_err=$((total_err + 1)) ;;
    esac
  else
    echo "    WARN: missing ${pass_input} (expected a passing witness)." >&2
  fi

  # ---- negative cases: each MUST fail ----
  shopt -s nullglob
  fail_inputs=("${ctest}"/fail_*.json)
  shopt -u nullglob

  if [[ "${#fail_inputs[@]}" -eq 0 ]]; then
    echo "    WARN: no fail_*.json for ${name} — every circuit needs >=1 failing witness (CLAUDE.md)." >&2
  fi

  for fin in "${fail_inputs[@]}"; do
    ran_any=1
    set +e
    gen_witness "${name}" "${fin}"
    rc=$?
    set -e
    case "${rc}" in
      0) echo "    FAIL: $(basename "${fin}") should have been REJECTED but a witness was produced" >&2; total_err=$((total_err + 1)) ;;
      2) echo "    ERROR: ${name} not compiled — run 'npm run circuits:build'." >&2; total_err=$((total_err + 1)) ;;
      *) echo "    PASS: $(basename "${fin}") correctly rejected"; total_fail=$((total_fail + 1)) ;;
    esac
  done
done

echo
echo "Summary: ${total_pass} passing-witness check(s), ${total_fail} rejection check(s), ${total_err} error(s)."

if [[ "${ran_any}" -eq 0 ]]; then
  echo "No circuit tests ran. Add fixtures under circuits/test/<name>/ and build circuits first." >&2
  # TODO: make this a hard failure once fixtures + circuits exist.
fi

if [[ "${total_err}" -gt 0 ]]; then
  exit 1
fi
