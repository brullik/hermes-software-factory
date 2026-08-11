#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-all-clean-canaries.sh must run as root\n' >&2
  exit 1
fi

INDEX=/etc/hermes-factory/canaries/index.json
VERIFIER_PYTHON=/opt/hermes-factory-verifier/venv/bin/python
QUALIFICATION_CONFIG=/etc/hermes-factory/qualification-control.yaml

if [[ ! -f "${INDEX}" || ! -x "${VERIFIER_PYTHON}" ]]; then
  printf 'clean canary index or verifier runtime is unavailable\n' >&2
  exit 66
fi

systemctl disable --now \
  hermes-factory-shadow-verify.timer \
  hermes-factory-shadow-finalize.timer >/dev/null 2>&1 || true

mapfile -t SCENARIOS < <("${VERIFIER_PYTHON}" -c \
  'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); print("\n".join(item["scenario_id"] for item in value["scenarios"]))' \
  "${INDEX}")
if (( ${#SCENARIOS[@]} != 10 )); then
  printf 'clean canary index does not contain exactly ten scenarios\n' >&2
  exit 65
fi

for scenario_id in "${SCENARIOS[@]}"; do
  if [[ ! "${scenario_id}" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
    printf 'clean canary index contains an unsafe scenario id\n' >&2
    exit 65
  fi
  STATUS_JSON="$(runuser -u hermesverifier -- \
    "${VERIFIER_PYTHON}" -m scripts.qualification_control \
    --config "${QUALIFICATION_CONFIG}" status)"
  EXISTING_STATUS="$(printf '%s' "${STATUS_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; value=json.load(sys.stdin); wanted=sys.argv[1]; print(next((item["status"] for item in value["clean_canaries"] if item["scenario_id"] == wanted), "MISSING"))' \
    "${scenario_id}")"
  if [[ "${EXISTING_STATUS}" == PASS ]]; then
    continue
  fi
  if [[ "${EXISTING_STATUS}" != MISSING ]]; then
    printf 'clean canary is not safely restartable: %s=%s\n' \
      "${scenario_id}" "${EXISTING_STATUS}" >&2
    exit 1
  fi
  systemctl start --wait "hermes-factory-clean-canary@${scenario_id}.service"
done

FIRST_CONFIG="$("${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["scenarios"][0]["config_path"])' \
  "${INDEX}")"
readarray -t Q8_IDENTITY < <("${VERIFIER_PYTHON}" -c \
  'import sys,yaml; v=yaml.safe_load(open(sys.argv[1],encoding="utf-8")); q=v["qualification"]; print(q["epoch_id"]); print(q["run_id"])' \
  "${FIRST_CONFIG}")
EPOCH_ID="${Q8_IDENTITY[0]}"
RUN_ID="${Q8_IDENTITY[1]}"
RUN_ROOT="/var/lib/hermes-factory-canaries/${EPOCH_ID}/${RUN_ID}"
GC_JSON="$("${VERIFIER_PYTHON}" -m scripts.pre_q8_repository_gc cleanup \
  --ledger "${RUN_ROOT}/repository-ledger.json" \
  --token-file /etc/hermes-factory/candidate-credentials.d/github-token \
  --output "${RUN_ROOT}/repository-cleanup-summary.json" --run-inactive)"
repository_residue="$(printf '%s' "${GC_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["repository_residue_count"])')"
cleanup_failed="$(printf '%s' "${GC_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["cleanup_failed_count"])')"
if [[ "${repository_residue}" != 0 || "${cleanup_failed}" != 0 ]]; then
  printf 'Q8 repository residue is nonzero\n' >&2
  exit 70
fi

FINAL_STATUS="$(runuser -u hermesverifier -- \
  "${VERIFIER_PYTHON}" -m scripts.qualification_control \
  --config "${QUALIFICATION_CONFIG}" status | \
  "${VERIFIER_PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
if [[ "${FINAL_STATUS}" != PROMOTION_READY ]]; then
  printf 'clean canary sequence did not reach PROMOTION_READY\n' >&2
  exit 1
fi
