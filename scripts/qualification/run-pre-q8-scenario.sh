#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-pre-q8-scenario.sh must run as root\n' >&2
  exit 1
fi

SCENARIO_ID="${1:-}"
if [[ ! "${SCENARIO_ID}" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
  printf 'PRE-Q8 scenario id is invalid\n' >&2
  exit 64
fi

CANDIDATE_PYTHON=/opt/hermes-factory-candidate/venv/bin/python
VERIFIER_PYTHON=/opt/hermes-factory-verifier/venv/bin/python
CANDIDATE_CONFIG="/etc/hermes-factory/pre-q8/${SCENARIO_ID}.yaml"
CANDIDATE_DATABASE="$("${VERIFIER_PYTHON}" -c \
  'import sys,yaml; value=yaml.safe_load(open(sys.argv[1],encoding="utf-8")); print(value["controller"]["database_url"].removeprefix("sqlite:///"))' \
  "${CANDIDATE_CONFIG}")"
TIMEOUT_SECONDS="${PRE_Q8_TIMEOUT_SECONDS:-172800}"
PRODUCT_ID=""

cleanup() {
  exit_status=$?
  set +e
  systemctl stop "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" >/dev/null 2>&1 || true
  systemctl stop "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service" >/dev/null 2>&1 || true
  exit "${exit_status}"
}
trap cleanup EXIT

if [[ -e "${CANDIDATE_DATABASE}" ]]; then
  printf 'PRE-Q8 refuses a non-fresh database: %s\n' "${SCENARIO_ID}" >&2
  exit 73
fi

runuser -u hermescandidate -- "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
  --config "${CANDIDATE_CONFIG}" prepare
systemctl start "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service"
SUBMIT_JSON="$(runuser -u hermescandidate -- "${CANDIDATE_PYTHON}" \
  -m scripts.canary_candidate --config "${CANDIDATE_CONFIG}" submit)"
PRODUCT_ID="$(printf '%s' "${SUBMIT_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["product_id"])')"
systemctl start "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service"

STARTED_AT="$(date +%s)"
while true; do
  TRUTH_JSON="$(runuser -u hermesverifier -- "${VERIFIER_PYTHON}" \
    -m scripts.candidate_truth "${CANDIDATE_DATABASE}" --worker-idle)"
  SCENARIO_STATUS="$(printf '%s' "${TRUTH_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["scenario_status"])')"
  PRODUCT_STATUS="$(printf '%s' "${TRUTH_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["product_status"])')"
  case "${SCENARIO_STATUS}" in
    PASS) break ;;
    VERIFY_FAILED)
      if [[ "${PRODUCT_STATUS}" == COMPLETED ]]; then break; fi
      printf 'PRE-Q8 completion verification failed before terminal state\n' >&2
      exit 1
      ;;
    TERMINAL_FAILURE|LIVENESS_FINDING)
      printf 'PRE-Q8 authoritative terminal state: %s=%s\n' "${SCENARIO_ID}" "${SCENARIO_STATUS}" >&2
      exit 1
      ;;
    WAITING_CAPABILITY|RUNNING) ;;
    *) printf 'PRE-Q8 unknown aggregate state: %s\n' "${SCENARIO_STATUS}" >&2; exit 1 ;;
  esac
  NOW="$(date +%s)"
  if (( NOW - STARTED_AT >= TIMEOUT_SECONDS )); then
    printf 'PRE-Q8 timed out: %s\n' "${SCENARIO_ID}" >&2
    exit 124
  fi
  sleep 15
done

runuser -u hermesverifier -- "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
  pre-q8-pass "${SCENARIO_ID}" "${PRODUCT_ID}" "${CANDIDATE_CONFIG}"
