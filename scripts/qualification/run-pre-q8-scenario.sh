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
SETPRIV=/usr/bin/setpriv
CANDIDATE_CONFIG="/etc/hermes-factory/pre-q8/${SCENARIO_ID}.yaml"
CANDIDATE_DATABASE="$("${VERIFIER_PYTHON}" -c \
  'import sys,yaml; value=yaml.safe_load(open(sys.argv[1],encoding="utf-8")); print(value["controller"]["database_url"].removeprefix("sqlite:///"))' \
  "${CANDIDATE_CONFIG}")"
TIMEOUT_SECONDS="${PRE_Q8_TIMEOUT_SECONDS:-172800}"
PRODUCT_ID=""
PHASE_ID="pre-q8:${SCENARIO_ID}"
INTERRUPTED=0
FAILURE_RECORDED=0

run_as_candidate() {
  "${SETPRIV}" --reuid=hermescandidate --regid=hermescandidate --init-groups \
    --no-new-privs -- /usr/bin/env HOME=/var/lib/hermes-factory-candidate \
    USER=hermescandidate LOGNAME=hermescandidate "$@"
}

run_as_verifier() {
  "${SETPRIV}" --reuid=hermesverifier --regid=hermesverifier --init-groups \
    --no-new-privs -- /usr/bin/env HOME=/var/lib/hermes-factory-verifier \
    USER=hermesverifier LOGNAME=hermesverifier "$@"
}

cleanup() {
  exit_status=$?
  set +e
  if (( exit_status != 0 && INTERRUPTED == 0 && FAILURE_RECORDED == 0 )); then
    run_as_verifier "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
      phase-fail "${PHASE_ID}" pre_q8_execution_failed >/dev/null 2>&1 || true
  fi
  systemctl stop "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" >/dev/null 2>&1 || true
  systemctl stop "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service" >/dev/null 2>&1 || true
  exit "${exit_status}"
}
trap 'INTERRUPTED=1; exit 75' INT TERM HUP
trap cleanup EXIT

fail_phase() {
  reason_code="$1"
  exit_code="$2"
  run_as_verifier "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
    phase-fail "${PHASE_ID}" "${reason_code}" >/dev/null
  FAILURE_RECORDED=1
  exit "${exit_code}"
}

PHASE_JSON="$(run_as_verifier "${VERIFIER_PYTHON}" \
  -m scripts.functional_qualification phase-start "${PHASE_ID}" "${TIMEOUT_SECONDS}")"
PHASE_STATUS="$(printf '%s' "${PHASE_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["status"])')"
DEADLINE_EPOCH="$(printf '%s' "${PHASE_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["deadline_epoch"])')"
if [[ "${PHASE_STATUS}" == PASS ]]; then
  exit 0
fi
if [[ "${PHASE_STATUS}" != RUNNING ]]; then
  FAILURE_RECORDED=1
  exit 1
fi
if (( $(date +%s) >= DEADLINE_EPOCH )); then
  printf 'PRE-Q8 durable deadline exhausted: %s\n' "${SCENARIO_ID}" >&2
  fail_phase pre_q8_timeout 124
fi

if [[ -e "${CANDIDATE_DATABASE}" ]]; then
  # A root-owned orchestration restart must continue the single durable first
  # attempt instead of converting an already-created Candidate database into a
  # new failure or deleting it.  canary_candidate status re-validates the
  # root-owned scenario digest and requires at most one product before exposing
  # its identity.  An EMPTY database is the bounded prepare-before-submit crash
  # window; submit is idempotent for the immutable scenario/candidate identity.
  STATUS_JSON="$(run_as_candidate "${CANDIDATE_PYTHON}" \
    -m scripts.canary_candidate --config "${CANDIDATE_CONFIG}" status)"
  PRODUCT_ID="$(printf '%s' "${STATUS_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; value=json.load(sys.stdin); print(value.get("product_id") or "")')"
  if [[ -z "${PRODUCT_ID}" ]]; then
    SUBMIT_JSON="$(run_as_candidate "${CANDIDATE_PYTHON}" \
      -m scripts.canary_candidate --config "${CANDIDATE_CONFIG}" submit)"
    PRODUCT_ID="$(printf '%s' "${SUBMIT_JSON}" | "${VERIFIER_PYTHON}" -c \
      'import json,sys; print(json.load(sys.stdin)["product_id"])')"
  fi
else
  run_as_candidate "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
    --config "${CANDIDATE_CONFIG}" prepare
  SUBMIT_JSON="$(run_as_candidate "${CANDIDATE_PYTHON}" \
    -m scripts.canary_candidate --config "${CANDIDATE_CONFIG}" submit)"
  PRODUCT_ID="$(printf '%s' "${SUBMIT_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["product_id"])')"
fi

if [[ -z "${PRODUCT_ID}" ]]; then
  printf 'PRE-Q8 durable product identity is unavailable: %s\n' "${SCENARIO_ID}" >&2
  exit 1
fi
systemctl start "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service"
systemctl start "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service"

while true; do
  TRUTH_JSON="$(run_as_verifier "${VERIFIER_PYTHON}" \
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
      fail_phase pre_q8_terminal_failure 1
      ;;
    WAITING_CAPABILITY|RUNNING) ;;
    *) printf 'PRE-Q8 unknown aggregate state: %s\n' "${SCENARIO_STATUS}" >&2; exit 1 ;;
  esac
  NOW="$(date +%s)"
  if (( NOW >= DEADLINE_EPOCH )); then
    printf 'PRE-Q8 timed out: %s\n' "${SCENARIO_ID}" >&2
    fail_phase pre_q8_timeout 124
  fi
  sleep 15
done

run_as_verifier "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
  pre-q8-pass "${SCENARIO_ID}" "${PRODUCT_ID}" "${CANDIDATE_CONFIG}"
