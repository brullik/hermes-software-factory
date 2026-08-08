#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-clean-canary.sh must run as root\n' >&2
  exit 1
fi

SCENARIO_ID="${1:-}"
if [[ ! "${SCENARIO_ID}" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
  printf 'clean canary scenario id is invalid\n' >&2
  exit 64
fi

CANDIDATE_PYTHON=/opt/hermes-factory-candidate/venv/bin/python
VERIFIER_PYTHON=/opt/hermes-factory-verifier/venv/bin/python
CANDIDATE_CONFIG="/etc/hermes-factory/canaries/${SCENARIO_ID}.yaml"
QUALIFICATION_CONFIG=/etc/hermes-factory/qualification-control.yaml
CANARY_DATABASE="/var/lib/hermes-factory-canaries/${SCENARIO_ID}/controller.db"
TIMEOUT_SECONDS="${CLEAN_CANARY_TIMEOUT_SECONDS:-172800}"
CANARY_ID=""
PRODUCT_ID=""
PRODUCT_STATUS="EMPTY"
STARTED_AT=0
FAILURE_REASON=orchestrator_error
INTERRUPTED=0

if [[ ! -x "${CANDIDATE_PYTHON}" || ! -x "${VERIFIER_PYTHON}" ]]; then
  printf 'candidate or verifier runtime is unavailable\n' >&2
  exit 69
fi
if [[ ! -f "${CANDIDATE_CONFIG}" ]]; then
  printf 'root-owned clean canary config is unavailable\n' >&2
  exit 66
fi
if [[ ! "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || (( TIMEOUT_SECONDS < 900 )); then
  printf 'clean canary timeout is invalid\n' >&2
  exit 64
fi

cleanup() {
  exit_status=$?
  set +e
  systemctl stop "hermes-factory-canary-worker@${SCENARIO_ID}.service" >/dev/null 2>&1 || true
  systemctl stop "hermes-factory-canary-controller@${SCENARIO_ID}.service" >/dev/null 2>&1 || true
  if (( exit_status != 0 && INTERRUPTED == 0 )) && [[ -n "${CANARY_ID}" ]]; then
    runuser -u hermesverifier -- \
      "${VERIFIER_PYTHON}" -m scripts.qualification_control \
      --config "${QUALIFICATION_CONFIG}" canary-fail \
      "${CANARY_ID}" "${FAILURE_REASON}" >/dev/null 2>&1 || true
  fi
  exit "${exit_status}"
}
trap cleanup EXIT
trap 'INTERRUPTED=1; exit 75' HUP INT TERM

if [[ ! -e "${CANARY_DATABASE}" ]]; then
  runuser -u hermescandidate -- \
    "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
    --config "${CANDIDATE_CONFIG}" prepare
fi

QUALIFICATION_JSON="$(runuser -u hermesverifier -- \
  "${VERIFIER_PYTHON}" -m scripts.qualification_control \
  --config "${QUALIFICATION_CONFIG}" status)"
CANARY_COUNT="$(printf '%s' "${QUALIFICATION_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; value=json.load(sys.stdin); scenario=sys.argv[1]; print(sum(item["scenario_id"] == scenario for item in value["clean_canaries"]))' \
  "${SCENARIO_ID}")"
if [[ "${CANARY_COUNT}" == 0 ]]; then
  PRESTART_JSON="$(runuser -u hermescandidate -- \
    "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
    --config "${CANDIDATE_CONFIG}" status)"
  PRESTART_STATUS="$(printf '%s' "${PRESTART_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["product_status"])')"
  if [[ "${PRESTART_STATUS}" != EMPTY ]]; then
    printf 'clean canary lacks governor identity for non-empty state\n' >&2
    exit 1
  fi
  START_JSON="$(runuser -u hermesverifier -- \
    "${VERIFIER_PYTHON}" -m scripts.qualification_control \
    --config "${QUALIFICATION_CONFIG}" canary-start "${SCENARIO_ID}" \
    --candidate-database "${CANARY_DATABASE}")"
  CANARY_ID="$(printf '%s' "${START_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["canary_id"])')"
  QUALIFICATION_JSON="$(runuser -u hermesverifier -- \
    "${VERIFIER_PYTHON}" -m scripts.qualification_control \
    --config "${QUALIFICATION_CONFIG}" status)"
elif [[ "${CANARY_COUNT}" != 1 ]]; then
  printf 'clean canary governor identity is ambiguous\n' >&2
  exit 1
fi
CANARY_JSON="$(printf '%s' "${QUALIFICATION_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; value=json.load(sys.stdin); scenario=sys.argv[1]; matches=[item for item in value["clean_canaries"] if item["scenario_id"] == scenario]; assert len(matches) == 1 and matches[0]["status"] == "RUNNING"; print(json.dumps(matches[0],sort_keys=True))' \
  "${SCENARIO_ID}")"
CANARY_ID="$(printf '%s' "${CANARY_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["canary_id"])')"
STARTED_AT="$(printf '%s' "${CANARY_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; from datetime import datetime; value=datetime.fromisoformat(json.load(sys.stdin)["started_at"]); assert value.tzinfo is not None; print(int(value.timestamp()))')"

STATUS_JSON="$(runuser -u hermescandidate -- \
  "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
  --config "${CANDIDATE_CONFIG}" status)"
PRODUCT_ID="$(printf '%s' "${STATUS_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin).get("product_id") or "")')"
PRODUCT_STATUS="$(printf '%s' "${STATUS_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["product_status"])')"

if [[ "${PRODUCT_STATUS}" != COMPLETED \
  && "${PRODUCT_STATUS}" != FAILED_SAFE \
  && "${PRODUCT_STATUS}" != CANCELLED ]]; then
  systemctl start "hermes-factory-canary-controller@${SCENARIO_ID}.service"
  if [[ -z "${PRODUCT_ID}" ]]; then
    SUBMIT_JSON="$(runuser -u hermescandidate -- \
      "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
      --config "${CANDIDATE_CONFIG}" submit)"
    PRODUCT_ID="$(printf '%s' "${SUBMIT_JSON}" | "${VERIFIER_PYTHON}" -c \
      'import json,sys; print(json.load(sys.stdin)["product_id"])')"
  fi
  systemctl start "hermes-factory-canary-worker@${SCENARIO_ID}.service"
fi

if [[ -z "${PRODUCT_ID}" || ! "${STARTED_AT}" =~ ^[0-9]+$ ]]; then
  printf 'clean canary durable identity is unavailable\n' >&2
  exit 1
fi

while true; do
  STATUS_JSON="$(runuser -u hermescandidate -- \
    "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
    --config "${CANDIDATE_CONFIG}" status)"
  PRODUCT_STATUS="$(printf '%s' "${STATUS_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["product_status"])')"
  if [[ "${PRODUCT_STATUS}" == COMPLETED ]]; then
    break
  fi
  if [[ "${PRODUCT_STATUS}" == FAILED_SAFE || "${PRODUCT_STATUS}" == CANCELLED ]]; then
    FAILURE_REASON=terminal_failure
    printf 'clean canary reached terminal failure: %s\n' "${PRODUCT_STATUS}" >&2
    exit 1
  fi
  NOW="$(date +%s)"
  if (( NOW - STARTED_AT >= TIMEOUT_SECONDS )); then
    FAILURE_REASON=timeout
    printf 'clean canary timed out in state %s\n' "${PRODUCT_STATUS}" >&2
    exit 124
  fi
  sleep 15
done

runuser -u hermesverifier -- \
  "${VERIFIER_PYTHON}" -m scripts.qualification_control \
  --config "${QUALIFICATION_CONFIG}" canary-complete \
  "${CANARY_ID}" "${PRODUCT_ID}" --candidate-database "${CANARY_DATABASE}"
