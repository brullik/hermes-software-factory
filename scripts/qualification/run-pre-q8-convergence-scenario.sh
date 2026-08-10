#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-pre-q8-convergence-scenario.sh must run as root\n' >&2
  exit 1
fi

RUN_ID="${1:-}"
SCENARIO_ID="${2:-}"
if [[ -z "${SCENARIO_ID}" && "${RUN_ID}" == *--* ]]; then
  SCENARIO_ID="${RUN_ID#*--}"
  RUN_ID="${RUN_ID%%--*}"
fi
if [[ ! "${RUN_ID}" =~ ^[a-z0-9][a-z0-9-]{7,63}$ ]] \
  || [[ ! "${SCENARIO_ID}" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; then
  printf 'convergence run/scenario identity is invalid\n' >&2
  exit 64
fi

CANDIDATE_PYTHON=/opt/hermes-factory-candidate/venv/bin/python
VERIFIER_PYTHON=/opt/hermes-factory-verifier/venv/bin/python
SETPRIV=/usr/bin/setpriv
CONFIG="/etc/hermes-factory/pre-q8-convergence/${RUN_ID}/${SCENARIO_ID}.yaml"
INDEX="/etc/hermes-factory/pre-q8-convergence/${RUN_ID}/index.json"
EPOCH_ID="$("${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["epoch_id"])' \
  "${INDEX}")"
STATE_ROOT="/var/lib/hermes-factory-pre-q8-convergence/${EPOCH_ID}/${RUN_ID}"
EVIDENCE_ROOT="${STATE_ROOT}/evidence/${SCENARIO_ID}"
RUNTIME_ROOT="${STATE_ROOT}/runtime/${SCENARIO_ID}"
RESULT_PATH="${STATE_ROOT}/results/${SCENARIO_ID}.json"
OBSERVATION_PATH="${RUNTIME_ROOT}/worker-observation.json"
PROGRESS_PATH="${RUNTIME_ROOT}/progress.json"
UNIT_PROPERTIES_PATH="${RUNTIME_ROOT}/unit-properties.txt"
SAFE_JOURNAL_PATH="${RUNTIME_ROOT}/safe-journal.json"
UNIT_INSTANCE="${RUN_ID}--${SCENARIO_ID}"
DATABASE=""
PRODUCT_ID=""
CONFIG_VALID=0
FAILURE_CLASS=CONVERGENCE_ORCHESTRATOR_FAILED
TIMEOUT_SECONDS="${PRE_Q8_CONVERGENCE_TIMEOUT_SECONDS:-172800}"
NO_PROGRESS_SECONDS="${PRE_Q8_CONVERGENCE_NO_PROGRESS_SECONDS:-1800}"

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
  trap - EXIT
  set +e
  systemctl stop "hermes-factory-pre-q8-convergence-worker@${UNIT_INSTANCE}.service" \
    >/dev/null 2>&1
  systemctl stop "hermes-factory-pre-q8-convergence-controller@${UNIT_INSTANCE}.service" \
    >/dev/null 2>&1
  if (( exit_status != 0 && CONFIG_VALID == 1 )) && [[ ! -f "${RESULT_PATH}" ]]; then
    if [[ -f "${DATABASE}" && ! -L "${DATABASE}" && ! -f "${PROGRESS_PATH}" ]]; then
      run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_runtime \
        worker-observation --database "${DATABASE}" \
        --unit "hermes-factory-pre-q8-convergence-worker@${UNIT_INSTANCE}.service" \
        --output "${OBSERVATION_PATH}" --progress-output "${PROGRESS_PATH}" \
        >/dev/null 2>&1 || true
    fi
    systemctl show \
      "hermes-factory-pre-q8-convergence-worker@${UNIT_INSTANCE}.service" \
      "hermes-factory-pre-q8-convergence-controller@${UNIT_INSTANCE}.service" \
      "hermes-factory-pre-q8-convergence-scenario@${UNIT_INSTANCE}.service" \
      -p Id -p ActiveState -p SubState -p Result -p NRestarts \
      -p ExecMainCode -p ExecMainStatus >"${UNIT_PROPERTIES_PATH}" 2>&1 || true
    journalctl \
      -u "hermes-factory-pre-q8-convergence-worker@${UNIT_INSTANCE}.service" \
      -u "hermes-factory-pre-q8-convergence-controller@${UNIT_INSTANCE}.service" \
      -n 200 --no-pager -o json \
      --output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,PRIORITY \
      >"${SAFE_JOURNAL_PATH}" 2>/dev/null || true
    chown hermesverifier:hermesfunctional \
      "${UNIT_PROPERTIES_PATH}" "${SAFE_JOURNAL_PATH}" >/dev/null 2>&1 || true
    chmod 0640 "${UNIT_PROPERTIES_PATH}" "${SAFE_JOURNAL_PATH}" \
      >/dev/null 2>&1 || true
    support_args=()
    [[ -f "${OBSERVATION_PATH}" ]] \
      && support_args+=(--support-source "${OBSERVATION_PATH}")
    [[ -f "${PROGRESS_PATH}" ]] \
      && support_args+=(--support-source "${PROGRESS_PATH}")
    [[ -f "${STATE_ROOT}/fixture-provision.json" ]] \
      && support_args+=(--support-source "${STATE_ROOT}/fixture-provision.json")
    for support_source in "${UNIT_PROPERTIES_PATH}" "${SAFE_JOURNAL_PATH}"; do
      [[ -f "${support_source}" ]] \
        && support_args+=(--support-source "${support_source}")
    done
    while IFS= read -r -d '' fault_receipt; do
      support_args+=(--support-source "${fault_receipt}")
    done < <(find "$(dirname "${DATABASE}")/fault-receipts" \
      -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null || true)
    while IFS= read -r -d '' scenario_result; do
      support_args+=(--support-source "${scenario_result}")
    done < <(find "${STATE_ROOT}/results" -maxdepth 1 -type f -name '*.json' \
      -print0 2>/dev/null || true)
    run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_convergence \
      --database "${STATE_ROOT}/convergence.db" --run-id "${RUN_ID}" failure \
      --config "${CONFIG}" --failure-class "${FAILURE_CLASS}" \
      --evidence-root "${EVIDENCE_ROOT}" --output "${RESULT_PATH}" \
      "${support_args[@]}" >/dev/null || exit_status=70
  fi
  exit "${exit_status}"
}
trap cleanup EXIT

(
  umask 0007
  run_as_verifier /usr/bin/mkdir -p -- \
    "${EVIDENCE_ROOT}" "${RUNTIME_ROOT}" "$(dirname "${RESULT_PATH}")"
)
IDENTITY_JSON="$(run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_runtime \
  config-identity --config "${CONFIG}" --expected-plane CONVERGENCE \
  --expected-scenario "${SCENARIO_ID}" \
  --allowed-root /var/lib/hermes-factory-pre-q8-convergence)"
DATABASE="$(printf '%s' "${IDENTITY_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["database_path"])')"
CONFIG_VALID=1
if [[ -e "${DATABASE}" ]]; then
  FAILURE_CLASS=STALE_CONVERGENCE_DATABASE
  exit 73
fi

FAILURE_CLASS=CANDIDATE_PREPARE_FAILED
run_as_candidate "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
  --config "${CONFIG}" prepare >/dev/null
run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_convergence \
  --database "${STATE_ROOT}/convergence.db" --run-id "${RUN_ID}" fresh \
  --config "${CONFIG}" --evidence-root "${EVIDENCE_ROOT}" >/dev/null
FAILURE_CLASS=CONTROLLER_UNIT_FAILED
systemctl reset-failed \
  "hermes-factory-pre-q8-convergence-controller@${UNIT_INSTANCE}.service" \
  "hermes-factory-pre-q8-convergence-worker@${UNIT_INSTANCE}.service" \
  >/dev/null 2>&1 || true
systemctl start "hermes-factory-pre-q8-convergence-controller@${UNIT_INSTANCE}.service"
FAILURE_CLASS=CANDIDATE_SUBMIT_FAILED
SUBMIT_JSON="$(run_as_candidate "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
  --config "${CONFIG}" submit)"
PRODUCT_ID="$(printf '%s' "${SUBMIT_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["product_id"])')"
FAILURE_CLASS=WORKER_UNIT_FAILED
systemctl start "hermes-factory-pre-q8-convergence-worker@${UNIT_INSTANCE}.service"

STARTED_AT="$(date +%s)"
LAST_CHANGED_AT="${STARTED_AT}"
LAST_FINGERPRINT=""
while true; do
  NOW="$(date +%s)"
  OBSERVATION_ARGS=()
  if (( NOW - LAST_CHANGED_AT >= NO_PROGRESS_SECONDS )); then
    OBSERVATION_ARGS+=(--no-progress-window-elapsed)
  fi
  if [[ "${SCENARIO_ID}" == provider-timeout-restart ]]; then
    OBSERVATION_ARGS+=(--intentional-restart-expected)
    if [[ -f "$(dirname "${DATABASE}")/fault-receipts/ONE_PROCESS_RESTART.json" ]]; then
      OBSERVATION_ARGS+=(--intentional-restart-receipt-verified)
    fi
  fi
  run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_runtime \
    worker-observation --database "${DATABASE}" \
    --unit "hermes-factory-pre-q8-convergence-worker@${UNIT_INSTANCE}.service" \
    --output "${OBSERVATION_PATH}" --progress-output "${PROGRESS_PATH}" \
    "${OBSERVATION_ARGS[@]}" >/dev/null
  FINGERPRINT="$("${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["progress"]["progress_fingerprint"])' \
    "${OBSERVATION_PATH}")"
  if [[ "${FINGERPRINT}" != "${LAST_FINGERPRINT}" ]]; then
    LAST_FINGERPRINT="${FINGERPRINT}"
    LAST_CHANGED_AT="${NOW}"
  fi
  ASSESSMENT_STATE="$("${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["assessment"]["state"])' \
    "${OBSERVATION_PATH}")"
  WORKER_IDLE="$("${VERIFIER_PYTHON}" -c \
    'import json,sys; print(str(json.load(open(sys.argv[1],encoding="utf-8"))["assessment"]["worker_idle"]).lower())' \
    "${OBSERVATION_PATH}")"
  if [[ "${ASSESSMENT_STATE}" == FAILED ]]; then
    FAILURE_CLASS=WORKER_UNIT_FAILED
    exit 1
  fi
  TRUTH_ARGS=("${DATABASE}")
  [[ "${WORKER_IDLE}" == true ]] && TRUTH_ARGS+=(--worker-idle)
  TRUTH_JSON="$(run_as_verifier "${VERIFIER_PYTHON}" \
    -m scripts.candidate_truth "${TRUTH_ARGS[@]}")"
  SCENARIO_STATUS="$(printf '%s' "${TRUTH_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["scenario_status"])')"
  case "${SCENARIO_STATUS}" in
    PASS) break ;;
    TERMINAL_FAILURE) FAILURE_CLASS=PRODUCT_TERMINAL_FAILURE; exit 1 ;;
    LIVENESS_FINDING) FAILURE_CLASS=CANDIDATE_LIVENESS_FAILURE; exit 1 ;;
    VERIFY_FAILED|WAITING_CAPABILITY|RUNNING) ;;
    *) FAILURE_CLASS=AUTHORITATIVE_STATE_UNKNOWN; exit 1 ;;
  esac
  if (( NOW - STARTED_AT >= TIMEOUT_SECONDS )); then
    FAILURE_CLASS=HARD_TIMEOUT
    exit 124
  fi
  if (( NOW - LAST_CHANGED_AT >= NO_PROGRESS_SECONDS )) \
    && [[ "${ASSESSMENT_STATE}" != IDLE ]]; then
    FAILURE_CLASS=NO_PROGRESS_TIMEOUT
    exit 124
  fi
  sleep 15
done

FAILURE_CLASS=OBSERVATION_VERIFICATION_FAILED
run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_convergence \
  --database "${STATE_ROOT}/convergence.db" --run-id "${RUN_ID}" observe \
  --config "${CONFIG}" --product-id "${PRODUCT_ID}" \
  --evidence-root "${EVIDENCE_ROOT}" --output "${RESULT_PATH}" >/dev/null
