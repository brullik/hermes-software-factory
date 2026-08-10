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
FUNCTIONAL_STATE=/var/lib/hermes-factory-functional
PRE_Q8_ROOT=/var/lib/hermes-factory-pre-q8
TIMEOUT_SECONDS="${PRE_Q8_TIMEOUT_SECONDS:-172800}"
NO_PROGRESS_SECONDS="${PRE_Q8_NO_PROGRESS_SECONDS:-1800}"
PRODUCT_ID=""
OFFICIAL_STARTED=0
FAILURE_CLASS=OFFICIAL_ORCHESTRATOR_FAILED
RUNTIME_ROOT="${FUNCTIONAL_STATE}/pre-q8-runtime/${SCENARIO_ID}"
OBSERVATION_PATH="${RUNTIME_ROOT}/worker-observation.json"
PROGRESS_PATH="${RUNTIME_ROOT}/progress.json"
UNIT_PROPERTIES_PATH="${RUNTIME_ROOT}/unit-properties.txt"
SAFE_JOURNAL_PATH="${RUNTIME_ROOT}/safe-journal.json"
STATUS_SUMMARY_PATH="${RUNTIME_ROOT}/official-status.json"
FIXTURE_RECEIPT=""

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
  systemctl stop "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" >/dev/null 2>&1
  systemctl stop "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service" >/dev/null 2>&1
  if (( exit_status != 0 && OFFICIAL_STARTED == 1 )); then
    if [[ -f "${CANDIDATE_DATABASE}" && ! -L "${CANDIDATE_DATABASE}" \
      && ! -f "${PROGRESS_PATH}" ]]; then
      run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_runtime \
        worker-observation --database "${CANDIDATE_DATABASE}" \
        --unit "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" \
        --output "${OBSERVATION_PATH}" --progress-output "${PROGRESS_PATH}" \
        >/dev/null 2>&1 || true
    fi
    systemctl show \
      "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" \
      "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service" \
      "hermes-factory-pre-q8@${SCENARIO_ID}.service" \
      -p Id -p ActiveState -p SubState -p Result -p NRestarts \
      -p ExecMainCode -p ExecMainStatus >"${UNIT_PROPERTIES_PATH}" 2>&1 || true
    journalctl \
      -u "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" \
      -u "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service" \
      -n 200 --no-pager -o json \
      --output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,PRIORITY \
      >"${SAFE_JOURNAL_PATH}" 2>/dev/null || true
    run_as_verifier "${VERIFIER_PYTHON}" -m scripts.functional_qualification status \
      >"${STATUS_SUMMARY_PATH}" 2>/dev/null || true
    chown hermesverifier:hermesfunctional \
      "${UNIT_PROPERTIES_PATH}" "${SAFE_JOURNAL_PATH}" "${STATUS_SUMMARY_PATH}" \
      >/dev/null 2>&1 || true
    chmod 0640 \
      "${UNIT_PROPERTIES_PATH}" "${SAFE_JOURNAL_PATH}" "${STATUS_SUMMARY_PATH}" \
      >/dev/null 2>&1 || true
    support_args=()
    [[ -f "${OBSERVATION_PATH}" ]] \
      && support_args+=(--support-source "${OBSERVATION_PATH}")
    [[ -f "${PROGRESS_PATH}" ]] \
      && support_args+=(--support-source "${PROGRESS_PATH}")
    [[ -n "${FIXTURE_RECEIPT}" && -f "${FIXTURE_RECEIPT}" ]] \
      && support_args+=(--support-source "${FIXTURE_RECEIPT}")
    for support_source in \
      "${UNIT_PROPERTIES_PATH}" "${SAFE_JOURNAL_PATH}" "${STATUS_SUMMARY_PATH}"; do
      [[ -f "${support_source}" ]] \
        && support_args+=(--support-source "${support_source}")
    done
    while IFS= read -r -d '' fault_receipt; do
      support_args+=(--support-source "${fault_receipt}")
    done < <(find "$(dirname "${CANDIDATE_DATABASE}")/fault-receipts" \
      -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null || true)
    if ! run_as_verifier "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
      pre-q8-fail "${SCENARIO_ID}" "${FAILURE_CLASS}" "${CANDIDATE_CONFIG}" \
      "${support_args[@]}"; then
      printf 'PRE-Q8 terminal failure transaction failed: %s\n' "${SCENARIO_ID}" >&2
      exit_status=70
    fi
  fi
  exit "${exit_status}"
}
trap cleanup EXIT

if [[ ! -x "${CANDIDATE_PYTHON}" || ! -x "${VERIFIER_PYTHON}" ]]; then
  printf 'Candidate or verifier runtime is unavailable\n' >&2
  exit 69
fi
if [[ ! -f "${CANDIDATE_CONFIG}" ]]; then
  printf 'root-owned PRE-Q8 config is unavailable\n' >&2
  exit 66
fi
if [[ ! "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] \
  || [[ ! "${NO_PROGRESS_SECONDS}" =~ ^[0-9]+$ ]] \
  || (( TIMEOUT_SECONDS < 900 || NO_PROGRESS_SECONDS < 60 \
        || NO_PROGRESS_SECONDS >= TIMEOUT_SECONDS )); then
  printf 'PRE-Q8 timeout policy is invalid\n' >&2
  exit 64
fi

IDENTITY_JSON="$(run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_runtime \
  config-identity --config "${CANDIDATE_CONFIG}" --expected-plane PRE_Q8 \
  --expected-scenario "${SCENARIO_ID}" --allowed-root "${PRE_Q8_ROOT}")"
CANDIDATE_DATABASE="$(printf '%s' "${IDENTITY_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["database_path"])')"
EPOCH_ID="$(printf '%s' "${IDENTITY_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["epoch_id"])')"
RUN_ID="$(printf '%s' "${IDENTITY_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["run_id"])')"
RUNTIME_ROOT="${FUNCTIONAL_STATE}/pre-q8-runtime/${EPOCH_ID}/${RUN_ID}/${SCENARIO_ID}"
OBSERVATION_PATH="${RUNTIME_ROOT}/worker-observation.json"
PROGRESS_PATH="${RUNTIME_ROOT}/progress.json"
UNIT_PROPERTIES_PATH="${RUNTIME_ROOT}/unit-properties.txt"
SAFE_JOURNAL_PATH="${RUNTIME_ROOT}/safe-journal.json"
STATUS_SUMMARY_PATH="${RUNTIME_ROOT}/official-status.json"
FIXTURE_RECEIPT="${PRE_Q8_ROOT}/${EPOCH_ID}/${RUN_ID}/fixture-provision.json"
(
  umask 0007
  run_as_verifier /usr/bin/mkdir -p -- "${RUNTIME_ROOT}"
)

OFFICIAL_STARTED=1
RECONCILE_JSON="$(run_as_verifier "${VERIFIER_PYTHON}" \
  -m scripts.functional_qualification pre-q8-reconcile \
  "${SCENARIO_ID}" "${CANDIDATE_CONFIG}")"
RECONCILE_STATUS="$(printf '%s' "${RECONCILE_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["status"])')"
case "${RECONCILE_STATUS}" in
  PASS) exit 0 ;;
  FAIL|QUALIFICATION_FAILED) exit 1 ;;
  MISSING) ;;
  *) printf 'PRE-Q8 crash reconciliation is ambiguous\n' >&2; exit 70 ;;
esac

run_as_verifier "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
  pre-q8-start "${SCENARIO_ID}" "${CANDIDATE_CONFIG}" >/dev/null
if [[ -e "${CANDIDATE_DATABASE}" ]]; then
  FAILURE_CLASS=STALE_DATABASE
  printf 'PRE-Q8 refuses a non-fresh database: %s\n' "${SCENARIO_ID}" >&2
  exit 73
fi

FAILURE_CLASS=CANDIDATE_PREPARE_FAILED
run_as_candidate "${CANDIDATE_PYTHON}" -m scripts.canary_candidate \
  --config "${CANDIDATE_CONFIG}" prepare
FAILURE_CLASS=CONTROLLER_UNIT_FAILED
systemctl reset-failed "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service" \
  "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" >/dev/null 2>&1 || true
systemctl start "hermes-factory-pre-q8-controller@${SCENARIO_ID}.service"
FAILURE_CLASS=CANDIDATE_SUBMIT_FAILED
SUBMIT_JSON="$(run_as_candidate "${CANDIDATE_PYTHON}" \
  -m scripts.canary_candidate --config "${CANDIDATE_CONFIG}" submit)"
PRODUCT_ID="$(printf '%s' "${SUBMIT_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["product_id"])')"
FAILURE_CLASS=WORKER_UNIT_FAILED
systemctl start "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service"

STARTED_AT="$(date +%s)"
while true; do
  INTENTIONAL_ARGS=()
  if [[ "${SCENARIO_ID}" == provider-timeout-restart ]]; then
    INTENTIONAL_ARGS+=(--intentional-restart-expected)
    if [[ -f "$(dirname "${CANDIDATE_DATABASE}")/fault-receipts/ONE_PROCESS_RESTART.json" ]]; then
      INTENTIONAL_ARGS+=(--intentional-restart-receipt-verified)
    fi
  fi
  run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_runtime \
    worker-observation --database "${CANDIDATE_DATABASE}" \
    --unit "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" \
    --output "${OBSERVATION_PATH}" --progress-output "${PROGRESS_PATH}" \
    "${INTENTIONAL_ARGS[@]}" >/dev/null
  PROGRESS_JSON="$(run_as_verifier "${VERIFIER_PYTHON}" \
    -m scripts.functional_qualification pre-q8-progress \
    "${SCENARIO_ID}" "${PROGRESS_PATH}")"
  SECONDS_WITHOUT_PROGRESS="$(printf '%s' "${PROGRESS_JSON}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["seconds_without_progress"])')"
  if (( SECONDS_WITHOUT_PROGRESS >= NO_PROGRESS_SECONDS )); then
    run_as_verifier "${VERIFIER_PYTHON}" -m scripts.pre_q8_runtime \
      worker-observation --database "${CANDIDATE_DATABASE}" \
      --unit "hermes-factory-pre-q8-worker@${SCENARIO_ID}.service" \
      --no-progress-window-elapsed --output "${OBSERVATION_PATH}" \
      --progress-output "${PROGRESS_PATH}" "${INTENTIONAL_ARGS[@]}" >/dev/null
  fi
  ASSESSMENT_STATE="$("${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["assessment"]["state"])' \
    "${OBSERVATION_PATH}")"
  WORKER_IDLE="$("${VERIFIER_PYTHON}" -c \
    'import json,sys; print(str(json.load(open(sys.argv[1],encoding="utf-8"))["assessment"]["worker_idle"]).lower())' \
    "${OBSERVATION_PATH}")"
  if [[ "${ASSESSMENT_STATE}" == FAILED ]]; then
    FAILURE_CLASS="$("${VERIFIER_PYTHON}" -c \
      'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["assessment"]["failure_class"])' \
      "${OBSERVATION_PATH}")"
    exit 1
  fi
  if [[ "${ASSESSMENT_STATE}" == UNKNOWN ]] \
    && (( SECONDS_WITHOUT_PROGRESS >= NO_PROGRESS_SECONDS )); then
    FAILURE_CLASS=WORKER_STATE_UNCLASSIFIED
    exit 1
  fi
  TRUTH_ARGS=("${CANDIDATE_DATABASE}")
  if [[ "${WORKER_IDLE}" == true ]]; then
    TRUTH_ARGS+=(--worker-idle)
  fi
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
  NOW="$(date +%s)"
  if (( NOW - STARTED_AT >= TIMEOUT_SECONDS )); then
    FAILURE_CLASS=HARD_TIMEOUT
    exit 124
  fi
  if (( SECONDS_WITHOUT_PROGRESS >= NO_PROGRESS_SECONDS )) \
    && [[ "${ASSESSMENT_STATE}" != IDLE ]]; then
    FAILURE_CLASS=NO_PROGRESS_TIMEOUT
    exit 124
  fi
  sleep 15
done

FAILURE_CLASS=OBSERVATION_VERIFICATION_FAILED
run_as_verifier "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
  pre-q8-pass "${SCENARIO_ID}" "${PRODUCT_ID}" "${CANDIDATE_CONFIG}"
OFFICIAL_STARTED=0
