#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-golden-product.sh must run as root\n' >&2
  exit 1
fi

CANDIDATE_PYTHON=/opt/hermes-factory-candidate/venv/bin/python
VERIFIER_PYTHON=/opt/hermes-factory-verifier/venv/bin/python
GOLDEN_CONFIG=/etc/hermes-factory/golden.yaml
DATABASE="$("${VERIFIER_PYTHON}" -c \
  'import sys,yaml; value=yaml.safe_load(open(sys.argv[1],encoding="utf-8")); print(value["controller"]["database_url"].removeprefix("sqlite:///"))' \
  "${GOLDEN_CONFIG}")"
GOLDEN_STATE_ROOT="$("${VERIFIER_PYTHON}" -c \
  'import sys,yaml; value=yaml.safe_load(open(sys.argv[1],encoding="utf-8")); print(value["paths"]["state"])' \
  "${GOLDEN_CONFIG}")"
INTAKE_BUDGET_SECONDS=86400
PRODUCT_BUDGET_SECONDS=259200
CURRENT_PHASE=""
INTERRUPTED=0
FAILURE_RECORDED=0

run_as_verifier() {
  runuser -u hermesverifier -- "${VERIFIER_PYTHON}" "$@"
}

cleanup() {
  exit_status=$?
  set +e
  if (( exit_status != 0 && INTERRUPTED == 0 && FAILURE_RECORDED == 0 )) && \
     [[ -n "${CURRENT_PHASE}" ]]; then
    reason_code=golden_product_execution_failed
    if [[ "${CURRENT_PHASE}" == golden-intake ]]; then
      reason_code=golden_intake_failed
    fi
    run_as_verifier -m scripts.functional_qualification \
      phase-fail "${CURRENT_PHASE}" "${reason_code}" >/dev/null 2>&1 || true
  fi
  systemctl stop hermes-factory-golden-worker.service >/dev/null 2>&1 || true
  systemctl stop hermes-factory-golden-controller.service >/dev/null 2>&1 || true
  exit "${exit_status}"
}
trap 'INTERRUPTED=1; exit 75' INT TERM HUP
trap cleanup EXIT

fail_phase() {
  reason_code="$1"
  exit_code="$2"
  run_as_verifier -m scripts.functional_qualification \
    phase-fail "${CURRENT_PHASE}" "${reason_code}" >/dev/null
  FAILURE_RECORDED=1
  exit "${exit_code}"
}

CURRENT_PHASE=golden-intake
INTAKE_PHASE="$(run_as_verifier -m scripts.functional_qualification \
  phase-start "${CURRENT_PHASE}" "${INTAKE_BUDGET_SECONDS}")"
INTAKE_STATUS="$(printf '%s' "${INTAKE_PHASE}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["status"])')"
INTAKE_DEADLINE="$(printf '%s' "${INTAKE_PHASE}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["deadline_epoch"])')"
EPOCH_ID="$(printf '%s' "${INTAKE_PHASE}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["epoch_id"])')"
if [[ ! "${EPOCH_ID}" =~ ^RE-[A-Z0-9][A-Z0-9-]{0,126}$ ]]; then
  printf 'Golden functional epoch identity is unsafe\n' >&2
  exit 65
fi
FUNCTIONAL_GOLDEN_ROOT="/var/lib/hermes-factory-functional/golden/${EPOCH_ID}"
INTAKE_EVIDENCE="${FUNCTIONAL_GOLDEN_ROOT}/intake-evidence.json"
GOLDEN_EVIDENCE="${FUNCTIONAL_GOLDEN_ROOT}/evidence.json"
if [[ "${INTAKE_STATUS}" == FAIL ]]; then
  FAILURE_RECORDED=1
  exit 1
fi
if [[ "${INTAKE_STATUS}" == RUNNING ]]; then
  if (( $(date +%s) >= INTAKE_DEADLINE )); then
    fail_phase golden_intake_timeout 124
  fi
  systemctl start hermes-factory-golden-controller.service
  if ! systemctl start --wait hermes-factory-golden-intake.service; then
    if (( $(date +%s) >= INTAKE_DEADLINE )); then
      fail_phase golden_intake_timeout 124
    fi
    fail_phase golden_intake_failed 1
  fi
  INTAKE_DIGEST="$(run_as_verifier -c \
    'from factory.common import sha256_file; import sys; print(sha256_file(sys.argv[1]))' \
    "${INTAKE_EVIDENCE}")"
  run_as_verifier -m scripts.functional_qualification \
    phase-pass "${CURRENT_PHASE}" "${INTAKE_DIGEST}" >/dev/null
elif [[ "${INTAKE_STATUS}" != PASS ]]; then
  fail_phase golden_intake_failed 1
fi

systemctl start hermes-factory-golden-controller.service

CURRENT_PHASE=golden-product
PRODUCT_PHASE="$(run_as_verifier -m scripts.functional_qualification \
  phase-start "${CURRENT_PHASE}" "${PRODUCT_BUDGET_SECONDS}")"
PRODUCT_PHASE_STATUS="$(printf '%s' "${PRODUCT_PHASE}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["status"])')"
PRODUCT_DEADLINE="$(printf '%s' "${PRODUCT_PHASE}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["deadline_epoch"])')"
if [[ "${PRODUCT_PHASE_STATUS}" == FAIL ]]; then
  FAILURE_RECORDED=1
  exit 1
fi
if [[ "${PRODUCT_PHASE_STATUS}" == RUNNING ]]; then
  if (( $(date +%s) >= PRODUCT_DEADLINE )); then
    fail_phase golden_product_timeout 124
  fi
  systemctl start hermes-factory-golden-worker.service
fi

if [[ "${PRODUCT_PHASE_STATUS}" == RUNNING ]]; then
  while true; do
    TRUTH="$(run_as_verifier -m scripts.candidate_truth "${DATABASE}" --worker-idle)"
    PRODUCT_STATUS="$(printf '%s' "${TRUTH}" | "${VERIFIER_PYTHON}" -c \
      'import json,sys; print(json.load(sys.stdin)["product_status"])')"
    SCENARIO_STATUS="$(printf '%s' "${TRUTH}" | "${VERIFIER_PYTHON}" -c \
      'import json,sys; print(json.load(sys.stdin)["scenario_status"])')"
    if [[ "${PRODUCT_STATUS}" == COMPLETED ]]; then break; fi
    if [[ "${SCENARIO_STATUS}" == TERMINAL_FAILURE || "${SCENARIO_STATUS}" == LIVENESS_FINDING ]]; then
      printf 'Golden Product reached authoritative terminal failure: %s\n' "${SCENARIO_STATUS}" >&2
      fail_phase golden_product_terminal_failure 1
    fi
    NOW="$(date +%s)"
    if (( NOW >= PRODUCT_DEADLINE )); then
      fail_phase golden_product_timeout 124
    fi
    sleep 15
  done
fi

if ! run_as_verifier -m scripts.golden_verify \
  --database "${DATABASE}" --state-root "${GOLDEN_STATE_ROOT}" --output "${GOLDEN_EVIDENCE}"; then
  if [[ "${PRODUCT_PHASE_STATUS}" == PASS ]]; then
    CURRENT_PHASE=""
    run_as_verifier -m scripts.functional_qualification factory-checks >/dev/null || true
  fi
  exit 1
fi
run_as_verifier -m scripts.functional_qualification \
  golden-complete "${GOLDEN_EVIDENCE}"
CURRENT_PHASE=""
STABLE_JSON="$("${VERIFIER_PYTHON}" -m scripts.stable_readiness)"
STABLE_HEALTH="$(printf '%s' "${STABLE_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["health"])')"
STABLE_INTAKE="$(printf '%s' "${STABLE_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["intake"])')"
FACTORY_CHECKS=(factory-checks --internal-verifier-pass)
if [[ "${STABLE_HEALTH}" == PASS ]]; then FACTORY_CHECKS+=(--stable-health-pass); fi
if [[ "${STABLE_INTAKE}" == PASS ]]; then FACTORY_CHECKS+=(--stable-intake-pass); fi
run_as_verifier -m scripts.functional_qualification "${FACTORY_CHECKS[@]}"
if [[ "${STABLE_HEALTH}" != PASS || "${STABLE_INTAKE}" != PASS ]]; then exit 1; fi
