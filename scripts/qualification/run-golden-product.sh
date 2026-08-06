#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-golden-product.sh must run as root\n' >&2
  exit 1
fi

CANDIDATE_PYTHON=/opt/hermes-factory-candidate/venv/bin/python
VERIFIER_PYTHON=/opt/hermes-factory-verifier/venv/bin/python
DATABASE=/var/lib/hermes-factory-golden/controller.db

cleanup() {
  exit_status=$?
  set +e
  systemctl stop hermes-factory-golden-worker.service >/dev/null 2>&1 || true
  systemctl stop hermes-factory-golden-controller.service >/dev/null 2>&1 || true
  exit "${exit_status}"
}
trap cleanup EXIT

systemctl start hermes-factory-golden-controller.service
systemctl start --wait hermes-factory-golden-intake.service
systemctl start hermes-factory-golden-worker.service

STARTED_AT="$(date +%s)"
while true; do
  TRUTH="$(runuser -u hermesverifier -- "${VERIFIER_PYTHON}" -m scripts.candidate_truth "${DATABASE}" --worker-idle)"
  PRODUCT_STATUS="$(printf '%s' "${TRUTH}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["product_status"])')"
  SCENARIO_STATUS="$(printf '%s' "${TRUTH}" | "${VERIFIER_PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["scenario_status"])')"
  if [[ "${PRODUCT_STATUS}" == COMPLETED ]]; then break; fi
  if [[ "${SCENARIO_STATUS}" == TERMINAL_FAILURE || "${SCENARIO_STATUS}" == LIVENESS_FINDING ]]; then
    printf 'Golden Product reached authoritative terminal failure: %s\n' "${SCENARIO_STATUS}" >&2
    exit 1
  fi
  NOW="$(date +%s)"
  if (( NOW - STARTED_AT >= 259200 )); then exit 124; fi
  sleep 15
done

runuser -u hermesverifier -- "${VERIFIER_PYTHON}" -m scripts.golden_verify
runuser -u hermesverifier -- "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
  golden-complete /var/lib/hermes-factory-functional/golden/evidence.json
STABLE_JSON="$("${VERIFIER_PYTHON}" -m scripts.stable_readiness)"
STABLE_HEALTH="$(printf '%s' "${STABLE_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["health"])')"
STABLE_INTAKE="$(printf '%s' "${STABLE_JSON}" | "${VERIFIER_PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["intake"])')"
if [[ "${STABLE_HEALTH}" != PASS || "${STABLE_INTAKE}" != PASS ]]; then exit 1; fi
runuser -u hermesverifier -- "${VERIFIER_PYTHON}" -m scripts.functional_qualification \
  factory-checks --internal-verifier-pass --stable-health-pass --stable-intake-pass
