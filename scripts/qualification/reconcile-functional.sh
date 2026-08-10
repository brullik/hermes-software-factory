#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'reconcile-functional.sh must run as root\n' >&2
  exit 1
fi

PYTHON=/opt/hermes-factory-verifier/venv/bin/python
CONTROL=("${PYTHON}" -m scripts.functional_qualification)

RESULT="$("${CONTROL[@]}" reconcile)"
STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["status"])')"

if [[ "${STATUS}" == WAITING_CAPABILITY ]]; then
  # The durable WAITING state and owner action are already committed.  Delivery
  # is retried by the path unit and must not convert a network-side notifier
  # failure into an internal qualification failure.
  systemctl start --no-block hermes-factory-owner-notifier.service
  exit 0
fi

if [[ "${STATUS}" == Q6_5_PROBE_REQUIRED ]]; then
  # Q6.5 proves both Telegram delivery operations and waits for their typed
  # receipts.  Bootstrap deliberately leaves the path disabled until the
  # initial qualification returns, so activate it for this boot before the
  # probe starts.  The final bootstrap step still owns persistent enablement.
  systemctl start hermes-factory-owner-notifier.path
  systemctl start hermes-factory-github-broker.service
  systemctl start --wait hermes-factory-capability-probe.service
  RESULT="$("${CONTROL[@]}" reconcile)"
  STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["status"])')"
  if [[ "${STATUS}" == WAITING_CAPABILITY ]]; then
    systemctl start --no-block hermes-factory-owner-notifier.service
    exit 0
  fi
fi

if [[ "${STATUS}" == QUALIFICATION_FAILED ]]; then
  # A terminal official Candidate is immutable. Future timer ticks are no-ops.
  exit 0
fi

if [[ "${STATUS}" == PRE_Q8_PENDING ]]; then
  # Official execution is gated by an independently signed convergence seal.
  exit 0
fi

if [[ "${STATUS}" == PRE_Q8_RUNNING ]]; then
  if ! systemctl start --wait hermes-factory-pre-q8.service; then
    FAILURE_STATUS="$("${CONTROL[@]}" status)"
    FAILURE_EPOCH_STATUS="$(printf '%s' "${FAILURE_STATUS}" | "${PYTHON}" -c \
      'import json,sys; print(json.load(sys.stdin)["epoch"]["status"])')"
    if [[ "${FAILURE_EPOCH_STATUS}" != QUALIFICATION_FAILED ]]; then
      FAILURE_SCENARIO="$(printf '%s' "${FAILURE_STATUS}" | "${PYTHON}" -c \
        'import json,sys; v=json.load(sys.stdin); runs=v.get("pre_q8_runs",[]); print(next((x["scenario_id"] for x in runs if x["status"]=="RUNNING"),"zero-dependency-cli"))')"
      "${CONTROL[@]}" pre-q8-fail "${FAILURE_SCENARIO}" \
        AGGREGATE_UNIT_FAILED "/etc/hermes-factory/pre-q8/${FAILURE_SCENARIO}.yaml" \
        >/dev/null
    fi
    exit 1
  fi
  RESULT="$("${CONTROL[@]}" status)"
  STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["epoch"]["status"])')"
fi

if [[ "${STATUS}" == GOLDEN_PRODUCT_PENDING ]]; then
  systemctl start --wait hermes-factory-golden-product.service
  RESULT="$("${CONTROL[@]}" status)"
  STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["epoch"]["status"])')"
fi

if [[ "${STATUS}" == FUNCTIONALLY_READY ]]; then
  systemctl start --wait hermes-factory-functional-ready.service
fi
