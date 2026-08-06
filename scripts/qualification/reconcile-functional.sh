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
  systemctl start hermes-factory-github-broker.service
  systemctl start --wait hermes-factory-capability-probe.service
  RESULT="$("${CONTROL[@]}" reconcile)"
  STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["status"])')"
fi

if [[ "${STATUS}" == PRE_Q8_PENDING ]]; then
  systemctl start --wait hermes-factory-pre-q8.service
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
