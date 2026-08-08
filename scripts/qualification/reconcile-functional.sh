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
  # Do not poll an unchanged missing credential. Dedicated systemd path units
  # observe the external credential/auth file change, run exactly one fresh
  # capability probe, and start this reconciler through OnSuccess.
  # The durable WAITING state and owner action are already committed.  Delivery
  # is retried by the path unit and must not convert a network-side notifier
  # failure into an internal qualification failure.
  if [[ "${STATUS}" == WAITING_CAPABILITY ]]; then
    systemctl start --no-block hermes-factory-owner-notifier.service
    exit 0
  fi
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

if [[ "${STATUS}" == PRODUCT_GITHUB_PROBE_REQUIRED ]]; then
  systemctl start hermes-factory-product-github-broker.service >/dev/null 2>&1 || true
  systemctl start --wait hermes-factory-product-github-capability.service
  RESULT="$("${CONTROL[@]}" reconcile)"
  STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["status"])')"
  if [[ "${STATUS}" == WAITING_CAPABILITY ]]; then
    systemctl start --no-block hermes-factory-owner-notifier.service
    exit 0
  fi
fi

if [[ "${STATUS}" == STABLE_PROVIDER_PROBE_REQUIRED ]]; then
  systemctl start --wait hermes-factory-stable-provider-capability.service
  RESULT="$("${CONTROL[@]}" reconcile)"
  STATUS="$(printf '%s' "${RESULT}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["status"])')"
  if [[ "${STATUS}" == WAITING_CAPABILITY ]]; then
    systemctl start --no-block hermes-factory-owner-notifier.service
    exit 0
  fi
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

# The same persistent reconciler owns every post-functional handoff.  Each
# action is selected from independent governor truth and is idempotent, so a
# reboot between Q7 authorization, Q8, promotion, or observation cannot require
# a Codex message or a manual next-stage start.
RELEASE_STATUS="$("${PYTHON}" -m scripts.qualification_control status | \
  "${PYTHON}" -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
case "${RELEASE_STATUS}" in
  SHADOW_RUNNING)
    systemctl enable --now \
      hermes-factory-shadow-verify.timer \
      hermes-factory-shadow-finalize.timer
    systemctl start --no-block hermes-factory-shadow-verify.service
    ;;
  CLEAN_CANARY)
    systemctl start --no-block hermes-factory-clean-canaries.service
    ;;
  PROMOTION_READY)
    systemctl start --no-block hermes-factory-qualification-promote.service
    ;;
  PROMOTED)
    systemctl enable --now hermes-factory-production-observation.timer
    systemctl start --no-block hermes-factory-production-observation.service
    ;;
  LTS)
    systemctl start --wait hermes-factory-support-bundle-reconciler.service
    systemctl start --wait hermes-factory-recursive-improvement.service
    # The production observation proof makes the provider adapter renew its
    # Stable-identity receipt, so final readiness never rests on a four-day-old
    # pre-qualification invocation.
    systemctl start --wait hermes-factory-stable-provider-capability.service
    systemctl start --wait hermes-factory-stable-runtime-attestation.service
    systemctl start --wait hermes-factory-ready-result.service
    systemctl disable hermes-factory-functional-qualification.timer >/dev/null 2>&1 || true
    systemctl disable \
      hermes-factory-shadow-verify.timer \
      hermes-factory-shadow-finalize.timer \
      hermes-factory-production-observation.timer >/dev/null 2>&1 || true
    ;;
  QUALIFICATION_FAILED)
    systemctl disable \
      hermes-factory-shadow-verify.timer \
      hermes-factory-shadow-finalize.timer \
      hermes-factory-production-observation.timer >/dev/null 2>&1 || true
    ;;
esac
