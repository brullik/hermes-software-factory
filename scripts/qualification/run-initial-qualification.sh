#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-initial-qualification.sh must run as root\n' >&2
  exit 1
fi

STAGES=(
  Q0_SOURCE_INTEGRITY
  Q1_STATIC_CONTRACTS
  Q2_MODEL_CHECKING
  Q3_PROPERTY_AND_MUTATION
  Q4_HISTORICAL_REPLAY
  Q5_MIGRATION_MATRIX
  Q6_SERVICE_E2E
)

systemctl start --wait hermes-factory-resilience-proof.service

for stage in "${STAGES[@]}"; do
  systemctl start --wait "hermes-factory-qualification-stage@${stage}.service"
done

# Q6 finishes in FUNCTIONAL_PENDING.  The durable functional orchestrator owns
# Q6.5 -> PRE-Q8 -> Golden Product and is the only authority that may enable Q7.
systemctl enable --now hermes-factory-functional-qualification.timer
systemctl start --wait hermes-factory-functional-qualification.service
