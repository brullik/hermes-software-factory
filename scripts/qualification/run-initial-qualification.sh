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

# Q7 starts only after all preceding gates have durably passed. The timers
# survive reboot while Candidate B remains isolated from Stable A authority.
systemctl enable --now hermes-factory-shadow-verify.timer
systemctl enable --now hermes-factory-shadow-finalize.timer
