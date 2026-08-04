#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-manifest-and-promotion.sh must run as root\n' >&2
  exit 1
fi

VERIFIER_PYTHON=/opt/hermes-factory-verifier/venv/bin/python
QUALIFICATION_CONFIG=/etc/hermes-factory/qualification-control.yaml
ROOT_HELPER=/usr/local/sbin/hermes-qualified-release-submit

if [[ ! -x "${VERIFIER_PYTHON}" || ! -x "${ROOT_HELPER}" ]]; then
  printf 'qualified verifier or root promotion helper is unavailable\n' >&2
  exit 69
fi

runuser -u hermesverifier -- \
  "${VERIFIER_PYTHON}" -m scripts.qualification_control \
  --config "${QUALIFICATION_CONFIG}" manifest-request
systemctl start --wait hermes-factory-independent-verifier.service
systemctl start --wait hermes-factory-qualification-admit.service
systemctl start --wait hermes-factory-qualification-install.service

mapfile -t RELEASE_IDENTITY < <(runuser -u hermesverifier -- \
  "${VERIFIER_PYTHON}" -c \
  'from pathlib import Path; from scripts.qualification_control import _load_config; value=_load_config(Path("/etc/hermes-factory/qualification-control.yaml")); print(value["factory_repository"]); print(value["source_commit"]); print(value["candidate_digest"])')
if (( ${#RELEASE_IDENTITY[@]} != 3 )); then
  printf 'qualified release identity is incomplete\n' >&2
  exit 65
fi
if [[ ! "${RELEASE_IDENTITY[0]}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || [[ ! "${RELEASE_IDENTITY[1]}" =~ ^[a-f0-9]{40}$ ]] \
  || [[ ! "${RELEASE_IDENTITY[2]}" =~ ^[a-f0-9]{64}$ ]]; then
  printf 'qualified release identity is invalid\n' >&2
  exit 65
fi

"${ROOT_HELPER}" \
  --repository "${RELEASE_IDENTITY[0]}" \
  --release-id "${RELEASE_IDENTITY[1]}" \
  --staging-digest "sha256:${RELEASE_IDENTITY[2]}"

runuser -u hermesverifier -- \
  "${VERIFIER_PYTHON}" -m scripts.qualification_control \
  --config "${QUALIFICATION_CONFIG}" promotion-observe
systemctl enable --now hermes-factory-production-observation.timer

