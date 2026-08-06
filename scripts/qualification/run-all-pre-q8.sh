#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-all-pre-q8.sh must run as root\n' >&2
  exit 1
fi

INDEX=/etc/hermes-factory/pre-q8/index.json
PYTHON=/opt/hermes-factory-verifier/venv/bin/python
mapfile -t SCENARIOS < <("${PYTHON}" -c \
  'import json,sys; value=json.load(open(sys.argv[1],encoding="utf-8")); print("\n".join(item["scenario_id"] for item in value["scenarios"]))' \
  "${INDEX}")
if (( ${#SCENARIOS[@]} != 10 )); then
  printf 'PRE-Q8 index must contain exactly ten scenarios\n' >&2
  exit 65
fi

for scenario_id in "${SCENARIOS[@]}"; do
  STATUS_JSON="$(runuser -u hermesverifier -- "${PYTHON}" -m scripts.functional_qualification status)"
  EXISTING="$(printf '%s' "${STATUS_JSON}" | "${PYTHON}" -c \
    'import json,sys; v=json.load(sys.stdin); s=sys.argv[1]; print(next((x["status"] for x in v.get("pre_q8",[]) if x["scenario_id"]==s),"MISSING"))' \
    "${scenario_id}")"
  if [[ "${EXISTING}" == PASS ]]; then
    continue
  fi
  if [[ "${EXISTING}" != MISSING ]]; then
    printf 'PRE-Q8 scenario is not first-run restartable: %s=%s\n' "${scenario_id}" "${EXISTING}" >&2
    exit 1
  fi
  systemctl start --wait "hermes-factory-pre-q8@${scenario_id}.service"
done
