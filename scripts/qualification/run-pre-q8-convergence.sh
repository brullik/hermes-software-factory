#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-pre-q8-convergence.sh must run as root\n' >&2
  exit 1
fi

RUN_ID="${1:-}"
if [[ ! "${RUN_ID}" =~ ^[a-z0-9][a-z0-9-]{7,63}$ ]]; then
  printf 'convergence run id is invalid\n' >&2
  exit 64
fi

PYTHON=/opt/hermes-factory-verifier/venv/bin/python
SETPRIV=/usr/bin/setpriv
CONTROL=/etc/hermes-factory/qualification-control.yaml
BASE_CONFIG=/etc/hermes-factory/candidate.yaml
CANDIDATE_ROOT=/opt/hermes-factory-candidate/current
SYSTEMD_ROOT="${CANDIDATE_ROOT}/config/systemd"
CATALOG="${CANDIDATE_ROOT}/qualification/canaries/catalog.yaml"
CONFIG_ROOT="/etc/hermes-factory/pre-q8-convergence/${RUN_ID}"
STATE_BASE=/var/lib/hermes-factory-pre-q8-convergence
LOG_ROOT=/var/log/hermes-factory-pre-q8-convergence
STATE_ROOT=""
DATABASE=""
MATRIX=""
SEAL=""
FIXTURE_RECEIPT=""
FIXTURE_ARCHIVE_RECEIPT=""
TOKEN_FILE=/etc/hermes-factory/candidate-credentials.d/github-token
KEY_FILE=/var/lib/hermes-factory-verifier/verifier-ed25519.key
FIXTURE_PROVISIONED=0
GITHUB_OWNER=""

run_as_verifier() {
  "${SETPRIV}" --reuid=hermesverifier --regid=hermesverifier --init-groups \
    --no-new-privs -- /usr/bin/env HOME=/var/lib/hermes-factory-verifier \
    USER=hermesverifier LOGNAME=hermesverifier "$@"
}

cleanup_fixture() {
  exit_status=$?
  trap - EXIT
  if (( FIXTURE_PROVISIONED == 1 )); then
    "${PYTHON}" -m scripts.pre_q8_fixture --token-file "${TOKEN_FILE}" \
      --owner "${GITHUB_OWNER}" archive --receipt "${FIXTURE_RECEIPT}" \
      --output "${FIXTURE_ARCHIVE_RECEIPT}" >/dev/null || exit_status=70
    if [[ -f "${FIXTURE_ARCHIVE_RECEIPT}" ]]; then
      chown root:hermesfunctional "${FIXTURE_ARCHIVE_RECEIPT}"
      chmod 0640 "${FIXTURE_ARCHIVE_RECEIPT}"
    fi
  fi
  exit "${exit_status}"
}
trap cleanup_fixture EXIT

IDENTITY_JSON="$("${PYTHON}" -m scripts.pre_q8_runtime build-identity \
  --control "${CONTROL}" --candidate-config "${BASE_CONFIG}" \
  --candidate-root "${CANDIDATE_ROOT}" --systemd-root "${SYSTEMD_ROOT}" \
  --capability-attestation /etc/hermes-factory/canary-capability-attestation.json)"
field() {
  printf '%s' "${IDENTITY_JSON}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}
SOURCE_COMMIT="$(field source_commit)"
STABLE_DIGEST="$(field stable_release_digest)"
CONTROLLER_DIGEST="$(field controller_release_digest)"
CANDIDATE_DIGEST="$(field candidate_digest)"
POLICY_DIGEST="$(field policy_digest)"
TOOLCHAIN_DIGEST="$(field toolchain_digest)"
GIT_TREE="$(field git_tree)"
EPOCH_ID="$(field epoch_id)"
REQUIREMENTS_DIGEST="$(field requirements_lock_digest)"
SYSTEMD_DIGEST="$(field systemd_bundle_digest)"
ATTESTATION_PATH="$(field capability_attestation_path)"
ATTESTATION_DIGEST="$(field capability_attestation_digest)"
FIXTURE_DIGEST="$(field fixture_seed_digest)"
STATE_ROOT="${STATE_BASE}/${EPOCH_ID}/${RUN_ID}"
DATABASE="${STATE_ROOT}/convergence.db"
MATRIX="${STATE_ROOT}/matrix.json"
SEAL="${STATE_ROOT}/seal.json"
FIXTURE_RECEIPT="${STATE_ROOT}/fixture-provision.json"
FIXTURE_ARCHIVE_RECEIPT="${STATE_ROOT}/fixture-archive.json"
MATRIX_PENDING_DIGEST="$(RUN_ID="${RUN_ID}" "${PYTHON}" -c \
  'from factory.common import sha256_text; import os; print(sha256_text("matrix-pending:"+os.environ["RUN_ID"]))')"
GITHUB_OWNER="$("${PYTHON}" -c \
  'import sys,yaml; print(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))["github"]["owner"])' \
  "${BASE_CONFIG}")"

run_as_verifier /usr/bin/install -d -m 2770 \
  "${STATE_ROOT}" "${STATE_ROOT}/results" "${STATE_ROOT}/evidence"
install -d -o root -g hermesfunctional -m 0750 "${CONFIG_ROOT}"

FIXTURE_JSON="$("${PYTHON}" -m scripts.pre_q8_fixture \
  --token-file "${TOKEN_FILE}" --owner "${GITHUB_OWNER}" provision \
  --plane convergence --run-id "${RUN_ID}" \
  --candidate-digest "${CANDIDATE_DIGEST}" \
  --receipt "${FIXTURE_RECEIPT}")"
FIXTURE_PROVISIONED=1
chown root:hermesfunctional "${FIXTURE_RECEIPT}"
chmod 0640 "${FIXTURE_RECEIPT}"
FIXTURE_URL="$(printf '%s' "${FIXTURE_JSON}" | "${PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["repository_url"])')"

"${PYTHON}" "${CANDIDATE_ROOT}/scripts/bootstrap/build-canary-configs.py" \
  --base-config "${BASE_CONFIG}" --catalog "${CATALOG}" \
  --output-root "${CONFIG_ROOT}" \
  --state-root /var/lib/hermes-factory-pre-q8-convergence \
  --log-root "${LOG_ROOT}" --candidate-digest "${CANDIDATE_DIGEST}" \
  --controller-release-digest "${CONTROLLER_DIGEST}" \
  --source-commit "${SOURCE_COMMIT}" --stable-release-digest "${STABLE_DIGEST}" \
  --policy-digest "${POLICY_DIGEST}" --toolchain-digest "${TOOLCHAIN_DIGEST}" \
  --git-tree "${GIT_TREE}" --requirements-lock-digest "${REQUIREMENTS_DIGEST}" \
  --systemd-bundle-digest "${SYSTEMD_DIGEST}" \
  --qualification-plane CONVERGENCE --run-id "${RUN_ID}" \
  --epoch-id "${EPOCH_ID}" \
  --fixture-seed-digest "${FIXTURE_DIGEST}" \
  --matrix-digest "${MATRIX_PENDING_DIGEST}" \
  --capability-attestation-path "${ATTESTATION_PATH}" \
  --capability-attestation-digest "${ATTESTATION_DIGEST}" \
  --existing-repository-url "${FIXTURE_URL}" --first-port 9000 >/dev/null
chown root:hermesfunctional "${CONFIG_ROOT}"/*.yaml
chmod 0640 "${CONFIG_ROOT}"/*.yaml
chown root:root "${CONFIG_ROOT}/index.json"
chmod 0644 "${CONFIG_ROOT}/index.json"

run_as_verifier "${PYTHON}" -m scripts.pre_q8_convergence --database "${DATABASE}" \
  --run-id "${RUN_ID}" init --candidate-digest "${CANDIDATE_DIGEST}" \
  --git-tree "${GIT_TREE}" --release-tree-digest "${CANDIDATE_DIGEST}" \
  --toolchain-digest "${TOOLCHAIN_DIGEST}" >/dev/null

mapfile -t SCENARIOS < <("${PYTHON}" -c \
  'from factory.functional_readiness import PRE_Q8_SCENARIOS; print("\n".join(PRE_Q8_SCENARIOS))')
for scenario_id in "${SCENARIOS[@]}"; do
  instance="${RUN_ID}--${scenario_id}"
  result_path="${STATE_ROOT}/results/${scenario_id}.json"
  if ! systemctl start --wait \
    "hermes-factory-pre-q8-convergence-scenario@${instance}.service"; then
    if [[ ! -f "${result_path}" ]]; then
      run_as_verifier "${PYTHON}" -m scripts.pre_q8_convergence --database "${DATABASE}" \
        --run-id "${RUN_ID}" failure \
        --config "${CONFIG_ROOT}/${scenario_id}.yaml" \
        --failure-class SCENARIO_UNIT_FAILED \
        --evidence-root "${STATE_ROOT}/evidence/${scenario_id}" \
        --output "${result_path}" >/dev/null
    fi
  fi
  run_as_verifier "${PYTHON}" -m scripts.pre_q8_convergence --database "${DATABASE}" \
    --run-id "${RUN_ID}" record "${result_path}" >/dev/null
done

MATRIX_JSON="$(run_as_verifier "${PYTHON}" -m scripts.pre_q8_convergence \
  --database "${DATABASE}" --run-id "${RUN_ID}" matrix --output "${MATRIX}")"
RUN_STATUS="$(printf '%s' "${MATRIX_JSON}" | "${PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["status"])')"

"${PYTHON}" -m scripts.pre_q8_fixture --token-file "${TOKEN_FILE}" \
  --owner "${GITHUB_OWNER}" archive --receipt "${FIXTURE_RECEIPT}" \
  --output "${FIXTURE_ARCHIVE_RECEIPT}" >/dev/null
FIXTURE_PROVISIONED=0
chown root:hermesfunctional "${FIXTURE_ARCHIVE_RECEIPT}"
chmod 0640 "${FIXTURE_ARCHIVE_RECEIPT}"

if [[ "${RUN_STATUS}" != CONVERGENCE_10_OF_10 ]]; then
  printf 'PRE-Q8 convergence sweep failed; matrix retained at %s\n' "${MATRIX}" >&2
  exit 1
fi
run_as_verifier "${PYTHON}" -m scripts.pre_q8_convergence --database "${DATABASE}" \
  --run-id "${RUN_ID}" seal --official-index "${CONFIG_ROOT}/index.json" \
  --matrix "${MATRIX}" --private-key "${KEY_FILE}" --output "${SEAL}"
