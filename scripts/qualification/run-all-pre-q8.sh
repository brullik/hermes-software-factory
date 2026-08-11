#!/usr/bin/env bash
# Terminal repository cleanup is exact DELETE before official finalize.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run-all-pre-q8.sh must run as root\n' >&2
  exit 1
fi

INDEX=/etc/hermes-factory/pre-q8/index.json
SEAL_INPUT="${1:-${PRE_Q8_CONVERGENCE_SEAL:-/var/lib/hermes-factory-convergence/admitted/seal.json}}"
SEAL=/var/lib/hermes-factory-convergence/admitted/seal.json
PYTHON=/opt/hermes-factory-verifier/venv/bin/python
SETPRIV=/usr/bin/setpriv
CONTROL=/etc/hermes-factory/qualification-control.yaml
BASE_CONFIG=/etc/hermes-factory/candidate.yaml
CANDIDATE_ROOT=/opt/hermes-factory-candidate/current
TOKEN_FILE=/etc/hermes-factory/candidate-credentials.d/github-token
if [[ -n "${CREDENTIALS_DIRECTORY:-}" ]]; then
  TOKEN_FILE="${CREDENTIALS_DIRECTORY}/github-token"
fi
FIXTURE_PROVISIONED=0
FIXTURE_RECEIPT=""
REPOSITORY_LEDGER=""
REPOSITORY_CLEANUP_SUMMARY=""
GITHUB_OWNER=""
OFFICIAL_INVOCATION=0

if [[ -n "${1:-}" ]]; then
  OFFICIAL_INVOCATION=1
  systemctl stop hermes-factory-functional-qualification.timer
  systemctl stop hermes-factory-functional-qualification.service \
    hermes-factory-pre-q8.service >/dev/null 2>&1 || true
fi

run_as_verifier() {
  "${SETPRIV}" --reuid=hermesverifier --regid=hermesverifier --init-groups \
    --no-new-privs -- /usr/bin/env HOME=/var/lib/hermes-factory-verifier \
    USER=hermesverifier LOGNAME=hermesverifier "$@"
}

run_as_candidate() {
  "${SETPRIV}" --reuid=hermescandidate --regid=hermescandidate --init-groups \
    --no-new-privs -- /usr/bin/env HOME=/var/lib/hermes-factory-candidate \
    USER=hermescandidate LOGNAME=hermescandidate "$@"
}

install_admitted_seal() {
  local source="$1"
  local destination="$2"
  local temporary
  if [[ ! -f "${source}" || -L "${source}" ]]; then
    printf 'signed convergence seal source is unsafe\n' >&2
    return 66
  fi
  install -d -o root -g hermesfunctional -m 0750 "$(dirname -- "${destination}")"
  if [[ -e "${destination}" ]]; then
    if [[ ! -f "${destination}" || -L "${destination}" ]]; then
      printf 'admitted convergence seal path is unsafe\n' >&2
      return 73
    fi
    if cmp -s -- "${source}" "${destination}"; then
      return 0
    fi
    printf 'admitted convergence seal conflicts\n' >&2
    return 73
  fi
  temporary="${destination}.tmp.$$"
  rm -f -- "${temporary}"
  install -o root -g hermesfunctional -m 0640 "${source}" "${temporary}"
  cmp -s -- "${source}" "${temporary}"
  sync -f "${temporary}"
  mv -T -- "${temporary}" "${destination}"
  sync -f "$(dirname -- "${destination}")"
}

cleanup_repositories() {
  exit_status=$?
  trap - EXIT
  if [[ -n "${REPOSITORY_LEDGER}" && -f "${REPOSITORY_LEDGER}" ]]; then
    "${PYTHON}" -m scripts.pre_q8_repository_gc cleanup \
      --ledger "${REPOSITORY_LEDGER}" --token-file "${TOKEN_FILE}" \
      --output "${REPOSITORY_CLEANUP_SUMMARY}" --run-inactive \
      >/dev/null || exit_status=70
  fi
  if (( OFFICIAL_INVOCATION == 1 )); then
    systemctl start hermes-factory-functional-qualification.timer \
      >/dev/null 2>&1 || exit_status=70
  fi
  exit "${exit_status}"
}
trap cleanup_repositories EXIT

if [[ -n "${1:-}" ]]; then
  if [[ ! -f "${SEAL_INPUT}" || -L "${SEAL_INPUT}" ]]; then
    printf 'signed convergence seal is unavailable\n' >&2
    exit 66
  fi
  IDENTITY_JSON="$("${PYTHON}" -m scripts.pre_q8_runtime build-identity \
    --control "${CONTROL}" --candidate-config "${BASE_CONFIG}" \
    --candidate-root "${CANDIDATE_ROOT}" \
    --systemd-root "${CANDIDATE_ROOT}/config/systemd" \
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
  RUN_ID="$("${PYTHON}" -c \
    'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["run_id"])' \
    "${SEAL_INPUT}")"
  MATRIX_DIGEST="$("${PYTHON}" -c \
    'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["matrix_digest"])' \
    "${SEAL_INPUT}")"
  GITHUB_OWNER="$("${PYTHON}" -c \
    'import sys,yaml; print(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))["github"]["owner"])' \
    "${BASE_CONFIG}")"
  RUN_ROOT="/var/lib/hermes-factory-pre-q8/${EPOCH_ID}/${RUN_ID}"
  FIXTURE_RECEIPT="${RUN_ROOT}/fixture-provision.json"
  REPOSITORY_LEDGER="${RUN_ROOT}/repository-ledger.json"
  REPOSITORY_CLEANUP_SUMMARY="${RUN_ROOT}/repository-cleanup-summary.json"
  (
    umask 0007
    run_as_candidate /usr/bin/mkdir -p -- \
      /var/lib/hermes-factory-pre-q8 "${RUN_ROOT}" /var/log/hermes-factory-pre-q8
  )
  FIXTURE_JSON="$("${PYTHON}" -m scripts.pre_q8_fixture \
    --token-file "${TOKEN_FILE}" --owner "${GITHUB_OWNER}" provision \
    --plane pre-q8 --run-id "${RUN_ID}" --candidate-digest "${CANDIDATE_DIGEST}" \
    --receipt "${FIXTURE_RECEIPT}")"
  FIXTURE_PROVISIONED=1
  chown root:hermesfunctional "${FIXTURE_RECEIPT}"
  chmod 0640 "${FIXTURE_RECEIPT}"
  "${PYTHON}" -m scripts.pre_q8_repository_gc record-fixture \
    --ledger "${REPOSITORY_LEDGER}" --receipt "${FIXTURE_RECEIPT}" \
    --epoch-id "${EPOCH_ID}" --owner "${GITHUB_OWNER}" >/dev/null
  FIXTURE_URL="$(printf '%s' "${FIXTURE_JSON}" | "${PYTHON}" -c \
    'import json,sys; print(json.load(sys.stdin)["repository_url"])')"
  "${PYTHON}" "${CANDIDATE_ROOT}/scripts/bootstrap/build-canary-configs.py" \
    --base-config "${BASE_CONFIG}" \
    --catalog "${CANDIDATE_ROOT}/qualification/canaries/catalog.yaml" \
    --output-root /etc/hermes-factory/pre-q8 \
    --state-root /var/lib/hermes-factory-pre-q8 \
    --log-root /var/log/hermes-factory-pre-q8 \
    --candidate-digest "${CANDIDATE_DIGEST}" \
    --controller-release-digest "${CONTROLLER_DIGEST}" \
    --source-commit "${SOURCE_COMMIT}" --stable-release-digest "${STABLE_DIGEST}" \
    --policy-digest "${POLICY_DIGEST}" --toolchain-digest "${TOOLCHAIN_DIGEST}" \
    --git-tree "${GIT_TREE}" --requirements-lock-digest "${REQUIREMENTS_DIGEST}" \
    --systemd-bundle-digest "${SYSTEMD_DIGEST}" --qualification-plane PRE_Q8 \
    --run-id "${RUN_ID}" --epoch-id "${EPOCH_ID}" \
    --fixture-seed-digest "${FIXTURE_DIGEST}" \
    --matrix-digest "${MATRIX_DIGEST}" \
    --capability-attestation-path "${ATTESTATION_PATH}" \
    --capability-attestation-digest "${ATTESTATION_DIGEST}" \
    --schema-registry-root /etc/hermes-factory/pre-q8-schema-registry \
    --existing-repository-url "${FIXTURE_URL}" --first-port 8890 >/dev/null
  chown root:hermesfunctional /etc/hermes-factory/pre-q8/*.yaml
  chmod 0640 /etc/hermes-factory/pre-q8/*.yaml
  chown root:root "${INDEX}"
  chmod 0644 "${INDEX}"
  install_admitted_seal "${SEAL_INPUT}" "${SEAL}"
fi

if [[ ! -f "${INDEX}" || ! -f "${SEAL}" ]]; then
  printf 'Official PRE-Q8 admission artifacts are unavailable\n' >&2
  exit 66
fi
if (( FIXTURE_PROVISIONED == 0 )); then
  EPOCH_ID="$("${PYTHON}" -c \
    'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["epoch_id"])' \
    "${INDEX}")"
  RUN_ID="$("${PYTHON}" -c \
    'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["run_id"])' \
    "${INDEX}")"
  GITHUB_OWNER="$("${PYTHON}" -c \
    'import sys,yaml; print(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))["github"]["owner"])' \
    "${BASE_CONFIG}")"
  FIXTURE_RECEIPT="/var/lib/hermes-factory-pre-q8/${EPOCH_ID}/${RUN_ID}/fixture-provision.json"
  REPOSITORY_LEDGER="/var/lib/hermes-factory-pre-q8/${EPOCH_ID}/${RUN_ID}/repository-ledger.json"
  REPOSITORY_CLEANUP_SUMMARY="/var/lib/hermes-factory-pre-q8/${EPOCH_ID}/${RUN_ID}/repository-cleanup-summary.json"
  [[ -f "${FIXTURE_RECEIPT}" && -f "${REPOSITORY_LEDGER}" ]] \
    && FIXTURE_PROVISIONED=1
fi

STATUS_JSON="$(run_as_verifier "${PYTHON}" -m scripts.functional_qualification status)"
EPOCH_STATUS="$(printf '%s' "${STATUS_JSON}" | "${PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["epoch"]["status"])')"
case "${EPOCH_STATUS}" in
  QUALIFICATION_FAILED)
    printf 'Official PRE-Q8 Candidate is terminal; timer retry is forbidden\n' >&2
    exit 1
    ;;
  GOLDEN_PRODUCT_PENDING|READY_EVALUATION|FUNCTIONALLY_READY|Q7_STARTED) exit 0 ;;
  PRE_Q8_PENDING|PRE_Q8_RUNNING) ;;
  *) printf 'Official PRE-Q8 is unavailable from %s\n' "${EPOCH_STATUS}" >&2; exit 1 ;;
esac

run_as_verifier "${PYTHON}" -m scripts.functional_qualification \
  --pre-q8-index "${INDEX}" pre-q8-admit "${SEAL}" >/dev/null

# Discovery belongs to the isolated convergence lane. This official loop is
# intentionally fail-fast because its first failure terminalizes the Candidate.
mapfile -t SCENARIOS < <(run_as_verifier "${PYTHON}" -c \
  'from factory.functional_readiness import PRE_Q8_SCENARIOS; print("\n".join(PRE_Q8_SCENARIOS))')
INDEX_ORDER="$("${PYTHON}" -c \
  'import json,sys; print("\n".join(x["scenario_id"] for x in json.load(open(sys.argv[1],encoding="utf-8"))["scenarios"]))' \
  "${INDEX}")"
if [[ "${INDEX_ORDER}" != "$(printf '%s\n' "${SCENARIOS[@]}")" ]]; then
  printf 'PRE-Q8 index order differs from the canonical catalog\n' >&2
  exit 65
fi

for scenario_id in "${SCENARIOS[@]}"; do
  scenario_failed=0
  systemctl start --wait "hermes-factory-pre-q8@${scenario_id}.service" \
    || scenario_failed=1
  "${PYTHON}" -m scripts.pre_q8_repository_gc freeze-scenario \
    --ledger "${REPOSITORY_LEDGER}" --scenario-id "${scenario_id}" \
    --evidence-root "/var/lib/hermes-factory-pre-q8/${EPOCH_ID}/${RUN_ID}/${scenario_id}/evidence" \
    >/dev/null
  if (( scenario_failed == 1 )); then
    STATUS_JSON="$(run_as_verifier "${PYTHON}" -m scripts.functional_qualification status)"
    EPOCH_STATUS="$(printf '%s' "${STATUS_JSON}" | "${PYTHON}" -c \
      'import json,sys; print(json.load(sys.stdin)["epoch"]["status"])')"
    if [[ "${EPOCH_STATUS}" != QUALIFICATION_FAILED ]]; then
      run_as_verifier "${PYTHON}" -m scripts.functional_qualification \
        pre-q8-fail "${scenario_id}" SCENARIO_UNIT_FAILED \
        "/etc/hermes-factory/pre-q8/${scenario_id}.yaml" >/dev/null
    fi
    exit 1
  fi
done

GC_JSON="$("${PYTHON}" -m scripts.pre_q8_repository_gc cleanup \
  --ledger "${REPOSITORY_LEDGER}" --token-file "${TOKEN_FILE}" \
  --output "${REPOSITORY_CLEANUP_SUMMARY}" --run-inactive)"
FIXTURE_PROVISIONED=0
repository_residue="$(printf '%s' "${GC_JSON}" | "${PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["repository_residue_count"])')"
cleanup_failed="$(printf '%s' "${GC_JSON}" | "${PYTHON}" -c \
  'import json,sys; print(json.load(sys.stdin)["cleanup_failed_count"])')"
if [[ "${repository_residue}" != 0 || "${cleanup_failed}" != 0 ]]; then
  printf 'Official PRE-Q8 repository residue is nonzero\n' >&2
  exit 70
fi

run_as_verifier "${PYTHON}" -m scripts.functional_qualification pre-q8-finalize >/dev/null
SOURCE_COMMIT="$("${PYTHON}" -c \
  'import sys,yaml; print(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))["source_commit"])' \
  "${CONTROL}")"
run_as_verifier "${PYTHON}" "${CANDIDATE_ROOT}/tools/preq8_final_assert.py" \
  --expected-source-commit "${SOURCE_COMMIT}" \
  --json-out "/var/lib/hermes-factory-pre-q8/${EPOCH_ID}/${RUN_ID}/preq8-final-assert.json"
