#!/usr/bin/env bash
set -euo pipefail
umask 022

# Install Candidate B and its independent verifier beside an existing Stable A.
# This script never writes Stable A's current tree, database, credentials, or units.

if [[ "${EUID}" -ne 0 ]]; then
  printf 'prepare-candidate-plane.sh must run as root\n' >&2
  exit 1
fi

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_USER="${SERVICE_USER:-hermesfactory}"
CANDIDATE_USER="${CANDIDATE_USER:-hermescandidate}"
VERIFIER_USER="${VERIFIER_USER:-hermesverifier}"
BROKER_USER="${BROKER_USER:-hermesgithubbroker}"
FUNCTIONAL_GROUP="${FUNCTIONAL_GROUP:-hermesfunctional}"
CANDIDATE_ROOT="${CANDIDATE_ROOT:-/opt/hermes-factory-candidate}"
VERIFIER_ROOT="${VERIFIER_ROOT:-/opt/hermes-factory-verifier}"
CANDIDATE_STATE="${CANDIDATE_STATE:-/var/lib/hermes-factory-candidate}"
VERIFIER_STATE="${VERIFIER_STATE:-/var/lib/hermes-factory-verifier}"
CANARY_STATE="${CANARY_STATE:-/var/lib/hermes-factory-canaries}"
CANARY_LOG_ROOT="${CANARY_LOG_ROOT:-/var/log/hermes-factory-canaries}"
SHADOW_OUTPUT_ROOT="${SHADOW_OUTPUT_ROOT:-/var/lib/hermes-factory-shadow-output}"
QUALIFICATION_BACKUP_ROOT="${QUALIFICATION_BACKUP_ROOT:-/var/lib/hermes-factory-qualification-backup}"
FUNCTIONAL_STATE="${FUNCTIONAL_STATE:-/var/lib/hermes-factory-functional}"
PRE_Q8_STATE="${PRE_Q8_STATE:-/var/lib/hermes-factory-pre-q8}"
PRE_Q8_LOG_ROOT="${PRE_Q8_LOG_ROOT:-/var/log/hermes-factory-pre-q8}"
IMPROVEMENT_STATE="${IMPROVEMENT_STATE:-/var/lib/hermes-factory-improvement-lab}"
CONFIG_ROOT="${CONFIG_ROOT:-/etc/hermes-factory}"
CANARY_EXISTING_REPOSITORY_URL="${CANARY_EXISTING_REPOSITORY_URL:-https://github.com/brullik/hermes-path-governor-shadow-20260803}"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
HERMES_AGENT_VERSION="${HERMES_AGENT_VERSION:-0.19.0}"
HERMES_AGENT_SHA256="${HERMES_AGENT_SHA256:-bd0bac012aee38a60894781f4597dc29ee7bedb3448540249921f10d3bef327f}"

for command_name in cc git make openssl podman restic "${PYTHON_BIN}"; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'Required Candidate B tool is missing: %s\n' "${command_name}" >&2
    exit 69
  fi
done
if [[ ! -x /usr/local/bin/osv-scanner ]]; then
  printf 'Required Candidate B tool is missing: /usr/local/bin/osv-scanner\n' >&2
  exit 69
fi
if [[ ! -d "${SOURCE_ROOT}/.git" ]]; then
  printf 'Candidate source must be a Git checkout\n' >&2
  exit 65
fi
if [[ -n "$(git -C "${SOURCE_ROOT}" status --porcelain=v1 --untracked-files=all)" ]]; then
  printf 'Candidate source checkout is not clean\n' >&2
  exit 65
fi
if [[ "$(git -C "${SOURCE_ROOT}" config --bool --get remote.origin.promisor || true)" == true ]] \
  || [[ -n "$(git -C "${SOURCE_ROOT}" config --get extensions.partialClone || true)" ]]; then
  printf 'Candidate source must be a complete Git checkout, not a partial clone\n' >&2
  exit 65
fi

SOURCE_COMMIT="$(git -C "${SOURCE_ROOT}" rev-parse HEAD)"
if [[ ! "${SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ ]]; then
  printf 'Candidate source commit is invalid\n' >&2
  exit 65
fi
if [[ ! -d /opt/hermes-factory/current || ! -f /var/lib/hermes-factory/controller.db ]]; then
  printf 'Stable A installation is unavailable\n' >&2
  exit 66
fi

if ! id "${CANDIDATE_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${CANDIDATE_STATE}" --create-home --shell /usr/sbin/nologin "${CANDIDATE_USER}"
fi
if ! id "${VERIFIER_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${VERIFIER_STATE}" --create-home --shell /usr/sbin/nologin "${VERIFIER_USER}"
fi
if ! getent group "${FUNCTIONAL_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${FUNCTIONAL_GROUP}"
fi
if ! id "${BROKER_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/hermes-factory-github-broker \
    --create-home --shell /usr/sbin/nologin "${BROKER_USER}"
fi
if [[ "${CANDIDATE_USER}" == "${VERIFIER_USER}" || "${CANDIDATE_USER}" == "${SERVICE_USER}" || "${VERIFIER_USER}" == "${SERVICE_USER}" ]]; then
  printf 'Stable, candidate, and verifier users must be distinct\n' >&2
  exit 78
fi
if ! getent group hermesshadow >/dev/null 2>&1; then
  groupadd --system hermesshadow
fi
for shadow_member in "${SERVICE_USER}" "${CANDIDATE_USER}" "${VERIFIER_USER}"; do
  usermod --append --groups hermesshadow "${shadow_member}"
done
for functional_member in "${SERVICE_USER}" "${CANDIDATE_USER}" "${VERIFIER_USER}" "${BROKER_USER}"; do
  usermod --append --groups "${FUNCTIONAL_GROUP}" "${functional_member}"
done
if ! grep -q "^${CANDIDATE_USER}:" /etc/subuid; then
  usermod --add-subuids 1100000-1165535 "${CANDIDATE_USER}"
fi
if ! grep -q "^${CANDIDATE_USER}:" /etc/subgid; then
  usermod --add-subgids 1100000-1165535 "${CANDIDATE_USER}"
fi

install -d -o root -g root -m 0755 \
  "${CANDIDATE_ROOT}" "${CANDIDATE_ROOT}/releases" "${CANDIDATE_ROOT}/venvs" \
  "${VERIFIER_ROOT}" "${VERIFIER_ROOT}/releases" "${VERIFIER_ROOT}/venvs"

ALLOW_EPOCH_SWITCH=0
if [[ -L "${CANDIDATE_ROOT}/current" ]] \
  && [[ "$(basename "$(readlink -f "${CANDIDATE_ROOT}/current")")" != "${SOURCE_COMMIT}" ]]; then
  OLD_SOURCE_COMMIT="$(basename "$(readlink -f "${CANDIDATE_ROOT}/current")")"
  OLD_QUALIFICATION_CONFIG="${CONFIG_ROOT}/qualification-control.yaml"
  if [[ ! -f "${OLD_QUALIFICATION_CONFIG}" ]]; then
    OLD_QUALIFICATION_CONFIG="${CONFIG_ROOT}/qualification-epochs/${OLD_SOURCE_COMMIT}/qualification-control.yaml"
  fi
  if [[ ! "${OLD_SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ ]] \
    || [[ ! -x "${VERIFIER_ROOT}/venv/bin/python" ]] \
    || [[ ! -f "${OLD_QUALIFICATION_CONFIG}" ]]; then
    printf 'Previous Candidate B epoch cannot be identified safely\n' >&2
    exit 73
  fi
  OLD_STATUS_JSON="$(runuser -u "${VERIFIER_USER}" -- \
    "${VERIFIER_ROOT}/venv/bin/python" -m scripts.qualification_control \
    --config "${OLD_QUALIFICATION_CONFIG}" status)"
  OLD_EPOCH_STATUS="$(OLD_STATUS_JSON="${OLD_STATUS_JSON}" \
    "${VERIFIER_ROOT}/venv/bin/python" -c \
    'import json,os; print(json.loads(os.environ["OLD_STATUS_JSON"])["status"])')"
  if [[ "${OLD_EPOCH_STATUS}" != QUALIFICATION_FAILED && "${OLD_EPOCH_STATUS}" != LTS ]]; then
    printf 'Previous Candidate B epoch is not terminal: %s\n' "${OLD_EPOCH_STATUS}" >&2
    exit 73
  fi
  systemctl disable --now \
    hermes-factory-shadow-verify.timer \
    hermes-factory-shadow-finalize.timer >/dev/null 2>&1 || true
  ACTIVE_CANDIDATE_UNITS="$(systemctl list-units --type=service --state=active \
    --no-legend --plain 'hermes-factory-candidate-*' 'hermes-factory-canary-*' \
    'hermes-factory-clean-canary@*' 'hermes-factory-shadow-*' || true)"
  if [[ -n "${ACTIVE_CANDIDATE_UNITS}" ]]; then
    printf 'Previous Candidate B processes are still active\n' >&2
    exit 73
  fi
  ALLOW_EPOCH_SWITCH=1
fi
install -d -o "${CANDIDATE_USER}" -g "${CANDIDATE_USER}" -m 0750 \
  "${CANDIDATE_STATE}" "${CANDIDATE_STATE}/evidence" \
  "${CANDIDATE_STATE}/qualification" "${CANDIDATE_STATE}/worktrees" \
  /var/log/hermes-factory-candidate
chgrp "${FUNCTIONAL_GROUP}" "${CANDIDATE_STATE}" "${CANDIDATE_STATE}/worktrees"
chmod 2770 "${CANDIDATE_STATE}" "${CANDIDATE_STATE}/worktrees"
install -d -o "${VERIFIER_USER}" -g "${VERIFIER_USER}" -m 0750 \
  "${VERIFIER_STATE}" "${VERIFIER_STATE}/evidence/${SOURCE_COMMIT}" \
  "${VERIFIER_STATE}/shadow-journal/${SOURCE_COMMIT}" \
  "${VERIFIER_STATE}/canaries/${SOURCE_COMMIT}" \
  "${VERIFIER_STATE}/manifests/${SOURCE_COMMIT}"
install -d -o "${CANDIDATE_USER}" -g "${CANDIDATE_USER}" -m 0750 \
  "${CANARY_STATE}" "${CANARY_STATE}/${SOURCE_COMMIT}" \
  "${CANARY_LOG_ROOT}" "${CANARY_LOG_ROOT}/${SOURCE_COMMIT}"
install -d -o "${VERIFIER_USER}" -g "${FUNCTIONAL_GROUP}" -m 2770 \
  "${FUNCTIONAL_STATE}" "${FUNCTIONAL_STATE}/q6-5" \
  "${FUNCTIONAL_STATE}/notifications" "${FUNCTIONAL_STATE}/notifications/outbox" \
  "${FUNCTIONAL_STATE}/notifications/receipts" "${IMPROVEMENT_STATE}"
install -d -o "${CANDIDATE_USER}" -g "${FUNCTIONAL_GROUP}" -m 2770 \
  "${PRE_Q8_STATE}" "${PRE_Q8_STATE}/${SOURCE_COMMIT}" \
  "${PRE_Q8_LOG_ROOT}" "${PRE_Q8_LOG_ROOT}/${SOURCE_COMMIT}"
install -d -o "${CANDIDATE_USER}" -g "${FUNCTIONAL_GROUP}" -m 2770 \
  /var/lib/hermes-factory-golden /var/log/hermes-factory-golden
install -d -o root -g hermesshadow -m 2750 "${SHADOW_OUTPUT_ROOT}"
install -d -o "${CANDIDATE_USER}" -g hermesshadow -m 2750 \
  "${SHADOW_OUTPUT_ROOT}/${SOURCE_COMMIT}"
install -d -o "${SERVICE_USER}" -g hermesshadow -m 2750 \
  /var/lib/hermes-factory-shadow-feed
install -d -o root -g "${CANDIDATE_USER}" -m 0750 \
  "${CONFIG_ROOT}/candidate-credentials.d"
install -d -o root -g root -m 0755 "${CONFIG_ROOT}/qualification-manifests"
install -d -o root -g root -m 0700 "${QUALIFICATION_BACKUP_ROOT}"
install -d -o root -g "${CANDIDATE_USER}" -m 0750 "${CONFIG_ROOT}/canaries"
install -d -o root -g "${CANDIDATE_USER}" -m 0750 "${CONFIG_ROOT}/pre-q8"
chown root:root "${CONFIG_ROOT}"
chmod 0711 "${CONFIG_ROOT}"

CANDIDATE_RELEASE="${CANDIDATE_ROOT}/releases/${SOURCE_COMMIT}"
VERIFIER_RELEASE="${VERIFIER_ROOT}/releases/${SOURCE_COMMIT}"
for release_root in "${CANDIDATE_RELEASE}" "${VERIFIER_RELEASE}"; do
  if [[ -e "${release_root}" ]]; then
    if [[ ! -d "${release_root}/.git" ]] \
      || [[ "$(git -C "${release_root}" rev-parse HEAD)" != "${SOURCE_COMMIT}" ]] \
      || [[ -n "$(git -C "${release_root}" status --porcelain=v1 --untracked-files=all)" ]]; then
      printf 'Existing immutable release conflicts: %s\n' "${release_root}" >&2
      exit 73
    fi
  else
    git clone --quiet --local --no-hardlinks "${SOURCE_ROOT}" "${release_root}"
    git -C "${release_root}" checkout --quiet --detach "${SOURCE_COMMIT}"
  fi
  chown -R root:root "${release_root}"
  find "${release_root}" -type d -exec chmod 0755 {} +
  if [[ -n "$(git -C "${release_root}" status --porcelain=v1 --untracked-files=all)" ]]; then
    printf 'Immutable release mode/content differs from Git: %s\n' "${release_root}" >&2
    exit 73
  fi
done

for plane in candidate verifier; do
  if [[ "${plane}" == candidate ]]; then
    plane_root="${CANDIDATE_ROOT}"
    release_root="${CANDIDATE_RELEASE}"
  else
    plane_root="${VERIFIER_ROOT}"
    release_root="${VERIFIER_RELEASE}"
  fi
  venv_root="${plane_root}/venvs/${SOURCE_COMMIT}"
  venv_ready_marker="${venv_root}/.hermes-bootstrap-complete"
  venv_valid=0
  if [[ -d "${venv_root}" ]] \
    && [[ -x "${venv_root}/bin/python" ]] \
    && [[ -f "${venv_ready_marker}" ]] \
    && [[ "$(<"${venv_ready_marker}")" == "${SOURCE_COMMIT}" ]] \
    && "${venv_root}/bin/python" -m pip check >/dev/null 2>&1; then
    venv_valid=1
  fi
  if [[ -e "${venv_root}" && "${venv_valid}" -ne 1 ]]; then
    if [[ -L "${plane_root}/venv" ]] \
      && [[ "$(readlink -f "${plane_root}/venv")" == "${venv_root}" ]]; then
      printf 'Refusing to rebuild the active incomplete environment: %s\n' "${venv_root}" >&2
      exit 73
    fi
    rm -rf -- "${venv_root}"
  fi
  if (( venv_valid != 1 )); then
    "${PYTHON_BIN}" -m venv "${venv_root}"
    "${venv_root}/bin/python" -m pip install --disable-pip-version-check \
      --requirement "${release_root}/requirements.lock"
    "${venv_root}/bin/python" -m pip install --disable-pip-version-check \
      --no-deps "git+file://${release_root}@${SOURCE_COMMIT}"
    "${venv_root}/bin/python" -m pip check
    printf '%s\n' "${SOURCE_COMMIT}" > "${venv_ready_marker}"
  fi
  chown -R root:root "${venv_root}"
  if [[ -e "${plane_root}/current" && ! -L "${plane_root}/current" ]]; then
    printf 'Candidate/verifier current path is not a symlink: %s\n' "${plane_root}/current" >&2
    exit 73
  fi
  if [[ -L "${plane_root}/current" ]] \
    && [[ "$(readlink -f "${plane_root}/current")" != "${release_root}" ]]; then
    if (( ALLOW_EPOCH_SWITCH != 1 )); then
      printf 'Refusing to change an active release epoch symlink: %s\n' "${plane_root}/current" >&2
      exit 73
    fi
  fi
  if [[ ! -e "${plane_root}/current" ]]; then
    ln -s "${release_root}" "${plane_root}/current"
  fi
  if [[ -e "${plane_root}/venv" && ! -L "${plane_root}/venv" ]]; then
    printf 'Candidate/verifier venv path is not a symlink: %s\n' "${plane_root}/venv" >&2
    exit 73
  fi
  if [[ -L "${plane_root}/venv" ]] \
    && [[ "$(readlink -f "${plane_root}/venv")" != "${venv_root}" ]]; then
    if (( ALLOW_EPOCH_SWITCH != 1 )); then
      printf 'Refusing to change an active release epoch venv: %s\n' "${plane_root}/venv" >&2
      exit 73
    fi
  fi
  if [[ ! -e "${plane_root}/venv" ]]; then
    ln -s "${venv_root}" "${plane_root}/venv"
  fi
done

if (( ALLOW_EPOCH_SWITCH == 1 )); then
  EPOCH_CONFIG_ARCHIVE="${CONFIG_ROOT}/qualification-epochs/${OLD_SOURCE_COMMIT}"
  install -d -o root -g root -m 0711 "${EPOCH_CONFIG_ARCHIVE}"
  for epoch_config in \
    qualification-control.yaml verifier.yaml candidate.yaml golden.yaml \
    candidate-model-registry.yaml canary-capability-attestation.json \
    q6-capability-attestation.json; do
    if [[ -e "${CONFIG_ROOT}/${epoch_config}" ]]; then
      if [[ -e "${EPOCH_CONFIG_ARCHIVE}/${epoch_config}" ]]; then
        printf 'Previous epoch config archive conflicts: %s\n' "${epoch_config}" >&2
        exit 73
      fi
      mv -- "${CONFIG_ROOT}/${epoch_config}" "${EPOCH_CONFIG_ARCHIVE}/${epoch_config}"
    fi
  done
  if [[ -d "${CONFIG_ROOT}/canaries" ]]; then
    if [[ -e "${EPOCH_CONFIG_ARCHIVE}/canaries" ]]; then
      printf 'Previous canary config archive conflicts\n' >&2
      exit 73
    fi
    mv -- "${CONFIG_ROOT}/canaries" "${EPOCH_CONFIG_ARCHIVE}/canaries"
  fi
  if [[ -d "${CONFIG_ROOT}/pre-q8" ]]; then
    if [[ -e "${EPOCH_CONFIG_ARCHIVE}/pre-q8" ]]; then
      printf 'Previous PRE-Q8 config archive conflicts\n' >&2
      exit 73
    fi
    mv -- "${CONFIG_ROOT}/pre-q8" "${EPOCH_CONFIG_ARCHIVE}/pre-q8"
  fi
  if [[ -f "${FUNCTIONAL_STATE}/q6-5/report-index.json" ]]; then
    install -d -o "${VERIFIER_USER}" -g "${FUNCTIONAL_GROUP}" -m 2770 \
      "${FUNCTIONAL_STATE}/q6-5/${OLD_SOURCE_COMMIT}"
    mv -- "${FUNCTIONAL_STATE}/q6-5/report-index.json" \
      "${FUNCTIONAL_STATE}/q6-5/${OLD_SOURCE_COMMIT}/report-index.json"
  fi
  ln -sfn "${VERIFIER_ROOT}/venvs/${SOURCE_COMMIT}" "${VERIFIER_ROOT}/venv"
  ln -sfn "${VERIFIER_RELEASE}" "${VERIFIER_ROOT}/current"
  ln -sfn "${CANDIDATE_ROOT}/venvs/${SOURCE_COMMIT}" "${CANDIDATE_ROOT}/venv"
  ln -sfn "${CANDIDATE_RELEASE}" "${CANDIDATE_ROOT}/current"
fi

HERMES_WHEEL_DIR="$(mktemp -d)"
trap 'rm -rf "${HERMES_WHEEL_DIR}"' EXIT
"${CANDIDATE_ROOT}/venv/bin/python" -m pip download \
  --disable-pip-version-check --no-cache-dir --no-deps \
  --dest "${HERMES_WHEEL_DIR}" "hermes-agent==${HERMES_AGENT_VERSION}"
HERMES_WHEEL="$(find "${HERMES_WHEEL_DIR}" -maxdepth 1 -type f -name 'hermes_agent-*.whl' -print -quit)"
if [[ -z "${HERMES_WHEEL}" ]] \
  || [[ "$(sha256sum "${HERMES_WHEEL}" | awk '{print $1}')" != "${HERMES_AGENT_SHA256}" ]]; then
  printf 'Hermes Agent wheel is missing or has the wrong digest\n' >&2
  exit 65
fi
"${CANDIDATE_ROOT}/venv/bin/python" -m pip install \
  --disable-pip-version-check --no-cache-dir "${HERMES_WHEEL}"
"${CANDIDATE_ROOT}/venv/bin/python" -m pip install \
  --disable-pip-version-check --requirement "${CANDIDATE_RELEASE}/requirements.lock"
"${CANDIDATE_ROOT}/venv/bin/python" -m pip check
rm -rf "${HERMES_WHEEL_DIR}"
trap - EXIT
chown -R root:root "${CANDIDATE_ROOT}/venvs/${SOURCE_COMMIT}"

if [[ ! -f "${CONFIG_ROOT}/candidate.yaml" ]]; then
  "${CANDIDATE_ROOT}/venv/bin/python" \
    "${CANDIDATE_ROOT}/current/scripts/bootstrap/build-candidate-config.py" \
    --source "${CANDIDATE_ROOT}/current/config/factory-config.example.yaml" \
    --output "${CONFIG_ROOT}/candidate.yaml" \
    --install-root "${CANDIDATE_ROOT}" \
    --state-root "${CANDIDATE_STATE}" \
    --log-root /var/log/hermes-factory-candidate \
    --admin-port 8788
  chown root:"${CANDIDATE_USER}" "${CONFIG_ROOT}/candidate.yaml"
  chmod 0640 "${CONFIG_ROOT}/candidate.yaml"
fi
if [[ ! -f "${CONFIG_ROOT}/candidate-model-registry.yaml" ]]; then
  install -o root -g "${CANDIDATE_USER}" -m 0640 \
    "${CANDIDATE_ROOT}/current/config/model-routing/model-registry.template.yaml" \
    "${CONFIG_ROOT}/candidate-model-registry.yaml"
fi
if [[ ! -f "${VERIFIER_STATE}/verifier-ed25519.key" ]]; then
  "${VERIFIER_ROOT}/venv/bin/python" -m scripts.release_qualify init-key \
    --private-key "${VERIFIER_STATE}/verifier-ed25519.key"
  chown "${VERIFIER_USER}":"${VERIFIER_USER}" "${VERIFIER_STATE}/verifier-ed25519.key"
  chmod 0600 "${VERIFIER_STATE}/verifier-ed25519.key"
fi

STABLE_DIGEST="$("${VERIFIER_ROOT}/venv/bin/python" -c \
  'from pathlib import Path; from factory.release_executor import _release_digest; print(_release_digest(Path("/opt/hermes-factory/current")).removeprefix("sha256:"))')"
CANDIDATE_DIGEST="$("${VERIFIER_ROOT}/venv/bin/python" -c \
  'from pathlib import Path; from factory.qualification_runner import _immutable_release_tree_digest; print(_immutable_release_tree_digest(Path("/opt/hermes-factory-candidate/current")))')"
CONTROLLER_DIGEST="$("${VERIFIER_ROOT}/venv/bin/python" -c \
  'from pathlib import Path; from factory.proof_obligations import controller_source_digest; print(controller_source_digest(Path("/opt/hermes-factory-candidate/current")))')"
POLICY_DIGEST="$(FACTORY_CONFIG="${CONFIG_ROOT}/candidate.yaml" \
  "${VERIFIER_ROOT}/venv/bin/python" -c \
  'from pathlib import Path; from factory.config import load_config; from factory.policy import policy_digest; print(policy_digest(load_config(Path("/etc/hermes-factory/candidate.yaml"))))')"
TOOLCHAIN_DIGEST="$(CONTROLLER_DIGEST="${CONTROLLER_DIGEST}" \
  "${VERIFIER_ROOT}/venv/bin/python" -c \
  'from factory.proof_obligations import local_toolchain_manifest; import os; print(local_toolchain_manifest(os.environ["CONTROLLER_DIGEST"]).manifest_digest)')"
VERIFIER_IDENTITY_JSON="$(runuser -u "${VERIFIER_USER}" -- \
  "${VERIFIER_ROOT}/venv/bin/python" -m scripts.release_qualify key-info \
  --private-key "${VERIFIER_STATE}/verifier-ed25519.key" \
  --code-root "${VERIFIER_RELEASE}")"
VERIFIER_KEY_DIGEST="$(VERIFIER_IDENTITY_JSON="${VERIFIER_IDENTITY_JSON}" \
  "${VERIFIER_ROOT}/venv/bin/python" -c \
  'import json,os; print(json.loads(os.environ["VERIFIER_IDENTITY_JSON"])["public_key_digest"])')"
VERIFIER_PUBLIC_KEY="$(VERIFIER_IDENTITY_JSON="${VERIFIER_IDENTITY_JSON}" \
  "${VERIFIER_ROOT}/venv/bin/python" -c \
  'import json,os; print(json.loads(os.environ["VERIFIER_IDENTITY_JSON"])["public_key"])')"
VERIFIER_DIGEST="$(VERIFIER_IDENTITY_JSON="${VERIFIER_IDENTITY_JSON}" \
  "${VERIFIER_ROOT}/venv/bin/python" -c \
  'import json,os; print(json.loads(os.environ["VERIFIER_IDENTITY_JSON"])["verifier_digest"])')"
MANIFEST_REQUEST_PATH="${VERIFIER_STATE}/manifests/${SOURCE_COMMIT}/unsigned-manifest.json"
SIGNED_MANIFEST_PATH="${VERIFIER_STATE}/manifests/${SOURCE_COMMIT}/signed-manifest.json"
RESILIENCE_PROOF_INDEX="${VERIFIER_STATE}/resilience/${SOURCE_COMMIT}/proof-index.json"
PROMOTION_RECEIPT_PATH="/var/lib/hermes-factory/evidence/root-release-hermes-factory-${SOURCE_COMMIT:0:12}.json"
PRODUCTION_OBSERVATION_PATH="${VERIFIER_STATE}/production-observation/${SOURCE_COMMIT}.json"
PRODUCTION_ROLLBACK_PATH="${VERIFIER_STATE}/production-observation/${SOURCE_COMMIT}-rollback.json"
FACTORY_REPOSITORY="$(${VERIFIER_ROOT}/venv/bin/python -c \
  'import yaml; value=yaml.safe_load(open("/etc/hermes-factory/config.yaml", encoding="utf-8")); github=value["github"]; print("{}/{}".format(github["owner"], github["factory_repository"]))')"

if [[ ! -f "${CONFIG_ROOT}/qualification-backup-password" ]]; then
  QUALIFICATION_PASSWORD_TMP="$(mktemp)"
  trap 'rm -f "${QUALIFICATION_PASSWORD_TMP}"' EXIT
  openssl rand -base64 48 > "${QUALIFICATION_PASSWORD_TMP}"
  install -o root -g root -m 0600 \
    "${QUALIFICATION_PASSWORD_TMP}" "${CONFIG_ROOT}/qualification-backup-password"
  rm -f "${QUALIFICATION_PASSWORD_TMP}"
  trap - EXIT
fi
if [[ ! -f "${QUALIFICATION_BACKUP_ROOT}/repository/config" ]]; then
  RESTIC_REPOSITORY="${QUALIFICATION_BACKUP_ROOT}/repository" \
  RESTIC_PASSWORD_FILE="${CONFIG_ROOT}/qualification-backup-password" \
    restic init >/dev/null
fi

Q6_ATTESTATION="${CONFIG_ROOT}/q6-capability-attestation.json"
Q6_PODMAN_STATE="${CANDIDATE_STATE}/podman"
Q6_RUNTIME_DIR="/run/hermes-factory-candidate"
env \
  SERVICE_USER="${CANDIDATE_USER}" \
  STATE_DIR="${Q6_PODMAN_STATE}" \
  RUNTIME_DIR="${Q6_RUNTIME_DIR}" \
  "${CANDIDATE_RELEASE}/scripts/bootstrap/preflight-rootless-podman.sh"
if [[ ! -f "${Q6_ATTESTATION}" ]]; then
  "${VERIFIER_ROOT}/venv/bin/python" \
    "${VERIFIER_RELEASE}/scripts/bootstrap/build-canary-attestation.py" \
    --output "${Q6_ATTESTATION}" \
    --plane ISOLATED_Q6 \
    --service-user "${CANDIDATE_USER}" \
    --state-dir "${Q6_PODMAN_STATE}" \
    --runtime-dir "${Q6_RUNTIME_DIR}" \
    --source-commit "${SOURCE_COMMIT}"
  chown root:"${VERIFIER_USER}" "${Q6_ATTESTATION}"
  chmod 0640 "${Q6_ATTESTATION}"
fi
Q6_ATTESTATION_DIGEST="$(sha256sum "${Q6_ATTESTATION}" | awk '{print $1}')"

if [[ ! -f "${CONFIG_ROOT}/qualification-control.yaml" ]]; then
  "${VERIFIER_ROOT}/venv/bin/python" \
    "${VERIFIER_ROOT}/current/scripts/bootstrap/build-qualification-config.py" \
    --output "${CONFIG_ROOT}/qualification-control.yaml" \
    --governor-database "${VERIFIER_STATE}/governor.db" \
    --candidate-repository-root "${CANDIDATE_RELEASE}" \
    --evidence-root "${VERIFIER_STATE}/evidence/${SOURCE_COMMIT}" \
    --shadow-journal-root "${VERIFIER_STATE}/shadow-journal/${SOURCE_COMMIT}" \
    --shadow-feed-root /var/lib/hermes-factory-shadow-feed \
    --candidate-shadow-output-root "${SHADOW_OUTPUT_ROOT}/${SOURCE_COMMIT}" \
    --stable-release-root /opt/hermes-factory/current \
    --candidate-database "${SHADOW_OUTPUT_ROOT}/${SOURCE_COMMIT}/candidate-shadow.db" \
    --q6-capability-attestation-path "${Q6_ATTESTATION}" \
    --q6-capability-attestation-digest "${Q6_ATTESTATION_DIGEST}" \
    --manifest-request-path "${MANIFEST_REQUEST_PATH}" \
    --signed-manifest-path "${SIGNED_MANIFEST_PATH}" \
    --verifier-private-key-path "${VERIFIER_STATE}/verifier-ed25519.key" \
    --manifest-install-root "${CONFIG_ROOT}/qualification-manifests" \
    --canary-catalog-path "${CANDIDATE_RELEASE}/qualification/canaries/catalog.yaml" \
    --canary-config-index "${CONFIG_ROOT}/canaries/index.json" \
    --resilience-proof-index "${RESILIENCE_PROOF_INDEX}" \
    --promotion-receipt-path "${PROMOTION_RECEIPT_PATH}" \
    --production-observation-path "${PRODUCTION_OBSERVATION_PATH}" \
    --production-rollback-path "${PRODUCTION_ROLLBACK_PATH}" \
    --factory-repository "${FACTORY_REPOSITORY}" \
    --source-commit "${SOURCE_COMMIT}" \
    --stable-release-digest "${STABLE_DIGEST}" \
    --controller-release-digest "${CONTROLLER_DIGEST}" \
    --candidate-digest "${CANDIDATE_DIGEST}" \
    --policy-digest "${POLICY_DIGEST}" \
    --toolchain-manifest-digest "${TOOLCHAIN_DIGEST}" \
    --trusted-verifier-public-key-digest "${VERIFIER_KEY_DIGEST}" \
    --verifier-digest "${VERIFIER_DIGEST}" \
    --verifier-public-key "${VERIFIER_PUBLIC_KEY}"
  chown root:"${VERIFIER_USER}" "${CONFIG_ROOT}/qualification-control.yaml"
  chmod 0640 "${CONFIG_ROOT}/qualification-control.yaml"
fi
if [[ ! -f "${CONFIG_ROOT}/verifier.yaml" ]]; then
  "${VERIFIER_ROOT}/venv/bin/python" \
    "${VERIFIER_ROOT}/current/scripts/bootstrap/build-verifier-config.py" \
    --output "${CONFIG_ROOT}/verifier.yaml" \
    --request-path "${MANIFEST_REQUEST_PATH}" \
    --signed-output-path "${SIGNED_MANIFEST_PATH}" \
    --private-key-path "${VERIFIER_STATE}/verifier-ed25519.key" \
    --manifest-install-root "${CONFIG_ROOT}/qualification-manifests" \
    --trusted-public-key-digest "${VERIFIER_KEY_DIGEST}" \
    --expected-source-commit "${SOURCE_COMMIT}" \
    --expected-candidate-digest "${CANDIDATE_DIGEST}" \
    --verifier-digest "${VERIFIER_DIGEST}"
  chown root:"${VERIFIER_USER}" "${CONFIG_ROOT}/verifier.yaml"
  chmod 0640 "${CONFIG_ROOT}/verifier.yaml"
fi

CANARY_ATTESTATION="${CONFIG_ROOT}/canary-capability-attestation.json"
if [[ ! -f "${CANARY_ATTESTATION}" ]]; then
  "${VERIFIER_ROOT}/venv/bin/python" \
    "${VERIFIER_ROOT}/current/scripts/bootstrap/build-canary-attestation.py" \
    --output "${CANARY_ATTESTATION}"
  chown root:"${CANDIDATE_USER}" "${CANARY_ATTESTATION}"
  chmod 0640 "${CANARY_ATTESTATION}"
fi
CANARY_ATTESTATION_DIGEST="$(sha256sum "${CANARY_ATTESTATION}" | awk '{print $1}')"
"${VERIFIER_ROOT}/venv/bin/python" \
  "${VERIFIER_ROOT}/current/scripts/bootstrap/build-canary-configs.py" \
  --base-config "${CONFIG_ROOT}/candidate.yaml" \
  --catalog "${CANDIDATE_RELEASE}/qualification/canaries/catalog.yaml" \
  --output-root "${CONFIG_ROOT}/canaries" \
  --state-root "${CANARY_STATE}/${SOURCE_COMMIT}" \
  --log-root "${CANARY_LOG_ROOT}/${SOURCE_COMMIT}" \
  --candidate-digest "${CANDIDATE_DIGEST}" \
  --controller-release-digest "${CONTROLLER_DIGEST}" \
  --capability-attestation-path "${CANARY_ATTESTATION}" \
  --capability-attestation-digest "${CANARY_ATTESTATION_DIGEST}" \
  --existing-repository-url "${CANARY_EXISTING_REPOSITORY_URL}" >/dev/null
chown root:"${CANDIDATE_USER}" "${CONFIG_ROOT}/canaries"/*.yaml
chmod 0640 "${CONFIG_ROOT}/canaries"/*.yaml
chown root:root "${CONFIG_ROOT}/canaries/index.json"
chmod 0644 "${CONFIG_ROOT}/canaries/index.json"
"${VERIFIER_ROOT}/venv/bin/python" \
  "${VERIFIER_ROOT}/current/scripts/bootstrap/build-canary-configs.py" \
  --base-config "${CONFIG_ROOT}/candidate.yaml" \
  --catalog "${CANDIDATE_RELEASE}/qualification/canaries/catalog.yaml" \
  --output-root "${CONFIG_ROOT}/pre-q8" \
  --state-root "${PRE_Q8_STATE}/${SOURCE_COMMIT}" \
  --log-root "${PRE_Q8_LOG_ROOT}/${SOURCE_COMMIT}" \
  --candidate-digest "${CANDIDATE_DIGEST}" \
  --controller-release-digest "${CONTROLLER_DIGEST}" \
  --capability-attestation-path "${CANARY_ATTESTATION}" \
  --capability-attestation-digest "${CANARY_ATTESTATION_DIGEST}" \
  --first-port 8890 \
  --existing-repository-url "${CANARY_EXISTING_REPOSITORY_URL}" >/dev/null
chown root:"${CANDIDATE_USER}" "${CONFIG_ROOT}/pre-q8"/*.yaml
chmod 0640 "${CONFIG_ROOT}/pre-q8"/*.yaml
chown root:root "${CONFIG_ROOT}/pre-q8/index.json"
chmod 0644 "${CONFIG_ROOT}/pre-q8/index.json"
"${VERIFIER_ROOT}/venv/bin/python" \
  "${VERIFIER_ROOT}/current/scripts/bootstrap/build-golden-config.py" \
  --candidate-config "${CONFIG_ROOT}/candidate.yaml" \
  --stable-config "${CONFIG_ROOT}/config.yaml" \
  --stable-telegram-environment "${CONFIG_ROOT}/telegram.env" \
  --output "${CONFIG_ROOT}/golden.yaml" \
  --state-root /var/lib/hermes-factory-golden \
  --log-root /var/log/hermes-factory-golden \
  --admin-port 8990
chown root:"${CANDIDATE_USER}" "${CONFIG_ROOT}/golden.yaml"
chmod 0640 "${CONFIG_ROOT}/golden.yaml"
install -d -o root -g root -m 0755 /usr/libexec
install -o root -g root -m 0755 \
  "${CANDIDATE_RELEASE}/scripts/broker/git-askpass.sh" \
  /usr/libexec/hermes-github-askpass
install -o root -g root -m 0700 \
  "${CANDIDATE_RELEASE}/scripts/deploy/release-submit.py" \
  /usr/local/sbin/hermes-qualified-release-submit

for unit in \
  hermes-factory-candidate-controller.service \
  hermes-factory-candidate-worker.service \
  hermes-factory-canary-controller@.service \
  hermes-factory-canary-worker@.service \
  hermes-factory-clean-canary@.service \
  hermes-factory-clean-canaries.service \
  hermes-factory-independent-verifier.service \
  hermes-factory-qualification.service \
  hermes-factory-qualification-promote.service \
  hermes-factory-resilience-proof.service \
  hermes-factory-production-observation.service \
  hermes-factory-production-observation.timer \
  hermes-factory-qualification-admit.service \
  hermes-factory-qualification-install.service \
  hermes-factory-qualification-stage@.service \
  hermes-factory-shadow-export.service \
  hermes-factory-shadow-evaluate.service \
  hermes-factory-shadow-fail@.service \
  hermes-factory-shadow-stop.service \
  hermes-factory-shadow-verify.service \
  hermes-factory-shadow-verify.timer \
  hermes-factory-shadow-finalize.service \
  hermes-factory-shadow-finalize.timer \
  hermes-factory-github-broker.service \
  hermes-factory-capability-probe.service \
  hermes-factory-capability-reconciler.service \
  hermes-factory-functional-qualification.service \
  hermes-factory-functional-qualification.timer \
  hermes-factory-functional-ready.service \
  hermes-factory-pre-q8-controller@.service \
  hermes-factory-pre-q8-worker@.service \
  hermes-factory-pre-q8@.service \
  hermes-factory-pre-q8.service \
  hermes-factory-golden-product.service \
  hermes-factory-golden-controller.service \
  hermes-factory-golden-worker.service \
  hermes-factory-golden-intake.service \
  hermes-factory-recursive-improvement.service \
  hermes-factory-recursive-improvement.timer \
  hermes-factory-owner-notifier.service \
  hermes-factory-owner-notifier.path \
  hermes-factory-support-bundle@.service; do
  unit_source="${CANDIDATE_RELEASE}/config/systemd/${unit}"
  unit_destination="/etc/systemd/system/${unit}"
  if [[ "${unit}" == hermes-factory-shadow-evaluate.service ]]; then
    rendered_unit="$(mktemp)"
    sed "s/@SOURCE_COMMIT@/${SOURCE_COMMIT}/g" "${unit_source}" > "${rendered_unit}"
    if grep -q '@SOURCE_COMMIT@' "${rendered_unit}"; then
      printf 'Candidate shadow unit still contains an unresolved source commit\n' >&2
      rm -f "${rendered_unit}"
      exit 65
    fi
    install -o root -g root -m 0644 "${rendered_unit}" "${unit_destination}"
    rm -f "${rendered_unit}"
  else
    install -o root -g root -m 0644 "${unit_source}" "${unit_destination}"
  fi
done
systemctl daemon-reload
for reset_unit in \
  hermes-factory-shadow-export.service \
  hermes-factory-shadow-evaluate.service \
  hermes-factory-shadow-verify.service \
  hermes-factory-shadow-finalize.service \
  hermes-factory-clean-canaries.service \
  hermes-factory-qualification-promote.service; do
  systemctl reset-failed "${reset_unit}" >/dev/null 2>&1 || true
done
runuser -u "${VERIFIER_USER}" -- \
  "${VERIFIER_ROOT}/venv/bin/python" -m scripts.qualification_control init
systemctl enable --now hermes-factory-owner-notifier.path
systemctl enable --now hermes-factory-recursive-improvement.timer
systemctl enable hermes-factory-qualification.service
if ! systemctl start --wait hermes-factory-qualification.service; then
  runuser -u "${VERIFIER_USER}" -- \
    "${VERIFIER_ROOT}/venv/bin/python" -m scripts.qualification_control \
    orchestration-fail
  exit 1
fi

printf 'Candidate B prepared at %s; Stable A was not modified.\n' "${SOURCE_COMMIT}"
