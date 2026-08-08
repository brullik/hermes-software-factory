#!/usr/bin/env bash
set -euo pipefail

# Idempotent, non-destructive Ubuntu bootstrap for the local controller baseline.
# Run as root on Ubuntu 24.04 only after reviewing preflight evidence.

if [[ "${EUID}" -ne 0 ]]; then
  printf 'install.sh must run as root\n' >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/hermes-factory}"
STATE_DIR="${STATE_DIR:-/var/lib/hermes-factory}"
CONFIG_DIR="${CONFIG_DIR:-/etc/hermes-factory}"
SERVICE_USER="${SERVICE_USER:-hermesfactory}"
CANDIDATE_USER="${CANDIDATE_USER:-hermescandidate}"
VERIFIER_USER="${VERIFIER_USER:-hermesverifier}"
BROKER_USER="${BROKER_USER:-hermesgithubbroker}"
CANDIDATE_INSTALL_ROOT="${CANDIDATE_INSTALL_ROOT:-/opt/hermes-factory-candidate}"
VERIFIER_INSTALL_ROOT="${VERIFIER_INSTALL_ROOT:-/opt/hermes-factory-verifier}"
CANDIDATE_STATE_DIR="${CANDIDATE_STATE_DIR:-/var/lib/hermes-factory-candidate}"
VERIFIER_STATE_DIR="${VERIFIER_STATE_DIR:-/var/lib/hermes-factory-verifier}"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
HERMES_AGENT_VERSION="${HERMES_AGENT_VERSION:-0.19.0}"
HERMES_AGENT_SHA256="${HERMES_AGENT_SHA256:-bd0bac012aee38a60894781f4597dc29ee7bedb3448540249921f10d3bef327f}"
OSV_SCANNER_VERSION="2.4.0"
OSV_SCANNER_SHA256="15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0"

for candidate_name in "${SERVICE_USER}" "${CANDIDATE_USER}" "${VERIFIER_USER}" "${BROKER_USER}"; do
  if [[ ! "${candidate_name}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    printf 'service user contains unsafe characters\n' >&2
    exit 78
  fi
done
if [[ "${SERVICE_USER}" == "${CANDIDATE_USER}" || "${SERVICE_USER}" == "${VERIFIER_USER}" || "${CANDIDATE_USER}" == "${VERIFIER_USER}" ]]; then
  printf 'Stable, candidate, and verifier users must be distinct\n' >&2
  exit 78
fi

if [[ ! -f /etc/os-release ]]; then
  printf 'Cannot identify operating system\n' >&2
  exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
if [[ "${ID}" != "ubuntu" || "${VERSION_ID}" != "24.04" ]]; then
  printf 'Expected Ubuntu 24.04, found %s %s\n' "${ID}" "${VERSION_ID}" >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates \
  caddy \
  build-essential \
  curl \
  docker.io \
  docker-compose-v2 \
  fail2ban \
  fuse-overlayfs \
  gh \
  git \
  logrotate \
  podman \
  restic \
  slirp4netns \
  sqlite3 \
  ufw \
  uidmap \
  unattended-upgrades \
  python3.12 \
  python3.12-venv \
  python-is-python3

if [[ ! -x /usr/local/bin/osv-scanner ]] \
  || [[ "$(sha256sum /usr/local/bin/osv-scanner | awk '{print $1}')" != "${OSV_SCANNER_SHA256}" ]]; then
  OSV_SCANNER_TMP="$(mktemp)"
  trap 'rm -f "${OSV_SCANNER_TMP}"' EXIT
  curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --proto-redir '=https' \
    --connect-timeout 15 \
    --max-time 600 \
    --output "${OSV_SCANNER_TMP}" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
  if [[ "$(sha256sum "${OSV_SCANNER_TMP}" | awk '{print $1}')" != "${OSV_SCANNER_SHA256}" ]]; then
    rm -f "${OSV_SCANNER_TMP}"
    printf 'OSV-Scanner digest mismatch\n' >&2
    exit 1
  fi
  install -o root -g root -m 0755 "${OSV_SCANNER_TMP}" /usr/local/bin/osv-scanner
  rm -f "${OSV_SCANNER_TMP}"
  trap - EXIT
fi

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${STATE_DIR}" --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
if ! id "${CANDIDATE_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${CANDIDATE_STATE_DIR}" --create-home --shell /usr/sbin/nologin "${CANDIDATE_USER}"
fi
if ! id "${VERIFIER_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${VERIFIER_STATE_DIR}" --create-home --shell /usr/sbin/nologin "${VERIFIER_USER}"
fi
if ! id "${BROKER_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${STATE_DIR}/product-github" \
    --create-home --shell /usr/sbin/nologin "${BROKER_USER}"
fi
if ! grep -q "^${SERVICE_USER}:" /etc/subuid; then
  usermod --add-subuids 1000000-1065535 "${SERVICE_USER}"
fi
if ! grep -q "^${SERVICE_USER}:" /etc/subgid; then
  usermod --add-subgids 1000000-1065535 "${SERVICE_USER}"
fi
if ! grep -q "^${CANDIDATE_USER}:" /etc/subuid; then
  usermod --add-subuids 1100000-1165535 "${CANDIDATE_USER}"
fi
if ! grep -q "^${CANDIDATE_USER}:" /etc/subgid; then
  usermod --add-subgids 1100000-1165535 "${CANDIDATE_USER}"
fi

install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 \
  "${INSTALL_ROOT}/current" "${STATE_DIR}/evidence" "${STATE_DIR}/worktrees" "${STATE_DIR}/profiles" "${STATE_DIR}/kanban" \
  /var/log/hermes-factory /run/hermes-factory
install -d -o root -g root -m 0750 "${INSTALL_ROOT}/bin"
install -d -o "${BROKER_USER}" -g "${SERVICE_USER}" -m 0770 \
  "${STATE_DIR}/product-github" \
  "${STATE_DIR}/evidence/product-github-receipts"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0770 \
  "${STATE_DIR}/worktrees/product-capability"
install -d -o "${CANDIDATE_USER}" -g "${CANDIDATE_USER}" -m 0750 \
  "${CANDIDATE_STATE_DIR}" \
  "${CANDIDATE_STATE_DIR}/evidence" \
  "${CANDIDATE_STATE_DIR}/qualification" \
  "${CANDIDATE_STATE_DIR}/worktrees" \
  /var/log/hermes-factory-candidate \
  /run/hermes-factory-candidate
install -d -o "${VERIFIER_USER}" -g "${VERIFIER_USER}" -m 0750 \
  "${VERIFIER_STATE_DIR}"
install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_DIR}" "${CONFIG_DIR}/credentials.d"
install -d -o root -g "${CANDIDATE_USER}" -m 0750 "${CONFIG_DIR}/candidate-credentials.d"
install -d -o root -g root -m 0755 "${CONFIG_DIR}/qualification-manifests"
install -d -o root -g "${SERVICE_USER}" -m 0750 \
  /var/cache/hermes-factory \
  /var/cache/hermes-factory/osv \
  /var/cache/hermes-factory/osv/osv-scanner \
  /var/cache/hermes-factory/osv/osv-scanner/PyPI
chown root:"${SERVICE_USER}" "${CONFIG_DIR}" "${CONFIG_DIR}/credentials.d"
chown root:root "${CONFIG_DIR}"
chmod 0711 "${CONFIG_DIR}"
chmod 0750 "${CONFIG_DIR}/credentials.d"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  install -o root -g "${SERVICE_USER}" -m 0640 \
    "${ROOT_DIR}/config/factory-config.example.yaml" "${CONFIG_DIR}/config.yaml"
fi

if [[ -n "$(find "${INSTALL_ROOT}/current" -mindepth 1 -print -quit)" ]]; then
  if ! diff -qr --exclude=.git "${ROOT_DIR}" "${INSTALL_ROOT}/current" >/dev/null; then
    printf 'Stable A already exists; upgrades require the qualified blue/green release path\n' >&2
    exit 73
  fi
else
  cp -a "${ROOT_DIR}/." "${INSTALL_ROOT}/current/"
fi
chown -R root:root "${INSTALL_ROOT}/current"
find "${INSTALL_ROOT}/current" -type d -exec chmod 0755 {} +
find "${INSTALL_ROOT}/current" -type f -exec chmod 0644 {} +
find "${INSTALL_ROOT}/current/scripts" -type f -name '*.sh' -exec chmod 0755 {} +
chmod 0755 "${INSTALL_ROOT}/current/scripts/deploy/promote-release.py"
install -d -o root -g root -m 0755 /usr/local/sbin
install -o root -g root -m 0755 \
  "${INSTALL_ROOT}/current/scripts/broker_epoch.py" /usr/libexec/hermes-broker-epoch
install -o root -g root -m 0755 \
  "${INSTALL_ROOT}/current/scripts/deploy/release-submit.py" \
  /usr/local/sbin/hermes-factory-release-submit

SUDOERS_RELEASE_TMP="$(mktemp)"
sed "s/@SERVICE_USER@/${SERVICE_USER}/" \
  "${INSTALL_ROOT}/current/config/sudoers/hermes-factory-release" > "${SUDOERS_RELEASE_TMP}"
install -o root -g root -m 0440 "${SUDOERS_RELEASE_TMP}" /etc/sudoers.d/hermes-factory-release
rm -f "${SUDOERS_RELEASE_TMP}"
visudo -cf /etc/sudoers.d/hermes-factory-release
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 "${INSTALL_ROOT}/venv"
"${PYTHON_BIN}" -m venv "${INSTALL_ROOT}/venv"
"${INSTALL_ROOT}/venv/bin/python" -m pip install --upgrade pip
"${INSTALL_ROOT}/venv/bin/python" -m pip install -r "${INSTALL_ROOT}/current/requirements-dev.txt"
"${INSTALL_ROOT}/venv/bin/python" -m pip install --no-deps "${INSTALL_ROOT}/current"

# Install the exact pinned Hermes wheel, verify its digest before installation,
# and expose only the root-owned CLI entry point.  Provider OAuth is deliberately
# a separate owner action and is never attempted by bootstrap.
HERMES_WHEEL_DIR="$(mktemp -d)"
trap 'rm -rf "${HERMES_WHEEL_DIR}"' EXIT
"${INSTALL_ROOT}/venv/bin/python" -m pip download \
  --disable-pip-version-check --no-cache-dir --no-deps \
  --dest "${HERMES_WHEEL_DIR}" "hermes-agent==${HERMES_AGENT_VERSION}"
HERMES_WHEEL="$(find "${HERMES_WHEEL_DIR}" -maxdepth 1 -type f -name 'hermes_agent-*.whl' -print -quit)"
if [[ -z "${HERMES_WHEEL}" ]]; then
  printf 'Hermes Agent wheel was not downloaded\n' >&2
  exit 1
fi
if [[ "$(sha256sum "${HERMES_WHEEL}" | awk '{print $1}')" != "${HERMES_AGENT_SHA256}" ]]; then
  printf 'Hermes Agent wheel digest mismatch\n' >&2
  exit 1
fi
"${INSTALL_ROOT}/venv/bin/python" -m pip install --disable-pip-version-check --no-cache-dir "${HERMES_WHEEL}"
chown -R root:root "${INSTALL_ROOT}/venv"
find "${INSTALL_ROOT}/venv" -type d -exec chmod 0755 {} +
find "${INSTALL_ROOT}/venv" -type f -exec chmod 0644 {} +
find "${INSTALL_ROOT}/venv/bin" -type f -exec chmod 0755 {} +
install -d -o root -g root -m 0755 /usr/local/bin
if [[ -e /usr/local/bin/hermes && ! -L /usr/local/bin/hermes ]]; then
  printf '/usr/local/bin/hermes exists and is not a symlink\n' >&2
  exit 78
fi
ln -sfn "${INSTALL_ROOT}/venv/bin/hermes" /usr/local/bin/hermes
install -o root -g root -m 0755 \
  "${INSTALL_ROOT}/current/scripts/bootstrap/factory-cli.sh" \
  "${INSTALL_ROOT}/bin/factory-cli"
ln -sfn "${INSTALL_ROOT}/bin/factory-cli" /usr/local/bin/factory

install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-controller.service" \
  /etc/systemd/system/hermes-factory-controller.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-gateway.service" \
  /etc/systemd/system/hermes-factory-gateway.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-product-github-broker.service" \
  /etc/systemd/system/hermes-factory-product-github-broker.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-worker.service" \
  /etc/systemd/system/hermes-factory-worker.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-worker-2.service" \
  /etc/systemd/system/hermes-factory-worker-2.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-backup.service" \
  /etc/systemd/system/hermes-factory-backup.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-backup.timer" \
  /etc/systemd/system/hermes-factory-backup.timer
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-backup-offsite.service" \
  /etc/systemd/system/hermes-factory-backup-offsite.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-backup-offsite.timer" \
  /etc/systemd/system/hermes-factory-backup-offsite.timer
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-osv-db.service" \
  /etc/systemd/system/hermes-factory-osv-db.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-osv-db.timer" \
  /etc/systemd/system/hermes-factory-osv-db.timer
install -o root -g "${SERVICE_USER}" -m 0750 \
  "${INSTALL_ROOT}/current/scripts/deploy/factory-rollback.sh" \
  "${INSTALL_ROOT}/bin/factory-rollback"

"${INSTALL_ROOT}/current/scripts/security/update-osv-database.sh"

systemctl daemon-reload
systemctl enable \
  docker.service \
  fail2ban.service \
  hermes-factory-controller.service \
  hermes-factory-product-github-broker.service \
  hermes-factory-worker.service \
  hermes-factory-worker-2.service \
  hermes-factory-backup.timer \
  hermes-factory-backup-offsite.timer \
  hermes-factory-osv-db.timer
systemctl start fail2ban.service
SERVICE_USER="${SERVICE_USER}" \
STATE_DIR="${STATE_DIR}" \
RUNTIME_DIR=/run/hermes-factory \
bash "${ROOT_DIR}/scripts/bootstrap/preflight-rootless-podman.sh"
printf 'Stable A bootstrap files installed. After Stable health is proven, prepare Candidate B only from a clean immutable Git checkout with prepare-candidate-plane.sh.\n'
