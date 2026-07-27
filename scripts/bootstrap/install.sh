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
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
HERMES_AGENT_VERSION="${HERMES_AGENT_VERSION:-0.19.0}"
HERMES_AGENT_SHA256="${HERMES_AGENT_SHA256:-bd0bac012aee38a60894781f4597dc29ee7bedb3448540249921f10d3bef327f}"

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
  docker.io \
  docker-compose-v2 \
  fail2ban \
  gh \
  git \
  logrotate \
  restic \
  sqlite3 \
  ufw \
  unattended-upgrades \
  python3.12 \
  python3.12-venv \
  python-is-python3

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${STATE_DIR}" --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 \
  "${INSTALL_ROOT}/current" "${STATE_DIR}/evidence" "${STATE_DIR}/worktrees" "${STATE_DIR}/profiles" "${STATE_DIR}/kanban" \
  /var/log/hermes-factory
install -d -o root -g root -m 0750 "${INSTALL_ROOT}/bin"
install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_DIR}" "${CONFIG_DIR}/credentials.d"
chown root:"${SERVICE_USER}" "${CONFIG_DIR}" "${CONFIG_DIR}/credentials.d"
chmod 0750 "${CONFIG_DIR}" "${CONFIG_DIR}/credentials.d"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  install -o root -g "${SERVICE_USER}" -m 0640 \
    "${ROOT_DIR}/config/factory-config.example.yaml" "${CONFIG_DIR}/config.yaml"
fi

cp -a "${ROOT_DIR}/." "${INSTALL_ROOT}/current/"
chown -R root:root "${INSTALL_ROOT}/current"
find "${INSTALL_ROOT}/current" -type d -exec chmod 0755 {} +
find "${INSTALL_ROOT}/current" -type f -exec chmod 0644 {} +
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
ln -sfn "${INSTALL_ROOT}/venv/bin/factory" /usr/local/bin/factory

install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-controller.service" \
  /etc/systemd/system/hermes-factory-controller.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-gateway.service" \
  /etc/systemd/system/hermes-factory-gateway.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-worker.service" \
  /etc/systemd/system/hermes-factory-worker.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-backup.service" \
  /etc/systemd/system/hermes-factory-backup.service
install -o root -g root -m 0644 \
  "${INSTALL_ROOT}/current/config/systemd/hermes-factory-backup.timer" \
  /etc/systemd/system/hermes-factory-backup.timer
install -o root -g "${SERVICE_USER}" -m 0750 \
  "${INSTALL_ROOT}/current/scripts/deploy/factory-rollback.sh" \
  "${INSTALL_ROOT}/bin/factory-rollback"

systemctl daemon-reload
systemctl enable docker.service fail2ban.service hermes-factory-controller.service hermes-factory-worker.service hermes-factory-backup.timer
systemctl start fail2ban.service
printf 'Bootstrap files installed. Credentials, Hermes compatibility, firewall, SSH hardening, and service start require separate evidence-backed steps.\n'
