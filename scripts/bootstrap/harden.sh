#!/usr/bin/env bash
set -euo pipefail

# Run only after a separate key-based session for the admin user has been
# verified. This guard prevents an accidental SSH lockout during bootstrap.
if [[ "${EUID}" -ne 0 ]]; then
  printf 'harden.sh must run as root\n' >&2
  exit 1
fi
if [[ "${HERMES_ADMIN_SESSION_VERIFIED:-}" != "1" ]]; then
  printf 'Refusing SSH hardening until HERMES_ADMIN_SESSION_VERIFIED=1\n' >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADMIN_USER="${ADMIN_USER:-hermesadmin}"
AUTHORIZED_KEY_FILE="${1:-}"
if [[ -z "${AUTHORIZED_KEY_FILE}" || ! -s "${AUTHORIZED_KEY_FILE}" ]]; then
  printf 'Pass a readable public key file as the first argument\n' >&2
  exit 1
fi

DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y sudo ufw openssh-server

if ! id "${ADMIN_USER}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --groups sudo "${ADMIN_USER}"
fi
install -d -o "${ADMIN_USER}" -g "${ADMIN_USER}" -m 0700 "/home/${ADMIN_USER}/.ssh"
install -o "${ADMIN_USER}" -g "${ADMIN_USER}" -m 0600 "${AUTHORIZED_KEY_FILE}" \
  "/home/${ADMIN_USER}/.ssh/authorized_keys"
printf '%s\n' "${ADMIN_USER} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${ADMIN_USER}"
chmod 0440 "/etc/sudoers.d/${ADMIN_USER}"
visudo -cf "/etc/sudoers.d/${ADMIN_USER}"

install -o root -g root -m 0644 \
  "${ROOT_DIR}/config/ssh/00-hermes-factory-hardening.conf" \
  /etc/ssh/sshd_config.d/00-hermes-factory-hardening.conf
install -o root -g root -m 0644 \
  "${ROOT_DIR}/config/ssh/99-hermes-factory-hardening.conf" \
  /etc/ssh/sshd_config.d/99-hermes-factory-hardening.conf
sshd -t

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw --force enable
systemctl reload ssh
printf 'SSH hardening and UFW applied for %s\n' "${ADMIN_USER}"
