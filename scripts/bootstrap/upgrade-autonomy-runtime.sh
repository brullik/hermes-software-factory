#!/usr/bin/env bash
set -euo pipefail

# Idempotent host migration for semantic-lifecycle releases. It installs only
# controller-owned tooling and systemd assets; no model or worker may invoke it.

if [[ "${EUID}" -ne 0 ]]; then
  printf 'upgrade-autonomy-runtime.sh must run as root\n' >&2
  exit 78
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_USER="${SERVICE_USER:-hermesfactory}"
STATE_DIR="${STATE_DIR:-/var/lib/hermes-factory}"
RUNTIME_DIR="/run/hermes-factory"

if [[ ! "${SERVICE_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  printf 'SERVICE_USER contains unsafe characters\n' >&2
  exit 78
fi
if [[ ! -f /etc/os-release ]]; then
  printf 'Cannot identify operating system\n' >&2
  exit 78
fi
# shellcheck disable=SC1091
. /etc/os-release
if [[ "${ID}" != "ubuntu" || "${VERSION_ID}" != "24.04" ]]; then
  printf 'Expected Ubuntu 24.04, found %s %s\n' "${ID}" "${VERSION_ID}" >&2
  exit 78
fi
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  printf 'Service user does not exist: %s\n' "${SERVICE_USER}" >&2
  exit 78
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential \
  fuse-overlayfs \
  podman \
  slirp4netns \
  uidmap

if ! grep -q "^${SERVICE_USER}:" /etc/subuid; then
  usermod --add-subuids 1000000-1065535 "${SERVICE_USER}"
fi
if ! grep -q "^${SERVICE_USER}:" /etc/subgid; then
  usermod --add-subgids 1000000-1065535 "${SERVICE_USER}"
fi

install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 \
  "${STATE_DIR}" "${RUNTIME_DIR}"
for service in \
  hermes-factory-controller.service \
  hermes-factory-gateway.service \
  hermes-factory-worker.service \
  hermes-factory-worker-2.service; do
  install -o root -g root -m 0644 \
    "${ROOT_DIR}/config/systemd/${service}" \
    "/etc/systemd/system/${service}"
done
install -o root -g root -m 0755 \
  "${ROOT_DIR}/scripts/deploy/release-submit.py" \
  /usr/local/sbin/hermes-factory-release-submit
systemctl daemon-reload

PROBE_DIR="$(mktemp -d "${STATE_DIR}/podman-preflight.XXXXXX")"
cleanup_probe() {
  if [[ "${PROBE_DIR}" == "${STATE_DIR}"/podman-preflight.* ]]; then
    rm -f -- "${PROBE_DIR}/Containerfile" "${PROBE_DIR}/payload"
    rmdir -- "${PROBE_DIR}" 2>/dev/null || true
  fi
}
trap cleanup_probe EXIT
install -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0644 \
  /dev/null "${PROBE_DIR}/payload"
printf 'FROM scratch\nCOPY payload /payload\n' > "${PROBE_DIR}/Containerfile"
chown "${SERVICE_USER}:${SERVICE_USER}" "${PROBE_DIR}/Containerfile"
runuser -u "${SERVICE_USER}" -- env \
  HOME="${STATE_DIR}" \
  XDG_RUNTIME_DIR="${RUNTIME_DIR}" \
  podman info --format json >/dev/null
runuser -u "${SERVICE_USER}" -- env \
  HOME="${STATE_DIR}" \
  XDG_RUNTIME_DIR="${RUNTIME_DIR}" \
  podman build --pull=never --no-cache \
  --tag localhost/hermes-toolchain-probe:latest \
  --file "${PROBE_DIR}/Containerfile" "${PROBE_DIR}" >/dev/null
runuser -u "${SERVICE_USER}" -- env \
  HOME="${STATE_DIR}" \
  XDG_RUNTIME_DIR="${RUNTIME_DIR}" \
  podman image rm --force localhost/hermes-toolchain-probe:latest >/dev/null

printf 'AUTONOMY HOST RUNTIME PASSED\n'
