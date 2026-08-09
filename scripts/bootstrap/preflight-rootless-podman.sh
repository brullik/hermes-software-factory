#!/usr/bin/env bash
set -euo pipefail

# Initialize and prove the rootless Podman network state before workers may
# advertise the container-builder capability. The probe is offline, bounded,
# and removes its temporary network, container image, and build context.

if [[ "${EUID}" -ne 0 ]]; then
  printf 'preflight-rootless-podman.sh must run as root\n' >&2
  exit 78
fi

SERVICE_USER="${SERVICE_USER:-hermesfactory}"
STATE_DIR="${STATE_DIR:-/var/lib/hermes-factory}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/hermes-factory}"

if [[ ! "${SERVICE_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]] \
  || [[ "${STATE_DIR}" != /* ]] \
  || [[ "${RUNTIME_DIR}" != /* ]]; then
  printf 'Rootless Podman preflight scope is invalid\n' >&2
  exit 78
fi
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  printf 'Rootless Podman service user is missing\n' >&2
  exit 78
fi

install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 \
  "${STATE_DIR}" "${RUNTIME_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 \
  "${RUNTIME_DIR}/containers" "${RUNTIME_DIR}/containers/networks"
cd "${STATE_DIR}"

PROBE_DIR="$(mktemp -d "${STATE_DIR}/podman-network-preflight.XXXXXX")"
PROBE_SUFFIX="$(basename "${PROBE_DIR}" | tr -cd 'A-Za-z0-9')"
PROBE_IMAGE="localhost/hermes-network-preflight:${PROBE_SUFFIX}"
PROBE_NETWORK="hermes-network-preflight-${PROBE_SUFFIX}"
PROBE_SOCKET="${RUNTIME_DIR}/hermes-network-preflight-${PROBE_SUFFIX}.sock"
SERVICE_PID=""
chown "${SERVICE_USER}:${SERVICE_USER}" "${PROBE_DIR}"
chmod 0700 "${PROBE_DIR}"

podman_as_service() {
  runuser -u "${SERVICE_USER}" -- env \
    HOME="${STATE_DIR}" \
    XDG_RUNTIME_DIR="${RUNTIME_DIR}" \
    podman --cgroup-manager=cgroupfs "$@"
}

podman_remote_as_service() {
  runuser -u "${SERVICE_USER}" -- env \
    HOME="${STATE_DIR}" \
    XDG_RUNTIME_DIR="${RUNTIME_DIR}" \
    /usr/bin/podman --remote --url "unix://${PROBE_SOCKET}" "$@"
}

cleanup_probe() {
  if [[ -S "${PROBE_SOCKET}" ]]; then
    podman_remote_as_service network rm --force "${PROBE_NETWORK}" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "${SERVICE_PID}" ]]; then
    kill "${SERVICE_PID}" >/dev/null 2>&1 || true
    wait "${SERVICE_PID}" >/dev/null 2>&1 || true
  fi
  rm -f -- "${PROBE_SOCKET}"
  podman_as_service image rm --force "${PROBE_IMAGE}" >/dev/null 2>&1 || true
  if [[ "${PROBE_DIR}" == "${STATE_DIR}"/podman-network-preflight.* ]]; then
    rm -f -- \
      "${PROBE_DIR}/Containerfile" \
      "${PROBE_DIR}/probe" \
      "${PROBE_DIR}/probe.c"
    rmdir -- "${PROBE_DIR}" 2>/dev/null || true
  fi
}
trap cleanup_probe EXIT

cat >"${PROBE_DIR}/probe.c" <<'EOF'
int main(void) { return 0; }
EOF
cat >"${PROBE_DIR}/Containerfile" <<'EOF'
FROM scratch
COPY probe /probe
ENTRYPOINT ["/probe"]
EOF
chown "${SERVICE_USER}:${SERVICE_USER}" \
  "${PROBE_DIR}/probe.c" "${PROBE_DIR}/Containerfile"
runuser -u "${SERVICE_USER}" -- \
  cc -static -Os -s -o "${PROBE_DIR}/probe" "${PROBE_DIR}/probe.c"

actual_runroot="$(podman_as_service info --format '{{.Store.RunRoot}}')"
expected_runroot="${RUNTIME_DIR}/containers"
if [[ "${actual_runroot}" != "${expected_runroot}" ]]; then
  printf 'Rootless Podman RunRoot mismatch: %s\n' "${actual_runroot}" >&2
  exit 78
fi

podman_as_service build --pull=never --no-cache \
  --tag "${PROBE_IMAGE}" \
  --file "${PROBE_DIR}/Containerfile" "${PROBE_DIR}" >/dev/null
podman_as_service system service --time=60 "unix://${PROBE_SOCKET}" \
  >/dev/null 2>&1 &
SERVICE_PID="$!"
for _attempt in $(seq 1 50); do
  if [[ -S "${PROBE_SOCKET}" ]]; then
    break
  fi
  sleep 0.1
done
if [[ ! -S "${PROBE_SOCKET}" ]]; then
  printf 'Rootless Podman API service did not become ready\n' >&2
  exit 78
fi
podman_remote_as_service run --rm --uts=host --network podman "${PROBE_IMAGE}"

IPAM_DATABASE="${expected_runroot}/networks/ipam.db"
if [[ ! -f "${IPAM_DATABASE}" || -L "${IPAM_DATABASE}" ]]; then
  printf 'Rootless Podman IPAM database was not initialized\n' >&2
  exit 78
fi
if [[ "$(stat -c '%U:%G:%a' "${IPAM_DATABASE}")" != "${SERVICE_USER}:${SERVICE_USER}:600" ]]; then
  printf 'Rootless Podman IPAM database ownership or mode is unsafe\n' >&2
  exit 78
fi

podman_remote_as_service network create "${PROBE_NETWORK}" >/dev/null
podman_remote_as_service network rm "${PROBE_NETWORK}" >/dev/null
kill "${SERVICE_PID}" >/dev/null 2>&1 || true
wait "${SERVICE_PID}" >/dev/null 2>&1 || true
SERVICE_PID=""
rm -f -- "${PROBE_SOCKET}"
podman_as_service image rm --force "${PROBE_IMAGE}" >/dev/null
trap - EXIT
rm -f -- \
  "${PROBE_DIR}/Containerfile" \
  "${PROBE_DIR}/probe" \
  "${PROBE_DIR}/probe.c"
rmdir -- "${PROBE_DIR}"

printf 'ROOTLESS PODMAN NETWORK PREFLIGHT PASSED\n'
printf 'RUNROOT=%s\n' "${actual_runroot}"
printf 'IPAM=READY\n'
