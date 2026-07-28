#!/usr/bin/env bash
set -euo pipefail

# Refresh only the public PyPI advisory archive. No product path, package name,
# version, or repository identifier is supplied to the remote endpoint.
DATABASE_URL="https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
CACHE_ROOT="/var/cache/hermes-factory/osv"
DESTINATION_DIR="${CACHE_ROOT}/osv-scanner/PyPI"
DESTINATION="${DESTINATION_DIR}/all.zip"

if [[ "${EUID}" -ne 0 ]]; then
  printf 'OSV database update must run as root\n' >&2
  exit 1
fi

install -d -o root -g hermesfactory -m 0750 \
  "${CACHE_ROOT}" \
  "${CACHE_ROOT}/osv-scanner" \
  "${DESTINATION_DIR}"

temporary="$(mktemp --tmpdir="${DESTINATION_DIR}" .all.zip.XXXXXX)"
cleanup() {
  rm -f -- "${temporary}"
}
trap cleanup EXIT

curl \
  --fail \
  --silent \
  --show-error \
  --location \
  --proto '=https' \
  --proto-redir '=https' \
  --connect-timeout 15 \
  --max-time 600 \
  --user-agent 'Hermes-Software-Factory/2.0 OSV-cache-updater' \
  --output "${temporary}" \
  "${DATABASE_URL}"

python3 -c \
  'import sys, zipfile; archive = zipfile.ZipFile(sys.argv[1]); bad = archive.testzip(); sys.exit(f"corrupt OSV database member: {bad}") if bad else sys.exit(0)' \
  "${temporary}"

chown root:hermesfactory "${temporary}"
chmod 0640 "${temporary}"
touch "${temporary}"
mv -f -- "${temporary}" "${DESTINATION}"
trap - EXIT

printf 'OSV PyPI database refreshed: %s\n' "$(sha256sum "${DESTINATION}" | cut -d ' ' -f 1)"
