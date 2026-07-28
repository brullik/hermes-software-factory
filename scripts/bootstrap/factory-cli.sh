#!/usr/bin/env bash
set -euo pipefail

# Always run the CLI from the active source release. The virtualenv can retain
# an older wheel between transactional source promotions; importing the active
# release keeps manual CLI operations consistent with systemd services.
INSTALL_ROOT="${HERMES_FACTORY_INSTALL_ROOT:-/opt/hermes-factory}"
CURRENT="${INSTALL_ROOT}/current"
if [[ ! -d "${CURRENT}/factory" ]]; then
  printf 'Active Hermes Factory release is missing: %s\n' "${CURRENT}" >&2
  exit 78
fi
export PYTHONPATH="${CURRENT}${PYTHONPATH:+:${PYTHONPATH}}"
exec "${INSTALL_ROOT}/venv/bin/python" -m factory.cli "$@"
