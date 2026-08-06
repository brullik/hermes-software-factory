#!/usr/bin/env sh
set -eu

case "${1:-}" in
  *sername*) printf '%s\n' "${GIT_USERNAME:-x-access-token}" ;;
  *assword*) printf '%s\n' "${GH_TOKEN:?missing broker credential}" ;;
  *) exit 64 ;;
esac
