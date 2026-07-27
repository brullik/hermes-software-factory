#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'install-telegram-credential.sh must run as root\n' >&2
  exit 1
fi

CREDENTIAL_DIR="/etc/hermes-factory/credentials.d"
TARGET="${CREDENTIAL_DIR}/telegram-token"
install -d -o root -g hermesfactory -m 0750 "${CREDENTIAL_DIR}"

token=""
if [[ -t 0 && -r /dev/tty ]]; then
  read -r -s -p 'Telegram bot token (input is not echoed): ' token < /dev/tty
  printf '\n' >&2
else
  IFS= read -r token
fi
if [[ -z "${token}" || "${token}" =~ [[:space:]] ]]; then
  unset token
  printf 'token must be a non-empty single-line value\n' >&2
  exit 2
fi

temporary="$(mktemp "${CREDENTIAL_DIR}/.telegram-token.XXXXXX")"
trap 'rm -f "${temporary}"; unset token' EXIT
umask 077
printf '%s\n' "${token}" > "${temporary}"
install -o root -g hermesfactory -m 0640 "${temporary}" "${TARGET}"
printf 'Telegram credential installed at %s\n' "${TARGET}"
