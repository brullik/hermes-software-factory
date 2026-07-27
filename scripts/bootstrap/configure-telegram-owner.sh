#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'configure-telegram-owner.sh must run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9]+$ ]]; then
  printf 'usage: configure-telegram-owner.sh <numeric-telegram-user-id>\n' >&2
  exit 2
fi

install -d -o root -g hermesfactory -m 0750 /etc/hermes-factory
temporary="$(mktemp /etc/hermes-factory/.telegram-env.XXXXXX)"
trap 'rm -f "${temporary}"' EXIT
printf 'FACTORY_TELEGRAM_OWNER_ID=%s\n' "$1" > "${temporary}"
install -o root -g hermesfactory -m 0640 "${temporary}" /etc/hermes-factory/telegram.env
printf 'Telegram owner allowlist configured for numeric user id %s\n' "$1"
