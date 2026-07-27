#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'configure-caddy.sh must run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 2 ]]; then
  printf 'usage: configure-caddy.sh <hostname> <tls-email>\n' >&2
  exit 2
fi

HOSTNAME_VALUE="$1"
TLS_EMAIL="$2"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ ! "${HOSTNAME_VALUE}" =~ ^[A-Za-z0-9.-]+$ || "${HOSTNAME_VALUE}" == *..* ]]; then
  printf 'hostname is invalid\n' >&2
  exit 2
fi
if [[ ! "${TLS_EMAIL}" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
  printf 'tls email is invalid\n' >&2
  exit 2
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y caddy
install -d -o root -g root -m 0750 /etc/hermes-factory /var/log/caddy
printf 'HERMES_PUBLIC_HOST=%s\nHERMES_TLS_EMAIL=%s\n' "${HOSTNAME_VALUE}" "${TLS_EMAIL}" \
  | install -o root -g root -m 0600 /dev/stdin /etc/hermes-factory/caddy.env
export HERMES_PUBLIC_HOST="${HOSTNAME_VALUE}"
export HERMES_TLS_EMAIL="${TLS_EMAIL}"
install -o root -g root -m 0644 "${ROOT_DIR}/config/caddy/Caddyfile" /etc/caddy/Caddyfile
install -d -o root -g root -m 0755 /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/hermes-factory.conf <<'EOF'
[Service]
EnvironmentFile=/etc/hermes-factory/caddy.env
EOF
systemctl daemon-reload
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
ufw allow 80/tcp
ufw allow 443/tcp
systemctl enable --now caddy.service
systemctl reload caddy.service
printf 'Caddy configured for %s\n' "${HOSTNAME_VALUE}"
