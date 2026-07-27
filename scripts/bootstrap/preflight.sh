#!/usr/bin/env bash
set -euo pipefail

printf 'timestamp=%s\n' "$(date -u +%FT%TZ)"
printf 'os='
. /etc/os-release
printf '%s %s\n' "$ID" "$VERSION_ID"
printf 'kernel=%s\n' "$(uname -r)"
printf 'arch=%s\n' "$(uname -m)"
printf 'virtualization=%s\n' "$(systemd-detect-virt || true)"
printf 'cpu_count=%s\n' "$(nproc)"
free -h
df -h /
ss -lntup || true
systemctl --failed --no-pager || true
docker version 2>/dev/null || true
git --version 2>/dev/null || true
gh --version 2>/dev/null || true
hermes --version 2>/dev/null || true
printf 'Preflight is read-only. Review evidence before bootstrap mutations.\n'
