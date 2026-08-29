#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
OUT=${1:-/root/moory-backup-$(date +%Y%m%d-%H%M%S).tar.gz}
tar --exclude='*.pem' --exclude='github-token' --exclude='id_*' --exclude='repos' -czf "$OUT" -C /srv moory/config/projects.json moory/logs 2>/dev/null || true
chmod 600 "$OUT"
echo "Non-secret backup created: $OUT"
