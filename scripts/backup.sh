#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
INSTALL_CONFIG=/etc/moory/install.env
if [[ -r $INSTALL_CONFIG ]]; then
  set -a
  source "$INSTALL_CONFIG"
  set +a
fi
ROOT=${MOORY_ROOT:-/srv/moory}
[[ $ROOT =~ ^/srv/[A-Za-z0-9][A-Za-z0-9._-]{1,63}$ && ! -L $ROOT ]] || { echo "Unsafe Moory root" >&2; exit 1; }
OUT=${1:-/root/moory-backup-$(date +%Y%m%d-%H%M%S).tar.gz}
tar -czf "$OUT" -C "$ROOT" config/projects.json
chmod 600 "$OUT"
echo "Non-secret backup created: $OUT"
