#!/usr/bin/env bash
set -Eeuo pipefail
REPO_URL=${MOORY_REPO_URL:-https://github.com/dalmaktube-creator/DV-Moory.git}
INSTALL_DIR=${MOORY_SOURCE_DIR:-/opt/moory}
[[ ${EUID} -eq 0 ]] || { echo "Run this installer with sudo." >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git ca-certificates
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch --prune origin
  git -C "$INSTALL_DIR" pull --ff-only origin main
else
  rm -rf "$INSTALL_DIR"
  git clone --depth 1 --branch main "$REPO_URL" "$INSTALL_DIR"
fi
exec "$INSTALL_DIR/scripts/install.sh"
