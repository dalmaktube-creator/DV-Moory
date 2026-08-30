#!/usr/bin/env bash
set -Eeuo pipefail
REPO_URL=https://github.com/dalmaktube-creator/DV-Moory.git
INSTALL_DIR=/opt/moory
[[ ${EUID} -eq 0 ]] || { echo "Run this installer with sudo." >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo "Ubuntu version could not be detected." >&2; exit 1; }
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo "Moory currently supports Ubuntu 24.04 only." >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git ca-certificates
if [[ -d "$INSTALL_DIR/.git" ]]; then
  [[ $(stat -c '%u' "$INSTALL_DIR") -eq 0 ]] || { echo "Unsafe /opt/moory ownership" >&2; exit 1; }
  [[ $(git -C "$INSTALL_DIR" remote get-url origin) == "$REPO_URL" ]] || { echo "Unexpected Moory origin" >&2; exit 1; }
  git -C "$INSTALL_DIR" fetch --prune origin
  git -C "$INSTALL_DIR" pull --ff-only origin main
else
  rm -rf /opt/moory
  git clone --depth 1 --branch main "$REPO_URL" "$INSTALL_DIR"
fi
if [[ -r /dev/tty ]]; then
  exec "$INSTALL_DIR/scripts/install.sh" </dev/tty
else
  exec "$INSTALL_DIR/scripts/install.sh"
fi
