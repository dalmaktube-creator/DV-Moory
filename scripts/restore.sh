#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
INSTALL_CONFIG=/etc/moory/install.env
[[ -r $INSTALL_CONFIG ]] || { echo "Moory install configuration was not found" >&2; exit 1; }
set -a
source "$INSTALL_CONFIG"
set +a
ROOT=${MOORY_ROOT:-/srv/moory}
PROJECTS_FILE="$ROOT/config/projects.json"
[[ $ROOT =~ ^/srv/[A-Za-z0-9][A-Za-z0-9._-]{1,63}$ && ! -L $ROOT ]] || { echo "Unsafe Moory root" >&2; exit 1; }
ARCHIVE=${1:-}
if [[ -z $ARCHIVE ]]; then
  printf 'Backup archive path: '
  read -r ARCHIVE
fi
ARCHIVE=$(realpath -e "$ARCHIVE")
[[ -f $ARCHIVE && ! -L $ARCHIVE ]] || { echo "Backup archive is invalid" >&2; exit 1; }
[[ $(basename "$ARCHIVE") =~ ^moory-backup-[0-9]{8}-[0-9]{6}\.tar\.gz$ ]] || { echo "Unexpected backup filename" >&2; exit 1; }
[[ $ARCHIVE == /root/* ]] || { echo "Backup must be stored under /root" >&2; exit 1; }
if tar -tzf "$ARCHIVE" | grep -Ev '^(config/)?projects\.json$|^config/$' | grep -q .; then
  echo "Backup contains unexpected files" >&2
  exit 1
fi
TMP=$(mktemp -d /root/moory-restore.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
tar --no-same-owner --no-same-permissions -xzf "$ARCHIVE" -C "$TMP"
RESTORED="$TMP/config/projects.json"
[[ -f $RESTORED ]] || RESTORED="$TMP/projects.json"
[[ -f $RESTORED ]] || { echo "Projects registry is missing from backup" >&2; exit 1; }
python3 - "$RESTORED" "$ROOT" <<'PY'
import json, re, sys
from pathlib import Path
registry = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(sys.argv[2]).resolve()
repos = (root / "repos").resolve()
if not isinstance(registry, dict) or len(registry) > 50:
    raise SystemExit("Invalid projects registry")
for name, config in registry.items():
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", name):
        raise SystemExit("Invalid project name")
    if not isinstance(config, dict):
        raise SystemExit("Invalid project configuration")
    repo = str(config.get("repo", ""))
    branch = str(config.get("branch", ""))
    path = Path(str(config.get("path", ""))).resolve()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise SystemExit("Invalid repository")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or ".." in branch:
        raise SystemExit("Invalid branch")
    if path == repos or repos not in path.parents:
        raise SystemExit("Project path is outside the repositories directory")
print("Backup registry validation passed")
PY
BACKUP="$PROJECTS_FILE.before-restore-$(date +%Y%m%d-%H%M%S)"
cp -a "$PROJECTS_FILE" "$BACKUP"
install -o root -g moory -m 640 "$RESTORED" "$PROJECTS_FILE"
if ! systemctl restart moory.service || ! /usr/local/lib/moory/healthcheck.sh; then
  echo "Restore health check failed; rolling back registry" >&2
  install -o root -g moory -m 640 "$BACKUP" "$PROJECTS_FILE"
  systemctl restart moory.service || true
  exit 1
fi
trap - EXIT
rm -rf "$TMP"
echo "Registry restored and health check passed"
