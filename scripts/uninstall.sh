#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_CONFIG=/etc/moory/install.env
if [[ -r $INSTALL_CONFIG ]]; then
  set -a
  source "$INSTALL_CONFIG"
  set +a
fi
ROOT=${MOORY_ROOT:-/srv/moory}
SOURCE=/opt/moory
RESET='\033[0m'; BOLD='\033[1m'; RED='\033[38;5;203m'; YELLOW='\033[38;5;220m'; GREEN='\033[38;5;82m'

if [[ ${EUID} -ne 0 ]]; then
  exec sudo -- "$0" "$@"
fi

printf "${RED}╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${RED}║${RESET}  ${BOLD}${RED}FULL MOORY UNINSTALL${RESET}                                      ${RED}║${RESET}\n"
printf "${RED}╚══════════════════════════════════════════════════════════════╝${RESET}\n\n"
printf "${YELLOW}${BOLD}WARNING:${RESET}\n"
printf "  • Moory services, configuration, logs and credentials will be deleted.\n"
printf "  • Every local project clone under %s/repos will be deleted.\n" "$ROOT"
printf "  • Any local change or commit that was not pushed will be lost.\n"
printf "  • GitHub repositories themselves will NOT be deleted.\n"
printf "  • The separate legacy /srv/dv-dev bridge will NOT be changed.\n\n"

if [[ -r "$ROOT/config/projects.json" ]]; then
  printf "${BOLD}Registered local projects:${RESET}\n"
  python3 - "$ROOT/config/projects.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    projects = json.loads(path.read_text())
except Exception:
    projects = {}
if not projects:
    print("  (none)")
for name, config in sorted(projects.items()):
    print(f"  - {name}: {config.get('path', 'unknown path')}")
PY
  printf "\n"
fi

RISK=0
if [[ -d "$ROOT/repos" ]]; then
  while IFS= read -r -d '' repo_dir; do
    if [[ -n $(git -C "$repo_dir" status --porcelain 2>/dev/null || true) ]]; then
      printf "${RED}Uncommitted changes:${RESET} %s\n" "$repo_dir"
      RISK=1
    fi
    if git -C "$repo_dir" rev-parse --abbrev-ref '@{upstream}' >/dev/null 2>&1; then
      AHEAD=$(git -C "$repo_dir" rev-list --count '@{upstream}..HEAD' 2>/dev/null || echo 0)
      if [[ $AHEAD -gt 0 ]]; then
        printf "${RED}Unpushed commits (%s):${RESET} %s\n" "$AHEAD" "$repo_dir"
        RISK=1
      fi
    fi
  done < <(find "$ROOT/repos" -mindepth 2 -maxdepth 2 -type d -name .git -printf '%h\0' 2>/dev/null)
fi
if [[ $RISK -eq 1 ]]; then
  printf "\n${RED}${BOLD}UNSYNCED LOCAL WORK WAS DETECTED.${RESET}\n"
fi

printf "\nType ${BOLD}YES${RESET} in uppercase to permanently remove Moory: "
read -r CONFIRMATION
if [[ $CONFIRMATION != YES ]]; then
  printf "${GREEN}Uninstall cancelled. Nothing was deleted.${RESET}\n"
  exit 0
fi

[[ $ROOT =~ ^/srv/[A-Za-z0-9][A-Za-z0-9._-]{1,63}$ ]] || { echo "Unsafe Moory root" >&2; exit 1; }
[[ $(realpath -m "$ROOT") == "$ROOT" ]] || { echo "Unsafe Moory root" >&2; exit 1; }
[[ $(realpath -m "$SOURCE") == /opt/moory ]] || { echo "Unsafe Moory source" >&2; exit 1; }
[[ ! -L "$ROOT" && ! -L "$SOURCE" ]] || { echo "Refusing to remove symbolic-link roots" >&2; exit 1; }

systemctl disable --now moory.service 2>/dev/null || true
systemctl disable --now moory-fetch.timer 2>/dev/null || true
rm -f /etc/systemd/system/moory.service
rm -f /etc/systemd/system/moory-fetch.service
rm -f /etc/systemd/system/moory-fetch.timer
rm -f /etc/caddy/conf.d/moory.caddy
rm -f /etc/systemd/system/caddy.service.d/moory.conf
rm -rf /etc/moory
systemctl daemon-reload
if command -v caddy >/dev/null && [[ -f /etc/caddy/Caddyfile ]]; then
  caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 && systemctl reload caddy 2>/dev/null || true
fi

rm -rf --one-file-system "$ROOT"
rm -rf --one-file-system /opt/moory
userdel moory 2>/dev/null || true
rm -f /usr/local/bin/moory /usr/local/bin/moory-setup /usr/local/bin/moory-configure-caddy
rm -rf /usr/local/lib/moory

printf "\n${GREEN}${BOLD}Moory was fully removed from this server.${RESET}\n"
printf "GitHub repositories were not deleted.\n"
printf "The separate /srv/dv-dev bridge was not changed.\n"
