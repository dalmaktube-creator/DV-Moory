#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_CONFIG=/etc/moory/install.env
if [[ -r $INSTALL_CONFIG ]]; then
  set -a
  source "$INSTALL_CONFIG"
  set +a
fi
ROOT=${MOORY_ROOT:-/srv/moory}
PROJECTS_FILE="$ROOT/config/projects.json"
REPOS_ROOT="$ROOT/repos"

[[ $ROOT =~ ^/srv/[A-Za-z0-9][A-Za-z0-9._-]{1,63}$ && ! -L $ROOT ]] || { echo "Unsafe Moory root" >&2; exit 1; }
[[ -r $PROJECTS_FILE ]] || { echo "Projects registry is not readable" >&2; exit 1; }

git_prefix=(git)
if [[ ${EUID} -eq 0 ]]; then
  git_prefix=(runuser -u moory -- env HOME="$ROOT" git)
fi

while IFS=$'\t' read -r name path; do
  [[ -n $name && -n $path ]] || continue
  candidate=$(realpath -m "$path")
  if [[ $candidate != "$REPOS_ROOT"/* || ! -d $candidate/.git || -L $candidate ]]; then
    echo "Skipping unsafe or missing clone: $name" >&2
    continue
  fi
  echo "Fetching $name..."
  "${git_prefix[@]}" -C "$candidate" config --replace-all remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"
  "${git_prefix[@]}" -C "$candidate" fetch --prune --prune-tags --tags origin
done < <(python3 - "$PROJECTS_FILE" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for name, config in sorted(data.items()):
    print(f"{name}\t{config['path']}")
PY
)

echo "Safe fetch completed. Local working files were not changed."
