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

AUTH_CONFIG="$ROOT/config/github-auth.env"
LOGS_DIR="$ROOT/logs"
ASKPASS_FILE=""
TOKEN_FILE=""

cleanup() {
  [[ -n $ASKPASS_FILE ]] && rm -f "$ASKPASS_FILE"
  [[ -n $TOKEN_FILE ]] && rm -f "$TOKEN_FILE"
  return 0
}
trap cleanup EXIT

auth_value() {
  [[ -r $AUTH_CONFIG ]] || return 0
  sed -n "s/^$1=//p" "$AUTH_CONFIG" | tail -n 1
}

AUTH_MODE=$(auth_value GITHUB_AUTH_MODE)

if [[ $AUTH_MODE == fine_grained_pat ]]; then
  TOKEN_SOURCE=$(auth_value GITHUB_TOKEN_PATH)
  [[ $TOKEN_SOURCE == "$ROOT/config/github-token" && -r $TOKEN_SOURCE ]] || { echo "GitHub token path is not allowlisted" >&2; exit 1; }
  TOKEN_FILE=$(mktemp "$LOGS_DIR/.git-fetch-token.XXXXXX")
  cat "$TOKEN_SOURCE" > "$TOKEN_FILE"
elif [[ $AUTH_MODE == github_app ]]; then
  MOORY_PYTHON="$ROOT/venv/bin/python"
  [[ -x $MOORY_PYTHON ]] || MOORY_PYTHON=python3
  TOKEN_FILE=$(mktemp "$LOGS_DIR/.git-fetch-token.XXXXXX")
  "$MOORY_PYTHON" - "$AUTH_CONFIG" > "$TOKEN_FILE" <<'PY'
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
import jwt
values = {}
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if "=" not in raw or raw.lstrip().startswith("#"):
        continue
    key, value = raw.split("=", 1)
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
        values[key] = value
app_id = values.get("GITHUB_APP_ID", "")
installation_id = values.get("GITHUB_INSTALLATION_ID", "")
key_path = Path(values.get("GITHUB_PRIVATE_KEY_PATH", ""))
if not app_id.isdigit() or not installation_id.isdigit() or not key_path.is_file():
    print("GitHub App configuration is invalid", file=sys.stderr)
    raise SystemExit(1)
now = int(time.time())
claims = {"iat": now - 60, "exp": now + 540, "iss": app_id}
app_jwt = jwt.encode(claims, key_path.read_text(encoding="utf-8"), algorithm="RS256")
endpoint = "https://api.github.com/app/installations/" + installation_id + "/access_tokens"
headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": "Bearer " + app_jwt,
    "Content-Type": "application/json",
    "User-Agent": "Moory-Fetch/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
}
request = urllib.request.Request(endpoint, data=b"{}", method="POST", headers=headers)
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
    print("Could not mint a GitHub App installation token", file=sys.stderr)
    raise SystemExit(1) from None
token = str(payload.get("token", ""))
if not token:
    print("GitHub App returned an invalid installation token", file=sys.stderr)
    raise SystemExit(1)
sys.stdout.write(token)
PY
fi

git_environment=(env HOME="$ROOT" GIT_TERMINAL_PROMPT=0)
if [[ -n $TOKEN_FILE ]]; then
  chmod 600 "$TOKEN_FILE"
  ASKPASS_FILE=$(mktemp "$LOGS_DIR/.git-fetch-askpass.XXXXXX")
  cat > "$ASKPASS_FILE" <<'SH'
#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' x-access-token;;
  *) cat "$MOORY_GITHUB_TOKEN_PATH";;
esac
SH
  chmod 700 "$ASKPASS_FILE"
  if [[ ${EUID} -eq 0 ]]; then
    chown moory:moory "$TOKEN_FILE" "$ASKPASS_FILE"
  fi
  git_environment+=("GIT_ASKPASS=$ASKPASS_FILE" "MOORY_GITHUB_TOKEN_PATH=$TOKEN_FILE")
fi

git_prefix=("${git_environment[@]}" git)
if [[ ${EUID} -eq 0 ]]; then
  git_prefix=(runuser -u moory -- "${git_environment[@]}" git)
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
