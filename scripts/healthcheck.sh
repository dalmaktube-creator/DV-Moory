#!/usr/bin/env bash
set -Eeuo pipefail
INSTALL_CONFIG=/etc/moory/install.env
if [[ -r $INSTALL_CONFIG ]]; then
  set -a
  source "$INSTALL_CONFIG"
  set +a
fi
ROOT=${MOORY_ROOT:-/srv/moory}
PORT=${MOORY_PORT:-8787}
printf 'Moory service: '; systemctl is-active moory || true
printf 'Caddy service: '; systemctl is-active caddy || true
printf 'MCP listener on port %s: ' "$PORT"; ss -lnt | grep -q "127.0.0.1:${PORT}" && echo listening || echo unavailable
printf 'Projects registry: '; test -r "$ROOT/config/projects.json" && echo readable || echo unavailable
printf 'GitHub authentication: '; test -r "$ROOT/config/github-auth.env" && echo configured || echo unavailable
"$ROOT/venv/bin/python" -m py_compile "$ROOT/app/server.py" && echo 'Python source: valid'
