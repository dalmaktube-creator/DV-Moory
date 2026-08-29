#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=${MOORY_ROOT:-/srv/moory}
printf 'Moory service: '; systemctl is-active moory || true
printf 'Caddy service: '; systemctl is-active caddy || true
printf 'MCP listener: '; ss -lnt | grep -q '127.0.0.1:8787' && echo listening || echo unavailable
printf 'Projects registry: '; test -r "$ROOT/config/projects.json" && echo readable || echo unavailable
printf 'GitHub authentication: '; test -r "$ROOT/config/github-auth.env" && echo configured || echo unavailable
"$ROOT/venv/bin/python" -m py_compile "$ROOT/app/server.py" && echo 'Python source: valid'
