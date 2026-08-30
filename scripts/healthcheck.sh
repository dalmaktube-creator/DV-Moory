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

FAILURES=0
fail() { printf 'FAILED: %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
DOMAIN=${MOORY_DOMAIN:-}
TOKEN_FILE=/etc/moory/caddy.env
AUTH_HEADER=$(mktemp)
trap 'rm -f "$AUTH_HEADER"' EXIT
if [[ -n $DOMAIN && -r $TOKEN_FILE ]]; then
  TOKEN=$(sed -n 's/^MOORY_TOKEN=//p' "$TOKEN_FILE" | tail -n 1)
  printf 'Authorization: Bearer %s\n' "$TOKEN" > "$AUTH_HEADER"; chmod 600 "$AUTH_HEADER"; unset TOKEN
  ENDPOINT="https://${DOMAIN}/mcp"
  unauth_code=$(curl -sS -o /dev/null -w '%{http_code}' "$ENDPOINT")
  [[ $unauth_code == 401 ]] || fail "public endpoint must reject unauthenticated requests"
  MCP_ACCEPT='Accept: application/json, text/event-stream'
  initialize=$(curl --fail-with-body -sS -H @"$AUTH_HEADER" -H "$MCP_ACCEPT" -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"moory-health","version":"1"}}}' "$ENDPOINT") || fail "MCP initialize request"
  grep -q 'protocolVersion' <<<"${initialize:-}" || fail "MCP initialize response"
  tools=$(curl --fail-with-body -sS -H @"$AUTH_HEADER" -H "$MCP_ACCEPT" -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' "$ENDPOINT") || fail "MCP tools/list request"
  grep -q 'list_projects' <<<"${tools:-}" || fail "MCP tools/list response"
  github=$(curl --fail-with-body -sS -H @"$AUTH_HEADER" -H "$MCP_ACCEPT" -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"github_health","arguments":{}}}' "$ENDPOINT") || fail "GitHub health request"
  grep -Eq 'Authentication: ok|"ok"[[:space:]]*:[[:space:]]*true' <<<"${github:-}" || fail "GitHub authentication health"
else
  fail "public domain or token configuration is missing"
fi
python3 -c 'import json,sys; from pathlib import Path; data=json.load(open(sys.argv[1], encoding="utf-8")); root=Path(sys.argv[2]).resolve(); assert isinstance(data,dict) and len(data)<=50; assert all(root in Path(v["path"]).resolve().parents for v in data.values())' "$ROOT/config/projects.json" "$ROOT/repos" || fail "projects registry validation"
if command -v runuser >/dev/null; then
  runuser -u moory -- test -w "$ROOT/logs/audit.jsonl" || fail "audit log is not writable by moory"
else
  test -w "$ROOT/logs/audit.jsonl" || fail "audit log is not writable"
fi
(( FAILURES == 0 )) || { printf 'Health check failed with %s problem(s).\n' "$FAILURES" >&2; exit 1; }
printf 'End-to-end health: valid\n'
