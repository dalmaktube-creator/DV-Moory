#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

INSTALL_CONFIG=/etc/moory/install.env
config_value() {
  local key=$1
  [[ -r $INSTALL_CONFIG ]] || return 0
  sed -n "s/^${key}=//p" "$INSTALL_CONFIG" | tail -n 1
}
CURRENT_ROOT=$(config_value MOORY_ROOT); CURRENT_ROOT=${CURRENT_ROOT:-/srv/moory}
CURRENT_PORT=$(config_value MOORY_PORT); CURRENT_PORT=${CURRENT_PORT:-8787}
DOMAIN=${1:-$(config_value MOORY_DOMAIN)}
PORT=${2:-$CURRENT_PORT}
CURRENT_HTTPS_PORT=$(config_value MOORY_HTTPS_PORT)
if [[ -z $CURRENT_HTTPS_PORT ]]; then
  if [[ -n $(config_value MOORY_DOMAIN) ]]; then CURRENT_HTTPS_PORT=443; else CURRENT_HTTPS_PORT=8443; fi
fi
HTTPS_PORT=${3:-$CURRENT_HTTPS_PORT}

[[ $DOMAIN =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $DOMAIN == *.* && $DOMAIN != *..* ]] || { echo "Usage: $0 mcp.example.com [local-port] [https-port]" >&2; exit 1; }
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1024 && $PORT -le 65535 ]] || { echo "Port must be between 1024 and 65535" >&2; exit 1; }
[[ $HTTPS_PORT =~ ^[1-9][0-9]{1,4}$ && ( $HTTPS_PORT -eq 443 || $HTTPS_PORT -ge 1024 ) && $HTTPS_PORT -le 65535 && $HTTPS_PORT -ne $PORT ]] || { echo "Invalid public HTTPS port or collision with local MCP port" >&2; exit 1; }
for protocol in tcp udp; do
  if [[ $protocol == tcp ]]; then flags=-lntp; else flags=-lnup; fi
  listeners=$(ss -H "$flags" "sport = :$HTTPS_PORT")
  if [[ -n $listeners ]] && grep -Fv '"caddy"' <<<"$listeners" >/dev/null; then
    echo "Public HTTPS $protocol port $HTTPS_PORT is occupied; choose another port (for example 9443)" >&2
    exit 1
  fi
done
if [[ $PORT != "$CURRENT_PORT" ]] && ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${PORT}$"; then
  echo "Port $PORT is already in use" >&2
  exit 1
fi

if ! command -v caddy >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  NEEDRESTART_MODE=l apt-get install --no-upgrade -y caddy
fi

BACKUP_DIR=$(mktemp -d /root/moory-endpoint-backup.XXXXXX)
# Back up only paths this operation manages; a failed backup blocks mutation.
MANAGED_PATHS=(etc/moory/install.env etc/moory/caddy.env etc/moory/domain etc/caddy/Caddyfile etc/caddy/conf.d/moory.caddy etc/systemd/system/caddy.service.d/moory.conf)
BACKUP_PATHS=()
for path in "${MANAGED_PATHS[@]}"; do
  [[ ! -e /$path ]] || BACKUP_PATHS+=("$path")
done
tar -C / -czf "$BACKUP_DIR/config.tar.gz" "${BACKUP_PATHS[@]}"
OPENED_UFW_PORTS=()
rollback() {
  local status=$?
  trap - ERR
  set +e
  for path in "${MANAGED_PATHS[@]}"; do rm -f "/$path"; done
  tar -C / -xzf "$BACKUP_DIR/config.tar.gz"
  for port in "${OPENED_UFW_PORTS[@]}"; do ufw --force delete allow "$port/tcp" >/dev/null; done
  systemctl daemon-reload
  systemctl restart moory.service 2>/dev/null || true
  systemctl restart caddy 2>/dev/null || true
  rm -rf "$BACKUP_DIR"
  exit "$status"
}
trap rollback ERR

install -d -o root -g moory -m 750 /etc/moory
cat > "$INSTALL_CONFIG" <<EOF
MOORY_ROOT=$CURRENT_ROOT
MOORY_PORT=$PORT
MOORY_DOMAIN=$DOMAIN
MOORY_HTTPS_PORT=$HTTPS_PORT
EOF
chown root:moory "$INSTALL_CONFIG"; chmod 640 "$INSTALL_CONFIG"

install -d -o root -g root -m 755 /etc/caddy/conf.d /etc/systemd/system/caddy.service.d
if [[ ! -f /etc/moory/caddy.env ]]; then
  TOKEN=$(openssl rand -hex 32)
  printf 'MOORY_TOKEN=%s\n' "$TOKEN" > /etc/moory/caddy.env
  chmod 600 /etc/moory/caddy.env
fi
printf '%s\n' "$DOMAIN" > /etc/moory/domain
chmod 600 /etc/moory/domain
cat > /etc/systemd/system/caddy.service.d/moory.conf <<'EOF'
[Service]
EnvironmentFile=/etc/moory/caddy.env
ExecStart=
ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
EOF
# HTTP-01 on TCP 80 keeps certificate issuance/renewal independent of TCP 443.
TLS_OPTIONS=
if [[ $HTTPS_PORT != 443 ]]; then
  TLS_OPTIONS='    tls {
        issuer acme {
            disable_tlsalpn_challenge
        }
    }'
fi
cat > /etc/caddy/conf.d/moory.caddy <<EOF
https://${DOMAIN}:${HTTPS_PORT} {
${TLS_OPTIONS}
    request_body {
        max_size 1MB
    }
    @unauthorized not header Authorization "Bearer {\$MOORY_TOKEN}"
    respond @unauthorized 401
    reverse_proxy 127.0.0.1:${PORT} {
        header_up Host 127.0.0.1:${PORT}
        transport http {
            dial_timeout 5s
            response_header_timeout 30s
        }
    }
}
EOF
# Never rewrite shared global options or inspect unrelated UDP 443.
# The public listener's TCP/UDP availability was checked above.
IMPORT_LINE='import /etc/caddy/conf.d/*.caddy'
if ! grep -Fqx "$IMPORT_LINE" /etc/caddy/Caddyfile; then
  cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.backup-$(date +%Y%m%d-%H%M%S)"
  printf '\n%s\n' "$IMPORT_LINE" >> /etc/caddy/Caddyfile
fi

if ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
  printf '\033[38;5;220m⚠ DNS does not resolve yet. Point the domain to this server, then retry.\033[0m\n'
fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  for port in 80 "$HTTPS_PORT"; do
    if ! ufw status | grep -Eq "^${port}/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere([[:space:]]|$)"; then
      ufw allow "$port/tcp" >/dev/null
      OPENED_UFW_PORTS+=("$port")
    fi
  done
fi

caddy fmt --overwrite /etc/caddy/conf.d/moory.caddy
set -a
source /etc/moory/caddy.env
set +a
caddy validate --config /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl restart moory.service
systemctl enable caddy >/dev/null
systemctl restart caddy
trap - ERR
rm -rf "$BACKUP_DIR"
AUTHORITY=$DOMAIN
[[ $HTTPS_PORT == 443 ]] || AUTHORITY="${DOMAIN}:${HTTPS_PORT}"
printf '\033[38;5;82m✔ Secure endpoint configured: https://%s/mcp\033[0m\n' "$AUTHORITY"
printf 'Caddy will automatically request and renew the SSL certificate. TCP 80 must remain reachable for HTTP-01.\n'
printf 'Allow TCP %s in your provider firewall. UDP is not required by MCP.\n' "$HTTPS_PORT"
