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

[[ $DOMAIN =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $DOMAIN == *.* && $DOMAIN != *..* ]] || { echo "Usage: $0 mcp.example.com [port]" >&2; exit 1; }
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1024 && $PORT -le 65535 ]] || { echo "Port must be between 1024 and 65535" >&2; exit 1; }
if [[ $PORT != "$CURRENT_PORT" ]] && ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${PORT}$"; then
  echo "Port $PORT is already in use" >&2
  exit 1
fi

if ! command -v caddy >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y caddy
fi

BACKUP_DIR=$(mktemp -d /root/moory-endpoint-backup.XXXXXX)
tar --ignore-failed-read -C / -czf "$BACKUP_DIR/config.tar.gz" etc/moory etc/caddy/Caddyfile etc/caddy/conf.d/moory.caddy etc/systemd/system/caddy.service.d/moory.conf 2>/dev/null || true
rollback() {
  rm -rf /etc/moory
  rm -f /etc/caddy/conf.d/moory.caddy
  rm -f /etc/systemd/system/caddy.service.d/moory.conf
  tar -C / -xzf "$BACKUP_DIR/config.tar.gz" 2>/dev/null || true
  systemctl daemon-reload
  systemctl restart moory.service 2>/dev/null || true
  systemctl restart caddy 2>/dev/null || true
  rm -rf "$BACKUP_DIR"
}
trap rollback ERR

install -d -o root -g moory -m 750 /etc/moory
cat > "$INSTALL_CONFIG" <<EOF
MOORY_ROOT=$CURRENT_ROOT
MOORY_PORT=$PORT
MOORY_DOMAIN=$DOMAIN
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
EOF
cat > /etc/caddy/conf.d/moory.caddy <<EOF
${DOMAIN} {
    @unauthorized not header Authorization "Bearer {\$MOORY_TOKEN}"
    respond @unauthorized 401
    reverse_proxy 127.0.0.1:${PORT} {
        header_up Host 127.0.0.1:${PORT}
    }
}
EOF
IMPORT_LINE='import /etc/caddy/conf.d/*.caddy'
if ! grep -Fqx "$IMPORT_LINE" /etc/caddy/Caddyfile; then
  cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.backup-$(date +%Y%m%d-%H%M%S)"
  printf '\n%s\n' "$IMPORT_LINE" >> /etc/caddy/Caddyfile
fi

if ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
  printf '\033[38;5;220m⚠ DNS does not resolve yet. Point the domain to this server, then retry.\033[0m\n'
fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
fi

caddy validate --config /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl restart moory.service
systemctl restart caddy
printf '\033[38;5;82m✔ Secure endpoint configured: https://%s/mcp\033[0m\n' "$DOMAIN"
printf 'Caddy will automatically request and renew the SSL certificate.\n'
