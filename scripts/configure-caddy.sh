#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
DOMAIN=${1:-}
[[ $DOMAIN =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Usage: $0 mcp.example.com" >&2; exit 1; }
command -v caddy >/dev/null || { echo "Caddy is not installed" >&2; exit 1; }

install -d -o root -g root -m 700 /etc/moory
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
    reverse_proxy 127.0.0.1:8787 {
        header_up Host 127.0.0.1:8787
    }
}
EOF
IMPORT_LINE='import /etc/caddy/conf.d/*.caddy'
if ! grep -Fqx "$IMPORT_LINE" /etc/caddy/Caddyfile; then
  cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.backup-$(date +%Y%m%d-%H%M%S)"
  printf '\n%s\n' "$IMPORT_LINE" >> /etc/caddy/Caddyfile
fi
caddy validate --config /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl restart caddy
printf '\033[38;5;82m✔ HTTPS configured: https://%s/mcp\033[0m\n' "$DOMAIN"
