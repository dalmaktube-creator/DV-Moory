#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run: sudo ./scripts/install.sh" >&2; exit 1; }
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_CONFIG=/etc/moory/install.env

config_value() {
  local key=$1
  [[ -r $INSTALL_CONFIG ]] || return 0
  sed -n "s/^${key}=//p" "$INSTALL_CONFIG" | tail -n 1
}
ask_default() {
  local prompt=$1 default=$2 value
  printf '\033[38;5;45m%s\033[0m [%s]: ' "$prompt" "$default" > /dev/tty
  IFS= read -r value < /dev/tty || true
  printf '%s' "${value:-$default}"
}

DEFAULT_ROOT=$(config_value MOORY_ROOT); DEFAULT_ROOT=${DEFAULT_ROOT:-/srv/moory}
DEFAULT_PORT=$(config_value MOORY_PORT); DEFAULT_PORT=${DEFAULT_PORT:-8787}
DEFAULT_DOMAIN=$(config_value MOORY_DOMAIN)

printf '\033[38;5;39m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[38;5;39m║\033[0m  \033[1;38;5;45mMOORY INSTALLER\033[0m  Secure GitHub ↔ MCP bridge                  \033[38;5;39m║\033[0m\n'
printf '\033[38;5;39m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n'
printf 'Choose the local runtime settings. Press Enter to use each default.\n\n'
ROOT=$(ask_default "Data path" "$DEFAULT_ROOT")
PORT=$(ask_default "Local MCP port" "$DEFAULT_PORT")
DOMAIN=$(ask_default "Public MCP domain (or type skip)" "${DEFAULT_DOMAIN:-skip}")
[[ $DOMAIN == skip ]] && DOMAIN=

[[ $ROOT =~ ^/srv/[A-Za-z0-9][A-Za-z0-9._-]{1,63}$ ]] || { echo "Data path must be a simple directory directly under /srv" >&2; exit 1; }
[[ ! -L $ROOT ]] || { echo "Data path must not be a symbolic link" >&2; exit 1; }
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1024 && $PORT -le 65535 ]] || { echo "Port must be between 1024 and 65535" >&2; exit 1; }
if [[ -n $DOMAIN ]]; then
  [[ $DOMAIN =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $DOMAIN == *.* && $DOMAIN != *..* ]] || { echo "Invalid domain name" >&2; exit 1; }
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip git openssh-client curl ca-certificates openssl caddy

if ! id moory >/dev/null 2>&1; then
  useradd --system --home-dir "$ROOT" --create-home --shell /usr/sbin/nologin moory
fi
install -d -o root -g moory -m 750 /etc/moory
cat > "$INSTALL_CONFIG" <<EOF
MOORY_ROOT=$ROOT
MOORY_PORT=$PORT
MOORY_DOMAIN=$DOMAIN
EOF
chown root:moory "$INSTALL_CONFIG"; chmod 640 "$INSTALL_CONFIG"

install -d -o moory -g moory -m 750 "$ROOT" "$ROOT/app" "$ROOT/repos" "$ROOT/logs"
install -d -o root -g moory -m 750 "$ROOT/config"
install -d -o moory -g moory -m 700 "$ROOT/.ssh"

python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install --upgrade pip
"$ROOT/venv/bin/pip" install -r "$SOURCE_DIR/requirements.lock"
install -o moory -g moory -m 640 "$SOURCE_DIR/src/moory/server.py" "$ROOT/app/server.py"
"$ROOT/venv/bin/python" -m py_compile "$ROOT/app/server.py"

[[ -f "$ROOT/config/projects.json" ]] || printf '{}\n' > "$ROOT/config/projects.json"
chown root:moory "$ROOT/config/projects.json"; chmod 640 "$ROOT/config/projects.json"
cat > "$ROOT/.ssh/known_hosts" <<'EOF'
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabH5C9okWi0dh2l9GKJl
EOF
chown moory:moory "$ROOT/.ssh/known_hosts"; chmod 600 "$ROOT/.ssh/known_hosts"

install -o root -g root -m 755 "$SOURCE_DIR/scripts/moory" /usr/local/bin/moory
install -d -o root -g root -m 755 /usr/local/lib/moory
install -o root -g root -m 755 "$SOURCE_DIR/scripts/update.sh" /usr/local/lib/moory/update.sh
install -o root -g root -m 755 "$SOURCE_DIR/scripts/uninstall.sh" /usr/local/lib/moory/uninstall.sh
install -o root -g root -m 755 "$SOURCE_DIR/scripts/moory-setup" /usr/local/bin/moory-setup
install -o root -g root -m 755 "$SOURCE_DIR/scripts/configure-caddy.sh" /usr/local/bin/moory-configure-caddy
sed "s|@MOORY_ROOT@|$ROOT|g" "$SOURCE_DIR/systemd/moory.service" > /etc/systemd/system/moory.service
chmod 644 /etc/systemd/system/moory.service
systemctl daemon-reload

MOORY_ROOT="$ROOT" MOORY_PORT="$PORT" MOORY_DOMAIN="$DOMAIN" /usr/local/bin/moory-setup
