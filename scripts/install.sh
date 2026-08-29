#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run: sudo ./scripts/install.sh" >&2; exit 1; }
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ROOT=/srv/moory

printf '\033[38;5;39m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[38;5;39m║\033[0m  \033[1;38;5;45mMOORY INSTALLER\033[0m  Secure GitHub ↔ MCP bridge                  \033[38;5;39m║\033[0m\n'
printf '\033[38;5;39m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n'

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip git openssh-client curl ca-certificates openssl caddy

if ! id moory >/dev/null 2>&1; then
  useradd --system --home-dir "$ROOT" --create-home --shell /usr/sbin/nologin moory
fi
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
install -o root -g root -m 755 "$SOURCE_DIR/scripts/moory-setup" /usr/local/bin/moory-setup
install -o root -g root -m 755 "$SOURCE_DIR/scripts/configure-caddy.sh" /usr/local/bin/moory-configure-caddy
install -o root -g root -m 644 "$SOURCE_DIR/systemd/moory.service" /etc/systemd/system/moory.service
systemctl daemon-reload

/usr/local/bin/moory-setup
