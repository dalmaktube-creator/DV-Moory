#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run: sudo moory update" >&2; exit 1; }
SOURCE=/opt/moory
INSTALL_CONFIG=/etc/moory/install.env
[[ -r $INSTALL_CONFIG ]] || { echo "Moory install configuration was not found" >&2; exit 1; }
set -a
source "$INSTALL_CONFIG"
set +a
ROOT=${MOORY_ROOT:-/srv/moory}
[[ $ROOT =~ ^/srv/[A-Za-z0-9][A-Za-z0-9._-]{1,63}$ && ! -L $ROOT ]] || { echo "Unsafe Moory root" >&2; exit 1; }
[[ -d $SOURCE/.git ]] || { echo "Moory source checkout was not found at /opt/moory" >&2; exit 1; }
BACKUP=$(mktemp -d /root/moory-update-backup.XXXXXX)
cp -a "$ROOT/app/server.py" "$BACKUP/server.py"
cp -a /usr/local/bin/moory "$BACKUP/moory"
cp -a /usr/local/bin/moory-setup "$BACKUP/moory-setup"
cp -a /usr/local/bin/moory-configure-caddy "$BACKUP/moory-configure-caddy"
cp -a /usr/local/lib/moory "$BACKUP/lib-moory"
cp -a /etc/systemd/system/moory.service "$BACKUP/moory.service"
rollback() {
  cp -a "$BACKUP/server.py" "$ROOT/app/server.py"
  cp -a "$BACKUP/moory" "$BACKUP/moory-setup" "$BACKUP/moory-configure-caddy" /usr/local/bin/
  rm -rf /usr/local/lib/moory
  cp -a "$BACKUP/lib-moory" /usr/local/lib/moory
  cp -a "$BACKUP/moory.service" /etc/systemd/system/moory.service
  systemctl daemon-reload
  systemctl restart moory 2>/dev/null || true
}
trap rollback ERR
git -C "$SOURCE" fetch --prune origin
git -C "$SOURCE" pull --ff-only origin main
"$ROOT/venv/bin/pip" install -r "$SOURCE/requirements.lock"
install -o moory -g moory -m 640 "$SOURCE/src/moory/server.py" "$ROOT/app/server.py"
install -o root -g root -m 755 "$SOURCE/scripts/moory" /usr/local/bin/moory
install -o root -g root -m 755 "$SOURCE/scripts/moory-setup" /usr/local/bin/moory-setup
install -o root -g root -m 755 "$SOURCE/scripts/configure-caddy.sh" /usr/local/bin/moory-configure-caddy
install -o root -g root -m 755 "$SOURCE/scripts/update.sh" /usr/local/lib/moory/update.sh
install -o root -g root -m 755 "$SOURCE/scripts/import-quick-repos.py" /usr/local/lib/moory/import-quick-repos.py
install -o root -g root -m 755 "$SOURCE/scripts/uninstall.sh" /usr/local/lib/moory/uninstall.sh
install -o root -g root -m 755 "$SOURCE/scripts/healthcheck.sh" /usr/local/lib/moory/healthcheck.sh
install -o root -g root -m 755 "$SOURCE/scripts/fetch.sh" /usr/local/lib/moory/fetch.sh
install -o root -g root -m 755 "$SOURCE/scripts/restore.sh" /usr/local/lib/moory/restore.sh
sed "s|@MOORY_ROOT@|$ROOT|g" "$SOURCE/systemd/moory.service" > /etc/systemd/system/moory.service
chmod 644 /etc/systemd/system/moory.service
install -o root -g root -m 644 "$SOURCE/systemd/moory-fetch.service" /etc/systemd/system/moory-fetch.service
install -o root -g root -m 644 "$SOURCE/systemd/moory-fetch.timer" /etc/systemd/system/moory-fetch.timer
"$ROOT/venv/bin/python" -m py_compile "$ROOT/app/server.py"
systemctl daemon-reload
systemctl restart moory
systemctl is-active --quiet moory
rm -rf "$BACKUP"; trap - ERR
printf '\033[38;5;82m✔ Moory updated successfully.\033[0m\n'
