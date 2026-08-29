#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run: sudo moory update" >&2; exit 1; }
SOURCE=/opt/moory
ROOT=/srv/moory
[[ -d $SOURCE/.git ]] || { echo "Moory source checkout was not found at /opt/moory" >&2; exit 1; }
BACKUP=$(mktemp -d /root/moory-update-backup.XXXXXX)
cp -a "$ROOT/app/server.py" "$BACKUP/server.py"
cp -a /usr/local/bin/moory /usr/local/bin/moory-setup "$BACKUP/"
trap 'cp -a "$BACKUP/server.py" "$ROOT/app/server.py"; cp -a "$BACKUP/moory" "$BACKUP/moory-setup" /usr/local/bin/; systemctl restart moory 2>/dev/null || true' ERR
git -C "$SOURCE" fetch --prune origin
git -C "$SOURCE" pull --ff-only origin main
"$ROOT/venv/bin/pip" install -r "$SOURCE/requirements.lock"
install -o moory -g moory -m 640 "$SOURCE/src/moory/server.py" "$ROOT/app/server.py"
install -o root -g root -m 755 "$SOURCE/scripts/moory" /usr/local/bin/moory
install -o root -g root -m 755 "$SOURCE/scripts/moory-setup" /usr/local/bin/moory-setup
install -o root -g root -m 755 "$SOURCE/scripts/update.sh" /usr/local/lib/moory/update.sh
install -o root -g root -m 644 "$SOURCE/systemd/moory.service" /etc/systemd/system/moory.service
"$ROOT/venv/bin/python" -m py_compile "$ROOT/app/server.py"
systemctl daemon-reload
systemctl restart moory
systemctl is-active --quiet moory
rm -rf "$BACKUP"; trap - ERR
printf '\033[38;5;82m✔ Moory updated successfully.\033[0m\n'
