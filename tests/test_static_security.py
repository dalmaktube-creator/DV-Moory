from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "src/moory/server.py").read_text(encoding="utf-8")

required = [
    'version="1.1.0"',
    "WRITE_LOCK",
    "TOKEN_LOCK",
    "Repository is not allowlisted",
    "PROJECTS_FILE",
    'GITHUB_AUTH_MODE',
    'fine_grained_pat',
    'MOORY_GITHUB_TOKEN_PATH',
    'worker_context',
    'detail=full as an explicit escape hatch',
    'repository_map',
    'moory_tool_catalog',
    'validate_project',
    'Repository code was parsed but not executed.',
    'apply_change_set',
    'validation_profile',
    'clean_after_rollback',
    'release_readiness',
    'error_groups',
    '"partial": bool(unavailable)',
    '"unavailable": unavailable',
    'Symbolic links are not readable',
    'rename to ',
    'copy to ',
    "GitHub API path is not allowlisted",
    "github_merge_pull_request",
    "github_get_actions_log",
    "github_create_release",
    "Possible secret detected; GitHub write blocked",
]
for value in required:
    assert value in source, value

for forbidden in [
    'shell=True',
    'os.system(',
    'subprocess.Popen',
    'method="DELETE"',
    'push --force',
    'reset --hard',
]:
    assert forbidden not in source, forbidden

print("Static security checks passed")

bootstrap = (root / "install.sh").read_text(encoding="utf-8")
installer = (root / "scripts/install.sh").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")
menu = (root / "scripts/moory").read_text(encoding="utf-8")
update = (root / "scripts/update.sh").read_text(encoding="utf-8")
uninstall = (root / "scripts/uninstall.sh").read_text(encoding="utf-8")
restore = (root / "scripts/restore.sh").read_text(encoding="utf-8")
caddy = (root / "scripts/configure-caddy.sh").read_text(encoding="utf-8")
fetch = (root / "scripts/fetch.sh").read_text(encoding="utf-8")
assert "MOORY_SOURCE_DIR" not in bootstrap
assert "rm -rf /opt/moory" in bootstrap
assert "Moory currently supports Ubuntu 24.04 only." in bootstrap
assert "Moory currently supports Ubuntu 24.04 only." in installer
assert "Moory requires Python 3.12 or newer" in installer
assert "https://raw.githubusercontent.com/dalmaktube-creator/DV-Moory/main/install.sh" in readme
assert "Project name is already registered" in menu
assert 'source "$INSTALL_CONFIG"' in update
assert 'sed "s|@MOORY_ROOT@|$ROOT|g"' in update
assert 'rm -rf --one-file-system "$ROOT"' in uninstall
assert 'Domain, port & HTTPS' in menu
assert 'Backup & restore' in menu
assert '-C "$ROOT" config/projects.json' in menu
assert 'Backup contains unexpected files' in restore
assert 'trap rollback ERR' in caddy
assert 'fetch --prune origin' in fetch
assert 'pull ' not in fetch
