from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "src/moory/server.py").read_text(encoding="utf-8")

required = [
    'version="1.0.0"',
    "WRITE_LOCK",
    "TOKEN_LOCK",
    "Repository is not allowlisted",
    "PROJECTS_FILE",
    'GITHUB_AUTH_MODE',
    'fine_grained_pat',
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
menu = (root / "scripts/moory").read_text(encoding="utf-8")
assert "MOORY_SOURCE_DIR" not in bootstrap
assert "rm -rf /opt/moory" in bootstrap
assert "--exclude='github-token'" in menu
assert "Project name is already registered" in menu
update = (root / "scripts/update.sh").read_text(encoding="utf-8")
uninstall = (root / "scripts/uninstall.sh").read_text(encoding="utf-8")
assert 'source "$INSTALL_CONFIG"' in update
assert 'sed "s|@MOORY_ROOT@|$ROOT|g"' in update
assert 'rm -rf --one-file-system "$ROOT"' in uninstall
assert 'Domain, port & HTTPS' in menu
assert '-C "$ROOT" config logs' in menu
