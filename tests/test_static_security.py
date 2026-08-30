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
    'safe_search_candidate',
    'filtered_sensitive_matches',
    'AKIA[0-9A-Z]{16}',
    'repository_map',
    'moory_tool_catalog',
    'validate_project',
    'Repository code was parsed but not executed.',
    'apply_change_set',
    'validation_profile',
    'clean_after_rollback',
    'release_readiness',
    'remote_fully_synced',
    'latest_ci_matches_head',
    'github_release_available',
    'set(registered).issubset(set(installed_repos))',
    'Audit log unavailable; GitHub write blocked',
    'apply_patch_preflight',
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
    "github_list_deployments",
    "github_get_deployment",
    "github_create_deployment",
    "github_create_deployment_status",
    "github_list_environments",
    "github_get_environment",
    "github_upsert_environment",
    "github_list_actions_variables",
    "github_upsert_actions_variable",
    "github_get_pages",
    "github_configure_pages",
    "github_request_pages_build",
    "github_list_workflows",
    "github_get_workflow",
    "github_set_workflow_state",
    "github_list_repository_artifacts",
    "github_get_artifact",
    "github_list_commit_checks",
    "github_get_check_run",
    "github_create_check_run",
    "github_update_check_run",
    "github_list_commit_statuses",
    "github_create_commit_status",
    "github_list_secret_scanning_alerts",
    "github_get_secret_scanning_alert",
    "github_list_secret_scanning_locations",
    "github_update_secret_scanning_alert",
    "github_list_code_scanning_alerts",
    "github_get_code_scanning_alert",
    "github_update_code_scanning_alert",
    "github_list_dependabot_alerts",
    "github_get_dependabot_alert",
    "github_list_code_quality_findings",
    "github_list_secret_scanning_bypass_requests",
    "github_get_secret_scanning_bypass_request",
    "github_list_repository_security_advisories",
    "github_get_repository_security_advisory",
    "github_create_repository_security_advisory",
    "github_update_repository_security_advisory",
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
setup = (root / "scripts/moory-setup").read_text(encoding="utf-8")
importer = (root / "scripts/import-quick-repos.py").read_text(encoding="utf-8")
update = (root / "scripts/update.sh").read_text(encoding="utf-8")
uninstall = (root / "scripts/uninstall.sh").read_text(encoding="utf-8")
restore = (root / "scripts/restore.sh").read_text(encoding="utf-8")
caddy = (root / "scripts/configure-caddy.sh").read_text(encoding="utf-8")
fetch = (root / "scripts/fetch.sh").read_text(encoding="utf-8")
health = (root / "scripts/healthcheck.sh").read_text(encoding="utf-8")
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
assert 'Restore health check failed; rolling back registry' in restore
assert '"next_page": safe_page + 1' in source
assert 'trap rollback ERR' in caddy
assert 'fetch --prune origin' in fetch
assert 'NEXT_VENV=' in update
assert 'chmod 755 "$NEXT_VENV"' in update
assert 'VENV_SWAPPED=1' in update
assert 'mv "$PREVIOUS_VENV" "$ROOT/venv"' in update
assert '"$ROOT/venv/bin/python" -m pip install --force-reinstall' in update
assert '"$ROOT/venv/bin/pip" install' not in update
assert 'tools/list' in health
assert 'github_health' in health
assert 'authentication' in health
assert 'projects registry validation' in health
assert '"$ROOT/venv/bin/python" /usr/local/lib/moory/import-quick-repos.py' in menu
assert 'if [[ -n ${MOORY_DOMAIN:-} ]]' in setup
assert 'github_app_installation_token' in importer
assert '/installation/repositories' in importer
assert 'ALL to register every available repository' in importer
assert 'moory-app-token-' in importer
assert 'temporary_token_path.unlink' in importer
assert 'pull ' not in fetch
