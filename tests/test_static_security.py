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
