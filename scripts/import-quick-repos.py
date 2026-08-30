#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import jwt

INSTALL_CONFIG = Path("/etc/moory/install.env")
API_BASE = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def fail(message: str) -> None:
    print(f"\033[38;5;203m✘ {message}\033[0m", file=sys.stderr)
    raise SystemExit(1)


def ok(message: str) -> None:
    print(f"\033[38;5;82m✔ {message}\033[0m")


def info(message: str) -> None:
    print(f"\033[38;5;45m➜ {message}\033[0m")


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file() or path.is_symlink():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.lstrip().startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            values[key] = value
    return values


def ask(prompt: str) -> str:
    sys.stdout.write(f"\033[38;5;255m{prompt}\033[0m: ")
    sys.stdout.flush()
    with open("/dev/tty", "r", encoding="utf-8") as tty:
        return tty.readline().strip()


def github_json(token: str, path: str, params: dict[str, str | int]) -> Any:
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(
        f"{API_BASE}{path}?{query}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Moory-Quick-Importer/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code in {401, 403}:
            fail("GitHub rejected the token or its repository permissions")
        fail(f"GitHub API returned HTTP {error.code}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        fail("Could not read repositories from GitHub")


def github_post_json(token: str, path: str, body: dict[str, Any]) -> Any:
    request = urllib.request.Request(
        f"{API_BASE}{path}",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Moory-Repository-Importer/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read(100_000).decode("utf-8", errors="replace"))
            message = str(payload.get("message", "GitHub rejected the request"))
        except (ValueError, AttributeError):
            message = "GitHub rejected the request"
        fail(f"GitHub API returned HTTP {error.code}: {message[:300]}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        fail("Could not write repository settings through GitHub")

def github_app_installation_token(auth: dict[str, str], config_dir: Path) -> tuple[str, dict[str, Any]]:
    app_id = auth.get("GITHUB_APP_ID", "")
    installation_id = auth.get("GITHUB_INSTALLATION_ID", "")
    key_path = Path(auth.get("GITHUB_PRIVATE_KEY_PATH", ""))
    expected_key = config_dir / "github-app.pem"
    if not app_id.isdigit() or not installation_id.isdigit():
        fail("GitHub App identifiers are invalid")
    if key_path.resolve() != expected_key.resolve() or not key_path.is_file():
        fail("GitHub App private key path is invalid")
    now = int(time.time())
    app_jwt = jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": app_id},
        key_path.read_text(encoding="utf-8"),
        algorithm="RS256",
    )
    request = urllib.request.Request(
        f"{API_BASE}/app/installations/{installation_id}/access_tokens",
        data=b"{}",
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "Content-Type": "application/json",
            "User-Agent": "Moory-Repository-Importer/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        fail(f"GitHub App authentication failed with HTTP {error.code}; verify the Installation ID")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        fail("Could not authenticate the GitHub App")
    token = str(payload.get("token", ""))
    if not token:
        fail("GitHub App returned an invalid installation token")
    return token, payload


def list_accessible_repositories(token: str) -> list[dict[str, Any]]:
    repositories: list[dict[str, Any]] = []
    for page in range(1, 11):
        batch = github_json(
            token,
            "/user/repos",
            {
                "affiliation": "owner,collaborator,organization_member",
                "sort": "full_name",
                "direction": "asc",
                "per_page": 100,
                "page": page,
            },
        )
        if not isinstance(batch, list):
            fail("GitHub returned an unexpected repository list")
        for item in batch:
            if not isinstance(item, dict):
                continue
            full_name = str(item.get("full_name", ""))
            if not REPO_RE.fullmatch(full_name):
                continue
            permissions = item.get("permissions") or {}
            repositories.append(
                {
                    "repo": full_name,
                    "branch": str(item.get("default_branch") or "main"),
                    "private": bool(item.get("private")),
                    "push": bool(permissions.get("push", False)),
                }
            )
        if len(batch) < 100:
            break
    return repositories


def list_installation_repositories(token: str, permissions: dict[str, Any]) -> list[dict[str, Any]]:
    repositories: list[dict[str, Any]] = []
    for page in range(1, 11):
        payload = github_json(token, "/installation/repositories", {"per_page": 100, "page": page})
        if not isinstance(payload, dict) or not isinstance(payload.get("repositories"), list):
            fail("GitHub App returned an unexpected repository list")
        batch = payload["repositories"]
        for item in batch:
            if not isinstance(item, dict):
                continue
            full_name = str(item.get("full_name", ""))
            if not REPO_RE.fullmatch(full_name):
                continue
            repositories.append(
                {
                    "repo": full_name,
                    "branch": str(item.get("default_branch") or "main"),
                    "private": bool(item.get("private")),
                    "push": permissions.get("contents") == "write",
                }
            )
        if len(batch) < 100:
            break
    return repositories


def ensure_deploy_key(token: str, repo: str, title: str, public_key: str) -> None:
    normalized = " ".join(public_key.strip().split()[:2])
    existing = github_json(token, f"/repos/{repo}/keys", {"per_page": 100, "page": 1})
    if isinstance(existing, list):
        for item in existing:
            if isinstance(item, dict) and " ".join(str(item.get("key", "")).split()[:2]) == normalized:
                ok(f"Deploy key already exists for {repo}")
                return
    github_post_json(
        token,
        f"/repos/{repo}/keys",
        {"title": title, "key": public_key.strip(), "read_only": False},
    )
    ok(f"Deploy key registered automatically for {repo}")


def project_alias(repo: str, used: set[str]) -> str:
    owner, name = repo.split("/", 1)

    def clean(value: str) -> str:
        value = re.sub(r"[^a-z0-9_-]+", "-", value.lower()).strip("-_")
        if not value or not value[0].isalpha():
            value = f"repo-{value}"
        if len(value) < 2:
            value = f"{value}-repo"
        return value[:32].rstrip("-_")

    alias = clean(name)
    if alias in used:
        alias = clean(f"{owner}-{name}")
    suffix = 2
    base = alias
    while alias in used:
        tail = f"-{suffix}"
        alias = f"{base[:32-len(tail)]}{tail}"
        suffix += 1
    return alias


def git_as_moory(root: Path, askpass: Path, token_path: Path, *args: str) -> None:
    command = [
        "runuser",
        "-u",
        "moory",
        "--",
        "env",
        f"HOME={root}",
        f"GIT_ASKPASS={askpass}",
        "GIT_TERMINAL_PROMPT=0",
        f"MOORY_TOKEN_PATH={token_path}",
        "git",
        *args,
    ]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        output = result.stdout.replace(str(token_path), "[token-file]")[-2000:]
        fail(f"Git operation failed:\n{output}")


def main() -> None:
    if os.geteuid() != 0:
        fail("Run this importer through sudo moory")

    install = read_env(INSTALL_CONFIG)
    root_input = Path(install.get("MOORY_ROOT", "/srv/moory"))
    if root_input.is_symlink():
        fail("Unsafe Moory root")
    root = root_input.resolve()
    if not re.fullmatch(r"/srv/[A-Za-z0-9][A-Za-z0-9._-]{1,63}", str(root)):
        fail("Unsafe Moory root")

    config_dir = root / "config"
    auth = read_env(config_dir / "github-auth.env")
    mode = auth.get("GITHUB_AUTH_MODE", "")
    token_path: Path | None = None
    app_payload: dict[str, Any] = {}
    if mode == "fine_grained_pat":
        token_input = Path(auth.get("GITHUB_TOKEN_PATH", str(config_dir / "github-token")))
        if token_input.is_symlink():
            fail("Unsafe GitHub token path")
        token_path = token_input.resolve()
        if config_dir.resolve() not in token_path.parents:
            fail("Unsafe GitHub token path")
        try:
            token = token_path.read_text(encoding="utf-8").strip()
        except OSError:
            fail("GitHub token file is not readable")
        if len(token) < 20 or any(char.isspace() for char in token):
            fail("GitHub token format is invalid")
        info("Reading repositories allowed by your Fine-grained GitHub token...")
        repositories = list_accessible_repositories(token)
    elif mode == "github_app":
        token, app_payload = github_app_installation_token(auth, config_dir)
        info("Reading repositories installed for your GitHub App...")
        repositories = list_installation_repositories(token, dict(app_payload.get("permissions") or {}))
    else:
        fail("GitHub authentication is not configured")
    if not repositories:
        fail("The token does not expose any repositories")

    registry_path = config_dir / "projects.json"
    original_registry_text = registry_path.read_text(encoding="utf-8") if registry_path.exists() else None
    registry = json.loads(original_registry_text) if original_registry_text is not None else {}
    registered_repos = {str(item.get("repo")) for item in registry.values() if isinstance(item, dict)}

    print("\nRepositories available through this token:\n")
    for index, repository in enumerate(repositories, 1):
        state = "registered" if repository["repo"] in registered_repos else "available"
        privacy = "private" if repository["private"] else "public"
        access = "write" if repository["push"] else "read"
        print(f"  {index:>3}) {repository['repo']}  [{privacy}, {access}, {state}]")
    print("\nEnter comma-separated numbers, or ALL to register every available repository.")
    selection = ask("Selection (example: 1,3 or ALL; Q cancels)")
    if selection.upper() == "Q":
        print("Cancelled. Nothing changed.")
        return
    if selection.upper() == "ALL":
        selected = [repo for repo in repositories if repo["repo"] not in registered_repos]
        if len(selected) > 10:
            confirmation = ask(f"This will clone {len(selected)} repositories. Type ALL again to confirm")
            if confirmation != "ALL":
                print("Cancelled. Nothing changed.")
                return
    else:
        indexes: set[int] = set()
        for part in selection.split(","):
            part = part.strip()
            if not part.isdigit() or not 1 <= int(part) <= len(repositories):
                fail("Selection must contain valid repository numbers")
            indexes.add(int(part) - 1)
        selected = [repositories[index] for index in sorted(indexes)]
        selected = [repo for repo in selected if repo["repo"] not in registered_repos]

    if not selected:
        ok("All selected repositories are already registered")
        return
    if len(registry) + len(selected) > 50:
        fail("Moory supports at most 50 registered projects; reduce the selection")


    repos_root = root / "repos"
    logs_root = root / "logs"
    repos_root.mkdir(parents=True, exist_ok=True)
    logs_root.mkdir(parents=True, exist_ok=True)
    used = set(registry)

    descriptor, askpass_name = tempfile.mkstemp(prefix="moory-askpass-", dir=logs_root)
    os.close(descriptor)
    askpass = Path(askpass_name)
    askpass.write_text(
        "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s\\n' x-access-token;;\n  *) cat \"$MOORY_TOKEN_PATH\";;\nesac\n",
        encoding="utf-8",
    )
    os.chmod(askpass, 0o700)
    subprocess.run(["chown", "moory:moory", str(askpass)], check=True)

    created_clones: list[Path] = []
    try:
        for repository in selected:
            repo = repository["repo"]
            branch = repository["branch"]
            alias = project_alias(repo, used)
            clone = (repos_root / alias).resolve()
            if repos_root.resolve() not in clone.parents:
                fail("Unsafe repository clone path")
            if clone.exists():
                fail(f"Clone path already exists: {clone}")
            info(f"Cloning {repo} as '{alias}'...")
            clone_url = "https://" + "github.com/" + repo + ".git"
            git_as_moory(root, askpass, token_path, "clone", clone_url, str(clone))
            created_clones.append(clone)
            remote_branch = subprocess.run(
                ["runuser", "-u", "moory", "--", "git", "-C", str(clone), "show-ref", "--verify", f"refs/remotes/origin/{branch}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if remote_branch.returncode == 0:
                git_as_moory(root, askpass, token_path, "-C", str(clone), "checkout", "-B", branch, f"origin/{branch}")
            else:
                git_as_moory(root, askpass, token_path, "-C", str(clone), "checkout", "-B", branch)
            registry[alias] = {"repo": repo, "branch": branch, "path": str(clone)}
            used.add(alias)
            ok(f"Registered {repo} as '{alias}'")

        temp_registry = registry_path.with_suffix(".tmp")
        temp_registry.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temp_registry, 0o640)
        temp_registry.replace(registry_path)
        subprocess.run(["chown", "root:moory", str(registry_path)], check=True)
        subprocess.run(["systemctl", "restart", "moory.service"], check=True)
        ok(f"Imported {len(selected)} repository/repositories from the token")
    except BaseException:
        if original_registry_text is None:
            registry_path.unlink(missing_ok=True)
        else:
            registry_path.write_text(original_registry_text, encoding="utf-8")
            os.chmod(registry_path, 0o640)
            subprocess.run(["chown", "root:moory", str(registry_path)], check=False)
        for clone in reversed(created_clones):
            shutil.rmtree(clone, ignore_errors=True)
        raise
    finally:
        askpass.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
