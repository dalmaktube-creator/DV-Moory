from __future__ import annotations

import ast
import io
import json
import os
import re
import shlex
import subprocess
import tempfile
import tomllib
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import jwt
from mcp.server import MCPServer

ProjectName = str

ROOT = Path(os.environ.get("MOORY_ROOT", "/srv/moory")).resolve()
PORT_TEXT = os.environ.get("MOORY_PORT", "8787")
if not PORT_TEXT.isdigit() or not 1024 <= int(PORT_TEXT) <= 65535:
    raise ValueError("MOORY_PORT must be between 1024 and 65535")
PORT = int(PORT_TEXT)
REPOS_ROOT = (ROOT / "repos").resolve()
PROJECTS_FILE = ROOT / "config/projects.json"


def load_projects() -> dict[str, dict[str, Any]]:
    if not PROJECTS_FILE.is_file():
        return {}
    raw = json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or len(raw) > 50:
        raise ValueError("Invalid projects registry")
    projects: dict[str, dict[str, Any]] = {}
    for name, config in raw.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", name):
            raise ValueError("Invalid project name in registry")
        if not isinstance(config, dict):
            raise ValueError("Invalid project configuration")
        repo = str(config.get("repo", ""))
        branch = str(config.get("branch", ""))
        path = Path(str(config.get("path", ""))).resolve()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("Invalid GitHub repository in registry")
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or ".." in branch:
            raise ValueError("Invalid branch in registry")
        if path == REPOS_ROOT or REPOS_ROOT not in path.parents:
            raise ValueError("Project path must be under the Moory repositories directory")
        projects[name] = {"repo": repo, "branch": branch, "path": path}
    return projects


PROJECTS = load_projects()
AUDIT_LOG = ROOT / "logs/audit.jsonl"
PATCH_TMP_DIR = ROOT / "logs"
GITHUB_AUTH_CONFIG = ROOT / "config/github-auth.env"
WRITE_LOCK = threading.Lock()
TOKEN_LOCK = threading.Lock()
CONTEXT_CACHE_LOCK = threading.Lock()
GH_TOKEN_CACHE: dict[str, Any] = {"token": "", "expires_epoch": 0, "expires_at": "", "permissions": {}, "repository_selection": "", "auth_mode": ""}
CONTEXT_CACHE: dict[tuple[str, str], dict[str, Any]] = {}
MAX_CONTEXT_CACHE_ENTRIES = 64
DETAIL_LEVELS = ("summary", "evidence", "full")
MAX_PATCH_BYTES = 500_000

SENSITIVE_SUFFIXES = {
    ".key", ".pem", ".p12", ".pfx", ".jks", ".keystore",
}
SENSITIVE_NAMES = {
    ".env", ".ssh", ".npmrc", ".pypirc", "auth.json",
    "credentials", "credentials.json", "google-services.json",
    "id_rsa", "id_ed25519", "secrets", "service-account.json",
}
SECRET_PATTERN = (
    r"-----BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY-----"
    r"|(?:MOORY_TOKEN|GITHUB_TOKEN)\s*=\s*[A-Za-z0-9_./+=:-]{20,}"
    r"|github_" r"pat_[A-Za-z0-9_]{20,}"
    r"|ghp_" r"[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|pypi-[A-Za-z0-9_-]{40,}"
    r"|npm_[A-Za-z0-9]{36}"
    r"|(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:/]+:[^\s@/]+@"
)

GIT_SECRET_PATTERN = (
    r"-----BEGIN (OPENSSH |RSA |EC )?PRIVATE KEY-----"
    r"|(MOORY_TOKEN|GITHUB_TOKEN)[[:space:]]*=[[:space:]]*[A-Za-z0-9_./+=:-]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,}"
    r"|sk_(live|test)_[A-Za-z0-9]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|pypi-[A-Za-z0-9_-]{40,}"
    r"|npm_[A-Za-z0-9]{36}"
)

mcp = MCPServer(
    name="Moory",
    version="1.1.0",
    description="Deterministic self-hosted MCP worker for bounded context, guarded changes, CI inspection, and curated GitHub operations.",
    instructions=(
        "Moory executes deterministic work; the connected agent reasons and decides. Start context work with "
        "worker_context detail=summary, escalate to evidence before editing, and use full only when evidence is "
        "truncated, ambiguous, contradictory, or insufficient. Read exact current file ranges before patching. "
        "Only use registered projects and approved branches. Never expose secrets, force-push, rewrite history, "
        "delete repositories, or run arbitrary shell commands. Validate changes before commit and push."
    ),
)


GH_API_BASE = "https://api.github.com"
GH_API_VERSION = "2022-11-28"
GH_USER_AGENT = "Moory/1.1.0"
MAX_GH_JSON_BYTES = 5_000_000
MAX_GH_LOG_ZIP_BYTES = 20_000_000
MAX_GH_LOG_TEXT_BYTES = 25_000_000
GH_LOG_REDACTIONS = [
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|token)\s+)[^\s]+"),
    re.compile(r"(?i)(MOORY_TOKEN\s*=\s*)[^\s]+"),
    re.compile(r"(?i)(GITHUB_TOKEN\s*=\s*)[^\s]+"),
    re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----.*?-----END (?:OPENSSH |RSA |EC )?PRIVATE KEY-----", re.DOTALL),
]


def load_key_value_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("Invalid GitHub App configuration")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def redact_github_text(text: str) -> str:
    result = text
    for pattern in GH_LOG_REDACTIONS:
        if pattern.groups:
            result = pattern.sub(lambda match: match.group(1) + "[REDACTED]", result)
        else:
            result = pattern.sub("[REDACTED PRIVATE KEY]", result)
    return result


def _read_limited(response: Any, maximum_bytes: int) -> bytes:
    data = response.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise ValueError("GitHub response exceeded the configured size limit")
    return data


def _github_http(
    path: str,
    *,
    method: str = "GET",
    token: str,
    body: dict[str, Any] | None = None,
    accept: str = "application/vnd.github+json",
    maximum_bytes: int = MAX_GH_JSON_BYTES,
) -> tuple[int, bytes, dict[str, str]]:
    if not path.startswith("/") or "\x00" in path:
        raise ValueError("Invalid GitHub API path")
    allowed_prefixes = ("/repos/", "/orgs/", "/users/", "/graphql", "/installation/", "/rate_limit")
    if not path.startswith(allowed_prefixes):
        raise ValueError("GitHub API path is not allowlisted")
    payload = None if body is None else json.dumps(body).encode("utf-8")
    headers = {
        "Accept": accept,
        "Authorization": "Bearer " + token,
        "User-Agent": GH_USER_AGENT,
        "X-GitHub-Api-Version": GH_API_VERSION,
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        GH_API_BASE + path,
        data=payload,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = _read_limited(response, maximum_bytes)
            return response.status, data, {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        raw = error.read(200_000)
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            message = str(parsed.get("message", "GitHub API request failed"))
        except (ValueError, AttributeError):
            message = "GitHub API request failed"
        raise RuntimeError(f"GitHub API HTTP {error.code}: {redact_github_text(message)[:500]}") from None
    except urllib.error.URLError as error:
        raise RuntimeError(f"GitHub API connection failed: {str(error.reason)[:300]}") from None


def github_installation_token() -> tuple[str, dict[str, Any]]:
    now = int(time.time())
    with TOKEN_LOCK:
        if GH_TOKEN_CACHE["token"] and now < int(GH_TOKEN_CACHE["expires_epoch"]) - 180:
            return str(GH_TOKEN_CACHE["token"]), dict(GH_TOKEN_CACHE)

        config = load_key_value_file(GITHUB_AUTH_CONFIG)
        mode = config.get("GITHUB_AUTH_MODE", "github_app")
        if mode == "fine_grained_pat":
            token_path = Path(config.get("GITHUB_TOKEN_PATH", "")).resolve()
            allowed_path = (ROOT / "config/github-token").resolve()
            if token_path != allowed_path or not token_path.is_file():
                raise ValueError("GitHub token path is not allowlisted")
            token = token_path.read_text(encoding="utf-8").strip()
            if len(token) < 20 or any(char.isspace() for char in token):
                raise ValueError("GitHub fine-grained token is invalid")
            GH_TOKEN_CACHE.update({
                "token": token, "expires_epoch": now + 900, "expires_at": "managed by user",
                "permissions": {}, "repository_selection": "registry", "auth_mode": mode,
            })
            return token, dict(GH_TOKEN_CACHE)

        if mode != "github_app":
            raise ValueError("Unsupported GitHub authentication mode")
        required = {"GITHUB_APP_ID", "GITHUB_INSTALLATION_ID", "GITHUB_PRIVATE_KEY_PATH"}
        if not required.issubset(config):
            raise ValueError("GitHub App configuration is incomplete")
        if not config["GITHUB_APP_ID"].isdigit() or not config["GITHUB_INSTALLATION_ID"].isdigit():
            raise ValueError("GitHub App numeric identifiers are invalid")
        private_key_path = Path(config["GITHUB_PRIVATE_KEY_PATH"]).resolve()
        allowed_key = (ROOT / "config/github-app.pem").resolve()
        if private_key_path != allowed_key:
            raise ValueError("GitHub private key path is not allowlisted")
        private_key = private_key_path.read_text(encoding="utf-8")
        app_jwt = jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": config["GITHUB_APP_ID"]},
            private_key, algorithm="RS256",
        )
        path = f"/app/installations/{config['GITHUB_INSTALLATION_ID']}/access_tokens"
        request = urllib.request.Request(
            GH_API_BASE + path, data=b"{}", method="POST",
            headers={
                "Accept": "application/vnd.github+json", "Authorization": "Bearer " + app_jwt,
                "User-Agent": GH_USER_AGENT, "X-GitHub-Api-Version": GH_API_VERSION,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                token_data = json.loads(_read_limited(response, 200_000))
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"GitHub App authentication failed with HTTP {error.code}") from None
        token = str(token_data.get("token", "")); expires_at = str(token_data.get("expires_at", ""))
        if not token or not expires_at:
            raise RuntimeError("GitHub App returned an invalid installation token")
        try:
            expires_epoch = int(datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp())
        except ValueError:
            expires_epoch = now + 3000
        GH_TOKEN_CACHE.update({
            "token": token, "expires_epoch": expires_epoch, "expires_at": expires_at,
            "permissions": token_data.get("permissions", {}),
            "repository_selection": token_data.get("repository_selection", ""), "auth_mode": mode,
        })
        return token, dict(GH_TOKEN_CACHE)


def github_repo(project: ProjectName) -> str:
    config = PROJECTS.get(project)
    if config is None:
        raise ValueError("Unknown or unregistered project")
    repo = str(config.get("repo", ""))
    if repo not in {str(item["repo"]) for item in PROJECTS.values()}:
        raise ValueError("Repository is not allowlisted")
    return repo


def github_json(
    project: ProjectName,
    suffix: str,
    *,
    query: dict[str, Any] | None = None,
) -> Any:
    if (suffix and not suffix.startswith("/")) or ".." in suffix or "\x00" in suffix:
        raise ValueError("Invalid repository API path")
    repo = github_repo(project)
    path = f"/repos/{repo}{suffix}"
    if query:
        filtered = {key: value for key, value in query.items() if value not in (None, "")}
        if filtered:
            path += "?" + urllib.parse.urlencode(filtered)
    token, _ = github_installation_token()
    _, raw, _ = _github_http(path, token=token)
    return json.loads(raw.decode("utf-8")) if raw else {}



def github_write_json(
    project: ProjectName,
    suffix: str,
    *,
    method: Literal["POST", "PATCH", "PUT"],
    body: dict[str, Any],
    audit_action: str,
) -> dict[str, Any]:
    if (suffix and not suffix.startswith("/")) or ".." in suffix or "\x00" in suffix:
        raise ValueError("Invalid repository API path")
    repo = github_repo(project)
    if not audit(f"{audit_action}_preflight", project, True, "write preflight"):
        raise RuntimeError("Audit log unavailable; GitHub write blocked")
    token, _ = github_installation_token()
    status, raw, _ = _github_http(
        f"/repos/{repo}{suffix}",
        method=method,
        token=token,
        body=body,
    )
    result = json.loads(raw.decode("utf-8")) if raw else {}
    audit(audit_action, project, 200 <= status < 300, f"HTTP {status}")
    return {"status": status, "data": result}


def github_org_json(project: ProjectName, suffix: str, query: dict[str, Any] | None = None) -> Any:
    if (suffix and not suffix.startswith("/")) or ".." in suffix or "\x00" in suffix:
        raise ValueError("Invalid organization API path")
    owner = github_repo(project).split("/", 1)[0]
    path = f"/orgs/{owner}{suffix}"
    if query:
        filtered = {key: value for key, value in query.items() if value not in (None, "")}
        if filtered: path += "?" + urllib.parse.urlencode(filtered)
    token, _ = github_installation_token()
    _, raw, _ = _github_http(path, token=token)
    return json.loads(raw.decode("utf-8")) if raw else {}


def github_user_json(project: ProjectName, suffix: str, query: dict[str, Any] | None = None) -> Any:
    if (suffix and not suffix.startswith("/")) or ".." in suffix or "\x00" in suffix:
        raise ValueError("Invalid user API path")
    owner = github_repo(project).split("/", 1)[0]
    path = f"/users/{owner}{suffix}"
    if query:
        filtered = {key: value for key, value in query.items() if value not in (None, "")}
        if filtered: path += "?" + urllib.parse.urlencode(filtered)
    token, _ = github_installation_token()
    _, raw, _ = _github_http(path, token=token)
    return json.loads(raw.decode("utf-8")) if raw else {}


def github_org_write_json(project: ProjectName, suffix: str, *, body: dict[str, Any], audit_action: str) -> dict[str, Any]:
    if (suffix and not suffix.startswith("/")) or ".." in suffix or "\x00" in suffix:
        raise ValueError("Invalid organization API path")
    owner = github_repo(project).split("/", 1)[0]
    if not audit(f"{audit_action}_preflight", project, True, "write preflight"):
        raise RuntimeError("Audit log unavailable; GitHub write blocked")
    token, _ = github_installation_token()
    status, raw, _ = _github_http(f"/orgs/{owner}{suffix}", method="POST", token=token, body=body)
    result = json.loads(raw.decode("utf-8")) if raw else {}
    audit(audit_action, project, 200 <= status < 300, f"HTTP {status}")
    return {"status": status, "data": result}


def github_graphql(project: ProjectName, query: str, variables: dict[str, Any], audit_action: str = "") -> dict[str, Any]:
    github_repo(project)
    if audit_action and not audit(f"{audit_action}_preflight", project, True, "write preflight"):
        raise RuntimeError("Audit log unavailable; GitHub GraphQL write blocked")
    token, _ = github_installation_token()
    status, raw, _ = _github_http("/graphql", method="POST", token=token, body={"query": query, "variables": variables})
    data = json.loads(raw.decode("utf-8")) if raw else {}
    if data.get("errors"): raise RuntimeError("GitHub GraphQL: " + json.dumps(data["errors"])[:1000])
    if audit_action: audit(audit_action, project, 200 <= status < 300, f"HTTP {status}")
    return data.get("data", {})


def validate_digest(value: str) -> str:
    clean = value.strip().lower()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", clean):
        raise ValueError("digest must use sha256: followed by 64 hexadecimal characters")
    return clean


def validate_title(value: str, label: str = "title") -> str:
    clean = value.strip()
    if not clean or len(clean) > 256 or "\x00" in clean:
        raise ValueError(f"{label} must be 1 to 256 characters")
    return clean


def validate_body(value: str, maximum: int = 60_000, label: str = "body") -> str:
    if "\x00" in value or len(value) > maximum:
        raise ValueError(f"{label} must be at most {maximum} characters")
    if redact_github_text(value) != value or re.search(SECRET_PATTERN, value, flags=re.IGNORECASE):
        raise ValueError("Possible secret detected; GitHub write blocked")
    return value.strip()


def validate_ref(value: str, label: str = "branch") -> str:
    clean = value.strip()
    if not clean or len(clean) > 200 or not re.fullmatch(r"[A-Za-z0-9._/\-]+", clean):
        raise ValueError(f"Invalid {label}")
    if clean.startswith("/") or clean.endswith("/") or "//" in clean or ".." in clean:
        raise ValueError(f"Invalid {label}")
    return clean


def validate_tag(value: str) -> str:
    clean = value.strip()
    if not clean or len(clean) > 150 or not re.fullmatch(r"[A-Za-z0-9._/+\-]+", clean):
        raise ValueError("Invalid tag name")
    if clean.startswith("/") or clean.endswith("/") or ".." in clean:
        raise ValueError("Invalid tag name")
    return clean


def validate_labels(labels: list[str]) -> list[str]:
    if len(labels) > 20:
        raise ValueError("At most 20 labels are allowed")
    clean: list[str] = []
    for label in labels:
        value = label.strip()
        if not value or len(value) > 50 or any(ord(char) < 32 for char in value):
            raise ValueError("Invalid label")
        clean.append(value)
    return list(dict.fromkeys(clean))


def duplicate_comment(project: ProjectName, issue_number: int, body: str) -> dict[str, Any] | None:
    comments = github_json(project, f"/issues/{issue_number}/comments", query={"per_page": 100})
    normalized = body.strip()
    for item in comments:
        if str(item.get("body", "")).strip() == normalized:
            return {
                "ok": False,
                "error": "Identical comment already exists",
                "existing_comment_id": item.get("id"),
                "html_url": item.get("html_url"),
            }
    return None


def require_positive_id(value: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def validate_environment_name(value: str) -> str:
    clean = value.strip()
    if not clean or len(clean) > 255 or any(ord(char) < 32 for char in clean):
        raise ValueError("Environment name must be 1 to 255 printable characters")
    return clean


def validate_variable_name(value: str) -> str:
    clean = value.strip().upper()
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,99}", clean):
        raise ValueError("Variable name must use 1 to 100 letters, numbers, or underscores")
    return clean


def validate_external_url(value: str, label: str) -> str:
    clean = value.strip()
    if not clean:
        return ""
    parsed = urllib.parse.urlparse(clean)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or len(clean) > 2_000:
        raise ValueError(f"Invalid {label}")
    return clean


def quote_path_value(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def compact_user(user: Any) -> str | None:
    return user.get("login") if isinstance(user, dict) else None


def compact_labels(labels: Any) -> list[str]:
    if not isinstance(labels, list):
        return []
    return [str(item.get("name")) for item in labels if isinstance(item, dict) and item.get("name")][:30]


def compact_issue(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": item.get("number"),
        "title": item.get("title"),
        "state": item.get("state"),
        "state_reason": item.get("state_reason"),
        "author": compact_user(item.get("user")),
        "assignees": [compact_user(user) for user in item.get("assignees", []) if compact_user(user)],
        "labels": compact_labels(item.get("labels")),
        "comments": item.get("comments"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "closed_at": item.get("closed_at"),
        "html_url": item.get("html_url"),
    }


def compact_pull(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": item.get("number"),
        "title": item.get("title"),
        "state": item.get("state"),
        "draft": item.get("draft"),
        "merged": item.get("merged"),
        "mergeable": item.get("mergeable"),
        "author": compact_user(item.get("user")),
        "head": (item.get("head") or {}).get("ref"),
        "head_sha": (item.get("head") or {}).get("sha"),
        "base": (item.get("base") or {}).get("ref"),
        "comments": item.get("comments"),
        "review_comments": item.get("review_comments"),
        "commits": item.get("commits"),
        "additions": item.get("additions"),
        "deletions": item.get("deletions"),
        "changed_files": item.get("changed_files"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "merged_at": item.get("merged_at"),
        "html_url": item.get("html_url"),
    }


def compact_release(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "tag_name": item.get("tag_name"),
        "name": item.get("name"),
        "draft": item.get("draft"),
        "prerelease": item.get("prerelease"),
        "target_commitish": item.get("target_commitish"),
        "author": compact_user(item.get("author")),
        "created_at": item.get("created_at"),
        "published_at": item.get("published_at"),
        "html_url": item.get("html_url"),
        "assets": [
            {
                "id": asset.get("id"),
                "name": asset.get("name"),
                "size": asset.get("size"),
                "download_count": asset.get("download_count"),
                "content_type": asset.get("content_type"),
                "browser_download_url": asset.get("browser_download_url"),
                "created_at": asset.get("created_at"),
            }
            for asset in item.get("assets", [])[:50]
            if isinstance(asset, dict)
        ],
    }


def compact_run(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "display_title": item.get("display_title"),
        "event": item.get("event"),
        "status": item.get("status"),
        "conclusion": item.get("conclusion"),
        "workflow_id": item.get("workflow_id"),
        "run_number": item.get("run_number"),
        "run_attempt": item.get("run_attempt"),
        "head_branch": item.get("head_branch"),
        "head_sha": item.get("head_sha"),
        "actor": compact_user(item.get("actor")),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "html_url": item.get("html_url"),
        "artifacts_url": item.get("artifacts_url"),
    }


def run_git(
    project: ProjectName,
    arguments: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 45,
    output_limit: int = 200_000,
) -> dict:
    config = PROJECTS.get(project)
    if config is None:
        return {"ok": False, "exit_code": -1, "output": "", "error": "Unknown project"}

    path = config["path"]
    if not path.is_dir():
        return {
            "ok": False,
            "exit_code": -1,
            "output": "",
            "error": "Project directory is missing",
        }

    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(ROOT),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "0",
    }

    askpass_path: Path | None = None
    temporary_token_path: Path | None = None
    auth_config = load_key_value_file(GITHUB_AUTH_CONFIG)
    if auth_config.get("GITHUB_AUTH_MODE") == "fine_grained_pat":
        token_path = Path(auth_config.get("GITHUB_TOKEN_PATH", "")).resolve()
        allowed_token_path = (ROOT / "config/github-token").resolve()
        if token_path != allowed_token_path or not token_path.is_file():
            return {"ok": False, "exit_code": -1, "output": "", "error": "GitHub token path is not allowlisted"}
        descriptor, askpass_name = tempfile.mkstemp(prefix=".git-askpass-", dir=ROOT / "logs")
        os.close(descriptor)
        askpass_path = Path(askpass_name)
        askpass_path.write_text(
            "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s\\n' x-access-token;;\n  *) cat \"$MOORY_GITHUB_TOKEN_PATH\";;\nesac\n",
            encoding="utf-8",
        )
        os.chmod(askpass_path, 0o700)
        environment["GIT_ASKPASS"] = str(askpass_path)
        environment["MOORY_GITHUB_TOKEN_PATH"] = str(token_path)
    elif auth_config.get("GITHUB_AUTH_MODE") == "github_app":
        try:
            token, _ = github_installation_token()
        except (ValueError, RuntimeError, OSError) as error:
            return {"ok": False, "exit_code": -1, "output": "", "error": redact_github_text(str(error))[:500]}
        descriptor, token_name = tempfile.mkstemp(prefix=".git-app-token-", dir=ROOT / "logs")
        os.close(descriptor)
        temporary_token_path = Path(token_name)
        temporary_token_path.write_text(token, encoding="utf-8")
        os.chmod(temporary_token_path, 0o600)
        descriptor, askpass_name = tempfile.mkstemp(prefix=".git-askpass-", dir=ROOT / "logs")
        os.close(descriptor)
        askpass_path = Path(askpass_name)
        askpass_path.write_text(
            "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s\\n' x-access-token;;\n  *) cat \"$MOORY_GITHUB_TOKEN_PATH\";;\nesac\n",
            encoding="utf-8",
        )
        os.chmod(askpass_path, 0o700)
        environment["GIT_ASKPASS"] = str(askpass_path)
        environment["MOORY_GITHUB_TOKEN_PATH"] = str(temporary_token_path)

    try:
        result = subprocess.run(
            ["git", "-C", str(path), *arguments],
            input=input_text,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=environment,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "exit_code": -1,
            "output": "",
            "error": "Command timed out",
        }
    finally:
        if askpass_path is not None:
            askpass_path.unlink(missing_ok=True)
        if temporary_token_path is not None:
            temporary_token_path.unlink(missing_ok=True)

    return {
        "ok": result.returncode == 0,
        "exit_code": result.returncode,
        "output": result.stdout[-output_limit:],
        "error": result.stderr[-50_000:],
    }


def audit(action: str, project: str, ok: bool, detail: str = "") -> bool:
    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "project": project,
        "ok": ok,
        "detail": detail[:300],
    }
    try:
        with AUDIT_LOG.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
            file.flush()
            os.fsync(file.fileno())
        return True
    except OSError:
        return False


def current_branch(project: ProjectName) -> tuple[bool, str]:
    result = run_git(project, ["branch", "--show-current"])
    if not result["ok"]:
        return False, result["error"] or "Could not read current branch"
    return True, result["output"].strip()


def guard_project(
    project: ProjectName,
    *,
    require_clean: bool,
) -> tuple[bool, str]:
    config = PROJECTS.get(project)
    if config is None:
        return False, "Unknown project"

    ok, branch = current_branch(project)
    if not ok:
        return False, branch
    if branch != config["branch"]:
        return False, f"Blocked branch: {branch}; allowed: {config['branch']}"

    if require_clean:
        status = run_git(project, ["status", "--porcelain"])
        if not status["ok"]:
            return False, status["error"] or "Could not read status"
        if status["output"].strip():
            return False, "Working tree must be clean"

    return True, branch


def is_sensitive_path(path: str) -> bool:
    normalized = path.replace("\\", "/").strip().strip('"').lower()
    parts = [part for part in normalized.split("/") if part]
    name = parts[-1] if parts else ""
    if any(part in SENSITIVE_NAMES or part.startswith(".env") for part in parts):
        return True
    return any(name.endswith(suffix) for suffix in SENSITIVE_SUFFIXES)


def safe_search_candidate(project: ProjectName, path: str) -> Path | None:
    """Resolve one search result without exposing sensitive files or symlinks."""
    config = PROJECTS.get(project)
    if config is None or not path or "\x00" in path or Path(path).is_absolute():
        return None
    if is_sensitive_path(path):
        return None
    root = config["path"].resolve()
    unresolved = root / path
    if unresolved.is_symlink():
        return None
    candidate = unresolved.resolve()
    if root not in candidate.parents or not candidate.is_file():
        return None
    relative = candidate.relative_to(root).as_posix()
    if is_sensitive_path(relative) or candidate.stat().st_size > 1_000_000:
        return None
    return candidate


def changed_paths(project: ProjectName) -> list[str]:
    result = run_git(project, ["status", "--porcelain", "--untracked-files=all"])
    if not result["ok"]:
        return []

    paths: list[str] = []
    for line in result["output"].splitlines():
        if len(line) < 4:
            continue
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.append(path.strip().strip('"'))
    return paths


@mcp.tool()
def list_projects() -> dict:
    """List only the registered and approved projects."""
    return {
        name: {
            "path": str(config["path"]),
            "allowed_branch": config["branch"],
        }
        for name, config in PROJECTS.items()
    }


@mcp.tool()
def git_status(project: ProjectName) -> dict:
    """Show the current branch and working-tree status."""
    return run_git(project, ["status", "--short", "--branch"])


@mcp.tool()
def recent_commits(project: ProjectName, limit: int = 10) -> dict:
    """Show 1 through 20 recent commits."""
    safe_limit = max(1, min(limit, 20))
    return run_git(
        project,
        [
            "log",
            f"-{safe_limit}",
            "--date=iso",
            "--pretty=format:%h | %ad | %an | %s",
        ],
    )


@mcp.tool()
def git_diff(project: ProjectName, staged: bool = False) -> dict:
    """Show the unstaged or staged diff without modifying files."""
    arguments = ["diff", "--no-ext-diff"]
    if staged:
        arguments.append("--cached")
    return run_git(project, arguments)


@mcp.tool()
def list_tracked_files(
    project: ProjectName,
    contains: str = "",
    limit: int = 200,
) -> dict:
    """List tracked files, optionally filtered by part of the path."""
    result = run_git(project, ["ls-files"], output_limit=1_000_000)
    if not result["ok"]:
        return result

    safe_limit = max(1, min(limit, 500))
    query = contains.lower().strip()
    files = [
        line for line in result["output"].splitlines()
        if not query or query in line.lower()
    ]
    result["output"] = "\n".join(files[:safe_limit])
    return result


@mcp.tool()
def read_tracked_file(
    project: ProjectName,
    path: str,
    start_line: int = 1,
    maximum_lines: int = 400,
) -> dict:
    """Read a tracked, non-sensitive file inside an approved project."""
    config = PROJECTS.get(project)
    if config is None:
        return {"ok": False, "error": "Unknown project"}
    if not path or "\x00" in path or Path(path).is_absolute():
        return {"ok": False, "error": "Invalid relative path"}
    if is_sensitive_path(path):
        return {"ok": False, "error": "Sensitive path is blocked"}

    root = config["path"].resolve()
    unresolved = root / path
    if unresolved.is_symlink():
        return {"ok": False, "error": "Symbolic links are not readable"}
    candidate = unresolved.resolve()
    if root not in candidate.parents:
        return {"ok": False, "error": "Path traversal is blocked"}

    tracked = run_git(project, ["ls-files", "--error-unmatch", "--", path])
    if not tracked["ok"]:
        return {"ok": False, "error": "File is not tracked"}
    if not candidate.is_file():
        return {"ok": False, "error": "File does not exist"}
    if candidate.stat().st_size > 1_000_000:
        return {"ok": False, "error": "File is too large"}

    lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    safe_start = max(1, start_line)
    safe_count = max(1, min(maximum_lines, 500))
    selected = lines[safe_start - 1:safe_start - 1 + safe_count]
    return {
        "ok": True,
        "path": path,
        "start_line": safe_start,
        "end_line": safe_start + len(selected) - 1,
        "total_lines": len(lines),
        "content": "\n".join(selected),
    }


@mcp.tool()
def search_tracked_code(
    project: ProjectName,
    text: str,
    maximum_results: int = 50,
) -> dict:
    """Search tracked project files for fixed text."""
    if not text or len(text) > 200:
        return {"ok": False, "error": "Search text must be 1 to 200 characters"}

    safe_limit = max(1, min(maximum_results, 100))
    result = run_git(
        project,
        ["grep", "-n", "-I", "--fixed-strings", "--", text],
        output_limit=1_000_000,
    )
    if result["exit_code"] == 1:
        return {"ok": True, "exit_code": 0, "output": "", "error": ""}
    if result["ok"]:
        safe_lines: list[str] = []
        filtered_sensitive_matches = 0
        for raw in result["output"].splitlines():
            match = re.match(r"^(.+):(\d+):(.*)$", raw)
            if not match or safe_search_candidate(project, match.group(1)) is None:
                filtered_sensitive_matches += 1
                continue
            safe_lines.append(raw)
        result["output"] = "\n".join(safe_lines[:safe_limit])
        result["total_safe_matches"] = len(safe_lines)
        result["truncated"] = len(safe_lines) > safe_limit
        result["filtered_sensitive_matches"] = filtered_sensitive_matches
    return result


@mcp.tool()
def moory_capabilities() -> dict:
    """Explain Moory's worker role, context levels, safety rules, and recommended change workflow."""
    return {
        "ok": True,
        "role": "Moory executes deterministic work; the connected agent reasons, decides, and reviews.",
        "context_levels": {
            "summary": "Use first for orientation; never edit from summary alone.",
            "evidence": "Use for source lines, errors, and facts before deciding a change.",
            "full": "Use only when evidence is truncated, ambiguous, contradictory, or insufficient.",
        },
        "rules": [
            "Read the exact latest target range before generating a patch.",
            "Every bounded result must disclose truncation and available escape hatches.",
            "Keep granular read tools available even when composite tools are used.",
        ],
        "change_workflow": [
            "sync and confirm a clean approved branch",
            "start with summary context",
            "escalate to evidence and read exact target lines",
            "dry-run and apply a bounded patch",
            "validate and review the diff",
            "commit, push, and inspect CI",
        ],
        "heavy_work": "Use GitHub Actions for APKs, binaries, emulators, matrices, and long tests.",
    }


@mcp.tool()
def moory_tool_catalog(profile: Literal["core", "git", "github", "all"] = "core") -> dict:
    """Discover compact task-oriented tool profiles without hiding the full escape hatch."""
    groups = {
        "core": ["moory_capabilities", "worker_context", "prepare_change_context", "validate_project", "apply_change_set", "commit_changes", "push_project", "inspect_ci_failure", "release_readiness"],
        "git": ["git_status", "recent_commits", "git_diff", "list_tracked_files", "read_tracked_file", "search_tracked_code", "sync_project", "apply_unified_patch", "validate_changes"],
        "github": ["github_health", "github_permission_diagnostics", "github_repo_summary", "github_list_issues", "github_get_issue", "github_list_pull_requests", "github_get_pull_request", "github_list_workflow_runs", "github_get_workflow_run", "github_get_actions_log", "github_list_artifacts", "github_list_releases", "github_get_release", "github_list_deployments", "github_get_deployment", "github_create_deployment", "github_create_deployment_status", "github_list_environments", "github_get_environment", "github_upsert_environment", "github_list_actions_variables", "github_upsert_actions_variable", "github_get_pages", "github_configure_pages", "github_request_pages_build"],
    }
    groups["github"].extend(["github_list_workflows", "github_get_workflow", "github_set_workflow_state", "github_list_repository_artifacts", "github_get_artifact", "github_list_commit_checks", "github_get_check_run", "github_create_check_run", "github_update_check_run", "github_list_commit_statuses", "github_create_commit_status"])
    groups["github"].extend(["github_list_secret_scanning_alerts", "github_get_secret_scanning_alert", "github_list_secret_scanning_locations", "github_update_secret_scanning_alert", "github_list_code_scanning_alerts", "github_get_code_scanning_alert", "github_update_code_scanning_alert", "github_list_dependabot_alerts", "github_get_dependabot_alert", "github_list_code_quality_findings", "github_list_secret_scanning_bypass_requests", "github_get_secret_scanning_bypass_request", "github_list_repository_security_advisories", "github_get_repository_security_advisory", "github_create_repository_security_advisory", "github_update_repository_security_advisory"])
    groups["github"].extend(["github_get_sbom", "github_list_attestations", "github_create_attestation", "github_list_packages", "github_list_package_versions", "github_submit_dependency_snapshot", "github_list_artifact_metadata", "github_create_artifact_storage_record", "github_create_artifact_deployment_record"])
    groups["github"].extend(["github_list_labels", "github_upsert_label", "github_list_milestones", "github_upsert_milestone", "github_get_requested_reviewers", "github_request_pull_request_reviewers", "github_add_issue_assignees", "github_list_discussions", "github_get_discussion", "github_create_discussion", "github_comment_discussion", "github_update_discussion", "github_get_pull_request_queue_state", "github_set_pull_request_queue_state"])
    groups["github"].extend(["github_get_repository_settings", "github_update_repository_settings", "github_list_collaborators", "github_upsert_collaborator", "github_list_repository_invitations", "github_list_rulesets", "github_get_ruleset", "github_upsert_ruleset", "github_get_custom_property_values", "github_update_custom_property_values"])
    selected = groups if profile == "all" else {profile: groups[profile]}
    return {
        "ok": True,
        "profile": profile,
        "tools": selected,
        "available_profiles": ["core", "git", "github", "all"],
        "dynamic_hiding": False,
        "next_recommended_action": "Start with the core profile; request git or github only when the task requires it.",
    }


@mcp.tool()
def worker_context(
    project: ProjectName,
    operation: Literal["overview", "search"] = "overview",
    query: str = "",
    detail: Literal["summary", "evidence", "full"] = "summary",
    limit: int = 20,
) -> dict:
    """Start with summary, use evidence before edits, and full only when evidence is insufficient."""
    # Keep detail=full as an explicit escape hatch; never silently hide unavailable context.
    config = PROJECTS.get(project)
    if config is None:
        return {"ok": False, "error": "Unknown project"}
    if operation not in {"overview", "search"} or detail not in {"summary", "evidence", "full"}:
        return {"ok": False, "error": "Invalid worker operation or detail level"}

    head_result = run_git(project, ["rev-parse", "HEAD"])
    if not head_result["ok"]:
        return head_result
    head_sha = head_result["output"].strip()
    cache_key = (project, head_sha)
    with CONTEXT_CACHE_LOCK:
        cached = CONTEXT_CACHE.get(cache_key)
    if cached is None:
        files_result = run_git(project, ["ls-files"], output_limit=2_000_000)
        if not files_result["ok"]:
            return files_result
        files = files_result["output"].splitlines()
        with CONTEXT_CACHE_LOCK:
            if len(CONTEXT_CACHE) >= MAX_CONTEXT_CACHE_ENTRIES:
                CONTEXT_CACHE.pop(next(iter(CONTEXT_CACHE)))
            CONTEXT_CACHE[cache_key] = {"files": list(files)}
        cache_hit = False
    else:
        files = list(cached["files"])
        cache_hit = True

    if operation == "overview":
        status = run_git(project, ["status", "--short", "--branch"])
        head = run_git(project, ["log", "-1", "--pretty=format:%H|%s"])
        extensions: dict[str, int] = {}
        for path in files:
            suffix = Path(path).suffix.lower() or "[none]"
            extensions[suffix] = extensions.get(suffix, 0) + 1
        result: dict[str, Any] = {
            "ok": status["ok"] and head["ok"],
            "project": project,
            "repository": str(config["repo"]),
            "allowed_branch": str(config["branch"]),
            "clean": not bool(run_git(project, ["status", "--porcelain"])["output"].strip()),
            "status": status["output"].strip(),
            "head": head["output"].strip(),
            "file_count": len(files),
            "top_extensions": sorted(extensions.items(), key=lambda item: (-item[1], item[0]))[:10],
            "detail": detail,
            "cache": {"strategy": "commit_sha", "head_sha": head_sha, "hit": cache_hit},
            "available_detail_levels": list(DETAIL_LEVELS),
            "truncated": False,
            "next_recommended_action": "Request evidence before making a code change." if detail == "summary" else "Read exact target ranges before editing.",
        }
        if detail in {"evidence", "full"}:
            result["top_level"] = sorted({path.split("/", 1)[0] for path in files})[:100]
            result["recent_commits"] = run_git(project, ["log", "-5", "--pretty=format:%h|%s"])["output"].splitlines()
            result["repository_map"] = {
                "tests": [path for path in files if "test" in path.lower()][:30],
                "workflows": [path for path in files if path.startswith(".github/workflows/")][:30],
                "configuration": [path for path in files if Path(path).name.lower() in {"pyproject.toml", "package.json", "build.gradle", "settings.gradle", "dockerfile", "requirements.txt", "requirements.lock"}][:30],
            }
        if detail == "full":
            result["files"] = files[:500]
            result["files_truncated"] = len(files) > 500
            result["truncated"] = len(files) > 500
        return result

    if not query or len(query) > 200:
        return {"ok": False, "error": "Search query must be 1 to 200 characters"}
    requested = max(1, min(limit, 100))
    safe_limit = min(requested, 10 if detail == "summary" else 30 if detail == "evidence" else 100)
    grep = run_git(project, ["grep", "-n", "-I", "--fixed-strings", "--", query], output_limit=2_000_000)
    if grep["exit_code"] == 1:
        return {"ok": True, "operation": "search", "detail": detail, "query": query, "matches": [], "total_matches": 0, "truncated": False, "available_detail_levels": list(DETAIL_LEVELS), "next_recommended_action": "Try another fixed-text query or inspect the repository overview."}
    if not grep["ok"]:
        return grep
    raw_matches = grep["output"].splitlines()
    safe_raw_matches: list[str] = []
    filtered_sensitive_matches = 0
    for raw in raw_matches:
        parsed = re.match(r"^(.+):(\d+):(.*)$", raw)
        if not parsed or safe_search_candidate(project, parsed.group(1)) is None:
            filtered_sensitive_matches += 1
            continue
        safe_raw_matches.append(raw)
    matches: list[dict[str, Any]] = []
    context_radius = 0 if detail == "summary" else 3 if detail == "evidence" else 12
    root = config["path"].resolve()
    for raw in safe_raw_matches[:safe_limit]:
        match = re.match(r"^(.+):(\d+):(.*)$", raw)
        if not match:
            continue
        path, line_text, preview = match.groups()
        line_number = int(line_text)
        item: dict[str, Any] = {"path": path, "line": line_number, "preview": preview[:500]}
        if context_radius:
            candidate = safe_search_candidate(project, path)
            if candidate is not None:
                content = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
                start = max(1, line_number - context_radius)
                end = min(len(content), line_number + context_radius)
                item.update({"context_start": start, "context_end": end, "context": "\n".join(content[start - 1:end])})
        matches.append(item)
    return {
        "ok": True,
        "operation": "search",
        "detail": detail,
        "query": query,
        "matches": matches,
        "total_matches": len(safe_raw_matches),
        "filtered_sensitive_matches": filtered_sensitive_matches,
        "truncated": len(safe_raw_matches) > len(matches),
        "available_detail_levels": list(DETAIL_LEVELS),
        "next_recommended_action": "Request evidence before editing." if detail == "summary" else "Read exact target ranges; use full only when this evidence is insufficient.",
    }


@mcp.tool()
def prepare_change_context(
    project: ProjectName,
    objective: str,
    search_terms: list[str],
    detail: Literal["summary", "evidence", "full"] = "summary",
    limit: int = 20,
) -> dict:
    """Search several bounded terms in one call and rank the files that deserve exact reads before editing."""
    clean_objective = objective.strip()
    if not clean_objective or len(clean_objective) > 500:
        return {"ok": False, "error": "Objective must be 1 to 500 characters"}
    if detail not in DETAIL_LEVELS:
        return {"ok": False, "error": "Invalid detail level"}
    terms = list(dict.fromkeys(term.strip() for term in search_terms if term.strip()))
    if not terms or len(terms) > 8 or any(len(term) > 200 for term in terms):
        return {"ok": False, "error": "Provide 1 to 8 search terms, each at most 200 characters"}
    safe_limit = max(1, min(limit, 50))
    searches: list[dict[str, Any]] = []
    scores: dict[str, int] = {}
    unavailable: dict[str, str] = {}
    truncated = False
    for term in terms:
        result = worker_context(project, operation="search", query=term, detail=detail, limit=safe_limit)
        if not result.get("ok"):
            unavailable[term] = str(result.get("error", "Search unavailable"))[:300]
            continue
        searches.append({"term": term, "matches": result.get("matches", []), "total_matches": result.get("total_matches", 0)})
        truncated = truncated or bool(result.get("truncated"))
        for match in result.get("matches", []):
            path = str(match.get("path", ""))
            if path:
                scores[path] = scores.get(path, 0) + 1
    ranked = [{"path": path, "score": score} for path, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:safe_limit]]
    return {
        "ok": True,
        "partial": bool(unavailable),
        "objective": clean_objective,
        "detail": detail,
        "available_detail_levels": list(DETAIL_LEVELS),
        "searches": searches,
        "ranked_files": ranked,
        "truncated": truncated,
        "unavailable": unavailable,
        "next_recommended_action": "Read exact ranges in the top-ranked files before generating a patch.",
    }


@mcp.tool()
def worker_benchmark(project: ProjectName, query: str = "") -> dict:
    """Compare actual granular and Worker tool payloads with deterministic byte and call measurements."""
    if len(query) > 200:
        return {"ok": False, "error": "Benchmark query must be at most 200 characters"}
    baseline_started = time.perf_counter()
    baseline = {
        "status": git_status(project),
        "commits": recent_commits(project, limit=5),
        "files": list_tracked_files(project, limit=500),
    }
    if query:
        baseline["search"] = search_tracked_code(project, query, maximum_results=50)
    baseline_elapsed_ms = round((time.perf_counter() - baseline_started) * 1000, 2)
    worker_started = time.perf_counter()
    worker = {
        "overview": worker_context(project, operation="overview", detail="summary", limit=20),
    }
    if query:
        worker["search"] = worker_context(project, operation="search", query=query, detail="summary", limit=10)
    worker_elapsed_ms = round((time.perf_counter() - worker_started) * 1000, 2)
    baseline_bytes = len(json.dumps(baseline, ensure_ascii=False).encode("utf-8"))
    worker_bytes = len(json.dumps(worker, ensure_ascii=False).encode("utf-8"))
    reduction = 0.0 if baseline_bytes == 0 else round((1 - worker_bytes / baseline_bytes) * 100, 2)
    baseline_calls = 4 if query else 3
    worker_calls = 2 if query else 1
    return {
        "ok": True,
        "measurement": "Actual serialized tool payloads measured as exact UTF-8 JSON bytes.",
        "token_claim": "Exact model tokens require the active model tokenizer; byte reduction is deterministic and tokenizer-independent input reduction.",
        "baseline": {"tool_calls": baseline_calls, "bytes": baseline_bytes, "elapsed_ms": baseline_elapsed_ms},
        "worker": {"tool_calls": worker_calls, "bytes": worker_bytes, "elapsed_ms": worker_elapsed_ms},
        "output_reduction_percent": reduction,
        "tool_call_reduction_percent": round((1 - worker_calls / baseline_calls) * 100, 2),
    }


@mcp.tool()
def validate_changes(project: ProjectName, staged: bool = False) -> dict:
    """Run Git whitespace validation without modifying files."""
    arguments = ["diff"]
    if staged:
        arguments.append("--cached")
    arguments.append("--check")
    return run_git(project, arguments)


@mcp.tool()
def validate_project(project: ProjectName) -> dict:
    """Run bounded static validation without executing repository code."""
    config = PROJECTS.get(project)
    if config is None:
        return {"ok": False, "error": "Unknown project"}
    whitespace = validate_changes(project, staged=False)
    listed = run_git(project, ["ls-files"], output_limit=2_000_000)
    if not listed.get("ok"):
        return listed
    root = config["path"].resolve()
    findings: list[dict[str, Any]] = []
    checked = {"python": 0, "json": 0, "toml": 0}
    skipped_large = 0
    for relative in listed.get("output", "").splitlines()[:2000]:
        suffix = Path(relative).suffix.lower()
        if suffix not in {".py", ".json", ".toml"} or is_sensitive_path(relative):
            continue
        candidate = (root / relative).resolve()
        if root not in candidate.parents or not candidate.is_file():
            continue
        if candidate.stat().st_size > 1_000_000:
            skipped_large += 1
            continue
        try:
            text = candidate.read_text(encoding="utf-8")
            if suffix == ".py":
                ast.parse(text, filename=relative)
                checked["python"] += 1
            elif suffix == ".json":
                json.loads(text)
                checked["json"] += 1
            else:
                tomllib.loads(text)
                checked["toml"] += 1
        except (OSError, UnicodeError, SyntaxError, ValueError) as error:
            findings.append({"path": relative, "line": getattr(error, "lineno", None), "error": str(error)[:500]})
            if len(findings) >= 50:
                break
    return {
        "ok": bool(whitespace.get("ok")) and not findings,
        "checks": {"whitespace": bool(whitespace.get("ok")), "syntax": checked},
        "findings": findings,
        "skipped_large_files": skipped_large,
        "truncated": len(findings) >= 50,
        "execution_policy": "Repository code was parsed but not executed.",
    }


@mcp.tool()
def sync_project(project: ProjectName) -> dict:
    """Fetch and fast-forward only the approved branch. Modifies the local clone."""
    with WRITE_LOCK:
        allowed, reason = guard_project(project, require_clean=True)
        if not allowed:
            audit("sync", project, False, reason)
            return {"ok": False, "error": reason}

        if not audit("sync_preflight", project, True, "write preflight"):
            return {"ok": False, "error": "Audit log unavailable; sync blocked"}
        branch = PROJECTS[project]["branch"]
        fetch = run_git(project, ["fetch", "origin", branch], timeout=90)
        if not fetch["ok"]:
            audit("sync", project, False, fetch["error"])
            return fetch

        merge = run_git(project, ["merge", "--ff-only", f"origin/{branch}"])
        audit("sync", project, merge["ok"], merge["error"])
        return merge


@mcp.tool()
def apply_unified_patch(
    project: ProjectName,
    patch_text: str,
    check_only: bool = True,
) -> dict:
    """Check or apply a unified Git patch. Set check_only=false to modify files."""
    patch_text = patch_text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    if patch_text and not patch_text.endswith("\n"):
        patch_text += "\n"
    encoded_size = len(patch_text.encode("utf-8", errors="ignore"))
    if not patch_text or encoded_size > MAX_PATCH_BYTES:
        return {"ok": False, "error": "Patch must be 1 to 500000 bytes"}
    if "\x00" in patch_text or "diff --git " not in patch_text:
        return {"ok": False, "error": "Invalid unified Git patch"}
    if re.search(SECRET_PATTERN, patch_text, flags=re.IGNORECASE):
        return {"ok": False, "error": "Possible secret detected; patch blocked"}

    patch_paths: list[str] = []
    metadata_prefixes = ("+++ b/", "--- a/", "rename from ", "rename to ", "copy from ", "copy to ")
    for line in patch_text.splitlines():
        for prefix in metadata_prefixes:
            if line.startswith(prefix):
                value = line[len(prefix):].strip().strip('"')
                if value != "/dev/null":
                    patch_paths.append(value)
                break
        if line.startswith("diff --git "):
            try:
                fields = shlex.split(line)
            except ValueError:
                return {"ok": False, "error": "Invalid patch path metadata"}
            for value in fields[2:4]:
                patch_paths.append(value[2:] if value.startswith(("a/", "b/")) else value)

    invalid_paths = [
        path for path in patch_paths
        if not path or "\x00" in path or Path(path).is_absolute() or ".." in Path(path).parts
    ]
    if invalid_paths:
        return {"ok": False, "error": "Patch contains an invalid path"}
    if any(is_sensitive_path(path) for path in patch_paths):
        return {"ok": False, "error": "Patch touches a blocked sensitive path"}

    with WRITE_LOCK:
        allowed, reason = guard_project(project, require_clean=True)
        if not allowed:
            audit("apply_patch", project, False, reason)
            return {"ok": False, "error": reason}

        if not check_only and not audit("apply_patch_preflight", project, True, "write preflight"):
            return {"ok": False, "error": "Audit log unavailable; patch blocked"}
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="dvpatch-",
                suffix=".diff",
                dir=str(PATCH_TMP_DIR),
                delete=False,
            ) as temporary:
                temporary.write(patch_text)
                temporary_path = temporary.name

            os.chmod(temporary_path, 0o600)
            check = run_git(
                project,
                ["apply", "--check", "--whitespace=error-all", temporary_path],
            )
            if not check["ok"]:
                raw_error = check["error"] or check["output"]
                category = "patch_check_failed"
                suggestion = "Read the latest target range and regenerate the patch."
                if "whitespace" in raw_error.lower():
                    category = "whitespace_error"
                    suggestion = "Remove whitespace errors and regenerate the patch."
                elif "corrupt patch" in raw_error.lower():
                    category = "invalid_patch"
                    suggestion = "Generate a complete unified Git patch with valid hunk counts."
                elif "patch does not apply" in raw_error.lower() or "while searching for" in raw_error.lower():
                    category = "stale_context"
                    suggestion = "Read the exact current file lines and regenerate the patch from that evidence."
                audit("check_patch", project, check["ok"], check["error"])
                return {**check, "diagnostic": {"category": category, "suggestion": suggestion}, "paths": list(dict.fromkeys(patch_paths))}
            if check_only:
                audit("check_patch", project, True, "Patch preflight passed")
                return {**check, "check_only": True, "paths": list(dict.fromkeys(patch_paths))}

            applied = run_git(
                project,
                ["apply", "--whitespace=error-all", temporary_path],
            )
            audit("apply_patch", project, applied["ok"], applied["error"])
            return applied
        finally:
            if temporary_path:
                Path(temporary_path).unlink(missing_ok=True)


@mcp.tool()
def apply_change_set(
    project: ProjectName,
    patch_text: str,
    check_only: bool = True,
    validation_profile: Literal["whitespace", "static"] = "static",
) -> dict:
    """Preflight, apply, validate, and summarize one tracked-file change set with rollback on validation failure."""
    if "--- /dev/null" in patch_text or "rename from " in patch_text or "copy from " in patch_text:
        return {"ok": False, "error": "Transactional change sets currently support tracked-file edits and deletions only"}
    preflight = apply_unified_patch(project, patch_text, check_only=True)
    if not preflight.get("ok"):
        return {"ok": False, "stage": "preflight", "preflight": preflight}
    if check_only:
        return {"ok": True, "stage": "preflight", "check_only": True, "validation_profile": validation_profile, "paths": preflight.get("paths", [])}
    applied = apply_unified_patch(project, patch_text, check_only=False)
    if not applied.get("ok"):
        return {"ok": False, "stage": "apply", "preflight": preflight, "applied": applied}
    validation = validate_project(project) if validation_profile == "static" else validate_changes(project, staged=False)
    diff = git_diff(project, staged=False)
    if validation.get("ok"):
        return {
            "ok": True,
            "stage": "validated",
            "paths": preflight.get("paths", []),
            "validation": validation,
            "diff": diff,
        }
    paths = list(dict.fromkeys(str(path) for path in preflight.get("paths", []) if path))
    rollback: list[dict[str, Any]] = []
    if paths:
        restored = run_git(project, ["restore", "--staged", "--worktree", "--", *paths])
        rollback.append(restored)
    clean = run_git(project, ["status", "--porcelain"])
    audit("apply_change_set_rollback", project, clean.get("ok") and not clean.get("output", "").strip(), validation.get("error", "validation failed"))
    return {
        "ok": False,
        "stage": "validation",
        "error": "Validation failed; tracked-file changes were rolled back.",
        "validation": validation,
        "rollback": rollback,
        "clean_after_rollback": clean.get("ok") and not clean.get("output", "").strip(),
        "diff_before_rollback": diff,
    }


@mcp.tool()
def commit_changes(project: ProjectName, message: str) -> dict:
    """Validate and commit all current changes on the approved branch."""
    clean_message = message.strip()
    if (
        len(clean_message) < 5
        or len(clean_message) > 120
        or "\n" in clean_message
        or "\r" in clean_message
    ):
        return {"ok": False, "error": "Commit message must be 5 to 120 characters"}

    with WRITE_LOCK:
        allowed, reason = guard_project(project, require_clean=False)
        if not allowed:
            audit("commit", project, False, reason)
            return {"ok": False, "error": reason}

        if not audit("commit_preflight", project, True, "write preflight"):
            return {"ok": False, "error": "Audit log unavailable; commit blocked"}
        paths = changed_paths(project)
        if not paths:
            return {"ok": False, "error": "There are no changes to commit"}

        blocked = [path for path in paths if is_sensitive_path(path)]
        if blocked:
            return {
                "ok": False,
                "error": "Sensitive files are blocked",
                "blocked_paths": blocked,
            }

        whitespace = run_git(project, ["diff", "--check"])
        if not whitespace["ok"]:
            return whitespace

        added = run_git(project, ["add", "-A"])
        if not added["ok"]:
            return added

        staged_check = run_git(project, ["diff", "--cached", "--check"])
        if not staged_check["ok"]:
            run_git(project, ["restore", "--staged", "--", *paths])
            return staged_check

        secret_scan = run_git(
            project,
            ["grep", "--cached", "-I", "-n", "-E", "-e", GIT_SECRET_PATTERN, "--", *paths],
            output_limit=1_000,
        )
        if secret_scan["exit_code"] == 0:
            run_git(project, ["restore", "--staged", "--", *paths])
            audit("commit", project, False, "Secret marker detected")
            return {
                "ok": False,
                "error": "Possible secret detected; commit blocked",
            }
        if secret_scan["exit_code"] not in (0, 1):
            run_git(project, ["restore", "--staged", "--", *paths])
            return secret_scan

        committed = run_git(project, ["-c", "user.name=Moory Worker", "-c", "user.email=moory@localhost", "commit", "-m", clean_message])
        if not committed["ok"]:
            run_git(project, ["restore", "--staged", "--", *paths])
        audit("commit", project, committed["ok"], clean_message)
        return committed


@mcp.tool()
def push_project(project: ProjectName) -> dict:
    """Push the approved branch without force. Requires a clean working tree."""
    with WRITE_LOCK:
        allowed, reason = guard_project(project, require_clean=True)
        if not allowed:
            audit("push", project, False, reason)
            return {"ok": False, "error": reason}

        if not audit("push_preflight", project, True, "write preflight"):
            return {"ok": False, "error": "Audit log unavailable; push blocked"}
        branch = PROJECTS[project]["branch"]
        pushed = run_git(project, ["push", "origin", branch], timeout=90)
        audit("push", project, pushed["ok"], pushed["error"])
        return pushed


@mcp.tool()
def github_health() -> dict:
    """Verify GitHub authentication, registered repository access, and rate limit."""
    try:
        token, token_info = github_installation_token()
        registered = sorted(str(config["repo"]) for config in PROJECTS.values())
        accessible: list[str] = []
        for repo in registered:
            _, raw, _ = _github_http(f"/repos/{repo}", token=token)
            item = json.loads(raw.decode("utf-8"))
            if item.get("full_name") == repo:
                accessible.append(repo)
        scope_matches_registry = bool(registered) and accessible == registered
        if token_info.get("auth_mode") == "github_app":
            _, raw, _ = _github_http("/installation/repositories?per_page=100", token=token)
            installed = json.loads(raw.decode("utf-8"))
            installed_repos = sorted(
                item.get("full_name") for item in installed.get("repositories", [])
                if isinstance(item, dict) and item.get("full_name")
            )
            # A GitHub App installation may expose more repositories than Moory
            # has registered. The registry remains the execution allowlist, so
            # health only needs every registered repository to be installed.
            scope_matches_registry = bool(registered) and set(registered).issubset(set(installed_repos))
        _, rate_raw, _ = _github_http("/rate_limit", token=token)
        rate = json.loads(rate_raw.decode("utf-8")).get("rate", {})
        return {
            "ok": scope_matches_registry, "authentication": "ok", "auth_mode": token_info.get("auth_mode"),
            "token_expires_at": token_info.get("expires_at"),
            "repository_selection": token_info.get("repository_selection"),
            "permissions": token_info.get("permissions"), "repositories": accessible,
            "scope_matches_registry": scope_matches_registry,
            "rate_limit": {"limit": rate.get("limit"), "remaining": rate.get("remaining"), "reset": rate.get("reset")},
        }
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_permission_diagnostics(project: ProjectName) -> dict:
    """Probe safe GitHub read capabilities and explain recommended write permissions without mutating data."""
    probes: dict[str, str] = {}
    try:
        repo = github_json(project, "")
        branch = str(repo.get("default_branch") or PROJECTS[project]["branch"])
        commit = github_json(project, "/commits/" + urllib.parse.quote(branch, safe=""))
        sha = str(commit.get("sha", ""))
        endpoints = {
            "metadata_read": "",
            "issues_read": "/issues",
            "pull_requests_read": "/pulls",
            "actions_read": "/actions/runs",
        }
        for name, suffix in endpoints.items():
            try:
                github_json(project, suffix, query={"per_page": 1} if suffix else None)
                probes[name] = "available"
            except Exception as error:
                probes[name] = "unavailable: " + redact_github_text(str(error))[:160]
        if sha:
            for name, suffix in {"checks_read": f"/commits/{sha}/check-runs", "statuses_read": f"/commits/{sha}/status"}.items():
                try:
                    github_json(project, suffix, query={"per_page": 1})
                    probes[name] = "available"
                except Exception as error:
                    probes[name] = "unavailable: " + redact_github_text(str(error))[:160]
        missing = [name for name, value in probes.items() if value.startswith("unavailable")]
        return {
            "ok": not missing,
            "project": project,
            "safe_read_probes": probes,
            "missing_read_capabilities": missing,
            "write_permissions": "Not probed because diagnostics must not mutate repositories.",
            "recommended_permissions": {"Metadata": "read", "Contents": "read/write", "Issues": "read/write", "Pull requests": "read/write", "Actions": "read/write", "Checks": "read", "Commit statuses": "read/write"},
        }
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_repo_summary(project: ProjectName) -> dict:
    """Read repository metadata and current open issue and pull request counts."""
    try:
        repo = github_json(project, "")
        pulls = github_json(project, "/pulls", query={"state": "open", "per_page": 100})
        issues = github_json(project, "/issues", query={"state": "open", "per_page": 100})
        issue_count = sum(1 for item in issues if "pull_request" not in item)
        return {
            "ok": True,
            "repository": repo.get("full_name"),
            "private": repo.get("private"),
            "archived": repo.get("archived"),
            "default_branch": repo.get("default_branch"),
            "visibility": repo.get("visibility"),
            "open_pull_requests": len(pulls),
            "open_issues": issue_count,
            "pushed_at": repo.get("pushed_at"),
            "updated_at": repo.get("updated_at"),
            "html_url": repo.get("html_url"),
        }
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_issues(
    project: ProjectName,
    state: Literal["open", "closed", "all"] = "open",
    limit: int = 20,
    page: int = 1,
) -> dict:
    """List repository issues, excluding pull requests."""
    try:
        safe_limit = max(1, min(limit, 100))
        safe_page = max(1, min(page, 1000))
        items = github_json(project, "/issues", query={"state": state, "per_page": safe_limit, "page": safe_page, "sort": "updated", "direction": "desc"})
        issues = [compact_issue(item) for item in items if "pull_request" not in item]
        return {"ok": True, "count": len(issues), "page": safe_page, "truncated": len(items) == safe_limit, "next_page": safe_page + 1 if len(items) == safe_limit else None, "issues": issues}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_issue(project: ProjectName, issue_number: int) -> dict:
    """Read one issue and up to 100 issue comments."""
    try:
        number = require_positive_id(issue_number, "issue_number")
        issue = github_json(project, f"/issues/{number}")
        if "pull_request" in issue:
            return {"ok": False, "error": "The requested number belongs to a pull request"}
        comments = github_json(project, f"/issues/{number}/comments", query={"per_page": 100})
        return {
            "ok": True,
            "issue": {**compact_issue(issue), "body": issue.get("body")},
            "comments": [
                {
                    "id": item.get("id"), "author": compact_user(item.get("user")),
                    "body": item.get("body"), "created_at": item.get("created_at"),
                    "updated_at": item.get("updated_at"), "html_url": item.get("html_url"),
                }
                for item in comments[:100]
            ],
        }
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_pull_requests(
    project: ProjectName,
    state: Literal["open", "closed", "all"] = "open",
    limit: int = 20,
    page: int = 1,
) -> dict:
    """List repository pull requests."""
    try:
        safe_limit = max(1, min(limit, 100))
        safe_page = max(1, min(page, 1000))
        items = github_json(project, "/pulls", query={"state": state, "per_page": safe_limit, "page": safe_page, "sort": "updated", "direction": "desc"})
        pulls = [compact_pull(item) for item in items[:safe_limit]]
        return {"ok": True, "count": len(pulls), "page": safe_page, "truncated": len(items) == safe_limit, "next_page": safe_page + 1 if len(items) == safe_limit else None, "pull_requests": pulls}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_pull_request(project: ProjectName, pull_number: int) -> dict:
    """Read a pull request, files, reviews, comments, checks, and commit status."""
    try:
        number = require_positive_id(pull_number, "pull_number")
        pull = github_json(project, f"/pulls/{number}")
        unavailable: dict[str, str] = {}

        def optional(name: str, suffix: str, default: Any, query: dict[str, Any] | None = None) -> Any:
            try:
                return github_json(project, suffix, query=query)
            except Exception as error:
                unavailable[name] = redact_github_text(str(error))[:300]
                return default

        files = optional("files", f"/pulls/{number}/files", [], {"per_page": 100})
        reviews = optional("reviews", f"/pulls/{number}/reviews", [], {"per_page": 100})
        issue_comments = optional("issue_comments", f"/issues/{number}/comments", [], {"per_page": 100})
        review_comments = optional("review_comments", f"/pulls/{number}/comments", [], {"per_page": 100})
        sha = str((pull.get("head") or {}).get("sha", ""))
        checks = optional("checks", f"/commits/{sha}/check-runs", {}, {"per_page": 100}) if sha else {}
        status = optional("statuses", f"/commits/{sha}/status", {}) if sha else {}
        return {
            "ok": True,
            "partial": bool(unavailable),
            "unavailable": unavailable,
            "pull_request": {**compact_pull(pull), "body": pull.get("body")},
            "files": [
                {
                    "filename": item.get("filename"), "status": item.get("status"),
                    "additions": item.get("additions"), "deletions": item.get("deletions"),
                    "changes": item.get("changes"), "blob_url": item.get("blob_url"),
                }
                for item in files[:100]
            ],
            "reviews": [
                {
                    "id": item.get("id"), "author": compact_user(item.get("user")),
                    "state": item.get("state"), "body": item.get("body"),
                    "submitted_at": item.get("submitted_at"), "commit_id": item.get("commit_id"),
                }
                for item in reviews[:100]
            ],
            "issue_comments": [
                {"id": item.get("id"), "author": compact_user(item.get("user")), "body": item.get("body"), "created_at": item.get("created_at"), "html_url": item.get("html_url")}
                for item in issue_comments[:100]
            ],
            "review_comments": [
                {"id": item.get("id"), "author": compact_user(item.get("user")), "body": item.get("body"), "path": item.get("path"), "line": item.get("line"), "created_at": item.get("created_at"), "html_url": item.get("html_url")}
                for item in review_comments[:100]
            ],
            "checks": [
                {"id": item.get("id"), "name": item.get("name"), "status": item.get("status"), "conclusion": item.get("conclusion"), "started_at": item.get("started_at"), "completed_at": item.get("completed_at"), "details_url": item.get("details_url")}
                for item in checks.get("check_runs", [])[:100]
            ],
            "combined_status": status.get("state"),
            "statuses": [
                {"context": item.get("context"), "state": item.get("state"), "description": item.get("description"), "target_url": item.get("target_url")}
                for item in status.get("statuses", [])[:100]
            ],
        }
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def release_readiness(project: ProjectName, tag_name: str = "") -> dict:
    """Check local Git state, remote divergence, latest CI, changelog, and optional tag availability without mutation."""
    config = PROJECTS.get(project)
    if config is None:
        return {"ok": False, "error": "Unknown project"}
    tag = tag_name.strip()
    if tag and (len(tag) > 150 or not re.fullmatch(r"[A-Za-z0-9._/+\-]+", tag)):
        return {"ok": False, "error": "Invalid tag name"}
    status = run_git(project, ["status", "--porcelain"])
    branch_result = run_git(project, ["branch", "--show-current"])
    branch_ok = branch_result.get("ok") and branch_result.get("output", "").strip() == config["branch"]
    head_result = run_git(project, ["rev-parse", "HEAD"])
    head_sha = head_result.get("output", "").strip() if head_result.get("ok") else ""
    sync = run_git(project, ["rev-list", "--left-right", "--count", f"HEAD...origin/{config['branch']}"])
    ahead = behind = 0
    if sync.get("ok"):
        try:
            left, right = sync.get("output", "0 0").split()
            ahead, behind = int(left), int(right)
        except (ValueError, TypeError):
            pass
    changelog = run_git(project, ["ls-files", "--error-unmatch", "--", "CHANGELOG.md"])
    partial = False
    latest: dict[str, Any] | None = None
    try:
        data = github_json(project, "/actions/runs", query={"branch": config["branch"], "per_page": 1})
        runs = data.get("workflow_runs", [])
        if runs:
            latest = compact_run(runs[0])
    except Exception:
        partial = True
    tag_exists = False
    if tag:
        tags = run_git(project, ["tag", "--list", tag])
        tag_exists = bool(tags.get("output", "").strip())
        remote_tags = run_git(project, ["ls-remote", "--tags", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"], timeout=90)
        tag_exists = tag_exists or bool(remote_tags.get("output", "").strip())
    release_exists = False
    if tag:
        try:
            releases = github_json(project, "/releases", query={"per_page": 100})
            release_exists = any(str(item.get("tag_name", "")) == tag for item in releases)
        except Exception:
            partial = True
    changelog_mentions_tag = True
    if tag and changelog.get("ok"):
        try:
            changelog_mentions_tag = tag.lstrip("v") in (config["path"] / "CHANGELOG.md").read_text(encoding="utf-8")
        except OSError:
            changelog_mentions_tag = False
    checks = {
        "allowed_branch": bool(branch_ok),
        "clean_worktree": bool(status.get("ok") and not status.get("output", "").strip()),
        "remote_fully_synced": bool(sync.get("ok") and ahead == 0 and behind == 0),
        "latest_ci_success": bool(latest and latest.get("status") == "completed" and latest.get("conclusion") == "success"),
        "latest_ci_matches_head": bool(latest and head_sha and latest.get("head_sha") == head_sha),
        "changelog_present": bool(changelog.get("ok")),
        "changelog_mentions_tag": changelog_mentions_tag,
        "tag_available": not tag_exists,
        "github_release_available": not release_exists,
    }
    ready = all(checks.values())
    return {
        "ok": True,
        "partial": partial,
        "project": project,
        "tag": tag or None,
        "checks": checks,
        "ahead": ahead,
        "behind": behind,
        "latest_workflow": latest,
        "ready": ready,
        "next_recommended_action": "Create a draft release only after every check is true." if ready else "Resolve failed readiness checks before releasing.",
    }


@mcp.tool()
def github_list_releases(project: ProjectName, limit: int = 20, page: int = 1) -> dict:
    """List releases and their assets."""
    try:
        safe_limit = max(1, min(limit, 100))
        safe_page = max(1, min(page, 1000))
        items = github_json(project, "/releases", query={"per_page": safe_limit, "page": safe_page})
        releases = [compact_release(item) for item in items[:safe_limit]]
        return {"ok": True, "count": len(releases), "page": safe_page, "truncated": len(items) == safe_limit, "next_page": safe_page + 1 if len(items) == safe_limit else None, "releases": releases}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_release(project: ProjectName, tag_name: str) -> dict:
    """Read one release by exact tag, including release notes and assets."""
    try:
        tag = tag_name.strip()
        if not tag or len(tag) > 150 or not re.fullmatch(r"[A-Za-z0-9._/+\-]+", tag):
            return {"ok": False, "error": "Invalid tag name"}
        try:
            item = github_json(project, "/releases/tags/" + urllib.parse.quote(tag, safe=""))
        except Exception as tag_error:
            items = github_json(project, "/releases", query={"per_page": 100})
            item = next((release for release in items if str(release.get("tag_name", "")) == tag), None)
            if item is None:
                raise tag_error
        return {"ok": True, "release": {**compact_release(item), "body": item.get("body")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_workflow_runs(
    project: ProjectName,
    branch: str = "",
    status: str = "",
    limit: int = 20,
    page: int = 1,
) -> dict:
    """List GitHub Actions workflow runs with optional branch and status filters."""
    allowed_statuses = {"", "queued", "in_progress", "completed", "requested", "waiting", "pending", "action_required", "cancelled", "failure", "neutral", "skipped", "stale", "success", "timed_out"}
    try:
        if status not in allowed_statuses:
            return {"ok": False, "error": "Invalid workflow status filter"}
        if branch and (len(branch) > 200 or not re.fullmatch(r"[A-Za-z0-9._/\-]+", branch)):
            return {"ok": False, "error": "Invalid branch filter"}
        safe_limit = max(1, min(limit, 100))
        safe_page = max(1, min(page, 1000))
        data = github_json(project, "/actions/runs", query={"branch": branch, "status": status, "per_page": safe_limit, "page": safe_page})
        runs = [compact_run(item) for item in data.get("workflow_runs", [])[:safe_limit]]
        return {"ok": True, "total_count": data.get("total_count"), "count": len(runs), "page": safe_page, "truncated": len(runs) == safe_limit, "next_page": safe_page + 1 if len(runs) == safe_limit else None, "workflow_runs": runs}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_workflow_run(project: ProjectName, run_id: int) -> dict:
    """Read one workflow run, its jobs, steps, and artifacts."""
    try:
        run = require_positive_id(run_id, "run_id")
        item = github_json(project, f"/actions/runs/{run}")
        jobs_data = github_json(project, f"/actions/runs/{run}/jobs", query={"per_page": 100})
        artifacts_data = github_json(project, f"/actions/runs/{run}/artifacts", query={"per_page": 100})
        jobs = []
        for job in jobs_data.get("jobs", [])[:100]:
            jobs.append({
                "id": job.get("id"), "name": job.get("name"), "status": job.get("status"),
                "conclusion": job.get("conclusion"), "started_at": job.get("started_at"),
                "completed_at": job.get("completed_at"), "html_url": job.get("html_url"),
                "steps": [
                    {"number": step.get("number"), "name": step.get("name"), "status": step.get("status"), "conclusion": step.get("conclusion"), "started_at": step.get("started_at"), "completed_at": step.get("completed_at")}
                    for step in job.get("steps", [])[:100]
                ],
            })
        artifacts = [
            {"id": artifact.get("id"), "name": artifact.get("name"), "size_in_bytes": artifact.get("size_in_bytes"), "expired": artifact.get("expired"), "created_at": artifact.get("created_at"), "expires_at": artifact.get("expires_at"), "archive_download_url": artifact.get("archive_download_url")}
            for artifact in artifacts_data.get("artifacts", [])[:100]
        ]
        return {"ok": True, "workflow_run": compact_run(item), "jobs": jobs, "artifacts": artifacts}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_actions_log(
    project: ProjectName,
    run_id: int,
    tail_lines: int = 300,
    contains: str = "",
) -> dict:
    """Download a bounded Actions log archive and return redacted matching or tail lines."""
    try:
        run = require_positive_id(run_id, "run_id")
        if len(contains) > 200:
            return {"ok": False, "error": "Log filter must be at most 200 characters"}
        safe_lines = max(1, min(tail_lines, 500))
        repo = github_repo(project)
        token, _ = github_installation_token()
        _, raw, _ = _github_http(
            f"/repos/{repo}/actions/runs/{run}/logs",
            token=token,
            accept="application/vnd.github+json",
            maximum_bytes=MAX_GH_LOG_ZIP_BYTES,
        )
        archive = zipfile.ZipFile(io.BytesIO(raw))
        members = [item for item in archive.infolist() if not item.is_dir()][:200]
        if sum(item.file_size for item in members) > MAX_GH_LOG_TEXT_BYTES:
            return {"ok": False, "error": "Expanded Actions logs exceed the configured size limit"}
        collected: list[str] = []
        query = contains.lower().strip()
        for member in members:
            if member.file_size > 5_000_000:
                continue
            text = archive.read(member).decode("utf-8", errors="replace")
            for line in text.splitlines():
                clean = redact_github_text(line)
                if not query or query in clean.lower():
                    collected.append(f"[{member.filename}] {clean}")
        selected = collected[:safe_lines] if query else collected[-safe_lines:]
        output = "\n".join(selected)
        if len(output) > 100_000:
            output = output[-100_000:]
        return {
            "ok": True,
            "files_scanned": len(members),
            "matching_lines": len(collected),
            "returned_lines": len(selected),
            "truncated": len(collected) > len(selected) or len(output) >= 100_000,
            "output": output,
        }
    except zipfile.BadZipFile:
        return {"ok": False, "error": "GitHub returned an invalid Actions log archive"}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def inspect_ci_failure(
    project: ProjectName,
    run_id: int,
    detail: Literal["summary", "evidence", "full"] = "summary",
) -> dict:
    """Combine a workflow run, failed steps, and bounded redacted logs; escalate detail only when needed."""
    if detail not in DETAIL_LEVELS:
        return {"ok": False, "error": "Invalid detail level"}
    data = github_get_workflow_run(project, run_id)
    if not data.get("ok"):
        return data
    failed_jobs: list[dict[str, Any]] = []
    for job in data.get("jobs", []):
        failed_steps = [step for step in job.get("steps", []) if step.get("conclusion") in {"failure", "timed_out", "cancelled", "action_required"}]
        if job.get("conclusion") in {"failure", "timed_out", "cancelled", "action_required"} or failed_steps:
            failed_jobs.append({"id": job.get("id"), "name": job.get("name"), "conclusion": job.get("conclusion"), "html_url": job.get("html_url"), "failed_steps": failed_steps})
    result: dict[str, Any] = {
        "ok": True,
        "partial": False,
        "detail": detail,
        "available_detail_levels": list(DETAIL_LEVELS),
        "workflow_run": data.get("workflow_run"),
        "failed_jobs": failed_jobs,
        "truncated": False,
        "next_recommended_action": "No CI failure was detected." if (data.get("workflow_run") or {}).get("conclusion") == "success" else ("Request evidence for redacted error lines." if detail == "summary" else "Read exact source ranges implicated by the failure before patching."),
    }
    if detail != "summary":
        lines = 100 if detail == "evidence" else 500
        logs = github_get_actions_log(project, run_id, tail_lines=lines, contains="")
        if logs.get("ok"):
            raw_log = str(logs.get("output", ""))
            error_pattern = re.compile(r"\b(error|failed|failure|exception|traceback|fatal|panic|timed out)\b", re.IGNORECASE)
            groups: list[dict[str, Any]] = []
            seen: set[str] = set()
            raw_lines = raw_log.splitlines()
            radius = 1 if detail == "evidence" else 2
            for index, line in enumerate(raw_lines):
                normalized = re.sub(r"\s+", " ", line).strip().casefold()
                if not error_pattern.search(line) or normalized in seen:
                    continue
                seen.add(normalized)
                start = max(0, index - radius)
                end = min(len(raw_lines), index + radius + 1)
                groups.append({"line": index + 1, "message": line[:500], "context": "\n".join(raw_lines[start:end])})
                if len(groups) >= (20 if detail == "evidence" else 60):
                    break
            result["error_groups"] = groups
            result["log_evidence"] = raw_log if detail == "full" else "\n\n".join(group["context"] for group in groups)
            result["truncated"] = bool(logs.get("truncated"))
        else:
            result["partial"] = True
            result["unavailable"] = {"logs": logs.get("error", "Log access unavailable")}
    return result


@mcp.tool()
def github_list_artifacts(project: ProjectName, run_id: int, limit: int = 50, page: int = 1) -> dict:
    """List artifacts produced by one workflow run."""
    try:
        run = require_positive_id(run_id, "run_id")
        safe_limit = max(1, min(limit, 100))
        safe_page = max(1, min(page, 1000))
        data = github_json(project, f"/actions/runs/{run}/artifacts", query={"per_page": safe_limit, "page": safe_page})
        artifacts = [
            {"id": item.get("id"), "name": item.get("name"), "size_in_bytes": item.get("size_in_bytes"), "expired": item.get("expired"), "created_at": item.get("created_at"), "expires_at": item.get("expires_at"), "archive_download_url": item.get("archive_download_url")}
            for item in data.get("artifacts", [])[:safe_limit]
        ]
        return {"ok": True, "total_count": data.get("total_count"), "count": len(artifacts), "page": safe_page, "truncated": len(artifacts) == safe_limit, "next_page": safe_page + 1 if len(artifacts) == safe_limit else None, "artifacts": artifacts}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_issue(
    project: ProjectName,
    title: str,
    body: str = "",
    labels: list[str] = [],
) -> dict:
    """Create a non-duplicate issue in an approved repository."""
    try:
        clean_title = validate_title(title)
        clean_body = validate_body(body)
        clean_labels = validate_labels(labels)
        existing = github_json(project, "/issues", query={"state": "all", "per_page": 100})
        for item in existing:
            if "pull_request" not in item and str(item.get("title", "")).strip().casefold() == clean_title.casefold():
                return {"ok": False, "error": "Issue with the same title already exists", "existing_issue": compact_issue(item)}
        with WRITE_LOCK:
            result = github_write_json(
                project, "/issues", method="POST",
                body={"title": clean_title, "body": clean_body, "labels": clean_labels},
                audit_action="github_create_issue",
            )
        return {"ok": True, "status": result["status"], "issue": {**compact_issue(result["data"]), "body": result["data"].get("body")}}
    except Exception as error:
        audit("github_create_issue", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_issue(
    project: ProjectName,
    issue_number: int,
    title: str | None = None,
    body: str | None = None,
    state: Literal["open", "closed"] | None = None,
    state_reason: Literal["completed", "not_planned", "reopened"] | None = None,
    labels: list[str] | None = None,
) -> dict:
    """Update an issue. Closing always requires a valid state reason."""
    try:
        number = require_positive_id(issue_number, "issue_number")
        current = github_json(project, f"/issues/{number}")
        if "pull_request" in current:
            return {"ok": False, "error": "The requested number belongs to a pull request"}
        payload: dict[str, Any] = {}
        if title is not None: payload["title"] = validate_title(title)
        if body is not None: payload["body"] = validate_body(body)
        if labels is not None: payload["labels"] = validate_labels(labels)
        if state is not None:
            payload["state"] = state
            if state == "closed":
                if state_reason not in {"completed", "not_planned"}:
                    return {"ok": False, "error": "Closing an issue requires state_reason completed or not_planned"}
                payload["state_reason"] = state_reason
            elif state_reason == "reopened":
                payload["state_reason"] = "reopened"
        if not payload:
            return {"ok": False, "error": "No issue updates were supplied"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/issues/{number}", method="PATCH", body=payload, audit_action="github_update_issue")
        return {"ok": True, "status": result["status"], "issue": {**compact_issue(result["data"]), "body": result["data"].get("body")}}
    except Exception as error:
        audit("github_update_issue", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_comment_issue(project: ProjectName, issue_number: int, body: str) -> dict:
    """Add a non-duplicate comment to an issue."""
    try:
        number = require_positive_id(issue_number, "issue_number")
        clean_body = validate_body(body, 30_000)
        if not clean_body:
            return {"ok": False, "error": "Comment body cannot be empty"}
        issue = github_json(project, f"/issues/{number}")
        if "pull_request" in issue:
            return {"ok": False, "error": "Use github_comment_pull_request for pull requests"}
        duplicate = duplicate_comment(project, number, clean_body)
        if duplicate: return duplicate
        with WRITE_LOCK:
            result = github_write_json(project, f"/issues/{number}/comments", method="POST", body={"body": clean_body}, audit_action="github_comment_issue")
        item = result["data"]
        return {"ok": True, "status": result["status"], "comment": {"id": item.get("id"), "body": item.get("body"), "author": compact_user(item.get("user")), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_comment_issue", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_pull_request(
    project: ProjectName,
    title: str,
    head: str,
    base: str = "main",
    body: str = "",
    draft: bool = True,
) -> dict:
    """Create a non-duplicate pull request. New pull requests default to draft."""
    try:
        clean_title = validate_title(title)
        clean_head = validate_ref(head, "head branch")
        clean_base = validate_ref(base, "base branch")
        clean_body = validate_body(body)
        existing = github_json(project, "/pulls", query={"state": "open", "head": f"{github_repo(project).split('/', 1)[0]}:{clean_head}", "base": clean_base, "per_page": 100})
        if existing:
            return {"ok": False, "error": "An open pull request already exists for these branches", "existing_pull_request": compact_pull(existing[0])}
        with WRITE_LOCK:
            result = github_write_json(
                project, "/pulls", method="POST",
                body={"title": clean_title, "head": clean_head, "base": clean_base, "body": clean_body, "draft": bool(draft)},
                audit_action="github_create_pull_request",
            )
        return {"ok": True, "status": result["status"], "pull_request": {**compact_pull(result["data"]), "body": result["data"].get("body")}}
    except Exception as error:
        audit("github_create_pull_request", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_pull_request(
    project: ProjectName,
    pull_number: int,
    title: str | None = None,
    body: str | None = None,
    state: Literal["open", "closed"] | None = None,
    base: str | None = None,
    confirmation: str = "",
) -> dict:
    """Update a pull request. Closing requires confirmation text CLOSE PR #number."""
    try:
        number = require_positive_id(pull_number, "pull_number")
        payload: dict[str, Any] = {}
        if title is not None: payload["title"] = validate_title(title)
        if body is not None: payload["body"] = validate_body(body)
        if base is not None: payload["base"] = validate_ref(base, "base branch")
        if state is not None:
            if state == "closed" and confirmation.strip() != f"CLOSE PR #{number}":
                return {"ok": False, "error": f"Closing requires confirmation: CLOSE PR #{number}"}
            payload["state"] = state
        if not payload:
            return {"ok": False, "error": "No pull request updates were supplied"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/pulls/{number}", method="PATCH", body=payload, audit_action="github_update_pull_request")
        return {"ok": True, "status": result["status"], "pull_request": {**compact_pull(result["data"]), "body": result["data"].get("body")}}
    except Exception as error:
        audit("github_update_pull_request", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_comment_pull_request(project: ProjectName, pull_number: int, body: str) -> dict:
    """Add a non-duplicate general comment to a pull request."""
    try:
        number = require_positive_id(pull_number, "pull_number")
        clean_body = validate_body(body, 30_000)
        if not clean_body:
            return {"ok": False, "error": "Comment body cannot be empty"}
        pull = github_json(project, f"/pulls/{number}")
        if not pull.get("number"):
            return {"ok": False, "error": "Pull request was not found"}
        duplicate = duplicate_comment(project, number, clean_body)
        if duplicate: return duplicate
        with WRITE_LOCK:
            result = github_write_json(project, f"/issues/{number}/comments", method="POST", body={"body": clean_body}, audit_action="github_comment_pull_request")
        item = result["data"]
        return {"ok": True, "status": result["status"], "comment": {"id": item.get("id"), "body": item.get("body"), "author": compact_user(item.get("user")), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_comment_pull_request", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_comment_pull_request_line(
    project: ProjectName,
    pull_number: int,
    body: str,
    commit_id: str,
    path: str,
    line: int,
    side: Literal["LEFT", "RIGHT"] = "RIGHT",
) -> dict:
    """Add a review comment to one changed line in a pull request."""
    try:
        number = require_positive_id(pull_number, "pull_number")
        clean_body = validate_body(body, 30_000)
        if not clean_body: return {"ok": False, "error": "Comment body cannot be empty"}
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit_id): return {"ok": False, "error": "commit_id must be a full 40-character SHA"}
        clean_path = path.strip().replace("\\", "/")
        if not clean_path or clean_path.startswith("/") or ".." in clean_path.split("/") or "\x00" in clean_path or len(clean_path) > 500:
            return {"ok": False, "error": "Invalid review file path"}
        clean_line = require_positive_id(line, "line")
        existing_comments = github_json(project, f"/pulls/{number}/comments", query={"per_page": 100})
        for item in existing_comments:
            if (
                str(item.get("body", "")).strip() == clean_body
                and item.get("path") == clean_path
                and item.get("line") == clean_line
                and str(item.get("commit_id", "")).lower() == commit_id.lower()
            ):
                return {"ok": False, "error": "Identical line comment already exists", "existing_comment_id": item.get("id"), "html_url": item.get("html_url")}
        with WRITE_LOCK:
            result = github_write_json(
                project, f"/pulls/{number}/comments", method="POST",
                body={"body": clean_body, "commit_id": commit_id.lower(), "path": clean_path, "line": clean_line, "side": side},
                audit_action="github_comment_pull_request_line",
            )
        item = result["data"]
        return {"ok": True, "status": result["status"], "comment": {"id": item.get("id"), "body": item.get("body"), "path": item.get("path"), "line": item.get("line"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_comment_pull_request_line", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_submit_pull_request_review(
    project: ProjectName,
    pull_number: int,
    event: Literal["COMMENT", "APPROVE", "REQUEST_CHANGES"],
    body: str,
    confirmation: str,
) -> dict:
    """Submit a PR review after exact confirmation REVIEW PR #number."""
    try:
        number = require_positive_id(pull_number, "pull_number")
        if confirmation.strip() != f"REVIEW PR #{number}":
            return {"ok": False, "error": f"Review requires confirmation: REVIEW PR #{number}"}
        clean_body = validate_body(body, 30_000)
        if event == "REQUEST_CHANGES" and not clean_body:
            return {"ok": False, "error": "Request changes requires a review body"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/pulls/{number}/reviews", method="POST", body={"event": event, "body": clean_body}, audit_action="github_submit_review")
        item = result["data"]
        return {"ok": True, "status": result["status"], "review": {"id": item.get("id"), "state": item.get("state"), "body": item.get("body"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_submit_review", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_merge_pull_request(
    project: ProjectName,
    pull_number: int,
    merge_method: Literal["merge", "squash", "rebase"] = "squash",
    commit_title: str = "",
    commit_message: str = "",
    confirmation: str = "",
) -> dict:
    """Merge a PR only after exact confirmation MERGE PR #number."""
    try:
        number = require_positive_id(pull_number, "pull_number")
        if confirmation.strip() != f"MERGE PR #{number}":
            return {"ok": False, "error": f"Merge requires confirmation: MERGE PR #{number}"}
        pull = github_json(project, f"/pulls/{number}")
        if pull.get("state") != "open" or pull.get("draft"):
            return {"ok": False, "error": "Pull request must be open and not draft"}
        if pull.get("mergeable") is False:
            return {"ok": False, "error": "Pull request is not mergeable"}
        payload: dict[str, Any] = {"merge_method": merge_method}
        if commit_title: payload["commit_title"] = validate_title(commit_title, "commit_title")
        if commit_message: payload["commit_message"] = validate_body(commit_message, 10_000)
        with WRITE_LOCK:
            result = github_write_json(project, f"/pulls/{number}/merge", method="PUT", body=payload, audit_action="github_merge_pull_request")
        data = result["data"]
        return {"ok": bool(data.get("merged")), "status": result["status"], "merged": data.get("merged"), "message": data.get("message"), "sha": data.get("sha")}
    except Exception as error:
        audit("github_merge_pull_request", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_rerun_workflow(
    project: ProjectName,
    run_id: int,
    failed_jobs_only: bool = True,
    confirmation: str = "",
) -> dict:
    """Rerun failed jobs or a whole workflow after exact confirmation RERUN RUN id."""
    try:
        run = require_positive_id(run_id, "run_id")
        if confirmation.strip() != f"RERUN RUN {run}":
            return {"ok": False, "error": f"Rerun requires confirmation: RERUN RUN {run}"}
        current = github_json(project, f"/actions/runs/{run}")
        if current.get("status") != "completed":
            return {"ok": False, "error": "Only completed workflow runs can be rerun"}
        suffix = f"/actions/runs/{run}/rerun-failed-jobs" if failed_jobs_only else f"/actions/runs/{run}/rerun"
        with WRITE_LOCK:
            result = github_write_json(project, suffix, method="POST", body={}, audit_action="github_rerun_workflow")
        return {"ok": True, "status": result["status"], "run_id": run, "failed_jobs_only": failed_jobs_only}
    except Exception as error:
        audit("github_rerun_workflow", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_cancel_workflow(project: ProjectName, run_id: int, confirmation: str = "") -> dict:
    """Cancel a queued or running workflow after exact confirmation CANCEL RUN id."""
    try:
        run = require_positive_id(run_id, "run_id")
        if confirmation.strip() != f"CANCEL RUN {run}":
            return {"ok": False, "error": f"Cancellation requires confirmation: CANCEL RUN {run}"}
        current = github_json(project, f"/actions/runs/{run}")
        if current.get("status") == "completed":
            return {"ok": False, "error": "Completed workflow runs cannot be cancelled"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/actions/runs/{run}/cancel", method="POST", body={}, audit_action="github_cancel_workflow")
        return {"ok": True, "status": result["status"], "run_id": run}
    except Exception as error:
        audit("github_cancel_workflow", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_dispatch_workflow(
    project: ProjectName,
    workflow: str,
    ref: str,
    inputs: dict[str, str] = {},
    confirmation: str = "",
) -> dict:
    """Dispatch an allowlisted workflow file after exact confirmation DISPATCH workflow ON ref."""
    try:
        clean_workflow = workflow.strip()
        if not re.fullmatch(r"[A-Za-z0-9._\-]+\.(?:yml|yaml)", clean_workflow):
            return {"ok": False, "error": "workflow must be a simple .yml or .yaml filename"}
        clean_ref = validate_ref(ref, "workflow ref")
        if confirmation.strip() != f"DISPATCH {clean_workflow} ON {clean_ref}":
            return {"ok": False, "error": f"Dispatch requires confirmation: DISPATCH {clean_workflow} ON {clean_ref}"}
        if len(inputs) > 20:
            return {"ok": False, "error": "At most 20 workflow inputs are allowed"}
        clean_inputs: dict[str, str] = {}
        for key, value in inputs.items():
            text_value = str(value)
            if (
                not re.fullmatch(r"[A-Za-z0-9_\-]{1,100}", key)
                or len(text_value) > 1_000
                or "\x00" in text_value
                or redact_github_text(text_value) != text_value
                or re.search(SECRET_PATTERN, text_value, flags=re.IGNORECASE)
            ):
                return {"ok": False, "error": "Invalid or sensitive workflow input"}
            clean_inputs[key] = text_value
        with WRITE_LOCK:
            result = github_write_json(project, f"/actions/workflows/{clean_workflow}/dispatches", method="POST", body={"ref": clean_ref, "inputs": clean_inputs}, audit_action="github_dispatch_workflow")
        return {"ok": True, "status": result["status"], "workflow": clean_workflow, "ref": clean_ref}
    except Exception as error:
        audit("github_dispatch_workflow", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_release(
    project: ProjectName,
    tag_name: str,
    name: str,
    body: str = "",
    target_commitish: str = "",
    prerelease: bool = True,
    publish: bool = False,
    confirmation: str = "",
) -> dict:
    """Create a draft release by default. Publishing requires confirmation PUBLISH tag."""
    try:
        tag = validate_tag(tag_name)
        clean_name = validate_title(name, "release name")
        clean_body = validate_body(body, 100_000)
        target = validate_ref(target_commitish, "target_commitish") if target_commitish else PROJECTS[project]["branch"]
        releases = github_json(project, "/releases", query={"per_page": 100})
        for item in releases:
            if item.get("tag_name") == tag:
                return {"ok": False, "error": "Release with this tag already exists", "existing_release": compact_release(item)}
        if publish and confirmation.strip() != f"PUBLISH {tag}":
            return {"ok": False, "error": f"Publishing requires confirmation: PUBLISH {tag}"}
        payload = {"tag_name": tag, "name": clean_name, "body": clean_body, "target_commitish": target, "draft": not publish, "prerelease": bool(prerelease)}
        with WRITE_LOCK:
            result = github_write_json(project, "/releases", method="POST", body=payload, audit_action="github_create_release")
        return {"ok": True, "status": result["status"], "release": {**compact_release(result["data"]), "body": result["data"].get("body")}}
    except Exception as error:
        audit("github_create_release", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_release(
    project: ProjectName,
    release_id: int,
    tag_name: str | None = None,
    name: str | None = None,
    body: str | None = None,
    target_commitish: str | None = None,
    prerelease: bool | None = None,
    publish: bool | None = None,
    confirmation: str = "",
) -> dict:
    """Update a release. Publishing a draft requires confirmation PUBLISH RELEASE id."""
    try:
        release = require_positive_id(release_id, "release_id")
        current = github_json(project, f"/releases/{release}")
        payload: dict[str, Any] = {}
        if tag_name is not None:
            if not current.get("draft"):
                return {"ok": False, "error": "Only draft release tags can be changed"}
            payload["tag_name"] = validate_tag(tag_name)
        if name is not None: payload["name"] = validate_title(name, "release name")
        if body is not None: payload["body"] = validate_body(body, 100_000)
        if target_commitish is not None:
            if not current.get("draft"):
                return {"ok": False, "error": "Only draft releases can be retargeted"}
            payload["target_commitish"] = validate_ref(target_commitish, "target_commitish")
        if prerelease is not None: payload["prerelease"] = bool(prerelease)
        if publish is not None:
            if publish and current.get("draft") and confirmation.strip() != f"PUBLISH RELEASE {release}":
                return {"ok": False, "error": f"Publishing requires confirmation: PUBLISH RELEASE {release}"}
            payload["draft"] = not publish
        if not payload:
            return {"ok": False, "error": "No release updates were supplied"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/releases/{release}", method="PATCH", body=payload, audit_action="github_update_release")
        return {"ok": True, "status": result["status"], "release": {**compact_release(result["data"]), "body": result["data"].get("body")}}
    except Exception as error:
        audit("github_update_release", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_deployments(project: ProjectName, ref: str = "", environment: str = "", limit: int = 20, page: int = 1) -> dict:
    """List deployments with optional ref and environment filters."""
    try:
        clean_ref = validate_ref(ref, "deployment ref") if ref else ""
        clean_environment = validate_environment_name(environment) if environment else ""
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, "/deployments", query={"ref": clean_ref, "environment": clean_environment, "per_page": safe_limit, "page": safe_page})
        deployments = [
            {
                "id": item.get("id"), "sha": item.get("sha"), "ref": item.get("ref"),
                "task": item.get("task"), "environment": item.get("environment"),
                "description": item.get("description"), "transient_environment": item.get("transient_environment"),
                "production_environment": item.get("production_environment"), "created_at": item.get("created_at"),
            }
            for item in items[:safe_limit]
        ]
        return {"ok": True, "count": len(deployments), "page": safe_page, "truncated": len(items) == safe_limit, "next_page": safe_page + 1 if len(items) == safe_limit else None, "deployments": deployments}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_deployment(project: ProjectName, deployment_id: int) -> dict:
    """Read one deployment and up to 100 recent statuses."""
    try:
        deployment = require_positive_id(deployment_id, "deployment_id")
        item = github_json(project, f"/deployments/{deployment}")
        statuses = github_json(project, f"/deployments/{deployment}/statuses", query={"per_page": 100})
        compact_statuses = [
            {
                "id": status.get("id"), "state": status.get("state"), "description": status.get("description"),
                "environment": status.get("environment"), "log_url": status.get("log_url"),
                "environment_url": status.get("environment_url"), "created_at": status.get("created_at"),
            }
            for status in statuses[:100]
        ]
        return {
            "ok": True,
            "deployment": {
                "id": item.get("id"), "sha": item.get("sha"), "ref": item.get("ref"),
                "task": item.get("task"), "environment": item.get("environment"),
                "description": item.get("description"), "transient_environment": item.get("transient_environment"),
                "production_environment": item.get("production_environment"), "created_at": item.get("created_at"),
            },
            "statuses": compact_statuses,
        }
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_deployment(project: ProjectName, ref: str, environment: str = "production", task: str = "deploy", description: str = "", transient_environment: bool = False, production_environment: bool = False, confirmation: str = "") -> dict:
    """Create a deployment after exact confirmation DEPLOY ref TO environment."""
    try:
        clean_ref = validate_ref(ref, "deployment ref")
        clean_environment = validate_environment_name(environment)
        clean_task = validate_ref(task, "deployment task")
        clean_description = validate_body(description, 140)
        if confirmation.strip() != f"DEPLOY {clean_ref} TO {clean_environment}":
            return {"ok": False, "error": f"Deployment requires confirmation: DEPLOY {clean_ref} TO {clean_environment}"}
        payload = {
            "ref": clean_ref, "environment": clean_environment, "task": clean_task,
            "description": clean_description, "auto_merge": False, "transient_environment": bool(transient_environment),
            "production_environment": bool(production_environment),
        }
        with WRITE_LOCK:
            result = github_write_json(project, "/deployments", method="POST", body=payload, audit_action="github_create_deployment")
        item = result["data"]
        return {"ok": True, "status": result["status"], "deployment": {"id": item.get("id"), "sha": item.get("sha"), "ref": item.get("ref"), "environment": item.get("environment"), "task": item.get("task"), "created_at": item.get("created_at")}}
    except Exception as error:
        audit("github_create_deployment", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_deployment_status(project: ProjectName, deployment_id: int, state: Literal["error", "failure", "inactive", "in_progress", "queued", "pending", "success"], description: str = "", environment: str = "", log_url: str = "", environment_url: str = "", auto_inactive: bool = True, confirmation: str = "") -> dict:
    """Create a deployment status after exact confirmation SET DEPLOYMENT id state."""
    try:
        deployment = require_positive_id(deployment_id, "deployment_id")
        if confirmation.strip() != f"SET DEPLOYMENT {deployment} {state}":
            return {"ok": False, "error": f"Status update requires confirmation: SET DEPLOYMENT {deployment} {state}"}
        payload: dict[str, Any] = {"state": state, "auto_inactive": bool(auto_inactive)}
        if description: payload["description"] = validate_body(description, 140)
        if environment: payload["environment"] = validate_environment_name(environment)
        if log_url: payload["log_url"] = validate_external_url(log_url, "log_url")
        if environment_url: payload["environment_url"] = validate_external_url(environment_url, "environment_url")
        with WRITE_LOCK:
            result = github_write_json(project, f"/deployments/{deployment}/statuses", method="POST", body=payload, audit_action="github_create_deployment_status")
        item = result["data"]
        return {"ok": True, "status": result["status"], "deployment_status": {"id": item.get("id"), "state": item.get("state"), "description": item.get("description"), "environment": item.get("environment"), "log_url": item.get("log_url"), "environment_url": item.get("environment_url"), "created_at": item.get("created_at")}}
    except Exception as error:
        audit("github_create_deployment_status", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_environments(project: ProjectName, limit: int = 20, page: int = 1) -> dict:
    """List repository deployment environments."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        data = github_json(project, "/environments", query={"per_page": safe_limit, "page": safe_page})
        environments = [
            {"id": item.get("id"), "name": item.get("name"), "url": item.get("html_url"), "protection_rules": item.get("protection_rules"), "deployment_branch_policy": item.get("deployment_branch_policy")}
            for item in data.get("environments", [])[:safe_limit]
        ]
        return {"ok": True, "total_count": data.get("total_count"), "count": len(environments), "page": safe_page, "truncated": len(environments) == safe_limit, "next_page": safe_page + 1 if len(environments) == safe_limit else None, "environments": environments}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_environment(project: ProjectName, environment: str) -> dict:
    """Read one deployment environment and its protection settings."""
    try:
        name = validate_environment_name(environment)
        item = github_json(project, "/environments/" + quote_path_value(name))
        return {"ok": True, "environment": {"id": item.get("id"), "name": item.get("name"), "url": item.get("html_url"), "protection_rules": item.get("protection_rules"), "deployment_branch_policy": item.get("deployment_branch_policy")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_upsert_environment(project: ProjectName, environment: str, wait_timer: int = 0, prevent_self_review: bool = False, reviewer_user_ids: list[int] = [], reviewer_team_ids: list[int] = [], branch_policy: Literal["all", "protected", "custom"] = "all", confirmation: str = "") -> dict:
    """Create or update an environment after exact confirmation CONFIGURE ENVIRONMENT name."""
    try:
        name = validate_environment_name(environment)
        if not isinstance(wait_timer, int) or isinstance(wait_timer, bool) or not 0 <= wait_timer <= 43_200:
            return {"ok": False, "error": "wait_timer must be between 0 and 43200 minutes"}
        if len(reviewer_user_ids) + len(reviewer_team_ids) > 6:
            return {"ok": False, "error": "At most six reviewers are allowed"}
        if confirmation.strip() != f"CONFIGURE ENVIRONMENT {name}":
            return {"ok": False, "error": f"Environment update requires confirmation: CONFIGURE ENVIRONMENT {name}"}
        reviewers = [{"type": "User", "id": require_positive_id(value, "reviewer user id")} for value in reviewer_user_ids]
        reviewers.extend({"type": "Team", "id": require_positive_id(value, "reviewer team id")} for value in reviewer_team_ids)
        policy: dict[str, bool] | None = None
        if branch_policy == "protected":
            policy = {"protected_branches": True, "custom_branch_policies": False}
        elif branch_policy == "custom":
            policy = {"protected_branches": False, "custom_branch_policies": True}
        payload = {
            "wait_timer": wait_timer, "prevent_self_review": bool(prevent_self_review),
            "reviewers": reviewers or None, "deployment_branch_policy": policy,
        }
        with WRITE_LOCK:
            result = github_write_json(project, "/environments/" + quote_path_value(name), method="PUT", body=payload, audit_action="github_upsert_environment")
        item = result["data"]
        return {"ok": True, "status": result["status"], "environment": {"id": item.get("id"), "name": item.get("name"), "url": item.get("html_url"), "protection_rules": item.get("protection_rules"), "deployment_branch_policy": item.get("deployment_branch_policy")}}
    except Exception as error:
        audit("github_upsert_environment", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_actions_variables(project: ProjectName, scope: Literal["repository", "environment"] = "repository", environment: str = "", limit: int = 30, page: int = 1) -> dict:
    """List repository or environment Actions variables without returning values."""
    try:
        if scope not in {"repository", "environment"}:
            return {"ok": False, "error": "Invalid variable scope"}
        clean_environment = validate_environment_name(environment) if scope == "environment" else ""
        safe_limit = max(1, min(limit, 30)); safe_page = max(1, min(page, 1000))
        suffix = "/actions/variables"
        if scope == "environment":
            suffix = "/environments/" + quote_path_value(clean_environment) + "/variables"
        data = github_json(project, suffix, query={"per_page": safe_limit, "page": safe_page})
        variables = [
            {"name": item.get("name"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at")}
            for item in data.get("variables", [])[:safe_limit]
        ]
        return {"ok": True, "scope": scope, "environment": clean_environment or None, "total_count": data.get("total_count"), "count": len(variables), "page": safe_page, "truncated": len(variables) == safe_limit, "next_page": safe_page + 1 if len(variables) == safe_limit else None, "values_redacted": True, "variables": variables}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_upsert_actions_variable(project: ProjectName, name: str, value: str, scope: Literal["repository", "environment"] = "repository", environment: str = "", confirmation: str = "") -> dict:
    """Create or update a non-secret Actions variable after exact confirmation."""
    try:
        if scope not in {"repository", "environment"}:
            return {"ok": False, "error": "Invalid variable scope"}
        clean_name = validate_variable_name(name)
        clean_value = validate_body(value, 10_000)
        clean_environment = validate_environment_name(environment) if scope == "environment" else ""
        suffix = "/actions/variables"
        if scope == "environment":
            suffix = "/environments/" + quote_path_value(clean_environment) + "/variables"
        item_suffix = suffix + "/" + quote_path_value(clean_name)
        exists = False
        try:
            github_json(project, item_suffix)
            exists = True
        except Exception as lookup_error:
            if "HTTP 404" not in str(lookup_error):
                raise
        action = "UPDATE" if exists else "CREATE"
        target = "repository" if scope == "repository" else f"environment {clean_environment}"
        required = f"{action} VARIABLE {clean_name} IN {target}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Variable write requires confirmation: {required}"}
        method: Literal["POST", "PATCH", "PUT"] = "PATCH" if exists else "POST"
        path = item_suffix if exists else suffix
        body = {"name": clean_name, "value": clean_value}
        with WRITE_LOCK:
            result = github_write_json(project, path, method=method, body=body, audit_action="github_upsert_actions_variable")
        return {"ok": True, "status": result["status"], "action": action.lower(), "scope": scope, "environment": clean_environment or None, "name": clean_name, "value_redacted": True}
    except Exception as error:
        audit("github_upsert_actions_variable", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_pages(project: ProjectName, limit: int = 20, page: int = 1) -> dict:
    """Read GitHub Pages configuration and recent builds."""
    try:
        site = github_json(project, "/pages")
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, "/pages/builds", query={"per_page": safe_limit, "page": safe_page})
        builds = [
            {"id": item.get("id"), "status": item.get("status"), "error": item.get("error"), "commit": item.get("commit"), "duration": item.get("duration"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at")}
            for item in items[:safe_limit]
        ]
        return {"ok": True, "configured": True, "site": {"url": site.get("html_url"), "status": site.get("status"), "cname": site.get("cname"), "https_enforced": site.get("https_enforced"), "build_type": site.get("build_type"), "source": site.get("source")}, "builds": builds, "page": safe_page, "truncated": len(items) == safe_limit, "next_page": safe_page + 1 if len(items) == safe_limit else None}
    except Exception as error:
        if "HTTP 404" in str(error):
            return {"ok": True, "configured": False, "site": None, "builds": []}
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_configure_pages(project: ProjectName, operation: Literal["create", "update"], build_type: Literal["legacy", "workflow"], branch: str = "", source_path: Literal["/", "/docs"] = "/", https_enforced: bool | None = None, confirmation: str = "") -> dict:
    """Create or update GitHub Pages after exact confirmation."""
    try:
        if operation not in {"create", "update"} or build_type not in {"legacy", "workflow"}:
            return {"ok": False, "error": "Invalid Pages operation or build type"}
        clean_branch = validate_ref(branch, "Pages branch") if branch else ""
        if source_path not in {"/", "/docs"}:
            return {"ok": False, "error": "Pages source path must be / or /docs"}
        payload: dict[str, Any] = {"build_type": build_type}
        if build_type == "legacy":
            if not clean_branch:
                return {"ok": False, "error": "Legacy Pages requires a source branch"}
            payload["source"] = {"branch": clean_branch, "path": source_path}
        elif clean_branch:
            payload["source"] = {"branch": clean_branch, "path": source_path}
        if https_enforced is not None:
            payload["https_enforced"] = bool(https_enforced)
        required = f"CONFIGURE PAGES {operation} {build_type}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Pages configuration requires confirmation: {required}"}
        method: Literal["POST", "PATCH", "PUT"] = "POST" if operation == "create" else "PUT"
        with WRITE_LOCK:
            result = github_write_json(project, "/pages", method=method, body=payload, audit_action="github_configure_pages")
        site = github_json(project, "/pages")
        return {"ok": True, "status": result["status"], "operation": operation, "site": {"url": site.get("html_url"), "status": site.get("status"), "https_enforced": site.get("https_enforced"), "build_type": site.get("build_type"), "source": site.get("source")}}
    except Exception as error:
        audit("github_configure_pages", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_request_pages_build(project: ProjectName, confirmation: str = "") -> dict:
    """Request a Pages build after exact confirmation BUILD PAGES."""
    try:
        if confirmation.strip() != "BUILD PAGES":
            return {"ok": False, "error": "Pages build requires confirmation: BUILD PAGES"}
        with WRITE_LOCK:
            result = github_write_json(project, "/pages/builds", method="POST", body={}, audit_action="github_request_pages_build")
        return {"ok": True, "status": result["status"], "build": {"url": result["data"].get("url"), "status": result["data"].get("status")}}
    except Exception as error:
        audit("github_request_pages_build", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_workflows(project: ProjectName, limit: int = 50, page: int = 1) -> dict:
    """List repository workflow definitions and states."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        data = github_json(project, "/actions/workflows", query={"per_page": safe_limit, "page": safe_page})
        workflows = [
            {"id": item.get("id"), "name": item.get("name"), "path": item.get("path"), "state": item.get("state"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "html_url": item.get("html_url")}
            for item in data.get("workflows", [])[:safe_limit]
        ]
        return {"ok": True, "total_count": data.get("total_count"), "count": len(workflows), "page": safe_page, "truncated": len(workflows) == safe_limit, "next_page": safe_page + 1 if len(workflows) == safe_limit else None, "workflows": workflows}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_workflow(project: ProjectName, workflow: str) -> dict:
    """Read one workflow by numeric ID or simple workflow filename."""
    try:
        clean_workflow = str(workflow).strip()
        if not re.fullmatch(r"(?:[1-9][0-9]{0,18}|[A-Za-z0-9._\-]+\.(?:yml|yaml))", clean_workflow):
            return {"ok": False, "error": "workflow must be a numeric ID or simple .yml/.yaml filename"}
        item = github_json(project, "/actions/workflows/" + clean_workflow)
        return {"ok": True, "workflow": {"id": item.get("id"), "name": item.get("name"), "path": item.get("path"), "state": item.get("state"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "html_url": item.get("html_url"), "badge_url": item.get("badge_url")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_set_workflow_state(project: ProjectName, workflow: str, action: Literal["enable", "disable"], confirmation: str = "") -> dict:
    """Enable or disable a workflow after exact confirmation."""
    try:
        clean_workflow = str(workflow).strip()
        if not re.fullmatch(r"(?:[1-9][0-9]{0,18}|[A-Za-z0-9._\-]+\.(?:yml|yaml))", clean_workflow):
            return {"ok": False, "error": "workflow must be a numeric ID or simple .yml/.yaml filename"}
        if action not in {"enable", "disable"}:
            return {"ok": False, "error": "action must be enable or disable"}
        required = f"{action.upper()} WORKFLOW {clean_workflow}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Workflow state change requires confirmation: {required}"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/actions/workflows/{clean_workflow}/{action}", method="PUT", body={}, audit_action="github_set_workflow_state")
        return {"ok": True, "status": result["status"], "workflow": clean_workflow, "action": action}
    except Exception as error:
        audit("github_set_workflow_state", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_commit_checks(project: ProjectName, ref: str, limit: int = 50, page: int = 1) -> dict:
    """List check runs for a commit SHA or ref."""
    try:
        clean_ref = validate_ref(ref, "check ref")
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        data = github_json(project, f"/commits/{clean_ref}/check-runs", query={"per_page": safe_limit, "page": safe_page})
        runs = [
            {"id": item.get("id"), "name": item.get("name"), "head_sha": item.get("head_sha"), "status": item.get("status"), "conclusion": item.get("conclusion"), "started_at": item.get("started_at"), "completed_at": item.get("completed_at"), "details_url": item.get("details_url"), "html_url": item.get("html_url")}
            for item in data.get("check_runs", [])[:safe_limit]
        ]
        return {"ok": True, "total_count": data.get("total_count"), "count": len(runs), "page": safe_page, "truncated": len(runs) == safe_limit, "next_page": safe_page + 1 if len(runs) == safe_limit else None, "check_runs": runs}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_check_run(project: ProjectName, check_run_id: int) -> dict:
    """Read one check run including bounded output."""
    try:
        check = require_positive_id(check_run_id, "check_run_id")
        item = github_json(project, f"/check-runs/{check}")
        return {"ok": True, "check_run": {"id": item.get("id"), "name": item.get("name"), "head_sha": item.get("head_sha"), "status": item.get("status"), "conclusion": item.get("conclusion"), "started_at": item.get("started_at"), "completed_at": item.get("completed_at"), "details_url": item.get("details_url"), "external_id": item.get("external_id"), "output": item.get("output"), "html_url": item.get("html_url")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_check_run(project: ProjectName, name: str, head_sha: str, status: Literal["queued", "in_progress", "completed"] = "queued", conclusion: Literal["action_required", "cancelled", "failure", "neutral", "success", "skipped", "stale", "timed_out"] | None = None, details_url: str = "", external_id: str = "", title: str = "", summary: str = "", text: str = "", confirmation: str = "") -> dict:
    """Create a check run after exact confirmation."""
    try:
        clean_name = validate_title(name, "check name")
        clean_sha = head_sha.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", clean_sha):
            return {"ok": False, "error": "head_sha must be a full 40-character commit SHA"}
        if (status == "completed") != (conclusion is not None):
            return {"ok": False, "error": "Completed checks require a conclusion; other states forbid it"}
        required = f"CREATE CHECK {clean_name} ON {clean_sha}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Check creation requires confirmation: {required}"}
        payload: dict[str, Any] = {"name": clean_name, "head_sha": clean_sha, "status": status}
        if details_url: payload["details_url"] = validate_external_url(details_url, "details_url")
        if external_id: payload["external_id"] = validate_title(external_id, "external_id")
        if conclusion: payload["conclusion"] = conclusion
        if title or summary or text:
            if not title or not summary:
                return {"ok": False, "error": "Check output requires both title and summary"}
            payload["output"] = {"title": validate_title(title, "output title"), "summary": validate_body(summary, 65_535), "text": validate_body(text, 65_535)}
        with WRITE_LOCK:
            result = github_write_json(project, "/check-runs", method="POST", body=payload, audit_action="github_create_check_run")
        item = result["data"]
        return {"ok": True, "status": result["status"], "check_run": {"id": item.get("id"), "name": item.get("name"), "head_sha": item.get("head_sha"), "status": item.get("status"), "conclusion": item.get("conclusion"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_create_check_run", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_check_run(project: ProjectName, check_run_id: int, status: Literal["queued", "in_progress", "completed"], conclusion: Literal["action_required", "cancelled", "failure", "neutral", "success", "skipped", "stale", "timed_out"] | None = None, details_url: str = "", title: str = "", summary: str = "", text: str = "", confirmation: str = "") -> dict:
    """Update a check run after exact confirmation."""
    try:
        check = require_positive_id(check_run_id, "check_run_id")
        if status not in {"queued", "in_progress", "completed"}:
            return {"ok": False, "error": "Invalid check status"}
        if status == "completed" and conclusion is None:
            return {"ok": False, "error": "Completed checks require a conclusion"}
        if status != "completed" and conclusion is not None:
            return {"ok": False, "error": "Only completed checks accept a conclusion"}
        required = f"UPDATE CHECK {check} TO {status}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Check update requires confirmation: {required}"}
        payload: dict[str, Any] = {"status": status}
        if conclusion: payload["conclusion"] = conclusion
        if details_url: payload["details_url"] = validate_external_url(details_url, "details_url")
        if title or summary or text:
            if not title or not summary:
                return {"ok": False, "error": "Check output requires both title and summary"}
            payload["output"] = {"title": validate_title(title, "output title"), "summary": validate_body(summary, 65_535), "text": validate_body(text, 65_535)}
        with WRITE_LOCK:
            result = github_write_json(project, f"/check-runs/{check}", method="PATCH", body=payload, audit_action="github_update_check_run")
        item = result["data"]
        return {"ok": True, "status": result["status"], "check_run": {"id": item.get("id"), "name": item.get("name"), "head_sha": item.get("head_sha"), "status": item.get("status"), "conclusion": item.get("conclusion"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_update_check_run", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_commit_statuses(project: ProjectName, ref: str, limit: int = 50, page: int = 1) -> dict:
    """List commit statuses for a SHA or ref."""
    try:
        clean_ref = validate_ref(ref, "status ref")
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, f"/commits/{clean_ref}/statuses", query={"per_page": safe_limit, "page": safe_page})
        statuses = [
            {"id": item.get("id"), "sha": item.get("sha"), "state": item.get("state"), "context": item.get("context"), "description": item.get("description"), "target_url": item.get("target_url"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at")}
            for item in items[:safe_limit]
        ]
        return {"ok": True, "count": len(statuses), "page": safe_page, "truncated": len(statuses) == safe_limit, "next_page": safe_page + 1 if len(statuses) == safe_limit else None, "statuses": statuses}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_commit_status(project: ProjectName, sha: str, state: Literal["error", "failure", "pending", "success"], context: str = "default", description: str = "", target_url: str = "", confirmation: str = "") -> dict:
    """Create a commit status after exact confirmation."""
    try:
        clean_sha = sha.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", clean_sha):
            return {"ok": False, "error": "sha must be a full 40-character commit SHA"}
        clean_context = validate_title(context, "status context")
        if len(clean_context) > 100:
            return {"ok": False, "error": "status context must be at most 100 characters"}
        clean_description = validate_body(description, 140)
        payload: dict[str, Any] = {"state": state, "context": clean_context, "description": clean_description}
        if target_url: payload["target_url"] = validate_external_url(target_url, "target_url")
        required = f"SET STATUS {clean_context} {state} ON {clean_sha}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Commit status requires confirmation: {required}"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/statuses/{clean_sha}", method="POST", body=payload, audit_action="github_create_commit_status")
        item = result["data"]
        return {"ok": True, "status": result["status"], "commit_status": {"id": item.get("id"), "sha": item.get("sha"), "state": item.get("state"), "context": item.get("context"), "description": item.get("description"), "target_url": item.get("target_url"), "created_at": item.get("created_at")}}
    except Exception as error:
        audit("github_create_commit_status", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_repository_artifacts(project: ProjectName, name: str = "", limit: int = 50, page: int = 1) -> dict:
    """List Actions artifacts across a repository."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        data = github_json(project, "/actions/artifacts", query={"name": validate_title(name, "artifact name") if name else "", "per_page": safe_limit, "page": safe_page})
        artifacts = [
            {"id": item.get("id"), "name": item.get("name"), "size_in_bytes": item.get("size_in_bytes"), "expired": item.get("expired"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "expires_at": item.get("expires_at"), "archive_download_url": item.get("archive_download_url"), "workflow_run": item.get("workflow_run")}
            for item in data.get("artifacts", [])[:safe_limit]
        ]
        return {"ok": True, "total_count": data.get("total_count"), "count": len(artifacts), "page": safe_page, "truncated": len(artifacts) == safe_limit, "next_page": safe_page + 1 if len(artifacts) == safe_limit else None, "artifacts": artifacts}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_artifact(project: ProjectName, artifact_id: int) -> dict:
    """Read one Actions artifact and its short-lived archive endpoint metadata."""
    try:
        artifact = require_positive_id(artifact_id, "artifact_id")
        item = github_json(project, f"/actions/artifacts/{artifact}")
        return {"ok": True, "artifact": {"id": item.get("id"), "name": item.get("name"), "size_in_bytes": item.get("size_in_bytes"), "expired": item.get("expired"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "expires_at": item.get("expires_at"), "archive_download_url": item.get("archive_download_url"), "workflow_run": item.get("workflow_run")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_secret_scanning_alerts(project: ProjectName, state: Literal["open", "resolved", "all"] = "open", limit: int = 50, page: int = 1) -> dict:
    """List secret scanning alerts without returning detected secret values."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        query = {"per_page": safe_limit, "page": safe_page, "state": "" if state == "all" else state}
        items = github_json(project, "/secret-scanning/alerts", query=query)
        alerts = [
            {"number": item.get("number"), "state": item.get("state"), "resolution": item.get("resolution"), "secret_type": item.get("secret_type"), "secret_type_display_name": item.get("secret_type_display_name"), "validity": item.get("validity"), "publicly_leaked": item.get("publicly_leaked"), "push_protection_bypassed": item.get("push_protection_bypassed"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "resolved_at": item.get("resolved_at"), "html_url": item.get("html_url")}
            for item in items[:safe_limit]
        ]
        return {"ok": True, "count": len(alerts), "page": safe_page, "truncated": len(alerts) == safe_limit, "next_page": safe_page + 1 if len(alerts) == safe_limit else None, "secrets_redacted": True, "alerts": alerts}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_secret_scanning_alert(project: ProjectName, alert_number: int) -> dict:
    """Read one secret scanning alert without returning the secret value."""
    try:
        number = require_positive_id(alert_number, "alert_number")
        item = github_json(project, f"/secret-scanning/alerts/{number}")
        alert = {"number": item.get("number"), "state": item.get("state"), "resolution": item.get("resolution"), "resolution_comment": item.get("resolution_comment"), "secret_type": item.get("secret_type"), "secret_type_display_name": item.get("secret_type_display_name"), "validity": item.get("validity"), "publicly_leaked": item.get("publicly_leaked"), "push_protection_bypassed": item.get("push_protection_bypassed"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "resolved_at": item.get("resolved_at"), "html_url": item.get("html_url")}
        return {"ok": True, "secrets_redacted": True, "alert": alert}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_secret_scanning_locations(project: ProjectName, alert_number: int, limit: int = 50, page: int = 1) -> dict:
    """List bounded locations for one secret scanning alert."""
    try:
        number = require_positive_id(alert_number, "alert_number")
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, f"/secret-scanning/alerts/{number}/locations", query={"per_page": safe_limit, "page": safe_page})
        locations = [{"type": item.get("type"), "details": item.get("details")} for item in items[:safe_limit]]
        return {"ok": True, "alert_number": number, "count": len(locations), "page": safe_page, "truncated": len(locations) == safe_limit, "next_page": safe_page + 1 if len(locations) == safe_limit else None, "locations": locations}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_secret_scanning_alert(project: ProjectName, alert_number: int, state: Literal["open", "resolved"], resolution: Literal["false_positive", "wont_fix", "revoked", "used_in_tests"] | None = None, resolution_comment: str = "", confirmation: str = "") -> dict:
    """Resolve or reopen a secret scanning alert after exact confirmation."""
    try:
        number = require_positive_id(alert_number, "alert_number")
        if state == "resolved" and resolution is None:
            return {"ok": False, "error": "Resolving a secret alert requires a resolution"}
        if state == "open" and (resolution is not None or resolution_comment):
            return {"ok": False, "error": "Reopening a secret alert forbids resolution fields"}
        required = f"UPDATE SECRET ALERT {number} TO {state}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Secret alert update requires confirmation: {required}"}
        payload: dict[str, Any] = {"state": state}
        if resolution is not None: payload["resolution"] = resolution
        if resolution_comment: payload["resolution_comment"] = validate_body(resolution_comment, 10_000)
        with WRITE_LOCK:
            result = github_write_json(project, f"/secret-scanning/alerts/{number}", method="PATCH", body=payload, audit_action="github_update_secret_scanning_alert")
        item = result["data"]
        return {"ok": True, "status": result["status"], "secrets_redacted": True, "alert": {"number": item.get("number"), "state": item.get("state"), "resolution": item.get("resolution"), "resolved_at": item.get("resolved_at"), "updated_at": item.get("updated_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_update_secret_scanning_alert", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_code_scanning_alerts(project: ProjectName, state: Literal["open", "dismissed", "fixed", "all"] = "open", severity: Literal["critical", "high", "medium", "low", "warning", "note", "error", "all"] = "all", limit: int = 50, page: int = 1) -> dict:
    """List code scanning alerts with bounded security metadata."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        query = {"per_page": safe_limit, "page": safe_page, "state": "" if state == "all" else state, "severity": "" if severity == "all" else severity}
        items = github_json(project, "/code-scanning/alerts", query=query)
        alerts = [
            {"number": item.get("number"), "state": item.get("state"), "dismissed_reason": item.get("dismissed_reason"), "rule": item.get("rule"), "tool": item.get("tool"), "most_recent_instance": item.get("most_recent_instance"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "dismissed_at": item.get("dismissed_at"), "fixed_at": item.get("fixed_at"), "html_url": item.get("html_url")}
            for item in items[:safe_limit]
        ]
        return {"ok": True, "count": len(alerts), "page": safe_page, "truncated": len(alerts) == safe_limit, "next_page": safe_page + 1 if len(alerts) == safe_limit else None, "alerts": alerts}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_code_scanning_alert(project: ProjectName, alert_number: int) -> dict:
    """Read one code scanning alert."""
    try:
        number = require_positive_id(alert_number, "alert_number")
        item = github_json(project, f"/code-scanning/alerts/{number}")
        return {"ok": True, "alert": {"number": item.get("number"), "state": item.get("state"), "dismissed_reason": item.get("dismissed_reason"), "dismissed_comment": item.get("dismissed_comment"), "rule": item.get("rule"), "tool": item.get("tool"), "most_recent_instance": item.get("most_recent_instance"), "instances_url": item.get("instances_url"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "dismissed_at": item.get("dismissed_at"), "fixed_at": item.get("fixed_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_code_scanning_alert(project: ProjectName, alert_number: int, state: Literal["open", "dismissed"], dismissed_reason: Literal["false positive", "won't fix", "used in tests"] | None = None, dismissed_comment: str = "", confirmation: str = "") -> dict:
    """Dismiss or reopen a code scanning alert after exact confirmation."""
    try:
        number = require_positive_id(alert_number, "alert_number")
        if state == "dismissed" and dismissed_reason is None:
            return {"ok": False, "error": "Dismissing a code scanning alert requires dismissed_reason"}
        if state == "open" and (dismissed_reason is not None or dismissed_comment):
            return {"ok": False, "error": "Reopening a code scanning alert forbids dismissal fields"}
        required = f"UPDATE CODE ALERT {number} TO {state}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Code alert update requires confirmation: {required}"}
        payload: dict[str, Any] = {"state": state}
        if dismissed_reason is not None: payload["dismissed_reason"] = dismissed_reason
        if dismissed_comment: payload["dismissed_comment"] = validate_body(dismissed_comment, 10_000)
        with WRITE_LOCK:
            result = github_write_json(project, f"/code-scanning/alerts/{number}", method="PATCH", body=payload, audit_action="github_update_code_scanning_alert")
        item = result["data"]
        return {"ok": True, "status": result["status"], "alert": {"number": item.get("number"), "state": item.get("state"), "dismissed_reason": item.get("dismissed_reason"), "dismissed_at": item.get("dismissed_at"), "updated_at": item.get("updated_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_update_code_scanning_alert", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_dependabot_alerts(project: ProjectName, state: Literal["open", "dismissed", "fixed", "auto_dismissed", "all"] = "open", severity: Literal["low", "medium", "high", "critical", "all"] = "all", limit: int = 50, page: int = 1) -> dict:
    """List repository Dependabot alerts."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        query = {"per_page": safe_limit, "page": safe_page, "state": "" if state == "all" else state, "severity": "" if severity == "all" else severity}
        items = github_json(project, "/dependabot/alerts", query=query)
        alerts = [
            {"number": item.get("number"), "state": item.get("state"), "dependency": item.get("dependency"), "security_advisory": item.get("security_advisory"), "security_vulnerability": item.get("security_vulnerability"), "dismissed_reason": item.get("dismissed_reason"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "fixed_at": item.get("fixed_at"), "html_url": item.get("html_url")}
            for item in items[:safe_limit]
        ]
        return {"ok": True, "count": len(alerts), "page": safe_page, "truncated": len(alerts) == safe_limit, "next_page": safe_page + 1 if len(alerts) == safe_limit else None, "alerts": alerts}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_dependabot_alert(project: ProjectName, alert_number: int) -> dict:
    """Read one Dependabot alert."""
    try:
        number = require_positive_id(alert_number, "alert_number")
        item = github_json(project, f"/dependabot/alerts/{number}")
        return {"ok": True, "alert": {"number": item.get("number"), "state": item.get("state"), "dependency": item.get("dependency"), "security_advisory": item.get("security_advisory"), "security_vulnerability": item.get("security_vulnerability"), "dismissed_reason": item.get("dismissed_reason"), "dismissed_comment": item.get("dismissed_comment"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "fixed_at": item.get("fixed_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_code_quality_findings(project: ProjectName, ref: str = "", limit: int = 50, page: int = 1) -> dict:
    """List repository code quality findings."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        data = github_json(project, "/code-quality/findings", query={"ref": validate_ref(ref, "quality ref") if ref else "", "per_page": safe_limit, "page": safe_page})
        items = data.get("findings", data if isinstance(data, list) else [])
        findings = [{"id": item.get("id"), "rule_id": item.get("rule_id"), "severity": item.get("severity"), "message": item.get("message"), "path": item.get("path"), "start_line": item.get("start_line"), "end_line": item.get("end_line"), "state": item.get("state"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(findings), "page": safe_page, "truncated": len(findings) == safe_limit, "next_page": safe_page + 1 if len(findings) == safe_limit else None, "findings": findings}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_secret_scanning_bypass_requests(project: ProjectName, status: Literal["pending", "approved", "denied", "cancelled", "completed", "expired", "all"] = "pending", limit: int = 50, page: int = 1) -> dict:
    """List delegated push-protection bypass requests."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        data = github_json(project, "/bypass-requests/secret-scanning", query={"status": "" if status == "all" else status, "per_page": safe_limit, "page": safe_page})
        items = data.get("bypass_requests", data if isinstance(data, list) else [])
        requests = [{"number": item.get("number"), "status": item.get("status"), "reason": item.get("reason"), "requester": compact_user(item.get("requester")), "reviewer": compact_user(item.get("reviewer")), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "expires_at": item.get("expires_at"), "html_url": item.get("html_url")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(requests), "page": safe_page, "truncated": len(requests) == safe_limit, "next_page": safe_page + 1 if len(requests) == safe_limit else None, "bypass_requests": requests}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_secret_scanning_bypass_request(project: ProjectName, request_number: int) -> dict:
    """Read one delegated push-protection bypass request."""
    try:
        number = require_positive_id(request_number, "request_number")
        item = github_json(project, f"/bypass-requests/secret-scanning/{number}")
        return {"ok": True, "bypass_request": {"number": item.get("number"), "status": item.get("status"), "reason": item.get("reason"), "requester": compact_user(item.get("requester")), "reviewer": compact_user(item.get("reviewer")), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "expires_at": item.get("expires_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_repository_security_advisories(project: ProjectName, state: Literal["triage", "draft", "published", "closed", "all"] = "all", limit: int = 50) -> dict:
    """List repository security advisories, including authorized private drafts."""
    try:
        safe_limit = max(1, min(limit, 100))
        items = github_json(project, "/security-advisories", query={"state": "" if state == "all" else state, "per_page": safe_limit})
        advisories = [
            {"ghsa_id": item.get("ghsa_id"), "cve_id": item.get("cve_id"), "summary": item.get("summary"), "severity": item.get("severity"), "state": item.get("state"), "identifiers": item.get("identifiers"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "published_at": item.get("published_at"), "closed_at": item.get("closed_at"), "html_url": item.get("html_url")}
            for item in items[:safe_limit]
        ]
        return {"ok": True, "count": len(advisories), "truncated": len(advisories) == safe_limit, "advisories": advisories}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_repository_security_advisory(project: ProjectName, ghsa_id: str) -> dict:
    """Read one repository security advisory by GHSA identifier."""
    try:
        ghsa = ghsa_id.strip().upper()
        if not re.fullmatch(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", ghsa):
            return {"ok": False, "error": "Invalid GHSA identifier"}
        item = github_json(project, f"/security-advisories/{ghsa}")
        return {"ok": True, "advisory": {"ghsa_id": item.get("ghsa_id"), "cve_id": item.get("cve_id"), "summary": item.get("summary"), "description": item.get("description"), "severity": item.get("severity"), "state": item.get("state"), "identifiers": item.get("identifiers"), "cwe_ids": item.get("cwe_ids"), "vulnerabilities": item.get("vulnerabilities"), "collaborating_users": item.get("collaborating_users"), "collaborating_teams": item.get("collaborating_teams"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "published_at": item.get("published_at"), "closed_at": item.get("closed_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_repository_security_advisory(project: ProjectName, summary: str, description: str, severity: Literal["low", "medium", "high", "critical"], ecosystem: Literal["rubygems", "npm", "pip", "maven", "nuget", "composer", "go", "rust", "erlang", "actions", "pub", "other", "swift"], package_name: str, vulnerable_version_range: str, patched_versions: str = "", cwe_ids: list[str] = [], confirmation: str = "") -> dict:
    """Create a draft repository security advisory after exact confirmation."""
    try:
        clean_summary = validate_title(summary, "advisory summary")
        clean_description = validate_body(description, 60_000)
        if ecosystem not in {"rubygems", "npm", "pip", "maven", "nuget", "composer", "go", "rust", "erlang", "actions", "pub", "other", "swift"}:
            return {"ok": False, "error": "Unsupported package ecosystem"}
        clean_package = validate_title(package_name, "package name")
        clean_range = validate_body(vulnerable_version_range, 256)
        if not clean_range:
            return {"ok": False, "error": "vulnerable_version_range is required"}
        clean_cwes = [item.strip().upper() for item in cwe_ids[:20]]
        if len(cwe_ids) > 20 or any(not re.fullmatch(r"CWE-[1-9][0-9]{0,5}", item) for item in clean_cwes):
            return {"ok": False, "error": "Invalid CWE identifiers"}
        required = f"CREATE SECURITY ADVISORY {clean_summary}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Security advisory creation requires confirmation: {required}"}
        vulnerability = {"package": {"ecosystem": ecosystem, "name": clean_package}, "vulnerable_version_range": clean_range, "patched_versions": validate_body(patched_versions, 256) or None}
        payload: dict[str, Any] = {"summary": clean_summary, "description": clean_description, "severity": severity, "vulnerabilities": [vulnerability]}
        if clean_cwes: payload["cwe_ids"] = clean_cwes
        with WRITE_LOCK:
            result = github_write_json(project, "/security-advisories", method="POST", body=payload, audit_action="github_create_repository_security_advisory")
        item = result["data"]
        return {"ok": True, "status": result["status"], "advisory": {"ghsa_id": item.get("ghsa_id"), "summary": item.get("summary"), "severity": item.get("severity"), "state": item.get("state"), "created_at": item.get("created_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_create_repository_security_advisory", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_repository_security_advisory(project: ProjectName, ghsa_id: str, summary: str | None = None, description: str | None = None, severity: Literal["low", "medium", "high", "critical"] | None = None, state: Literal["draft", "published", "closed"] | None = None, confirmation: str = "") -> dict:
    """Update or publish a repository security advisory after exact confirmation."""
    try:
        ghsa = ghsa_id.strip().upper()
        if not re.fullmatch(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", ghsa):
            return {"ok": False, "error": "Invalid GHSA identifier"}
        payload: dict[str, Any] = {}
        if summary is not None: payload["summary"] = validate_title(summary, "advisory summary")
        if description is not None: payload["description"] = validate_body(description, 60_000)
        if severity is not None: payload["severity"] = severity
        if state is not None: payload["state"] = state
        if not payload:
            return {"ok": False, "error": "No advisory updates were supplied"}
        required = f"UPDATE SECURITY ADVISORY {ghsa}"
        if state == "published": required = f"PUBLISH SECURITY ADVISORY {ghsa}"
        if confirmation.strip() != required:
            return {"ok": False, "error": f"Security advisory update requires confirmation: {required}"}
        with WRITE_LOCK:
            result = github_write_json(project, f"/security-advisories/{ghsa}", method="PATCH", body=payload, audit_action="github_update_repository_security_advisory")
        item = result["data"]
        return {"ok": True, "status": result["status"], "advisory": {"ghsa_id": item.get("ghsa_id"), "summary": item.get("summary"), "severity": item.get("severity"), "state": item.get("state"), "updated_at": item.get("updated_at"), "published_at": item.get("published_at"), "closed_at": item.get("closed_at"), "html_url": item.get("html_url")}}
    except Exception as error:
        audit("github_update_repository_security_advisory", project, False, str(error))
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_sbom(project: ProjectName, limit: int = 200) -> dict:
    """Export a bounded SPDX SBOM summary from the dependency graph."""
    try:
        data = github_json(project, "/dependency-graph/sbom")
        sbom = data.get("sbom", data); packages = sbom.get("packages", [])[:max(1, min(limit, 1000))]
        compact = [{"SPDXID": item.get("SPDXID"), "name": item.get("name"), "versionInfo": item.get("versionInfo"), "licenseDeclared": item.get("licenseDeclared"), "licenseConcluded": item.get("licenseConcluded"), "externalRefs": item.get("externalRefs")} for item in packages]
        return {"ok": True, "name": sbom.get("name"), "documentNamespace": sbom.get("documentNamespace"), "count": len(compact), "truncated": len(sbom.get("packages", [])) > len(compact), "packages": compact}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_attestations(project: ProjectName, subject_digest: str, predicate_type: str = "", limit: int = 50) -> dict:
    """List repository attestations for a SHA-256 subject digest."""
    try:
        digest = validate_digest(subject_digest); safe_limit = max(1, min(limit, 100))
        data = github_json(project, "/attestations/" + quote_path_value(digest), query={"predicate_type": predicate_type.strip(), "per_page": safe_limit})
        items = data.get("attestations", [])[:safe_limit]
        attestations = [{"repository_id": item.get("repository_id"), "bundle_url": item.get("bundle_url"), "initiator": item.get("initiator")} for item in items]
        return {"ok": True, "subject_digest": digest, "count": len(attestations), "truncated": len(items) == safe_limit, "attestations": attestations}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_packages(project: ProjectName, package_type: Literal["npm", "maven", "rubygems", "docker", "nuget", "container"] = "container", visibility: Literal["public", "private", "internal", "all"] = "all", limit: int = 50, page: int = 1) -> dict:
    """List packages owned by the registered repository owner."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        owner_type = (github_json(project, "").get("owner") or {}).get("type"); account_json = github_org_json if owner_type == "Organization" else github_user_json
        items = account_json(project, "/packages", {"package_type": package_type, "visibility": "" if visibility == "all" else visibility, "per_page": safe_limit, "page": safe_page})
        packages = [{"id": item.get("id"), "name": item.get("name"), "package_type": item.get("package_type"), "visibility": item.get("visibility"), "version_count": item.get("version_count"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "html_url": item.get("html_url")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(packages), "page": safe_page, "truncated": len(packages) == safe_limit, "packages": packages}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_package_versions(project: ProjectName, package_type: Literal["npm", "maven", "rubygems", "docker", "nuget", "container"], package_name: str, state: Literal["active", "deleted"] = "active", limit: int = 50, page: int = 1) -> dict:
    """List versions for a package owned by the repository owner."""
    try:
        name = quote_path_value(validate_title(package_name, "package name")); safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        owner_type = (github_json(project, "").get("owner") or {}).get("type"); account_json = github_org_json if owner_type == "Organization" else github_user_json
        items = account_json(project, f"/packages/{package_type}/{name}/versions", {"state": state, "per_page": safe_limit, "page": safe_page})
        versions = [{"id": item.get("id"), "name": item.get("name"), "url": item.get("url"), "package_html_url": item.get("package_html_url"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "metadata": item.get("metadata")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(versions), "page": safe_page, "truncated": len(versions) == safe_limit, "versions": versions}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_attestation(project: ProjectName, bundle: dict[str, Any], confirmation: str = "") -> dict:
    """Store a Sigstore attestation bundle after exact confirmation."""
    try:
        encoded = json.dumps(bundle, separators=(",", ":"))
        if len(encoded) > 2_000_000 or not isinstance(bundle.get("mediaType"), str) or not isinstance(bundle.get("verificationMaterial"), dict) or not isinstance(bundle.get("dsseEnvelope"), dict):
            return {"ok": False, "error": "Invalid or oversized Sigstore bundle"}
        if redact_github_text(encoded) != encoded: return {"ok": False, "error": "Sensitive attestation bundle blocked"}
        if confirmation.strip() != "CREATE ATTESTATION": return {"ok": False, "error": "Attestation creation requires confirmation: CREATE ATTESTATION"}
        with WRITE_LOCK: result = github_write_json(project, "/attestations", method="POST", body={"bundle": bundle}, audit_action="github_create_attestation")
        return {"ok": True, "status": result["status"], "attestation": result["data"]}
    except Exception as error:
        audit("github_create_attestation", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_submit_dependency_snapshot(project: ProjectName, snapshot: dict[str, Any], confirmation: str = "") -> dict:
    """Submit a dependency graph snapshot after exact confirmation."""
    try:
        encoded = json.dumps(snapshot, separators=(",", ":")); required = {"version", "job", "sha", "ref", "detector", "manifests"}
        if len(encoded) > 5_000_000 or not required.issubset(snapshot) or redact_github_text(encoded) != encoded:
            return {"ok": False, "error": "Invalid, sensitive, or oversized dependency snapshot"}
        if confirmation.strip() != "SUBMIT DEPENDENCY SNAPSHOT": return {"ok": False, "error": "Dependency submission requires confirmation: SUBMIT DEPENDENCY SNAPSHOT"}
        with WRITE_LOCK: result = github_write_json(project, "/dependency-graph/snapshots", method="POST", body=snapshot, audit_action="github_submit_dependency_snapshot")
        return {"ok": True, "status": result["status"], "snapshot": result["data"]}
    except Exception as error:
        audit("github_submit_dependency_snapshot", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_artifact_metadata(project: ProjectName, subject_digest: str) -> dict:
    """List organization storage and deployment records for an artifact digest."""
    try:
        digest = validate_digest(subject_digest); path = "/artifacts/" + quote_path_value(digest) + "/metadata/"
        storage = github_org_json(project, path + "storage-records")
        deployments = github_org_json(project, path + "deployment-records")
        return {"ok": True, "subject_digest": digest, "storage_records": storage.get("storage_records", []), "deployment_records": deployments.get("deployment_records", [])}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_artifact_storage_record(project: ProjectName, name: str, subject_digest: str, registry_url: str, artifact_url: str = "", version: str = "", repository: str = "", status: Literal["active", "eol", "deleted"] = "active", confirmation: str = "") -> dict:
    """Create an organization artifact storage record after exact confirmation."""
    try:
        digest = validate_digest(subject_digest); clean_name = validate_title(name, "artifact name")
        required = f"STORE ARTIFACT {clean_name}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Storage record requires confirmation: {required}"}
        payload = {"name": clean_name, "digest": digest, "registry_url": validate_external_url(registry_url, "registry_url"), "status": status, "github_repository": github_repo(project), "return_records": True}
        if artifact_url: payload["artifact_url"] = validate_external_url(artifact_url, "artifact_url")
        if version: payload["version"] = validate_title(version, "version")
        if repository: payload["repository"] = validate_title(repository, "registry repository")
        with WRITE_LOCK: result = github_org_write_json(project, "/artifacts/metadata/storage-record", body=payload, audit_action="github_create_artifact_storage_record")
        return {"ok": True, "status": result["status"], "records": result["data"]}
    except Exception as error:
        audit("github_create_artifact_storage_record", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_artifact_deployment_record(project: ProjectName, name: str, subject_digest: str, logical_environment: str, deployment_name: str, status: Literal["deployed", "decommissioned"] = "deployed", physical_environment: str = "", cluster: str = "", version: str = "", runtime_risks: list[Literal["critical-resource", "internet-exposed", "lateral-movement", "sensitive-data"]] = [], confirmation: str = "") -> dict:
    """Create or update an artifact deployment record after exact confirmation."""
    try:
        digest = validate_digest(subject_digest); clean_name = validate_title(name, "artifact name")
        required = f"DEPLOY ARTIFACT {clean_name} TO {logical_environment.strip()}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Deployment record requires confirmation: {required}"}
        payload = {"name": clean_name, "digest": digest, "status": status, "logical_environment": validate_title(logical_environment, "logical environment"), "deployment_name": validate_title(deployment_name, "deployment name"), "runtime_risks": list(dict.fromkeys(runtime_risks)), "github_repository": github_repo(project), "return_records": True}
        if physical_environment: payload["physical_environment"] = validate_title(physical_environment, "physical environment")
        if cluster: payload["cluster"] = validate_title(cluster, "cluster")
        if version: payload["version"] = validate_title(version, "version")
        with WRITE_LOCK: result = github_org_write_json(project, "/artifacts/metadata/deployment-record", body=payload, audit_action="github_create_artifact_deployment_record")
        return {"ok": True, "status": result["status"], "records": result["data"]}
    except Exception as error:
        audit("github_create_artifact_deployment_record", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_labels(project: ProjectName, limit: int = 50, page: int = 1) -> dict:
    """List repository labels."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, "/labels", query={"per_page": safe_limit, "page": safe_page})
        labels = [{"name": item.get("name"), "color": item.get("color"), "description": item.get("description"), "default": item.get("default")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(labels), "page": safe_page, "truncated": len(labels) == safe_limit, "labels": labels}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_upsert_label(project: ProjectName, name: str, color: str, description: str = "", new_name: str = "", confirmation: str = "") -> dict:
    """Create or update a label after exact confirmation."""
    try:
        clean_name = validate_title(name, "label name"); clean_color = color.strip().lstrip("#").lower()
        if not re.fullmatch(r"[0-9a-f]{6}", clean_color): return {"ok": False, "error": "Label color must be six hexadecimal characters"}
        required = f"UPSERT LABEL {clean_name}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Label change requires confirmation: {required}"}
        path = "/labels/" + quote_path_value(clean_name); payload = {"new_name": validate_title(new_name, "new label name") if new_name else clean_name, "color": clean_color, "description": validate_body(description, 100, "description")}
        try: github_json(project, path); method = "PATCH"
        except Exception: path = "/labels"; method = "POST"; payload["name"] = payload.pop("new_name")
        with WRITE_LOCK: result = github_write_json(project, path, method=method, body=payload, audit_action="github_upsert_label")
        return {"ok": True, "status": result["status"], "label": result["data"]}
    except Exception as error:
        audit("github_upsert_label", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_milestones(project: ProjectName, state: Literal["open", "closed", "all"] = "open", limit: int = 50, page: int = 1) -> dict:
    """List repository milestones."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, "/milestones", query={"state": state, "per_page": safe_limit, "page": safe_page})
        milestones = [{"number": item.get("number"), "title": item.get("title"), "state": item.get("state"), "description": item.get("description"), "due_on": item.get("due_on"), "open_issues": item.get("open_issues"), "closed_issues": item.get("closed_issues")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(milestones), "page": safe_page, "truncated": len(milestones) == safe_limit, "milestones": milestones}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_upsert_milestone(project: ProjectName, title: str, milestone_number: int = 0, state: Literal["open", "closed"] = "open", description: str = "", due_on: str = "", confirmation: str = "") -> dict:
    """Create or update a milestone after exact confirmation."""
    try:
        clean_title = validate_title(title, "milestone title"); required = f"UPSERT MILESTONE {clean_title}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Milestone change requires confirmation: {required}"}
        payload = {"title": clean_title, "state": state, "description": validate_body(description, 1000, "description")}
        if due_on:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", due_on): return {"ok": False, "error": "due_on must be an ISO UTC timestamp"}
            payload["due_on"] = due_on
        path = "/milestones" if milestone_number <= 0 else f"/milestones/{require_positive_id(milestone_number, 'milestone number')}"; method = "POST" if milestone_number <= 0 else "PATCH"
        with WRITE_LOCK: result = github_write_json(project, path, method=method, body=payload, audit_action="github_upsert_milestone")
        return {"ok": True, "status": result["status"], "milestone": result["data"]}
    except Exception as error:
        audit("github_upsert_milestone", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_requested_reviewers(project: ProjectName, pull_number: int) -> dict:
    """List users and teams currently requested to review a pull request."""
    try:
        number = require_positive_id(pull_number, "pull number"); data = github_json(project, f"/pulls/{number}/requested_reviewers")
        users = [compact_user(item) for item in data.get("users", [])]
        teams = [{"id": item.get("id"), "name": item.get("name"), "slug": item.get("slug")} for item in data.get("teams", [])]
        return {"ok": True, "pull_number": number, "users": users, "teams": teams}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_request_pull_request_reviewers(project: ProjectName, pull_number: int, reviewers: list[str] = [], team_reviewers: list[str] = [], confirmation: str = "") -> dict:
    """Request pull request reviewers after exact confirmation."""
    try:
        number = require_positive_id(pull_number, "pull number")
        clean_users = list(dict.fromkeys(validate_title(item, "reviewer") for item in reviewers))[:15]
        clean_teams = list(dict.fromkeys(validate_title(item, "team reviewer") for item in team_reviewers))[:15]
        if not clean_users and not clean_teams: return {"ok": False, "error": "At least one reviewer or team is required"}
        required = f"REQUEST REVIEWERS PR #{number}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Review request requires confirmation: {required}"}
        with WRITE_LOCK: result = github_write_json(project, f"/pulls/{number}/requested_reviewers", method="POST", body={"reviewers": clean_users, "team_reviewers": clean_teams}, audit_action="github_request_pull_request_reviewers")
        return {"ok": True, "status": result["status"], "review_request": result["data"]}
    except Exception as error:
        audit("github_request_pull_request_reviewers", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_add_issue_assignees(project: ProjectName, issue_number: int, assignees: list[str], confirmation: str = "") -> dict:
    """Add issue or pull request assignees after exact confirmation."""
    try:
        number = require_positive_id(issue_number, "issue number"); clean = list(dict.fromkeys(validate_title(item, "assignee") for item in assignees))[:10]
        if not clean: return {"ok": False, "error": "At least one assignee is required"}
        required = f"ASSIGN ISSUE #{number}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Assignment requires confirmation: {required}"}
        with WRITE_LOCK: result = github_write_json(project, f"/issues/{number}/assignees", method="POST", body={"assignees": clean}, audit_action="github_add_issue_assignees")
        return {"ok": True, "status": result["status"], "issue": compact_issue(result["data"])}
    except Exception as error:
        audit("github_add_issue_assignees", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_discussions(project: ProjectName, limit: int = 20) -> dict:
    """List discussion categories and recent repository discussions."""
    try:
        owner, repo = github_repo(project).split("/", 1); safe_limit = max(1, min(limit, 50))
        query = "query($owner:String!,$repo:String!,$limit:Int!){repository(owner:$owner,name:$repo){discussionCategories(first:100){nodes{id name slug}} discussions(first:$limit,orderBy:{field:UPDATED_AT,direction:DESC}){nodes{id number title url createdAt updatedAt author{login} category{id name} answerChosenAt comments{totalCount}}}}}"
        data = github_graphql(project, query, {"owner": owner, "repo": repo, "limit": safe_limit})
        repository = data.get("repository") or {}; nodes = repository.get("discussions", {}).get("nodes", [])
        discussions = [{"id": item.get("id"), "number": item.get("number"), "title": item.get("title"), "url": item.get("url"), "author": (item.get("author") or {}).get("login"), "category": item.get("category"), "comments": (item.get("comments") or {}).get("totalCount"), "answer_chosen_at": item.get("answerChosenAt"), "updated_at": item.get("updatedAt")} for item in nodes]
        return {"ok": True, "count": len(discussions), "categories": repository.get("discussionCategories", {}).get("nodes", []), "discussions": discussions}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_discussion(project: ProjectName, discussion_number: int, comment_limit: int = 50) -> dict:
    """Read one repository discussion and bounded comments."""
    try:
        owner, repo = github_repo(project).split("/", 1); number = require_positive_id(discussion_number, "discussion number"); safe_limit = max(1, min(comment_limit, 100))
        query = "query($owner:String!,$repo:String!,$number:Int!,$limit:Int!){repository(owner:$owner,name:$repo){discussion(number:$number){id number title body url createdAt updatedAt author{login} category{id name} answerChosenAt comments(first:$limit){nodes{id body createdAt updatedAt author{login} isAnswer}}}}}"
        data = github_graphql(project, query, {"owner": owner, "repo": repo, "number": number, "limit": safe_limit}); item = (data.get("repository") or {}).get("discussion")
        if not item: return {"ok": False, "error": "Discussion not found"}
        comments = item.pop("comments", {}).get("nodes", [])
        return {"ok": True, "discussion": item, "comments": comments, "comment_count": len(comments)}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_create_discussion(project: ProjectName, category_id: str, title: str, body: str, confirmation: str = "") -> dict:
    """Create a repository discussion after exact confirmation."""
    try:
        clean_title = validate_title(title, "discussion title"); clean_body = validate_body(body, 60000, "discussion body")
        required = f"CREATE DISCUSSION {clean_title}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Discussion creation requires confirmation: {required}"}
        owner, repo = github_repo(project).split("/", 1)
        repository_query = "query($owner:String!,$repo:String!){repository(owner:$owner,name:$repo){id}}"; repository_id = github_graphql(project, repository_query, {"owner": owner, "repo": repo})["repository"]["id"]
        query = "mutation($repository:ID!,$category:ID!,$title:String!,$body:String!){createDiscussion(input:{repositoryId:$repository,categoryId:$category,title:$title,body:$body}){discussion{id number title url}}}"
        with WRITE_LOCK: data = github_graphql(project, query, {"repository": repository_id, "category": validate_title(category_id, "category id"), "title": clean_title, "body": clean_body}, "github_create_discussion")
        return {"ok": True, "discussion": data["createDiscussion"]["discussion"]}
    except Exception as error:
        audit("github_create_discussion", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_comment_discussion(project: ProjectName, discussion_id: str, body: str, reply_to_id: str = "", confirmation: str = "") -> dict:
    """Add a discussion comment or reply after exact confirmation."""
    try:
        clean_body = validate_body(body, 60000, "comment body"); clean_id = validate_title(discussion_id, "discussion id")
        required = f"COMMENT DISCUSSION {clean_id}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Discussion comment requires confirmation: {required}"}
        query = "mutation($discussion:ID!,$body:String!,$reply:ID){addDiscussionComment(input:{discussionId:$discussion,body:$body,replyToId:$reply}){comment{id body url createdAt}}}"
        with WRITE_LOCK: data = github_graphql(project, query, {"discussion": clean_id, "body": clean_body, "reply": validate_title(reply_to_id, "reply id") if reply_to_id else None}, "github_comment_discussion")
        return {"ok": True, "comment": data["addDiscussionComment"]["comment"]}
    except Exception as error:
        audit("github_comment_discussion", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_pull_request_queue_state(project: ProjectName, pull_number: int) -> dict:
    """Read a pull request's merge queue state."""
    try:
        owner, repo = github_repo(project).split("/", 1); number = require_positive_id(pull_number, "pull number")
        query = "query($owner:String!,$repo:String!,$number:Int!){repository(owner:$owner,name:$repo){pullRequest(number:$number){id number url mergeQueueEntry{id position state estimatedTimeToMerge}}}}"
        data = github_graphql(project, query, {"owner": owner, "repo": repo, "number": number}); item = (data.get("repository") or {}).get("pullRequest")
        if not item: return {"ok": False, "error": "Pull request not found"}
        return {"ok": True, "pull_request": item, "queued": item.get("mergeQueueEntry") is not None}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_set_pull_request_queue_state(project: ProjectName, pull_number: int, action: Literal["enqueue", "dequeue"], confirmation: str = "") -> dict:
    """Add or remove a pull request from the merge queue after exact confirmation."""
    try:
        owner, repo = github_repo(project).split("/", 1); number = require_positive_id(pull_number, "pull number")
        required = f"{action.upper()} PR #{number}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Merge queue change requires confirmation: {required}"}
        query = "query($owner:String!,$repo:String!,$number:Int!){repository(owner:$owner,name:$repo){pullRequest(number:$number){id mergeQueueEntry{id}}}}"; pull = github_graphql(project, query, {"owner": owner, "repo": repo, "number": number})["repository"]["pullRequest"]
        if not pull: return {"ok": False, "error": "Pull request not found"}
        if action == "enqueue": mutation = "mutation($id:ID!){enqueuePullRequest(input:{pullRequestId:$id}){mergeQueueEntry{id position state estimatedTimeToMerge}}}"; variables = {"id": pull["id"]}; key = "enqueuePullRequest"
        else: mutation = "mutation($id:ID!){dequeuePullRequest(input:{id:$id}){mergeQueueEntry{id position state}}}"; variables = {"id": pull["id"]}; key = "dequeuePullRequest"
        with WRITE_LOCK: data = github_graphql(project, mutation, variables, "github_set_pull_request_queue_state")
        return {"ok": True, "action": action, "merge_queue_entry": data[key].get("mergeQueueEntry")}
    except Exception as error:
        audit("github_set_pull_request_queue_state", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_discussion(project: ProjectName, discussion_id: str, title: str | None = None, body: str | None = None, category_id: str | None = None, confirmation: str = "") -> dict:
    """Update a discussion after exact confirmation."""
    try:
        clean_id = validate_title(discussion_id, "discussion id")
        if title is None and body is None and category_id is None: return {"ok": False, "error": "At least one discussion change is required"}
        required = f"UPDATE DISCUSSION {clean_id}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Discussion update requires confirmation: {required}"}
        variables = {"id": clean_id, "title": validate_title(title, "discussion title") if title is not None else None, "body": validate_body(body, 60000, "discussion body") if body is not None else None, "category": validate_title(category_id, "category id") if category_id is not None else None}
        query = "mutation($id:ID!,$title:String,$body:String,$category:ID){updateDiscussion(input:{discussionId:$id,title:$title,body:$body,categoryId:$category}){discussion{id number title body url category{id name} updatedAt}}}"
        with WRITE_LOCK: data = github_graphql(project, query, variables, "github_update_discussion")
        return {"ok": True, "discussion": data["updateDiscussion"]["discussion"]}
    except Exception as error:
        audit("github_update_discussion", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_repository_settings(project: ProjectName) -> dict:
    """Read bounded repository administration settings."""
    try:
        repo = github_json(project, "")
        fields = ("id", "name", "full_name", "description", "homepage", "visibility", "private", "archived", "default_branch", "has_issues", "has_projects", "has_wiki", "has_discussions", "allow_squash_merge", "allow_merge_commit", "allow_rebase_merge", "allow_auto_merge", "delete_branch_on_merge", "web_commit_signoff_required")
        return {"ok": True, "settings": {key: repo.get(key) for key in fields}}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_repository_settings(project: ProjectName, description: str | None = None, homepage: str | None = None, has_issues: bool | None = None, has_projects: bool | None = None, has_wiki: bool | None = None, has_discussions: bool | None = None, allow_squash_merge: bool | None = None, allow_merge_commit: bool | None = None, allow_rebase_merge: bool | None = None, allow_auto_merge: bool | None = None, delete_branch_on_merge: bool | None = None, web_commit_signoff_required: bool | None = None, confirmation: str = "") -> dict:
    """Update non-destructive repository settings after exact confirmation."""
    try:
        payload: dict[str, Any] = {}
        if description is not None: payload["description"] = validate_body(description, 350, "description")
        if homepage is not None: payload["homepage"] = validate_external_url(homepage) if homepage else ""
        toggles = {"has_issues": has_issues, "has_projects": has_projects, "has_wiki": has_wiki, "has_discussions": has_discussions, "allow_squash_merge": allow_squash_merge, "allow_merge_commit": allow_merge_commit, "allow_rebase_merge": allow_rebase_merge, "allow_auto_merge": allow_auto_merge, "delete_branch_on_merge": delete_branch_on_merge, "web_commit_signoff_required": web_commit_signoff_required}
        for key, value in toggles.items():
            if value is not None: payload[key] = bool(value)
        if not payload: return {"ok": False, "error": "At least one repository setting is required"}
        required = "UPDATE REPOSITORY SETTINGS"
        if confirmation.strip() != required: return {"ok": False, "error": f"Repository settings update requires confirmation: {required}"}
        with WRITE_LOCK: result = github_write_json(project, "", method="PATCH", body=payload, audit_action="github_update_repository_settings")
        return {"ok": True, "status": result["status"], "updated": sorted(payload), "settings": result["data"]}
    except Exception as error:
        audit("github_update_repository_settings", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_collaborators(project: ProjectName, affiliation: Literal["outside", "direct", "all"] = "all", permission: Literal["pull", "triage", "push", "maintain", "admin", "all"] = "all", limit: int = 50, page: int = 1) -> dict:
    """List direct and outside repository collaborators."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, "/collaborators", query={"affiliation": affiliation, "permission": "" if permission == "all" else permission, "per_page": safe_limit, "page": safe_page})
        collaborators = [{"login": item.get("login"), "id": item.get("id"), "type": item.get("type"), "role_name": item.get("role_name"), "permissions": item.get("permissions"), "html_url": item.get("html_url")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(collaborators), "page": safe_page, "truncated": len(collaborators) == safe_limit, "collaborators": collaborators}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_upsert_collaborator(project: ProjectName, username: str, permission: Literal["pull", "triage", "push", "maintain", "admin"] = "pull", confirmation: str = "") -> dict:
    """Invite or update a collaborator after exact confirmation."""
    try:
        clean = validate_title(username, "username")
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", clean): return {"ok": False, "error": "Invalid GitHub username"}
        required = f"GRANT {permission} TO {clean}"
        if confirmation.strip() != required: return {"ok": False, "error": f"Collaborator change requires confirmation: {required}"}
        with WRITE_LOCK: result = github_write_json(project, f"/collaborators/{quote_path_value(clean)}", method="PUT", body={"permission": permission}, audit_action="github_upsert_collaborator")
        invitation = result["data"] if isinstance(result["data"], dict) else {}
        return {"ok": True, "status": result["status"], "username": clean, "permission": permission, "invitation": {"id": invitation.get("id"), "html_url": invitation.get("html_url")}}
    except Exception as error:
        audit("github_upsert_collaborator", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_repository_invitations(project: ProjectName, limit: int = 50, page: int = 1) -> dict:
    """List pending repository invitations."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, "/invitations", query={"per_page": safe_limit, "page": safe_page})
        invitations = [{"id": item.get("id"), "invitee": compact_user(item.get("invitee")), "inviter": compact_user(item.get("inviter")), "permissions": item.get("permissions"), "created_at": item.get("created_at"), "expired": item.get("expired"), "html_url": item.get("html_url")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(invitations), "page": safe_page, "truncated": len(invitations) == safe_limit, "invitations": invitations}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_list_rulesets(project: ProjectName, include_parents: bool = True, limit: int = 50, page: int = 1) -> dict:
    """List repository rulesets, optionally including inherited rulesets."""
    try:
        safe_limit = max(1, min(limit, 100)); safe_page = max(1, min(page, 1000))
        items = github_json(project, "/rulesets", query={"includes_parents": str(bool(include_parents)).lower(), "per_page": safe_limit, "page": safe_page})
        rulesets = [{"id": item.get("id"), "name": item.get("name"), "target": item.get("target"), "source_type": item.get("source_type"), "source": item.get("source"), "enforcement": item.get("enforcement"), "node_id": item.get("node_id"), "links": item.get("_links")} for item in items[:safe_limit]]
        return {"ok": True, "count": len(rulesets), "page": safe_page, "truncated": len(rulesets) == safe_limit, "rulesets": rulesets}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_ruleset(project: ProjectName, ruleset_id: int, include_parents: bool = True) -> dict:
    """Read one repository ruleset."""
    try:
        rid = require_positive_id(ruleset_id, "ruleset id")
        item = github_json(project, f"/rulesets/{rid}", query={"includes_parents": str(bool(include_parents)).lower()})
        return {"ok": True, "ruleset": item}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_upsert_ruleset(project: ProjectName, name: str, target: Literal["branch", "tag", "push"], enforcement: Literal["disabled", "active", "evaluate"], conditions: dict[str, Any], rules: list[dict[str, Any]], bypass_actors: list[dict[str, Any]] = [], ruleset_id: int = 0, confirmation: str = "") -> dict:
    """Create or update a repository ruleset after exact confirmation."""
    try:
        clean_name = validate_title(name, "ruleset name")
        if len(rules) > 100 or len(bypass_actors) > 100: return {"ok": False, "error": "Ruleset lists are too large"}
        encoded = json.dumps({"conditions": conditions, "rules": rules, "bypass_actors": bypass_actors}, separators=(",", ":"))
        if len(encoded) > 200_000 or redact_github_text(encoded) != encoded: return {"ok": False, "error": "Invalid, oversized, or sensitive ruleset payload"}
        payload: dict[str, Any] = {"name": clean_name, "target": target, "enforcement": enforcement, "conditions": conditions, "rules": rules}
        if bypass_actors: payload["bypass_actors"] = bypass_actors
        if ruleset_id:
            rid = require_positive_id(ruleset_id, "ruleset id")
            required = f"UPDATE RULESET {rid}"
            suffix = f"/rulesets/{rid}"; method: Literal["POST", "PUT"] = "PUT"
        else:
            required = f"CREATE RULESET {clean_name}"
            suffix = "/rulesets"; method = "POST"
        if confirmation.strip() != required: return {"ok": False, "error": f"Ruleset change requires confirmation: {required}"}
        with WRITE_LOCK: result = github_write_json(project, suffix, method=method, body=payload, audit_action="github_upsert_ruleset")
        return {"ok": True, "status": result["status"], "ruleset": result["data"]}
    except Exception as error:
        audit("github_upsert_ruleset", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_get_custom_property_values(project: ProjectName) -> dict:
    """Read custom property values assigned to a repository."""
    try:
        items = github_json(project, "/properties/values")
        return {"ok": True, "count": len(items), "properties": items}
    except Exception as error:
        return {"ok": False, "error": redact_github_text(str(error))[:500]}


@mcp.tool()
def github_update_custom_property_values(project: ProjectName, properties: list[dict[str, Any]], confirmation: str = "") -> dict:
    """Set or unset repository custom property values after exact confirmation."""
    try:
        if not properties or len(properties) > 100: return {"ok": False, "error": "Provide 1 through 100 custom properties"}
        normalized: list[dict[str, Any]] = []
        for item in properties:
            if not isinstance(item, dict) or set(item) != {"property_name", "value"}: return {"ok": False, "error": "Each custom property requires only property_name and value"}
            name = validate_title(str(item["property_name"]), "property name")
            value = item["value"]
            if value is not None and not isinstance(value, str) and not (isinstance(value, list) and all(isinstance(part, str) for part in value)): return {"ok": False, "error": f"Invalid value for custom property {name}"}
            normalized.append({"property_name": name, "value": value})
        encoded = json.dumps(normalized, separators=(",", ":"))
        if len(encoded) > 100_000 or redact_github_text(encoded) != encoded: return {"ok": False, "error": "Oversized or sensitive custom property payload"}
        required = "UPDATE CUSTOM PROPERTIES"
        if confirmation.strip() != required: return {"ok": False, "error": f"Custom property update requires confirmation: {required}"}
        with WRITE_LOCK: result = github_write_json(project, "/properties/values", method="PATCH", body={"properties": normalized}, audit_action="github_update_custom_property_values")
        return {"ok": True, "status": result["status"], "updated": [item["property_name"] for item in normalized]}
    except Exception as error:
        audit("github_update_custom_property_values", project, False, str(error)); return {"ok": False, "error": redact_github_text(str(error))[:500]}


def main() -> None:
    """Run the hardened local Streamable HTTP MCP transport."""
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=PORT,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )


if __name__ == "__main__":
    main()
