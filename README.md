# Moory

Moory is a self-hosted, security-hardened MCP bridge that lets Notion AI work with explicitly registered Git repositories and curated GitHub APIs. It includes guarded code changes, commits, pushes, issues, pull requests, Actions, logs, releases, secret scanning and audit logging.

## Quick setup

Install Moory on a fresh Ubuntu 24.04 server with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/dalmaktube-creator/DV-Moory/main/install.sh | sudo bash
```

The installer asks for the data path, local port, public domain, GitHub authentication mode and first repository.

For personal use, choose **Quick Mode** and provide a fine-grained GitHub token limited to the repositories Moory should access.

After installation, open the control center with:

```bash
sudo moory
```

## Worker core

Moory keeps reasoning with the connected agent and moves deterministic repository work to the server.

- `worker_context` provides a compact repository overview or fixed-text code search.
- `detail=summary` minimizes routine output, `detail=evidence` includes nearby source context, and `detail=full` is an explicit escape hatch.
- Results are bounded and report truncation instead of silently hiding additional matches.
- `moory_capabilities` teaches connected agents when to escalate context and why summary alone is not edit evidence.
- `moory_tool_catalog` exposes compact `core`, `git`, and `github` profiles while keeping the full tool escape hatch.
- Repository file maps are cached by the exact commit SHA while worktree status remains live.
- `worker_benchmark` reports measured JSON bytes and calls without claiming exact token savings.
- `inspect_ci_failure` combines failed jobs with bounded, deduplicated, redacted error groups and nearby log context.
- `github_permission_diagnostics` probes safe read capabilities without mutating repositories.
- `validate_project` parses tracked Python, JSON, and TOML files without executing repository code.
- `apply_change_set` preflights tracked-file patches, runs static validation by default, and rolls back on validation failure.
- `release_readiness` reports branch, worktree, remote divergence, latest CI, changelog, and tag checks without mutation.

The original granular read tools remain available, so agents can always inspect exact files and line ranges when compact context is insufficient.

## GitHub coverage

Moory exposes curated tools for repository content, issues, pull requests, reviews, Actions runs, workflows, checks, commit statuses, artifacts, releases, deployments, environments, Actions variables, Pages, security alerts, advisories, supply-chain metadata, labels, milestones, discussions, merge queues, collaborators, rulesets and custom properties.

Known platform limits:

- Repository custom property values require organization-owned repositories.
- GitHub Packages endpoints reject GitHub App installation tokens and need a classic token with package scopes.
- Classic Projects endpoints are retired and intentionally unsupported.
- Delete, archive and visibility changes are intentionally not implemented.

## Security model

- Registered repository and branch allowlist
- No arbitrary shell or raw GitHub API endpoint
- No force-push, history rewrite or repository deletion
- Confirmation gates for merge, review, workflow mutations and release publication
- Secret detection before writes
- Short-lived GitHub App tokens in Hardened Mode
- Dedicated SSH deploy key per repository
- Sanitized audit logs
- Hardened systemd sandbox
- Local-only MCP listener behind HTTPS Bearer authentication
- Optional MCP OAuth 2.1 mode for ChatGPT and other OAuth-capable clients

## ChatGPT OAuth mode

Moory can expose the MCP Authorization Server endpoints required by ChatGPT's
Custom MCP connection. In this mode, ChatGPT uses Authorization Code + PKCE;
Moory sends the user to GitHub for sign-in and then issues its own short-lived
MCP access and refresh tokens. The GitHub OAuth token is exchanged only for the
user identity and is not stored. Setup also requires an explicit allowlist of
GitHub usernames; an arbitrary GitHub account cannot use the bridge.

During `moory-setup`, configure the HTTPS domain first, then enable
**ChatGPT / MCP OAuth**. Create a GitHub OAuth App with this callback URL:

```text
https://YOUR_DOMAIN/oauth/github/callback
```

After setup, use `https://YOUR_DOMAIN/mcp` in ChatGPT's Custom MCP server
configuration and select OAuth. Do not put the legacy Bearer token into
ChatGPT when OAuth mode is enabled.

The OAuth mode publishes protected-resource metadata, authorization-server
metadata, dynamic client registration, `/authorize`, and `/token`. The legacy
Caddy Bearer-token mode remains the default when OAuth is disabled.

## Supported platform

- Ubuntu 24.04
- Python 3.12+
- systemd
- Caddy for public HTTPS

## Documentation

- `docs/INSTALL-FA.md` — Persian installation guide
- `docs/SECURITY-FA.md` — security guide
- `docs/ARCHITECTURE-FA.md` — architecture
- `docs/MIGRATION-FA.md` — migration
- `SECURITY.md` — vulnerability reporting

## License

Apache License 2.0.
