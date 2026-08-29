# Moory

Moory is a self-hosted, security-hardened MCP bridge that lets Notion AI work with explicitly registered Git repositories and curated GitHub APIs. It includes guarded code changes, commits, pushes, issues, pull requests, Actions, logs, releases, secret scanning and audit logging.

## Easy installation

After the first public release, install on Ubuntu with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/dalmaktube-creator/DV-Moory/main/install.sh | sudo bash
```

The colored setup wizard asks you to choose:

1. **Quick Mode** — fine-grained GitHub token; fastest for personal use.
2. **Hardened Mode** — GitHub App and short-lived tokens; recommended for production.

After installation, open the control center at any time:

```bash
sudo moory
```

The menu manages repositories, authentication, Notion connection details, status, logs, backups, token rotation and updates. Users do not need to remember maintenance commands.

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

## Supported platform

- Ubuntu 22.04 or 24.04
- Python 3.11+
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
