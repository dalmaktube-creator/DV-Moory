# Agent instructions

This repository contains the Moory MCP server.

- Never commit tokens, private keys, deploy keys, keystores, credentials, or environment files.
- Never add arbitrary shell execution, arbitrary GitHub API paths, force push, reset-hard, repository deletion, or secret-management tools.
- Keep all repository and branch access allowlisted.
- Keep write operations serialized and audited.
- Require exact confirmation text for merge, review, workflow mutation, PR closure, and release publication.
- Run `./scripts/test.sh` before every commit.
- Update CHANGELOG.md for releases.
- Deployment changes must preserve rollback and systemd hardening.
