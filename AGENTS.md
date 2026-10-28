# Agent instructions

This repository contains the Moory MCP server.

- Never commit tokens, private keys, deploy keys, keystores, credentials, or environment files.
- Never add arbitrary shell execution, arbitrary GitHub API paths, force push, reset-hard, repository deletion, or secret-management tools.
- Keep all repository and branch access allowlisted.
- Keep write operations serialized and audited.
- Keep exact operation-marker checks for merge, review, workflow mutation, PR closure and publication. For an operation the user has already explicitly requested, the agent fills the technical `confirmation` field itself; never demand that the user repeat a magic phrase. Ask only if intent, target, scope or an irreversible consequence is unclear. This is not blanket permission for unrelated actions or permission to bypass any safety check.
- Run `./scripts/test.sh` before every commit.
- Update CHANGELOG.md for releases.
- Deployment changes must preserve rollback and systemd hardening.
