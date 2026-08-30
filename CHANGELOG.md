# Changelog

## Unreleased

- Added authenticated private Git fetch and push support for Quick Mode without storing tokens in remote URLs.
- Preserved available pull request data when optional Checks or status permissions are unavailable.
- Added the bounded `worker_context` tool with `summary`, `evidence`, and `full` escape-hatch levels.
- Added agent-facing capability discovery and explicit context-escalation instructions.
- Added anti-blindness metadata and commit-SHA repository-map caching.
- Added measurable worker benchmarking and safe GitHub permission diagnostics.
- Added a composite CI failure inspector with bounded redacted logs.
- Added patch input normalization and actionable preflight diagnostics.
- Made failed commit staging transactional and recoverable.
- Added transactional tracked-file change sets with validation rollback.
- Added non-mutating release-readiness checks.
- Added repository-map hints for tests, workflows, and configuration files.
- Grouped and deduplicated CI failure evidence with bounded context.
- Added non-executing static validation for Python, JSON, and TOML files.
- Made static validation the default transactional change-set profile.
- Added task-oriented tool discovery profiles without claiming dynamic tool hiding.

## 1.0.0

- Security audit hardening for bootstrap paths, backups, symlink reads and patch rename/copy metadata.

- Added guarded GitHub write operations for issues, PRs, reviews, workflow runs, and releases.
- Added exact confirmation gates, duplicate prevention, and write secret scanning.
- Verified real GitHub App read/write access by safely closing a stale completed issue.

## 0.3.0

- Added read-only GitHub App adapter for issues, PRs, reviews, Actions logs, artifacts, releases, and assets.

## 0.2.0

- Added restricted Git write workflow: patch check/apply, validation, commit, sync, and push.

## 0.1.0

- Initial read-only Git bridge.
