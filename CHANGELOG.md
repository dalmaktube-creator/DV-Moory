# Changelog

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
