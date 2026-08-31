# Changelog

## 1.4.0 — 2026-08-31

- Projects now default to writing every branch, so a project registered without explicit patterns is no longer locked to its default branch.
- Added `delete_branch` for local and remote branch deletion behind a `DELETE BRANCH <project> <branch>` confirmation; the registered default branch and the checked-out branch stay protected.
- `github_update_repository_settings` can now rename a repository through a validated `name` argument.

## 1.3.1 — 2026-08-31

- Fixed background fetch stopping at an interactive GitHub credential prompt; `scripts/fetch.sh` now authenticates the same way the server does, with a temporary askpass helper, a short-lived token file, and `GIT_TERMINAL_PROMPT=0`.
- Background fetch mints a GitHub App installation token when the install uses App authentication, and otherwise reads the allowlisted fine-grained token path.

## 1.3.0 — 2026-08-31

- Fixed the public endpoint not surviving a reboot: the Caddy service is now enabled during setup.
- The health check now fails when the Moory or Caddy services are not enabled for autostart.
- Added `list_branches` for local and remote branch inventory with commit metadata.
- Added read-only `ref` support to `read_tracked_file`, `list_tracked_files`, `search_tracked_code`, and `recent_commits`, plus `ref` and `compare_to` on `git_diff`.
- Reads from another ref never check out, so the working tree stays untouched and sensitive-path filtering still applies.
- Projects may declare `write_branches` patterns, so writes are no longer limited to a single branch.
- Added `checkout_branch` and `create_branch` behind exact confirmation gates and a clean-tree requirement.
- `sync_project` and `push_project` now act on the checked-out writable branch instead of the registered default.
- The background fetch now retrieves every branch and tag instead of a single branch.
- The setup menu can register extra writable branch patterns for a project.

## 1.2.0 — 2026-08-31

- Expanded curated GitHub coverage across deployments, CI, security, supply chain, collaboration, and administration.
- Kept exact confirmation gates, write locking, audit logging, and the no-delete policy on every new write tool.
- Documented that repository custom property values require organization-owned repositories.
- Documented that GitHub Packages endpoints reject GitHub App installation tokens.
- Documented that classic Projects endpoints are retired and intentionally unsupported.

- Added bounded repository settings inventory and guarded non-destructive updates.
- Added collaborator inventory, pending invitations, and guarded role grants.
- Added repository ruleset inventory and guarded create/update controls.
- Added repository custom property reads and guarded value updates.
- Fixed package inventory for repositories owned by user accounts.
- Added guarded label and milestone management.
- Added pull request reviewer requests and issue assignee workflows.
- Added GitHub Discussions reads, creation, comments, and updates through GraphQL.
- Added merge queue inspection plus guarded enqueue and dequeue controls.
- Preserved the no-delete policy across collaboration tooling.
- Added SPDX SBOM export and organization package inventory reads.
- Added repository attestation reads and guarded Sigstore bundle creation.
- Added guarded dependency snapshot submission with bounded sensitive-content checks.
- Added linked-artifact storage and deployment reads plus guarded writes.
- Added strict SHA-256 digest validation and organization-scoped API routing.
- Added redacted secret-scanning reads, locations, and guarded resolution controls.
- Added code-scanning reads plus guarded dismissal and reopen controls.
- Added Dependabot, code-quality, and delegated bypass-request reads.
- Added repository security advisory reads and guarded draft/update/publish tools.
- Preserved the no-delete policy across all security tooling.
- Added workflow discovery plus guarded enable and disable controls.
- Added guarded GitHub Check Run creation and lifecycle updates.
- Added commit-status reads and guarded status creation.
- Added repository-wide artifact discovery and artifact metadata reads.
- Added guarded deployment reads, creation, and status updates.
- Added deployment-environment inspection and protected configuration updates.
- Added repository and environment Actions variable management with value redaction.
- Added GitHub Pages inspection, configuration, and build requests.

## 1.1.0 — 2026-08-30

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
- Benchmarked actual serialized baseline and Worker tool payloads with deterministic byte counts.
- Moved the public Quick Setup command to the top of the README.
- Added explicit Ubuntu 24.04 and Python 3.12 installer compatibility gates.

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
