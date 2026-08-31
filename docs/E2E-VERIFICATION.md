# Live end-to-end verification (v1.2.0)

Date: 2026-08-31. Repository: `dalmaktube-creator/DV-Moory` (project `dv-moory`).
Head commit under test: `07c8729`. All fixtures are prefixed `moory-e2e`.

## Method

Every runtime tool was invoked against the live repository. Write tools were
exercised on disposable fixtures (issue, label, milestone, environment,
variable, check run, commit status, deployment, discussion, ruleset, draft
advisory). Each confirmation gate was probed first with an empty or wrong
confirmation to prove it blocks, then re-called with the exact string the
gate returned.

## Verified live (read and write paths)

- Issues: create, get, comment, update, assign, list
- Labels and milestones: upsert, list
- Environments: upsert, get, list
- Actions variables: upsert (value redacted in output), list
- Checks: create, update to completed, get, list
- Commit statuses: create, list
- Deployments: create, status, get, list
- Discussions: create, get, comment, update, list
- Rulesets: upsert scoped to `refs/heads/moory-e2e-*`, get, list
- Security advisories: create draft, get, update to closed, list
- Workflows: get, disable, re-enable, rerun failed jobs, runs, logs
- Releases: create, get, update draft, list, release readiness
- Repository administration: settings read and update, collaborators,
  invitations, permission diagnostics, health
- Git core: status, diff, patch check and apply, validate, commit, push, sync
- Context: worker_context overview and search at summary and evidence,
  prepare_change_context, inspect_ci_failure, worker_benchmark, tool catalog

## Confirmation gates proven to block

`UPSERT LABEL`, `UPSERT MILESTONE`, `CONFIGURE ENVIRONMENT`,
`CREATE VARIABLE <name> IN <scope>`, `CREATE CHECK <name> ON <sha>`,
`UPDATE CHECK <id> TO <status>`, `SET STATUS <context> <state> ON <sha>`,
`DEPLOY <sha> TO <env>`, `SET DEPLOYMENT <id> <state>`, `CREATE DISCUSSION`,
`COMMENT DISCUSSION`, `UPDATE DISCUSSION`, `CREATE RULESET`,
`CREATE SECURITY ADVISORY`, `UPDATE SECURITY ADVISORY <GHSA>`,
`ASSIGN ISSUE #<n>`, `DISPATCH <workflow> ON <ref>`,
`DISABLE WORKFLOW <file>`, `ENABLE WORKFLOW <file>`, `RERUN RUN <id>`,
`CANCEL RUN <id>`, `GRANT <role> TO <user>`, `REQUEST REVIEWERS PR #<n>`,
`ENQUEUE PR #<n>`, `CLOSE PR #<n>`, `REVIEW PR #<n>`, `MERGE PR #<n>`,
`BUILD PAGES`, `UPDATE SECRET ALERT <n> TO <state>`,
`UPDATE CODE ALERT <n> TO <state>`, `STORE ARTIFACT <name>`,
`DEPLOY ARTIFACT <name> TO <env>`, `SUBMIT DEPENDENCY SNAPSHOT`,
`UPDATE REPOSITORY SETTINGS`, `UPDATE CUSTOM PROPERTIES`, `PUBLISH <tag>`,
`PUSH <project>`.

## Blocked by repository or platform state, not by Moory

- Secret scanning alerts, locations, alert update: secret scanning disabled
- Code scanning alerts and alert update: no analysis uploaded
- Dependabot alerts: alerts disabled for this repository
- Code quality findings: endpoint unavailable for this repository
- Secret scanning bypass requests: not accessible by an installation token
- SBOM and dependency snapshot: dependency graph disabled
- Packages and package versions: REST package endpoints reject App tokens
- Custom property values: requires an organization-owned repository
- Attestations and artifact metadata, storage, deployment records: no signed
  artifact data on this repository. Moory input validation was still proven
  locally (an invalid Sigstore bundle was rejected before any API call)
- Pages: disabled on this repository. The gate was verified and configuration
  was intentionally skipped to avoid publishing a public site

## Not exercisable without a second branch

Moory has no branch-creation tool and only the approved branch is writable,
so the pull request family cannot produce a live PR here. Argument
validation, confirmation gates, and 404 handling were verified against a
nonexistent pull request instead. This is a deliberate design boundary.

## Conclusion

No Moory defect was found. Every failure traced to a disabled repository
feature, a platform restriction on installation tokens, or an intentional
safety boundary: confirmation gates, no-delete policy, single-branch scope.
