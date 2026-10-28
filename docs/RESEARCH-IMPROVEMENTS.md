# Research-derived security and context improvements

Baseline: `59a3115fe8c86bc5a7234e791e350aa8d916994e`.

## Security before compactness

Ordinary source reads can contain credentials even when the file path is not
sensitive. Known credential patterns, quoted credential assignments and common
credential-valued fields are now masked. File reads mask the complete source
before pagination so a value split across pages cannot evade detection. Character
positions and CR/LF are preserved; `sha256` and continued-read guards still identify
the original file bytes. Redacted results explicitly include `redacted`, span
metadata and the identity/content distinction. There is no raw-secret escape hatch.

Search previews and nearby context also mask the complete bounded source before
extracting snippets, including matches inside multiline private keys. Unreadable
sources are explicitly omitted, never replaced with an unmasked grep fallback.
Per-call retained source caches and snippet sizes are bounded.

A final outbound text/structured-output filter also covers search results, Git
output, GitHub responses and exception messages. Structured credential keys are
masked even for short values. Secret-bearing dictionary keys block the result
rather than silently colliding after masking. Audit details are sanitized.

Detection is based on known patterns and key names: it is not a proof that every
possible secret is recognized. Conservative matching can hide non-secret examples;
redaction is explicit. It is intentional that a masked source cannot be rebuilt
byte-for-byte from its returned content. The original-byte SHA is a stale-context
guard, not a promise that returned masked text hashes to it. Read exact non-masked
ranges before editing; existing patch/commit secret checks remain enforced.

## Correct tracked-file maps

`worker_context` fingerprints the complete NUL-delimited tracked-file inventory,
in addition to the commit SHA. Staged additions/deletions therefore invalidate the
map without requiring a commit. An incomplete inventory is an error, never a
complete-looking cached map. Content edits do not require rebuilding a name-only
map. Live Git status remains uncached, and a failed status read cannot report a
clean repository. This adds an inventory read for correctness; it is not claimed
to make every overview call faster.

## Actual tool registration profiles

The following are optional **operator-controlled startup settings**, read from
the service environment. The existing updater and systemd EnvironmentFile remain
unchanged. Omitted settings preserve legacy behavior; nothing automatically removes
an existing integration's tools during this release.

| Setting | Behavior |
| --- | --- |
| `MOORY_TOOL_PROFILE=all` | Default; retain the full existing surface. |
| `MOORY_TOOL_PROFILE=core` | Repository/context/change workflow and selected GitHub/CI tools. |
| `MOORY_TOOL_PROFILE=research` | Only recognized read tools, including GitHub read operations. |
| `MOORY_TOOL_PROFILE=github` | GitHub API tools plus capability/catalog/diagnostic tools. |
| `MOORY_READ_ONLY=1` | Strictly remove write tools for any profile and reject stale write calls. |

Valid read-only values are `0`, `1`, `false`, `true`; invalid settings fail startup.
After an operator changes settings, restart through the normal operational process
and reconnect/rediscover in clients that cache tool schemas. This catalog cannot
change its own policy at runtime. Read/destructive/idempotency annotations describe
behavior but are not permission enforcement; server-side registration and call
checks are the enforcement. No generic shell or raw GitHub API tool was added.

## Read-only Python structure

`code_outline` parses tracked `.py` files using the standard-library AST, without
importing or running project code. It returns class/function/async-function names,
qualified names, parameter names and line ranges. Defaults, bodies and docstrings
are not emitted. Results are paginated with a source SHA guard. This is structure
for navigation, **not edit evidence**, full LSP reference resolution, or semantic
support for other languages. Exact source reading remains available separately.

## Authorized, bounded log snapshots

Completed-run log snapshots are cached in memory only after redaction. Cache keys
partition by project/repository, the server's current GitHub credential fingerprint,
run attempt/revision and a filter fingerprint. Every lookup first performs a live
run-read authorization check; failure never falls back to cached content. Rotated
credentials and changed run attempts cannot reuse the old entry. Running runs are
not cached. Concurrent misses can independently fetch; no single-flight or global
network lock is claimed.

Limits are a 120-second TTL, at most four entries, two million UTF-8 text bytes per
entry and eight million text bytes total. These limits bound retained log text,
not total Python object/process memory. Oversized snapshots still use the existing
bounded download/pagination path without entering the cache. Cached snapshots may
remain available for their TTL even if GitHub logs are subsequently deleted, as
long as the live run authorization check still succeeds. No files are persisted,
no writes are cached/retried, and TTL expiry/source changes still require the
normal SHA-guarded continuation rules. The cache is partitioned by Moory's backend
GitHub identity, not a new per-chat-user authorization system.

## Build/schema identity and aggregate metrics

`server_diagnostics` reports the source-file SHA-256, actual registered-schema hash,
SDK version, selected policy, uptime, aggregate tool duration/text-byte/error
counters, aggregate GitHub HTTP counters and log-cache occupancy. It never returns
arguments, responses, token values or request paths. Metrics are in-process and
bounded; they measure server work and text bytes, not exact model tokens, total
wire bytes or end-user/model latency. Schema/build hashes identify changes; they
cannot force a client to refresh its tool catalog.

## Validation

`./scripts/test.sh` retains all earlier checks and runs the new suite in
`tests/test_research_improvements.py`. It uses temporary real Git repositories,
synthetic credentials, mocked GitHub archives/authorization and a real local
Streamable HTTP client/server. It covers staged cache invalidation, incomplete
inventory/status failures, redacted historical and paginated reads, nested and
typed outbound data, audit hygiene, effective profiles/read-only call rejection,
log authorization/identity/attempt/filter/TTL/memory behavior, non-executing Python
outlines and privacy-preserving diagnostics. No live repository or service is
modified by these tests. Deployment and live acceptance remain separate steps.
