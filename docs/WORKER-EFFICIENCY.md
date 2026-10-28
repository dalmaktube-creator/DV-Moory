# Lossless worker evidence: validation report

Baseline: `957f2f3d871ce1c0ceb9659de03599feb9a00475`.
Validation date: 2026-10-29. SDK: pinned `mcp==2.1.1`.

## Scope

The change reduces generated JSON whitespace, batches exact file ranges,
serializes transactional apply/validate/rollback, and bounds CI error contexts
while keeping complete redacted log evidence accessible through SHA-guarded
pagination. It does not introduce arbitrary remote commands, relax allowlists,
or change workflow/merge/release confirmation requirements.

## Synthetic measurements

The same in-memory Actions ZIP was used with the baseline and candidate modules:
`start`, an `AssertionError` line containing 240,000 `x` characters, then
`failed tail`. The GitHub run metadata was identical. Evidence dictionaries
were serialized as UTF-8 JSON with compact separators for both versions.

| Measurement | Baseline | Candidate |
| --- | ---: | ---: |
| CI evidence JSON bytes | 200,372 | 2,234 |
| Actual SDK `list_projects` text bytes for the same one-project registry | 146 | 101 |

The `list_projects` JSON values were equal after decoding. CI summaries are
intentionally different representations: the candidate exposes source identity,
truncation and a full-evidence cursor instead of repeating giant contexts.
The regression suite separately reconstructs the complete redacted log across
pages and compares every character, including the giant assertion line.

These are fixture-specific byte counts, not tokenizer measurements, production
latency benchmarks or universal savings estimates. Log pagination currently
re-downloads the archive; it trades bounded context for additional network reads.

## Test coverage

Run `./scripts/test.sh` using the dependencies from `requirements.lock`.
The existing static, authentication and endpoint-port regressions remain enabled.
`tests/test_worker_efficiency.py` adds real temporary Git repositories and covers:

- Exact multi-page UTF-8 reads, CRLF, long lines and historical Git blobs.
- Changed-source rejection, shared batch budgets, sensitive paths and symlinks.
- HEAD/file SHA guards and both successful and failed new-file transactions.
- Rollback of edits, deletions and additions, including validator exceptions.
- A competing writer blocked throughout validation and rollback.
- CI failures outside the old tail window, very long assertions, redaction,
  changed log identities and oversized archive membership.
- Explicit Git output truncation and incomplete static inventories.
- Compact serialization with the actual SDK, preservation of typed output schema
  and structured content, plus an actual Streamable HTTP client/server round trip.

## Operational boundaries

Static parsing is not test execution. Local test results and GitHub CI must be
reported separately from installation and acceptance tests on the running server.
Other processes writing directly to repositories are outside the in-process lock;
coordinate them separately. Live runtime deployment still uses the existing
operator-controlled updater and its rollback/health checks.
