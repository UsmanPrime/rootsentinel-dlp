# Phase 03 verification evidence

## Baseline and scope

The inspected starting branch was `main`, origin
`https://github.com/UsmanPrime/rootsentinel-dlp.git`, with local and remote HEAD
`566c2df540e013a56010af7cd1485e55832da6ac`. The starting working tree was clean.
Phase 01/02 evidence, migrations, authentication, scan/registry/policy interfaces,
frontend integration and CI were inspected. The existing cryptographic core,
detector, policies and registry services are preserved.

Implemented: retained snapshots, controlled single-use release, actual incident
investigation/export, HMAC event chains, independent checkpoints, key provisioning/
rotation, secured APIs and a minimal real browser workflow. No staging adapter,
cloud deployment, arbitrary forwarding or Phase 04 dashboard is included.

## Local results

Environment: Windows AMD64, Python 3.13.4, existing pinned external Phase 02 environment.
Dependencies were not changed. Detailed commands, versions and sanitized output are in
[phase-03-checks.json](phase-03-checks.json).

| Check | Observed result |
|---|---|
| Full `python -B -m pytest -p no:cacheprovider -q` | 159 passed; 606 cryptographic subtests passed |
| Fixture manifest verification | 11 verified, unchanged |
| Dependency consistency | `pip check` passed |
| Frontend typecheck/build | Passed |
| Original crypto/tests/manifest diff against Phase 02 | No changes |
| `git diff --check` | Passed |
| Focused gateway run after adding PostgreSQL user/session acquisition locks | 41 passed |
| OpenAPI export | 27 paths, generated from real application |
| Real Chrome HTTP acceptance | Passed; details below |

One existing upstream Starlette/HTTPX deprecation warning remains. It is recorded,
not hidden. The obsolete Phase 02 assertion that no release endpoint exists was
replaced with an assertion permitting exactly the controlled release route. Existing
test behavior otherwise remains; interrupted-input testing now also covers transfers.
The database inventory assertion includes the six new tables.

## Release, race and failure evidence

HTTP tests independently hash response bytes and compare full content, not just a
server-reported verdict. Blocked requests return JSON with no protected payload.
Tests cover missing/changed snapshots, corrupted persisted digest/length, expiry,
stale policy/registry, ERROR, unknown IDs, cross-user/anonymous access, CSRF and public
mode denial. Admin cannot bypass BLOCK or download another user's payload.

Concurrent release produces one 200 and one 409; duplicate creation keys produce
one transfer. Controlled barriers show policy/registry mutations cannot commit inside
release acquisition. Changing the snapshot after capture cannot change the delivered
buffer. Snapshot disappearance, DB commit failure, mandatory audit failure and checkpoint
failure release no bytes. Startup recovery marks unfinished release DELIVERY_UNKNOWN.
ASGI send exceptions/disconnects record uncertainty and return the processing slot.

Incident tests link BLOCK to actual scan evidence, enforce role/revision checks,
reject markup/control injection, require resolution and prove closure never grants
release. JSON export excludes payloads, credentials, keys and runtime paths.

HMAC tests use independently constructed reference bytes and cover modified content,
sequence, order, middle deletion, previous MAC, MAC, key ID, canonical representation,
wrong/missing keys, concurrent appends and rotation. Database-admin trigger bypass plus
an independently retained checkpoint detects tail removal. A separate test demonstrates
the documented inability to detect rewritten uncheckpointed tails.

## Migrations and storage

Alembic 0002 adds transfers, release attempts, incidents/history and audit events/head.
Fresh migration, repeated upgrade, isolated downgrade/re-upgrade, Phase 02 data-preserving
upgrade and schema/model consistency are tested. SQLite foreign keys, uniqueness,
immutable-history triggers and serialized transactions pass locally.

Windows private directories/files are checked with read-only DACL inspection; POSIX
uses restrictive modes and no-follow opening. Generated UUID filenames, hardlink/reparse
rejection, private snapshots, bounded cleanup, retained expiry and unrelated-file
preservation are tested. POSIX symlink coverage runs in Linux CI; Windows native symlink
creation may be unavailable to the test account. No system permissions were changed.

The local Docker Linux engine was unavailable, so PostgreSQL is **not claimed as locally
tested**. Candidate CI must validate the PostgreSQL 17 fixture before main publication.

## Real-browser evidence

[phase-03-browser.json](phase-03-browser.json) records Chrome 156.0.8078.80 over real
loopback HTTP, Vite proxy and Uvicorn. Exact and partial protected fixtures BLOCKed;
direct forged release requests returned 409. Analyst actions and sanitized exports
worked. The benign download contained exactly 2,720 expected bytes with independently
computed SHA-256 `efecb5a34398f8906907275a3f4f8dc49da495c05281008fc0447bab0d95881d`.
Audit verification, sign-in/out and desktop/mobile no-overflow checks passed with zero
page errors. Credentials and downloaded test payloads remain outside the repository.

## Measured performance

[phase-03-benchmark.json](phase-03-benchmark.json) contains reproducible local SQLite
samples, timing ranges, query counts and methodology. Three 10 MiB samples had median
snapshot capture 32.165 ms, scan-to-decision 1,937.157 ms and release preflight 437.360 ms.
Ten audit samples had median append 14.247 ms and verification 40.364 ms. Three blocked
scan/incident samples had median 95.968 ms. Scan/release used Python allocation tracing;
these are local synthetic observations, not throughput or production SLA claims.

Preflight used 26 SQL statements in these samples. The maximum traced Python allocation
for 10 MiB scan/release was 12,966,083 bytes; this excludes the preallocated source buffer
and is not process RSS. The design caps two processing slots and 20 pending snapshots;
interpreter, descriptor, intake and transport overhead are additional.

## Defects found and resolved during verification

- Generated migration referenced an unimported application type; replaced with stable SQL types.
- Decision expiry was missing from the audit detail allowlist; added canonical UTC binding.
- Duplicate nosniff headers were consolidated by middleware.
- Browser select needed an explicit accessible name; long evidence identifiers needed mobile wrapping.
- Transfer list initially loaded full scan evidence per row; changed to bounded summaries.
- Windows paths needed explicit ACL/owner verification, not just reparse-point rejection.
- Release locks user/session records on PostgreSQL to serialize revocation with acquisition.

## Publication gates and remaining limitations

The candidate working-tree secret/privacy scan found no findings. Final staged audit,
candidate commit SHA, hosted CI and publication outcome are recorded in
`phase-03-checkpoint.json` when observed. No CI success or main publication is inferred
from a local pass. A safe candidate branch is used before fast-forwarding main.

Limits remain explicit: one worker/workspace, local authenticated mode, fixed-size raw-byte
blind spots, 20,000-event audit cap, no guaranteed recipient storage, no exactly-once
delivery, no secure media erasure, and no protection from host/key compromise. External
checkpoints require independent retention and durable storage. Missing mandatory audit
dependencies deny release and can require operator recovery. Public mode is closed.

Phase 04 should consume the typed REST/OpenAPI contracts; preserve the release invariant,
ownership/CSRF checks, terminal/uncertain states and truthful audit limitations.

Current checkpoint status: local implementation gates pass; hosted CI/publication pending.
