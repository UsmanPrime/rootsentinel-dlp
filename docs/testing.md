# Testing and evaluation

## Phase 01 commands

From `backend`: `python -B -m unittest tests.test_crypto tests.test_config -v` (no dependencies).
After installing the pinned test environment: `python -m pytest` (all phases).
From repository root: `python -B scripts/fixtures.py`.
From `frontend`: `npm ci --ignore-scripts --no-audit --no-fund`,
`npm run typecheck`, `npm run build`.

The test suite uses unittest cases discovered by both runners. It checks standard
SHA-256 vectors; exact chunk boundaries; short reads; raw encoding; independent
descriptor bytes and three-leaf tree expectations; every leaf for specified and
additional deterministic tree sizes; malformed proofs; empty trees; maximum/oversize
inputs; file mutations; ordering; and safe external path configuration.

`scripts/fixtures.py` constructs only synthetic bytes in memory. Its default mode
checks `fixtures/manifest.json`. `--write-manifest` deliberately updates the manifest
but never writes payload files. Do not use that flag to hide unexplained test drift.

## Phase 02 release checks

From the source root, using the isolated locked environment:

```sh
python -B scripts/verify_phase02.py
python -B scripts/export_openapi.py
python -B scripts/audit_publication.py
python -B scripts/benchmark_phase02.py --output docs/evidence/phase-02-benchmark.json
```

Verification records actual sanitized command output in `phase-02-checks.json`.
The benchmark uses temporary external SQLite data, deterministic blocks, three
matching measurements and 100 policy/exact-lookup measurements. Its traced Python
allocation peak is not process RSS. Database file size is cumulative metadata
storage, not a proprietary-payload store. Shared-host load and tracing affect timings.

The new pytest tests cover fixed-chunk fixtures and known misses, policy precedence,
strict thresholds, lifecycle/history, authorization/ownership, CSRF/Origin/Host,
session expiry/revocation/rotation, login limits, frozen intake, actual-byte size
enforcement, interrupted ASGI requests, malformed filenames, public-mode denial,
database rollback, immutable-row triggers, concurrent registrations/scans and query
count bounds. Every test database is created by the actual Alembic migration.

Set `ROOTSENTINEL_TEST_POSTGRES_URL` to a private, dedicated test DSN to run the same
system fixtures on both engines. It creates/drops isolated random test schemas.
Without that setting, a passing run proves SQLite behavior only. CI includes a
disposable PostgreSQL service; observed CI results belong in evidence, not assumptions.

The test client currently emits one upstream deprecation warning for HTTPX; the
pinned API remains operational. No warning is suppressed to hide a test failure.

### Browser verification

Install optional `backend/requirements-browser.lock`; use an installed Chrome. Set
`ROOTSENTINEL_BROWSER_STATE` to a new, absolute directory outside source/OneDrive.
In `backend`, run `python -B -m tests.browser_server`; start Vite with a matching
`ROOTSENTINEL_ORIGIN` (and proxy port if changed). From root run
`python -B scripts/browser_check.py` with the same state/origin variables.

The harness creates random, temporary local credentials without printing them.
The browser script reads them privately, exercises actual login/registration/scans/
logout and writes only non-sensitive assertions to `phase-02-browser.json`. Stop
the harness gracefully to remove credentials and its temporary database. If killed
abruptly, remove only that known test directory after verifying the harness stopped.
Do not publish raw browser traces, HARs or snapshots containing form values.

API-only callers must supply Origin and the CSRF token as well as a session cookie.
For a classroom demonstration, use the normal hidden-prompt bootstrap documented in
the developer guide rather than the automated browser-test credential file.

## Required later security scenarios

Each result must record objective, fixture, expected decision, observed decision,
evidence, limitation, test command, commit/environment and actual pass/fail.

| Scenario | Expected baseline behavior |
|---|---|
| Exact and renamed protected file | BLOCK; release returns no payload |
| Ordinary distinct file | ALLOW; returned bytes have scanned digest |
| Empty file | Scan valid; protected registration rejected |
| Small/large files | Exact matching remains correct within 10 MiB bound |
| Single-byte change in multiblock file | Remaining aligned qualifying blocks trigger BLOCK |
| Aligned partial copy / embedding | BLOCK at configured threshold |
| One-byte boundary shift | Document expected fixed-block miss, not fake prevention |
| Encoding and line endings | Raw-byte differences; report lost matches honestly |
| Shared content | All implicated assets shown; no unique-ownership inference |
| Valid/corrupt proofs | Success/failure against separately trusted manifest |
| Concurrency | Isolated decisions; overload rejected; no duplicate delivery |
| Interrupted/oversized uploads | No release; cleanup; 413 for excess bytes |
| Malformed names, symlinks, traversal | Reject unsafe admission; no escaped file access |
| Policy precedence/admin override | Exact block wins; no privileged P0 bypass |
| Unauthorized/API cross-session access | Denied without evidence disclosure |
| Audit edits/reordering | Verification fails without attacker knowing audit key |
| Audit tail deletion | Detected against retained checkpoint; state residual limitation |
| TOCTOU mutation | Only frozen checked bytes can be delivered |
| Agent/network disconnection | No delivery on unknown decision; idempotent retry |
| Outside-gateway copy | Explicitly not prevented; do not invent a gateway event |
| Stale registry/policy | Rescan or deny before release |

No transfer, policy, auth, agent or audit test is claimed as passed in Phase 01.

## Benchmark protocol (later phase)

Use synthetic files of 0 B, 100 B, 1 KiB, 8 KiB, 1 MiB and 10 MiB. Compare fixed
chunk sizes 256 B, 1 KiB, 4 KiB offline without changing the product's v1 profile.
Perform five warm-ups and thirty measured repetitions; retain raw results,
environment and commit. Report median/p95/range, throughput, peak memory, fingerprint
storage, proof size and proof verification time. Separate cold public starts.

Measure precision/recall/FPR against labelled ground truth. Use N/A for zero
denominators. Separate detector recall from correct enforcement of its decision:
a correctly enforced ALLOW may still be a false negative. CDC comparisons require
a real validated implementation; no placeholder results. A two-second warm local
1 MiB target is unmeasured, not an achieved benchmark.

## Phase 03 gates

Run `python -B scripts/verify_phase03.py`, `python -B scripts/export_openapi.py`,
`python -B scripts/audit_publication.py`, and `python -B scripts/benchmark_phase03.py`.
Start the existing external `tests.browser_server` harness plus Vite, then run
`python -B scripts/browser_phase03.py`. Browser tests independently hash the actual saved
HTTP response, forge a release for BLOCK, resolve/export incidents and verify the HMAC chain.

`test_gateway.py` covers positive/zero-content-negative HTTP paths, ownership, CSRF, public
mode, stale registry/policy, expiry, missing/modified snapshot, persisted digest/length
corruption, single use, concurrent release and idempotency, pending/rate caps, database and
mandatory audit/checkpoint failures, snapshot disappearance, immutable-buffer mutation,
recovery, incident permissions/version conflicts and malformed IDs/filenames. Controlled
thread barriers prove policy/registry changes wait for release acquisition. ASGI send-failure
and disconnect probes verify DELIVERY_UNKNOWN semantics; they do not infer recipient receipt.

`test_audit.py` uses an independent HMAC reference, mutation/reorder/deletion/canonical/key
faults, immutable triggers, concurrent append ordering, rotation and externally anchored
tail truncation. An explicit test demonstrates the uncheckpointed tail limitation.
Existing cryptographic tests and 606 subtests remain unchanged. The sole replaced Phase 02
contract assertion is ?no release API exists?; it now permits exactly the controlled route.

All database-dependent tests share the SQLite/PostgreSQL fixture. Set the dedicated test
DSN or observe candidate CI; do not claim PostgreSQL from SQLite alone. Linux CI exercises
POSIX symlinks/modes; Windows runs additionally exercise DACL validation. A Windows account
without symlink creation privilege cannot prove native symlink creation coverage locally.
