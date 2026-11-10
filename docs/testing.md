# Testing and evaluation

This document lists the tests by level, says what each level proves and where it runs, and
states what is not tested. Run results are recorded in the evidence files
([evidence index](evidence/README.md)), not here.

## 1. CI jobs

`.github/workflows/ci.yml` runs on every push and pull request. Actions are pinned to commit SHAs,
checkout uses `persist-credentials: false`, and the workflow token is read-only. The nine jobs are the
required checks on `main`.

| Job | Runs |
|---|---|
| `backend (3.12)`, `backend (3.13)` | `pytest` in `backend` (SQLite), `scripts/fixtures.py`, `scripts/frontend_contracts.py --check`, `git diff --exit-code` |
| `browser` | Builds the interface, serves it from the API (`tests.browser_server`), runs `scripts/browser_phase04.py` and `scripts/browser_phase04_negative.py`; uploads only the two sanitized JSON reports |
| `postgres` | The same backend `pytest` suite against a disposable PostgreSQL 17 service, `git diff --exit-code` |
| `frontend` | `npm ci`, `npm run typecheck`, `npm run format:check` (Prettier), `npm test` (Vitest), `npm run build`, `git diff --exit-code` |
| `agent (3.12)`, `agent (3.13)` | `scripts/source_corpus.py`, agent `pytest`, `scripts/demo_agent.py`, `scripts/audit_publication.py`, `git diff --exit-code` |
| `agent-windows` | `scripts/source_corpus.py`, agent `pytest` and `scripts/demo_agent.py` on Windows |
| `container` | Builds the hosted image with `--build-arg ROOTSENTINEL_COMMIT=$GITHUB_SHA`, checks its size budget, startup refusal, smoke test with `--expect-commit`, unprivileged uid, server `HOME`, and restart idempotence |

## 2. Unit and cryptographic tests

From `backend`, without any dependency: `python -B -m unittest tests.test_crypto tests.test_config -v`.
With the pinned test environment: `python -m pytest` runs every backend test.

`test_crypto.py` checks standard SHA-256 vectors, exact chunk boundaries, short reads, raw encoding,
independent descriptor bytes and three-leaf tree expectations, every leaf for specified and additional
deterministic tree sizes, malformed proofs, empty trees, maximum and oversize inputs, file mutations and
ordering. `test_config.py` checks safe external path configuration.

From the repository root, `python -B scripts/fixtures.py` rebuilds the synthetic fixtures in memory and
checks `fixtures/manifest.json`. `--write-manifest` deliberately updates the manifest but never writes
payload files; do not use it to hide unexplained drift. `python -B scripts/frontend_contracts.py --check`
fails when `frontend/src/lib/contracts.ts` no longer matches `docs/openapi.json`.

## 3. API and integration tests

Every test database is created by the real Alembic migration. By default the suite runs on SQLite. Set
`ROOTSENTINEL_TEST_POSTGRES_URL` to a private, dedicated test DSN to run the same system fixtures on
PostgreSQL as well; the fixture creates and drops random test schemas. A passing SQLite run proves SQLite
behavior only; the `postgres` CI job covers PostgreSQL.

| File (`backend/tests`) | Covers |
|---|---|
| `test_api_security.py` | Complete API journey, anonymous denial, role restrictions, object access, session hashing/expiry/revocation/rotation, CSRF/Origin/Host, login throttling, filename and label injection, upload limits and cleanup, frozen bytes, infrastructure failure never allows, `public_demo` denial, OpenAPI release contract |
| `test_additional_gates.py` | Concurrent scans, immutable historical rows, incomplete Content-Length, actual-byte counting, ASGI disconnects, sanitized unexpected errors, no content in logs, missing registry fails closed, no combining of assets, cookie settings, snapshot links, disabled users |
| `test_detection_policy.py` | Fixture evaluation matrix, size boundaries, empty registration rejected, one-byte change, documented transform misses, repetition and shared assets, versions and retirement, policy threshold and disable, invalid thresholds, query count and evidence cap |
| `test_database.py` | Migration indexes and constraints, immutability triggers and foreign keys, rollback, concurrent registration |
| `test_gateway.py` | Single-use verified download and checkpoint, BLOCK with zero content, preflight fail-closed, ownership, unsafe filenames, idempotency, missing key and audit failure, concurrent release, expiry and restart, incident conflicts, buffer survives snapshot change after capture, rate and capacity bounds, disconnect and send failure (`DELIVERY_UNKNOWN`), tampered audit, private snapshot permissions, no payload in logs |
| `test_gateway_edges.py` | Upload cap boundaries, a lying Content-Length, empty file, safe and refused names, exact content type, release replay, release after expiry, policy and registry staleness, repeated BLOCK release, a 12-way parallel release race that delivers once, edited stored audit event, deleted newest event against the checkpoint, tampered and corrupt checkpoint files |
| `test_authorization_matrix.py` | Every OpenAPI operation against anonymous, EMPLOYEE, ANALYST and ADMIN; every mutation without CSRF, from another Origin, and every operation with a foreign Host; cross-employee isolation; `/auth/session` 204 and never 401; session fixation; logout; expiry; hosted cookie flags; concurrent sessions |
| `test_audit.py` | Independent HMAC reference, tamper attacks, uncheckpointed tail limitation, key rotation, concurrent appends, checkpoint detection of a rewritten head, log injection, private-file link checks |
| `test_presentation.py` | Tree projection bounds and uneven topology, overview roles, tree route trusted-root proof and authorization, incident filter and sort |
| `test_hosted.py` | Hosted settings, static serving and traversal, enforced CSP with HSTS only when hosted, every anonymous route denied, `public_demo` still closed, hop-count client address, upload/session/retention/rate overrides, `bootstrap`, and the gateway invariants in the hosted configuration |
| `test_client_ip.py` | `ROOTSENTINEL_CLIENT_IP_HEADER`: one valid address only, forged `X-Forwarded-For` ignored, shared `unidentified` bucket, startup refusal with hops, stable 429 codes, health probes counted separately, Host check before client identification, the counter advances only on sign-in, fixed log classification with no request value |
| `test_idle.py` | Zero database statements and zero connection checkouts over a simulated idle hour with `/health` every 10 minutes, `/health` without a database call, expiry at the due time and not before, the due time after a restart, cleanup triggered by snapshot files without the registry lock, retry after a failed pass, pool settings |
| `test_operations.py` | `/health` fields (`hosted`, `commit`, `max_upload_bytes`), commit validation and fallback order, peak-memory (`VmHWM`) reading and logging |
| `test_transparency_tree.py` | RFC 9162 tree without a database: every root, inclusion proof and consistency proof for sizes 1 to 128 against an independent reference, the published Certificate Transparency vectors, tampered leaf, root and path, forked and rewritten trees, the signed-bytes encoding, RFC 8032 key vector, wrong key and altered head rejected |
| `test_transparency_log.py` | Heads at every 64th event, at release and on request; API bounds; append-only triggers; restart rebuild; altered event, altered head, truncation and rollback fail closed; release refused without the key or when signing fails; memory equals database after a failed transaction; events from another process; evidence export bundle; key tool and key file checks; rotation |
| `test_witness.py` | `scripts/witness.py` over real HTTP against a local server: first head, unchanged, growth with a consistency proof, rollback and rewrite detected with the saved head kept, unpinned key, sign-in and network failures; offline bundle verification and every change to a bundle rejected |
| `test_operator_tools.py` | `app.cli` account commands and `app.audit_keys` provisioning: hidden prompts, no secret output, no overwrite, rotation |
| `test_smoke_probe.py` | The login-throttle probe in `scripts/smoke_public.py` with mocked responses |

Controlled thread barriers prove that policy and registry changes wait for release acquisition. ASGI
send-failure and disconnect probes verify `DELIVERY_UNKNOWN`; they do not infer recipient receipt. An
explicit audit test demonstrates the uncheckpointed tail limitation. Linux CI exercises POSIX symlinks and
modes; Windows runs additionally exercise DACL validation. A Windows account without symlink creation
privilege cannot prove native symlink coverage locally.

API-only callers must supply Origin and the CSRF token as well as a session cookie.

## 4. Frontend tests

From `frontend`: `npm test`, `npm run typecheck`, `npm run format:check` and `npm run build`.

| File | Covers |
|---|---|
| `src/api.test.ts` | Same-origin cookies, CSRF only in the header, 401 handling, empty logout, fixture byte identity |
| `src/lib/hooks.test.tsx` | Same-tick double-submission guard, safe error state and intentional retry |
| `src/lib/quality.test.tsx` | Hosted badge from `/health` and never from the hostname, label sanitizer, verdict numbers, incident sorting |
| `src/features/integrity/Integrity.test.tsx` | Tampered copies leave the stored proof unchanged, uneven topology, keyboard leaf selection, empty tree |
| `src/features/transfers/Gateway.test.ts` | Independent hashing of downloaded bytes before saving |

## 5. Browser acceptance

`scripts/browser_phase04.py` and `scripts/browser_phase04_negative.py` drive a real Chromium against the
built interface served by the API (`backend/tests/browser_server.py` with `ROOTSENTINEL_FRONTEND_DIR`), on a
disposable SQLite database with random credentials that are never printed. They run in the `browser` CI job.

* `browser_phase04.py` asserts that the served page carries the enforced CSP (`default-src 'none'`, no
  `'unsafe-inline'`, no report-only header). It signs in for each role, registers and verifies proofs, checks
  BLOCK with a forged release denied, clicks "Verified download" then "Download once" and compares the saved
  bytes, exports evidence, verifies the audit chain, checks stale release, 48 route and viewport overflow
  checks (8 routes at 320, 375, 768, 1024, 1440 and 1920 px), mobile navigation, RBAC through the interface and
  the API, and session revocation. It injects axe with `page.evaluate` (the page's CSP does not govern that
  channel) and fails on any violation of the axe rules tagged `wcag2a`, `wcag2aa`, `wcag21aa` and `wcag22aa`. It fails on any CSP violation and on any console
  error other than Chrome's "Failed to load resource" lines for HTTP error statuses the negative checks cause
  on purpose.
* `browser_phase04_negative.py` covers expired transfers, CSRF rejection, offline error and recovery,
  same-tick duplicate submission, session expiry, a tampered audit chain, and a mandatory audit failure that
  prevents release. It fails on any CSP violation. `browser_phase04_faults.py` is its helper and only touches
  the disposable browser database.

Both write their reports and screenshots to `$ROOTSENTINEL_BROWSER_EVIDENCE` (default
`<ROOTSENTINEL_BROWSER_STATE>/evidence`), never into `docs/evidence`. Do not publish raw traces, HARs or
snapshots containing form values. axe results are automated checks, not a full accessibility audit.

Local run (Windows PowerShell, repository root, browser lock installed with
`pip install -r backend/requirements-browser.lock`, then `python -m playwright install chromium`):

```powershell
$env:ROOTSENTINEL_FRONTEND_DIST = Join-Path $env:LOCALAPPDATA 'RootSentinel\ui-build'
Push-Location frontend; npm.cmd run build; Pop-Location
$env:ROOTSENTINEL_BROWSER_STATE = Join-Path $env:LOCALAPPDATA ('RootSentinel\browser-' + (Get-Date -Format yyyyMMddHHmmss))
$env:ROOTSENTINEL_FRONTEND_DIR = $env:ROOTSENTINEL_FRONTEND_DIST
$env:ROOTSENTINEL_ORIGIN = 'http://127.0.0.1:5173'
$env:ROOTSENTINEL_API_PORT = '5173'
$env:ROOTSENTINEL_BROWSER_CHANNEL = ''
Push-Location backend; python -B -m tests.browser_server
```

The state directory must be new and outside the source tree and OneDrive. In a second terminal with the same
`ROOTSENTINEL_BROWSER_STATE`, `ROOTSENTINEL_ORIGIN` and `ROOTSENTINEL_BROWSER_CHANNEL`, run
`python -B scripts/browser_phase04.py`, then `python -B scripts/browser_phase04_negative.py`. An empty channel
uses Playwright's Chromium; leaving the variable unset uses installed Chrome. Stop the server with Ctrl+C,
which removes its credential file; never point it at an operator database. For a classroom demonstration,
use the normal hidden-prompt account setup from the [developer guide](developer-guide.md), not the browser
test credentials.

`scripts/browser_check.py` and `scripts/browser_phase03.py` have been removed.

## 6. Staging agent

From `agent`: `python -m pytest -p no:cacheprovider` (ideally with `--basetemp` outside OneDrive). Levels:
unit tests (`test_labels_journal_admission.py`, `test_fsutil_cli.py`), fault injection against a stateful fake
gateway (`test_pipeline_faults.py`: 401, 403, 429, 503, timeouts, dropped connections, tampered and truncated
release bodies), the ADMIN register tool against a scripted client (`test_register_tool.py`), and real-gateway
tests (`test_gateway_integration.py`, `test_cli_ready_register.py`) that start the actual FastAPI application
over a real loopback socket with Secure cookies. The real-gateway fixture bypasses only the login throttle and
the transfer-call counter, in the test process, so a whole suite from one address does not trip them; the
fake gateway covers throttle behavior. Crash tests run the agent in a subprocess, end it with `os._exit` at
named failpoints, then restart it.

`python -B scripts/demo_agent.py [--evidence PATH]` starts a disposable gateway (temporary runtime,
generated key and credentials, synthetic corpus), runs the agent through 13 end-to-end checks, and removes
everything. `python -B scripts/source_corpus.py` checks the synthetic corpus manifest. See
[staging-spec](staging-spec.md).

## 7. Container and hosted checks

The `container` job builds the image, measures its uncompressed size (`du -sxb /` in the image) against
`IMAGE_SIZE_BUDGET_MIB` (258), checks that it refuses to start without an https origin, starts it with a
disposable SQLite database and throwaway generated secrets, and runs `scripts/smoke_public.py --expect-commit
$GITHUB_SHA`. The smoke test checks the warm-up, `/health` and the deployed commit, the hosted headers
including the enforced CSP, sign-in, an ALLOW and a BLOCK, single use, and the audit sequence. The job then
checks that the server runs as uid 10001 with `HOME=/nonexistent`, and restarts the container to prove that
bootstrap is idempotent and data survives.

After a deploy, run the same smoke test against the hosted URL ([deployment](deployment.md)). Deployed
measurements (cold start, sign-in time, client identification) are in the
[Phase 06A evidence](evidence/phase-06a.md).

## 8. Scanners and publication hygiene

In CI: `scripts/audit_publication.py` (credential patterns, private paths, generated files) in the agent
jobs, and `git diff --exit-code` after the backend, postgres, frontend and agent jobs, so a run that changes
tracked files fails.

Run during the quality review, not in CI: `bandit` and `semgrep` (Python and TypeScript static analysis),
`pip-audit` and `npm audit` (known vulnerable dependencies), `gitleaks` (secrets in history and the working
tree; `.gitleaksignore` records one reviewed false positive), `trivy` (image and configuration; `.trivyignore`
records DS002, DS031 and DS026 with reasons), `hadolint` (Dockerfile), `actionlint` and `zizmor` (workflow).
`actionlint` is not part of CI.

## 9. Security scenario matrix

| Scenario | Expected behavior | Covered by |
|---|---|---|
| Exact and renamed protected file | BLOCK; release returns no payload | `test_detection_policy.py`, `test_gateway.py`, `test_gateway_edges.py`, agent `test_gateway_integration.py` |
| Ordinary distinct file | ALLOW; returned bytes have the scanned digest | `test_gateway.py`, `test_hosted.py`, `Gateway.test.ts`, `browser_phase04.py` |
| Empty file | Scan valid; protected registration rejected | `test_detection_policy.py`, `test_gateway_edges.py` |
| Size boundaries | Correct at the upload cap; one byte over is 413 | `test_detection_policy.py`, `test_gateway_edges.py`, `test_api_security.py` |
| Single-byte change in a multiblock file | Remaining aligned blocks trigger BLOCK | `test_detection_policy.py` |
| Aligned partial copy or embedding | BLOCK at the configured threshold | `test_detection_policy.py`, agent `test_gateway_integration.py` |
| One-byte shift, line endings, encoding, compression | Documented fixed-block misses, not fake prevention | `test_detection_policy.py`, agent `test_gateway_integration.py` |
| Shared content | All implicated assets shown; no combining across assets | `test_detection_policy.py`, `test_additional_gates.py` |
| Valid and corrupt proofs | Success or failure against the registry's trusted root | `test_crypto.py`, `test_presentation.py`, `Integrity.test.tsx`, `browser_phase04.py` |
| Concurrency | Isolated decisions; overload rejected; one delivery | `test_additional_gates.py`, `test_gateway.py`, `test_gateway_edges.py`, `test_database.py` |
| Interrupted or oversized uploads | No release; cleanup; 413 for excess bytes | `test_additional_gates.py`, `test_api_security.py`, `test_gateway.py`, `test_gateway_edges.py` |
| Malformed names, links, traversal | Unsafe input refused; no escaped file access | `test_api_security.py`, `test_gateway_edges.py`, `test_hosted.py`, `test_audit.py`, agent `test_fsutil_cli.py` |
| Policy precedence, no override | Exact match wins; no role bypasses BLOCK | `test_detection_policy.py`, `test_gateway.py` |
| Unauthorized or cross-user access | Denied without evidence disclosure | `test_authorization_matrix.py`, `test_api_security.py` |
| CSRF, Origin, Host | Refused on every operation | `test_authorization_matrix.py`, `test_api_security.py`, `test_hosted.py` |
| Session fixation, expiry, logout | Client-chosen IDs never adopted; expired and ended sessions refused | `test_authorization_matrix.py`, `test_api_security.py` |
| Login guessing, client IP spoofing | Per-account, per-client and global limits; forged headers cannot pick a bucket | `test_api_security.py`, `test_client_ip.py`, `test_hosted.py`, `test_smoke_probe.py` |
| Release replay, expiry, staleness | Nothing delivered; a fresh transfer rescans | `test_gateway.py`, `test_gateway_edges.py`, agent `test_gateway_integration.py` |
| Audit edits and reordering | Verification fails without the audit key; release stops | `test_audit.py`, `test_gateway.py`, `test_gateway_edges.py` |
| Audit tail deletion | Detected against a retained checkpoint; uncheckpointed tail is a stated limitation | `test_audit.py`, `test_gateway_edges.py` |
| Audit rollback or rewrite across a restart | Refused at startup against the stored signed tree heads; detected by a witness that kept a head; a rollback that removes the heads is invisible to a party without one (stated limitation) | `test_transparency_log.py`, `test_witness.py` |
| TOCTOU mutation | Only frozen checked bytes can be delivered | `test_api_security.py`, `test_gateway.py`, agent `test_pipeline_faults.py` |
| Agent or network disconnection | No delivery on an unknown decision; idempotent retry | agent `test_pipeline_faults.py`, `test_gateway_integration.py` |
| Secrets in output | No password, token or key in logs, reports or command output | `test_operator_tools.py`, `test_hosted.py`, `test_gateway.py`, agent `test_pipeline_faults.py` and `test_fsutil_cli.py`, publication audit |
| Content Security Policy | Enforced on every response; zero violations in the browser run | `test_hosted.py`, `browser_phase04.py`, `browser_phase04_negative.py`, `smoke_public.py` |
| Copy outside the gateway | Not prevented; no gateway event is invented | No test: outside the enforcement boundary |

## 10. Benchmarks (not executed in full)

`scripts/benchmark_phase02.py --output <file>` and `scripts/benchmark_phase03.py` measured local synthetic
samples (SQLite, deterministic blocks); their results are in the Phase 02 and Phase 03 evidence. Traced Python
allocation peaks are not process RSS. Shared-host load and tracing affect timings. Deployed cold start and
sign-in time are in the Phase 06A evidence.

The full protocol below has not been executed. Use synthetic files of 0 B, 100 B, 1 KiB, 8 KiB, 1 MiB and
10 MiB. Compare fixed chunk sizes 256 B, 1 KiB and 4 KiB offline without changing the product's v1 profile.
Perform five warm-ups and thirty measured repetitions; retain raw results, environment and commit. Report
median, p95 and range, throughput, peak memory, fingerprint storage, proof size and proof verification time.
Separate cold starts.

Measure precision, recall and false positive rate against labelled ground truth. Use N/A for zero
denominators. Separate detector recall from correct enforcement of its decision: a correctly enforced ALLOW
may still be a false negative. Content-defined chunking comparisons need a real validated implementation;
no placeholder results.

## 11. Phase gate scripts (historical)

`scripts/verify_phase02.py`, `verify_phase03.py` and `verify_phase05.py` were the release gates of their
phases. They rerun the test suites and write sanitized results to `docs/evidence/phase-02-checks.json`,
`phase-03-checks.json` and `phase-05-checks.json`; `benchmark_phase03.py` writes
`docs/evidence/phase-03-benchmark.json`, and `benchmark_phase02.py` writes wherever `--output` points.
**Running them rewrites recorded evidence**: inspect the diff and discard it unless a new record is intended.
`verify_phase05.py` also checks that `backend/app`, `backend/migrations`, `docs/openapi.json` and `frontend`
are unchanged from the Phase 04 head; later phases changed those paths, so that check now fails by design.
`python -B scripts/export_openapi.py` regenerates `docs/openapi.json` after an approved API change.
