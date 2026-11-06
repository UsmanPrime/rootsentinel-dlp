# Phase 05 verification record — local staging gateway agent

Status: **local gates PASS on Windows. Hosted CI results are pending hosted CI: nothing has been pushed.**
Hosted Linux, Python 3.12, PostgreSQL and hosted Windows results do not exist yet and are not claimed.

Baseline: `3662f4fc46cc2648609cecf8fd63886fd2b78d2a` (`main` and `origin/main`, Phase 04 plus its history-correction record).
Work branch: `phase-05-candidate` (local only). Feature commit: `97558a5dab2014040e79b1328280def8fa1dd819`.
Specification: [staging-spec.md](../staging-spec.md). Threat model: [threat-model.md](../threat-model.md).
Machine-readable results: `phase-05-checks.json` (all release checks) and `phase-05-demo.json` (end-to-end demo).

## Boundary: nothing in the gateway changed

`git diff --exit-code 3662f4f… -- backend/app backend/migrations docs/openapi.json frontend` is empty, as is the diff of
`backend/app/crypto`, `backend/tests/test_crypto.py` and `fixtures/manifest.json`. No file in `backend/app` or `frontend/src`
mentions the agent (checked by `scripts/verify_phase05.py`), so the public browser workflow cannot depend on it. The only file
added under `backend/` is the test harness `backend/tests/agent_server.py`.

## Checks actually run (Windows 11, Python 3.13.4, SQLite, Node 24.11.0; recorded in `phase-05-checks.json`)

| Check | Result |
|---|---|
| Backend `python -B -m pytest -p no:cacheprovider -q` (external basetemp) | **172 passed, 606 subtests passed**, 1 warning (existing Starlette/httpx deprecation), 133 s in the verification run (108 s in an earlier run); same counts as Phase 04 |
| Agent `python -m pytest -p no:cacheprovider -q` from `agent` | **96 passed, 3 skipped** in 51 s (skips: two POSIX-only tests, one symlink test that needs a privilege this account lacks) |
| `scripts/fixtures.py` | 11 synthetic fixture manifests verified |
| `scripts/frontend_contracts.py --check` | 39 contracts verified |
| `scripts/source_corpus.py` | 8 synthetic corpus manifests verified |
| `scripts/audit_publication.py` | 194 candidates, **0 findings** (the local-only handoff file is excluded via `.git/info/exclude`) |
| Frontend `npm run typecheck`, `npm test`, `npm run build` | typecheck passed; **19 tests passed**; build passed (output to an external directory; the four existing `use client` warnings) |
| `git diff --check` | clean |
| `scripts/demo_phase05.py` end to end on a disposable gateway | **13 of 13 checks passed** in 92 s, twice (the second run produced `phase-05-demo.json`) |

## Acceptance criteria

| # | Evidence (tests are in `agent/tests`; "real gateway" means the actual FastAPI application over a loopback socket) | Result |
|---|---|---|
| 1 | `test_c1_benign_file_is_delivered_byte_identical_and_staging_is_emptied` (real gateway); demo check 3 | PASS locally |
| 2 | `test_c2_renamed_protected_copy_never_reaches_outbound_and_opens_a_high_incident`: outbound empty, quarantine report payload free, analyst sees a HIGH incident for that transfer, `POST /audit/verify` valid; demo checks 4–6 | PASS locally |
| 3 | `test_c3_…` x7: aligned two-block copy and a single aligned block are blocked (default threshold 1024); sub-threshold tail, shifted, CRLF, UTF-16 and zipped copies are **delivered and asserted as known misses**; demo check 7 | PASS locally |
| 4 | `test_c4_growing_file_is_not_submitted_until_it_is_stable`; demo check 8 (journal timestamp after the writer finished) | PASS locally |
| 5 | `test_c5_unsafe_entries_…` (hardlink, directory with nested file, empty, 10 MiB + 1, Windows junction; symlink and FIFO on POSIX) plus `test_fsutil_cli.py`; zero transfers created; demo check 9 | PASS locally; symlink and FIFO paths are POSIX-only (see CI) |
| 6 | `test_pipeline_faults.py`: submit faults 401, 429 (rate and pending cap), 503 (capacity and database), 400 incomplete upload, dropped connection and timeout; backend down; 403 origin; wrong credentials and role; release 503/STALE/consumed-then-dropped/tampered/truncated; digest lie. Nothing delivered early, one idempotency key reused, no duplicate transfer on recovery. Real gateway: `test_c6_…` (revoked session, non-EMPLOYEE account, wrong origin) | PASS locally |
| 7 | `test_c7_crash_neither_loses_nor_silently_duplicates` x6 crash points on the real gateway (`os._exit` in a subprocess, then restart): exactly one outbound copy, source kept until delivered, a spent release stays visible, audit chain verifies; demo checks 11–12 | PASS locally |
| 8 | `test_c8_stale_decision_…` (registry and policy change) and `test_c8_a_file_allowed_a_moment_ago_is_blocked…`; demo check 10 | PASS locally |
| 9 | `test_c9_kill_during_the_outbound_write_leaves_no_partial_visible_file`: nothing visible in outbound after the kill, leftover only in `state/tmp`, cleaned and delivered on restart | PASS locally |
| 10 | `test_no_credentials_cookies_or_tokens_leak_…` (password, session cookie and CSRF searched in logs, journal, reports and names), `test_cli_has_no_password_option_and_rejects_abbreviations`, credentials file rules, `scripts/audit_publication.py` 0 findings | PASS locally |
| 11 | `agent` (Ubuntu, Python 3.12 and 3.13) and `agent-windows` (Python 3.13) jobs added to `.github/workflows/ci.yml` | **pending hosted CI** |
| 12 | Backend 172 + 606 subtests, boundary diffs empty, existing five CI jobs unchanged in the workflow | PASS locally; hosted result **pending hosted CI** |
| 13 | `scripts/demo_phase05.py`, [staging-spec](../staging-spec.md), threat-model section, this file | delivered |

Linux-only, therefore **pending hosted CI**: symlink swap rejection with `O_NOFOLLOW`, FIFO, POSIX mode checks, directory fsync,
and the second-uid permission-separation test (`test_a_second_uid_can_fill_staging_but_cannot_write_outbound_while_the_agent_delivers`),
which is skipped on Windows.

## Windows file identity measured early

On this machine (Windows 11, Python 3.13.4, NTFS), before the design depended on it: `os.lstat` returns non-zero, distinct
`(st_dev, st_ino)`, stable across rename and equal to the `fstat` of an opened handle; hardlinks report `st_nlink == 2` with the
same inode; junctions have the reparse attribute `0x400`; `os.fsync` works on files but a directory handle cannot be fsynced.
`DirEntry.stat()` from `scandir` returned `st_ino == 0`, so admission uses `os.lstat` per entry and fails closed
(`IDENTITY_UNAVAILABLE`) if an inode ever reads 0. Python 3.12 on Windows was not available to test.

## Defects found by the tests during development (and fixed)

* `--once` could exit with a file unprocessed when the file changed while a cycle was running: a cycle that journaled anything now
  always triggers another scan.
* An idle agent with a wrong role or bad credentials started without complaint: it now logs in at start-up and fails fast.
* Several test-harness races and over-strict assertions were corrected (for example the report carries the sanitized label, not a path).

## Informal checks (not evidence)

A throwaway smoke of the POSIX code paths was run once inside the Kali WSL2 distribution on its own Python 3.14.7 (outside the
supported 3.12–3.13 range), using a copy of the agent in that distribution's temporary directory, later removed: descriptor-relative
listing, symlink-swap rejection, no-overwrite rename, private-mode enforcement, credentials mode 0600, directory fsync, instance lock
and an end-to-end deliver/quarantine all behaved as designed. This is only an early signal; hosted Linux CI is the proof.

## Not done, pending, and limitations

* **Pending hosted CI:** hosted Linux, Python 3.12, PostgreSQL and hosted Windows results. No commit has been pushed.
* Nothing from the cut list was cut (`requeue`, `status`, `--require-ready` and the Windows job are all implemented).
* The agent does not verify the DACL of the credentials file on Windows; the file is **not** claimed to be ACL protected.
* No operating-system-wide interception: USB, e-mail, clipboard, other applications and direct copying are not covered; Windows
  permission separation between staging and outbound is an operator step and cannot be shown on a one-user machine.
* Fixed-block limits: shifted, re-encoded, compressed or archived copies and below-threshold copies are delivered (asserted).
* Stability polling cannot tell a paused writer from a finished one; files over 10 MiB and nested folders are never scanned.
* Timings from the demo (about one second per file including process start-up) are single local runs, not a benchmark.
* `scripts/verify_phase05.py` leaves its temporary directory in the system temp folder; delete it manually.
* A persistent local setup (keys, users, credentials, `%LOCALAPPDATA%\RootSentinel\phase05`) was deliberately **not** created; the
  exact commands are in [staging-spec](../staging-spec.md) for the operator to run.
