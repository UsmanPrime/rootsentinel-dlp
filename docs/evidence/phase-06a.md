# Phase 06A verification record — hosted presenter demo, stage 1

Status: **local gates PASS on Windows. Hosted CI is pending hosted CI. Nothing has been deployed and no deployed measurement
exists** (cold start, memory on the host, login time on the host and the right trusted-proxy hop count are all still to be measured).
Docker is not available on the development machine, so the image was never built locally and the CI `container` job is the first
place it will be built and run.

Baseline: `c0a1669d0e399dd5774d916b5c0d735e6c6a4783` (`main`, Phase 05 published). Work branch: `phase-06a-candidate`.
Feature commit: `809205e3b5e7dd39ce818d438528bd473b030328`. Procedure and the steps only the operator can do:
[deployment.md](../deployment.md). Threat model: [threat-model.md](../threat-model.md).

## Scope and decisions

* Stage 1 only: an authenticated, presenter-driven demonstration. **No visitor mode, no anonymous session, no fixture catalogue.**
* The hosted app runs with `ROOTSENTINEL_MODE=local` over an `https://` origin; `Settings.hosted` is derived from the scheme. This
  is the least invasive choice: `mode` gates only the `public_demo` blanket denial, the account CLI, the loopback cookie exemption
  and two reporting fields. `public_demo` is not weakened (tested). Reasoning in deployment.md.
* No file in `backend/app/crypto`, `detection.py`, `policy.py`, `scans.py`, `transfers.py`, `snapshots.py`, `audit.py`,
  `private_files.py`, `models.py`, `incidents.py`, `registry.py`, `backend/migrations` or `docs/openapi.json` changed (empty diff
  against the baseline; the regenerated schema has the same 29 paths and no diff). The changed backend files are `api.py`,
  `gateway_api.py` (the transfer limiter's two limits became constructor arguments, same defaults), `settings.py`, plus the new
  `bootstrap.py` and `static_site.py`.
* Frontend: only a visible notice (login card and footer): use synthetic files only, never upload confidential data. No contract
  regeneration was needed.
* CSP: the built `index.html` has no inline script or style. The only inline styles are four React `style` props
  (`Evidence.tsx`, `Integrity.tsx`, two in `Overview.tsx`), so the report-only policy uses `style-src 'self'` plus
  `style-src-attr 'unsafe-inline'`. It is **report-only** and not enforced.

## Checks actually run (Windows 11, Python 3.13.4, SQLite, Node 24.11.0)

| Check | Result |
|---|---|
| Backend `pytest -p no:cacheprovider -q` (external basetemp) | **231 passed, 1 skipped, 606 subtests passed**, 185 s. The 172 earlier tests and 606 subtests are unchanged; 59 tests are new (`test_hosted.py`); the one skip is a symlink test that needs a privilege this account lacks (runs on Linux CI) |
| Agent `pytest` from `agent` | **96 passed, 3 skipped** (same as Phase 05) |
| Frontend `npm run typecheck`, `npm test`, `npm run build` | typecheck passed; **19 tests passed**; build passed (external output directory; initial bundle 291 kB, 94 kB gzip) |
| `scripts/fixtures.py`, `scripts/source_corpus.py`, `scripts/frontend_contracts.py --check` | 11 manifests, 8 manifests, 39 contracts verified |
| `scripts/export_openapi.py` | 29 paths, `docs/openapi.json` unchanged |
| `scripts/audit_publication.py` | 208 candidates, **0 findings** (before this record was added) |
| `git diff --check` | clean |
| Boundary diff against the baseline (protected files and migrations) | empty |

A mutation check (making `forwarded_client` ignore the header) made the spoofing test fail, so that test discriminates.

### What the new tests prove (hosted configuration, real application, synthetic data)

Settings validation and unchanged defaults; frontend served with SPA fallback; `Cache-Control: no-store`, nosniff, frame denial,
HSTS and CSP-report-only on every hosted response and none of them on plain local http; unknown files and `/api` paths give typed
JSON 404; seven traversal attempts cannot read a file outside the frontend directory; interactive docs and `/openapi.json` are off
when hosted and in `public_demo`; Host and Origin checks apply to static files and extra hosts are exact; **all 32 anonymous
route/method pairs answer 401 and the only routes outside `/api/v1` are `/health` and the frontend catch-all**; `public_demo` still
denies every API route; `forwarded_client` (hop count, spoofing, fail-closed fallbacks) and its effect on the login limit; the
upload cap, session lifetime, retention and rate overrides; `bootstrap` (idempotent, hash-only input, rotation revokes sessions,
disable, invalid and unsafe files, no secret in output, one audit event and a checkpoint); and the four invariants in the hosted
configuration: a scan ALLOW is not a release credential, release is single use and owner-only, a BLOCK never delivers, and a
tampered audit chain stops the release (503, nothing consumed).

### Local simulation of the container flow (not Docker, not a deployed measurement)

Using the same steps the entrypoint performs, on this machine: generated key, hash file made with `make_account_hashes.py`,
`alembic upgrade head`, `bootstrap` twice (first `created=1`, `seeded=1`; second `unchanged=1`, `seeded=0 existing=1`), `uvicorn` with
the hosted settings, then `smoke_public.py` against it with the https origin emulated: **14 checks PASS** (warm-up, local mode with
release configured, HSTS, CSP-report-only, docs not published, frontend served, anonymous 401, sign-in, cookie flags, benign ALLOW,
byte-identical release by independent SHA-256, second release refused, protected BLOCK, blocked release delivers nothing),
audit sequence 15, sign-out. The server logged four start-up lines and nothing else. The login probe printed fifteen 401 then 429.
Timings from that run (warm-up 1.6 s, sign-in 0.12 s) are from a local process and say nothing about Render.

## Pending hosted CI, not yet run

* All jobs on the new branch, including the new `container` job (image build, refusal without an https origin, container start,
  smoke test, server uid 10001, restart and idempotent bootstrap) and the new tests on Linux, Python 3.12 and PostgreSQL.
* The Dockerfile, entrypoint and `render.yaml` have never been built or validated by Docker or Render.

## Risks and limitations

* On Render's free tier checkpoints and snapshots are lost on restart: the audit chain is tamper evident within one container
  lifetime only, with no forensic claim (deployment.md, "Audit integrity on a hosted free tier").
* Vendor facts not verified: Render's free CPU and memory, whether a card is required, secret-file permissions (the entrypoint
  copies the files to 0600 for this reason), whether the Neon pooler works with prepared statements (the direct endpoint is
  documented), which Render regions exist, and Render's Blueprint schema for the exact keys in `render.yaml`.
* The trusted proxy hop count is unknown until measured; the default 0 ignores `X-Forwarded-For`, which makes every visitor share
  the proxy's address for the login limit. A classroom behind one NAT shares one address regardless.
* Neon's free compute allowance (100 CU-hours per month per its plan page) lasts about 17 days at 0.25 CU if the service is kept
  awake, because the app queries the database once a minute.
* The 0.1 CPU Argon2id cost (64 MiB, 3 passes, 4 lanes, two concurrent slots) and total memory on the free instance are unmeasured.
* `bootstrap` treats the accounts file as the source of truth only for the accounts it lists; it does not delete accounts.
* The notice asking for synthetic files is a reminder, not a control; real data uploaded by an authenticated user is retained as
  hashes and a label in the database.
* No push to `main`, no tag and no deployment has been performed.
