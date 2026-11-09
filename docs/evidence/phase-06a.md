# Phase 06A verification record: hosted presenter demo

Status: **deployed and smoke-tested (15 of 15 checks) at https://rootsentinel-dlp.onrender.com. Per-client login throttling is
NOT yet working on the host**: hop counts 1 and 2 failed, and the new single-address header option is **LIVE VERIFICATION PENDING**
until the Part B probe results are added. Deploy logs, plan limits, cold-start boot times and environment variable names were read
from the Render and Neon dashboards. Peak memory, Neon scale-to-zero and whether a card is required are still not verified; the
reasons are given below.

Stage 2 branch: `chore/phase-06a-close` from `origin/main` at `569295aea10264db872d5ed2988ca10c2af670e7` (CI run `42576611571`,
9 of 9 jobs). Stage 1 (local gates, before deployment) is kept unchanged at the end of this file. Procedure:
[deployment.md](../deployment.md). Threat model: [threat-model.md](../threat-model.md).

**Sources used below.** *Operator*: measured live by the project owner and reported for this record. *Probe*: measured by
the scripted, credential-free requests from the development machine described here. *CI*: read from a GitHub Actions log.
*Code*: read from the repository at this branch. *Dashboard*: read by Claude, read only, from the owner's signed-in Render and
Neon tabs on 2026-11-09 between 11:27 and 11:32 UTC. Nothing was edited, deployed, restarted or revealed, and no billing page
was opened. The dashboards show local time (GMT+5); every time below is converted to UTC. Values are recorded here as text; no
screenshots are kept in the repository.

## Deployment configuration

| Item | Value | Source |
|---|---|---|
| Web service | Render free instance, Docker runtime (this repository's `Dockerfile`), Blueprint managed, deploys `main` (live commit `569295a`) | Dashboard (service header); `render.yaml` (`plan: free`, `runtime: docker`) |
| Web service region | Singapore | Operator (not shown on the pages read) |
| Plan limits | memory **512 MB**, CPU **0.15** | Dashboard (Metrics page, "Limit") |
| Database | Neon **Free plan**, region **AWS Asia Pacific 1 (Singapore)**; one branch `production`; primary compute autoscaling **0.25 to 2 CU** | Dashboard (Neon project and Computes pages) |
| Database version and endpoint | PostgreSQL 17, **direct** (non-pooled) endpoint | Operator (the connection string was not read) |
| Neon scale to zero (autosuspend) | **not verified**: shown only inside the compute's Edit dialog, which was deliberately not opened | |
| Environment variable names | `ROOTSENTINEL_DATABASE_URL`, `ROOTSENTINEL_MAX_UPLOAD_BYTES`, `ROOTSENTINEL_MODE`, `ROOTSENTINEL_ORIGIN`, `ROOTSENTINEL_RETENTION_SECONDS`, `ROOTSENTINEL_SESSION_SECONDS`, `ROOTSENTINEL_TRANSFER_RATE_PER_MINU…` (name cut off on screen), `ROOTSENTINEL_TRUSTED_PROXY_HOPS`. **No `HOME`** and no `ROOTSENTINEL_CLIENT_IP_HEADER`. Values were not revealed | Dashboard (Environment page, names only) |
| Deploy trigger | `branch: main`, `autoDeployTrigger: checksPass` | `render.yaml` |
| Branch protection | ruleset `protect-main` (id 26833962), active on the default branch: no deletion, no non-fast-forward, 9 required checks: `backend (3.12)`, `backend (3.13)`, `browser`, `postgres`, `frontend`, `agent (3.12)`, `agent (3.13)`, `agent-windows`, `container` | GitHub API, 2026-11-09 |
| Edge in front of Render | responses carry `Server: cloudflare`, a `CF-RAY` header, `rndr-id` and `x-render-origin-server: uvicorn` | Probe, `GET /`, 2026-11-09T10:26:51Z |
| Health body | `{"status":"ok","mode":"local","release_configured":true}` | Probe, same time |
| `ROOTSENTINEL_TRUSTED_PROXY_HOPS` | `render.yaml` sets `"0"`; the hop trials below changed it in the dashboard | `render.yaml`; Operator |
| `ROOTSENTINEL_CLIENT_IP_HEADER` | not in `render.yaml` on purpose: the dashboard is the single source for it | this record |

## The two deploy failures

**Dashboard verified** from the Render deploy list (8 deploys) and both deploy logs. Both failures are on commit `6277f0e`.

| Deploy | Trigger | Started (UTC) | Duration | Result |
|---|---|---|---|---|
| `dep-dbomlpvf3r2c73blnktg` | Blueprint | 06:40:39 | 40.3 s | failed, "Exited with status 1" (failure 1) |
| `dep-dbomomdg1s2s73fmp41g` | Manual | about 06:46 | 26.7 s | failed, "Exited with status 1" (failure 2) |
| `dep-dbompqpsrm7s73cfnetg` | Manual | 06:49:15 | 1 min 22 s | first successful deploy |
| four further deploys | health check path change, Auto-Deploy, Manual x2 | 06:52 to 09:44 | 57.7 s to 1 min 4 s | all succeeded |
| `dep-dbopeadg1s2s73fuhmsg` | Manual, `569295a` | 09:49:29 | 1 min 3 s | succeeded, **live** |

1. **Audit key secret file not found.** The first deploy ran before the `audit-keys.json` secret file was uploaded. The log shows
   `rootsentinel: the audit key secret file was not found; upload it as a secret file (see docs/deployment.md)` at 06:41:17 and
   06:41:19, then `Exited with status 1` (`docker/entrypoint.sh`, line 30). This is the intended fail-closed behaviour, not a
   defect. Fix: upload the secret file (deployment checklist step 5).
2. **libpq: `could not open certificate file "/root/.postgresql/postgresql.crt": Permission denied`.** Logged at 06:47:24 for
   both IPv4 addresses of the Neon host, followed by the SQLAlchemy error link and the instance restart. The entrypoint starts as
   root, then drops to uid 10001 with `setpriv`, which does not change environment variables, so the server inherited `HOME=/root`.
   libpq looks for an optional client certificate under `$HOME/.postgresql/`. A missing file (ENOENT) is skipped, but a refused one
   (EACCES, because uid 10001 cannot enter `/root`) is fatal. Fix in code: every command run as uid 10001 gets
   `HOME=/nonexistent`, the same as its passwd entry (commit `c79a445`). CI regression (commit `569295a`, `container` job): reads the
   server's own environment as uid 10001 and asserts `HOME=/nonexistent`; checks that the application variables still reach it;
   checks that the certificate path gives `FileNotFoundError`; and has a **negative control** where the same stat with `HOME=/root`
   must give `PermissionError`, which proves the check can fail. A temporary dashboard `HOME` variable was used as a workaround
   before the code fix. **Dashboard verified: removed** (no `HOME` among the environment variable names).

**IPv6 lines in the logs.** Dashboard verified, partly. In failure 2 the same libpq error lists three IPv6 addresses of the Neon
host, each with `connection is bad: ... Network is unreachable`, next to the two IPv4 addresses that failed with the certificate
error. So the instance has no IPv6 route and the IPv4 attempts were the ones that reached the server. In the successful deploy
logs and in the application logs read (10:26 to 11:23 UTC) **no** IPv6 line appears: libpq reports the per-address errors only
when every address fails. The operator's "IPv6 lines followed by a successful connection" was therefore **not seen** in any log
that was read; it is plausible but not verified.

## Startup facts

Dashboard verified from the deploy logs:

| Deploy | Bootstrap | Checkpoint | Live |
|---|---|---|---|
| First successful (`6277f0e`, 06:49:15) | `accounts: created=3 updated=0 unchanged=0` (06:50:05); `assets: seeded=1 existing=0` (06:50:10) | anchored for this container run (06:50:11) | "Your service is live" 06:50:37, primary URL `https://rootsentinel-dlp.onrender.com` |
| Latest live (`569295a`, 09:49:29) | `accounts: created=0 updated=0 unchanged=3` (09:50:08); `assets: seeded=0 existing=1` (09:50:09) | anchored (09:50:10) | 09:50:32 |

Correction to the earlier operator note: `created=3` and `seeded=1` come from the **first** successful deploy, not the latest. The
latest deploy and every cold start below report `unchanged=3` and `existing=1`, which shows the bootstrap is idempotent against the
same Neon database. Each new container anchors its own checkpoint (they are not durable across restarts). Render logs
`Setting WEB_CONCURRENCY=1 by default, based on available CPUs in the instance`. The probe confirms the service answers at that URL
with `mode: local` and `release_configured: true` (table above).

## Smoke test on the live service (Operator, 15 of 15 PASS)

`python -B scripts/smoke_public.py --base-url https://rootsentinel-dlp.onrender.com --username presenter-analyst`

| # | Check | Result |
|---|---|---|
| 1 | warm-up: `/health` answered | PASS (warm service: 1.3 s) |
| 2 | gateway reports local mode with release configured | PASS |
| 3 | HSTS header present | PASS |
| 4 | CSP (report-only) header present | PASS |
| 5 | API documentation is not published | PASS |
| 6 | frontend is served from the same origin | PASS |
| 7 | anonymous API access is denied | PASS |
| 8 | sign in (Argon2id verification time included) | PASS (2.67 s) |
| 9 | session cookie is HttpOnly, Secure and SameSite=Strict | PASS |
| 10 | benign fixture is ALLOWED | PASS |
| 11 | released bytes match an independently computed SHA-256 | PASS |
| 12 | a second release is refused (single use) | PASS |
| 13 | protected fixture is BLOCKED | PASS |
| 14 | release of the blocked transfer delivers nothing | PASS |
| 15 | sign out | PASS |

## Measurements

| Measurement | Value | Source and time |
|---|---|---|
| Sign-in time, live (Argon2id t=3, m=64 MiB, p=4) | 2.67 s | Operator, smoke test |
| Sign-in time, CI container | 0.05 s (earlier run); 0.06 s in run `42601238590` | Operator; CI log 2026-11-09T10:30:08Z |
| Warm-up, warm service | 1.3 s | Operator, smoke test |
| Cold start | see the next table | Probe |
| Peak memory, 24 h and 10:27 to 11:22 UTC | **not verified**: the Render Metrics page shows only the limits; it says memory and CPU usage need a paid compute plan | Dashboard |
| Plan memory and CPU | 512 MB and **0.15 CPU** (an earlier secondary source said 0.1 CPU) | Dashboard (Metrics page) |
| Request logs | not available: the "Request logs" option is disabled on this plan | Dashboard (Logs page) |
| Card required, Render / Neon | **pending, from operator** (billing pages are deliberately not browsed) | |
| Image size, uncompressed | 224,987,716 bytes = 214.6 MiB (`du -sxb /` inside the image) | CI run `42601238590`, commit `fc5aae8` |
| Image size, compressed content | 63,874,048 bytes (`docker save`, containerd image store) | CI run `42598215274`, commit `5126399` |
| Image size budget | 258 MiB uncompressed = ceil(214.57 x 1.2), enforced in the `container` job | `.github/workflows/ci.yml` |

`docker image inspect .Size` is 63,850,634 to 63,850,805 bytes in the same runs. On the runner's containerd image store both it and
`docker save` report compressed layer content, which is why the budget uses `du -sxb /`.

**Image size breakdown (uncompressed).** Local Docker Desktop (Linux engine 29.6.1) build of commit `e4195f7` with the same
Dockerfile and no build arguments, as in CI; base `python:3.13-slim` at digest
`sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`; every value is `du -sxb` inside a container,
2026-11-09 about 10:48 UTC. The local total equals the CI total to the byte (224,987,716 bytes): the build is reproducible across the two machines.

| Part | Bytes | MiB | Share |
|---|---|---|---|
| Base image (`python:3.13-slim`, whole filesystem, including its own 5,695,244 bytes of site-packages) | 114,790,742 | 109.5 | 51.0 % |
| Python packages added by `backend/requirements.lock` (site-packages 115,303,994 minus the base's 5,695,244) | 109,608,750 | 104.5 | 48.7 % |
| Frontend build (`/opt/rootsentinel/frontend`) | 409,785 | 0.4 | 0.2 % |
| Application code (`/app/backend`) | 168,507 | 0.2 | 0.1 % |
| Other (entrypoint, account and directory changes; the remainder) | 9,932 | 0.0 | 0.0 % |
| **Total** | **224,987,716** | **214.6** | |

Largest site-packages entries: `psycopg_binary.libs` 52,919,471 bytes (the bundled libpq and OpenSSL), `sqlalchemy` 22,533,895,
`psycopg_binary` 8,629,410, `pip` 5,545,809, `pydantic_core` 5,408,907, `pydantic` 3,760,948. Nearly all the size is the Python
runtime and the PostgreSQL driver; the application and the frontend are under 1 MiB together.

### Cold start

Probe: `cold_start.py` (credential-free, development machine). Before each run it sent nothing to the service for 17 minutes
(1,020 s; the previous request from this machine ended before each idle window began), then started `GET /health` and `GET /`
in parallel at the same instant. Each retries every 3 s until the first HTTP 200; every request below succeeded on the first
attempt, so the time is one long request held open while the instance started. All times UTC, 2026-11-09.

| Run | Idle window from | First request | `/health` 200 at | `/health` | `/` (frontend index) 200 at | `/` | Validity |
|---|---|---|---|---|---|---|---|
| 1 | 10:27:13.764 | 10:44:13.765 | 10:45:05.686 | **51.92 s** | 10:45:06.297 | 52.53 s | valid (inferred, see below) |
| 2 | 10:45:06.299 | 11:02:06.318 | 11:03:08.980 | **62.66 s** | 11:03:08.977 | 62.66 s | valid (inferred, see below) |
| 3 | 11:03:09.000 | 11:20:09.002 | 11:21:01.994 | **52.99 s** | 11:21:02.005 | 53.00 s | valid (inferred, see below) |

`/health`: median 52.99 s, maximum 62.66 s (no average is given). An earlier unplanned request at 10:25:54Z also took 51.9 s, but
its idle time is unknown, so it is not counted.

**Where the time goes (Dashboard, Render application logs, whole seconds).** Offsets are from the probe's first request.

| Run | Previous instance shut down | Instance | First container line (bootstrap result) | `Started server process` | `Uvicorn running` | `/health` 200 (probe) |
|---|---|---|---|---|---|---|
| 1 | 10:41:53 (`nf6ph`) | `4d6z8` | 10:44:41 (+27 s) | 10:44:55 (+41 s) | 10:44:59 (+45 s) | +51.9 s |
| 2 | 11:00:07 (`4d6z8`) | `12wh7` | 11:02:38 (+32 s) | 11:02:55 (+49 s) | 11:03:00 (+54 s) | +62.7 s |
| 3 | 11:18:09 (`12wh7`) | `1bn65` | 11:20:40 (+31 s) | 11:20:56 (+47 s) | 11:21:01 (+52 s) | +53.0 s |

* 27 to 32 s pass before the container prints anything. This covers instance start, image start, the Alembic migrations and the
  bootstrap, which both connect to Neon. The logs do not separate these, so the Neon wake-up share is **not verified**.
* 14 to 17 s pass between the bootstrap result and `Started server process` (checkpoint anchoring and importing the application on
  0.15 CPU), then 4 to 5 s until uvicorn is ready.
* 1 to 9 s pass between `Uvicorn running` and the probe's 200 (Render's routing to the new instance). The log has one-second
  resolution, so this part is approximate.

**Why the runs are counted as valid.** Render's request logs are not available on this plan, so other traffic cannot be read
directly. The application logs rule it out indirectly. The instances that served runs 1 and 2 shut down 15 min 1 s and 15 min 0 s
after the probe's own last request (10:45:06 to 11:00:07, and 11:03:09 to 11:18:09), and the instance before run 1 shut down at
10:41:53, about 15 min after the probe's earlier requests. A request from anyone else during an idle window would have done one of
two visible things: kept the instance up past that point, or started a new instance before the probe's request. The logs show
neither. Each new instance's first line comes 27 to 32 s after the probe's request, with no log line in between. This is an
inference from the logs, not a request-level record.

## Client identification for the login limiter

**What the limiter does (Code, `backend/app/auth.py`).** Three 60 s windows: 30 attempts for everyone together, 15 per client key,
5 per user name. Each now answers 429 with its own code:
`LOGIN_RATE_LIMIT_GLOBAL`, `LOGIN_RATE_LIMIT_CLIENT`, `LOGIN_RATE_LIMIT_ACCOUNT`. The status and body shape are unchanged; the old
single code was `LOGIN_RATE_LIMIT`, and the frontend and agent react to the status, not the code. At most two Argon2id
verifications run at once; a third concurrent sign-in gets 503 `LOGIN_CAPACITY` at once (it is not queued).

**The account code does not reveal whether an account exists.** The limiter runs before the database is queried and keys the
account window on a digest of the submitted name. Names must already be canonical (`^[a-z0-9][a-z0-9_.-]*$`, 3 to 64
characters); any other spelling is rejected with 422 before the limiter, so one account cannot get two buckets. A test sends five
wrong passwords for an existing and for a nonexistent name: both then get the identical 429 `LOGIN_RATE_LIMIT_ACCOUNT` body
without a cookie, and the correct password is also refused while the window is full.

**Hop trials (Operator, live).** The probe sends 16 wrong-password sign-ins with unique user names from one network. With a working
client key the 16th gets 429. The dashboard confirms `ROOTSENTINEL_TRUSTED_PROXY_HOPS` exists as a dashboard variable (its value
was not revealed) and that `ROOTSENTINEL_CLIENT_IP_HEADER` is **not** set on the host.

| `ROOTSENTINEL_TRUSTED_PROXY_HOPS` | Result from one network | Verdict |
|---|---|---|
| 1 | 16 x 401, 0 x 429 | FAILED |
| 2 (dashboard, redeployed) | 16 x 401, 0 x 429 | FAILED |

**Why hop counting was abandoned.** With a fixed number of trusted proxies that each append their peer, the entry N places from
the right of `X-Forwarded-For` is the real client. On Render the per-client window never filled, so the selected entry changed
between requests from the same client. Working hypothesis, **not verified**: Render keeps a client-sent `X-Forwarded-For` and the
path through Cloudflare and Render's proxies does not append a fixed number of entries. The Cloudflare headers in the probe above
support the "Cloudflare in front" part only. Hop counting gives no reliable client key here; the proposal below sets it back to 0.

**The header option (this branch).** `ROOTSENTINEL_CLIENT_IP_HEADER` (default empty, which keeps the earlier behaviour exactly):

* The client key is that one header, used only when it appears exactly once and holds exactly one valid IPv4 or IPv6 address.
  IPv4-mapped IPv6 becomes IPv4; zone identifiers, ports, lists and anything else are rejected.
* Missing or invalid values all share one `unidentified` key, so a forged value can never choose its own bucket. The count is
  logged at 1, 10, 100 and so on, without the raw value.
* `X-Forwarded-For` is ignored in this mode. Startup refuses the header together with nonzero hops; the header name must match a
  strict token pattern. The error messages do not echo the configured value.
* uvicorn runs with `--no-proxy-headers` on both start lines of the entrypoint (a test checks this), so it never rewrites the
  client address before the app sees it; the app is the only place that decides.

**Threat assumptions.** This is only correct if Cloudflare fronts **every** request that reaches the service at
`rootsentinel-dlp.onrender.com` and overwrites `True-Client-IP` with the address it saw. Any path to the service that skips that
edge lets a client choose its own key. A local test shows the risk: without an edge, a spoofed `True-Client-IP` on each request
gives 16 x 401. The live spoofed probe is the deciding test. If it is not limited, the header is not trustworthy and must be removed
(back to hops 0). **LIVE VERIFICATION PENDING.**

**What still protects sign-in if per-client throttling cannot be made to work (Code).** The global limit of 30 per minute; the
5 per minute per user name limit, independent of addresses (which also lets anyone lock a known name out for a minute); at most two
concurrent Argon2id verifications; the Argon2id cost itself; the same work and the same `INVALID_CREDENTIALS` answer for unknown and
known names. With no per-client key, one client can use up the global limit and block everyone's sign-in for up to a minute.

**Probe procedure.** `scripts/smoke_public.py --probe-login-throttle` with `--wait-seconds 65` before each run, because a run
fills the per-client window for 60 s and three back-to-back runs would exceed the global limit of 30.
`--spoof-client-ip-headers` forges random `True-Client-IP`, `CF-Connecting-IP` and `X-Forwarded-For` on every request.
`--expect limited` passes only on fifteen 401 then a 429 with code `LOGIN_RATE_LIMIT_CLIENT`; `--expect unlimited` passes only on
sixteen 401; any 429 with another code is reported as inconclusive (exit 2), never as a pass.

## Security versus usability

* **Argon2id cost.** 2.67 s per sign-in on the free instance against 0.05 to 0.06 s in CI. Two verifications can run at once, so
  in a class where many people sign in together, people beyond two get 503 `LOGIN_CAPACITY` and must retry. Sign-ins should be
  staggered. The cost was not lowered: it is what makes a stolen hash file expensive to attack.
* **Shared addresses.** A class behind one NAT shares one client key (15 per minute) whatever identification is used, and all
  users share the global 30 per minute.
* **Visitor mode** remains out of scope. Whether to add an anonymous synthetic-only visitor mode is a Phase 06B decision.

## Hosting limitations

* Audit checkpoints and snapshots live on the container's ephemeral disk and are lost on every restart or deploy: the audit chain
  is tamper evident within one container lifetime only.
* The free instance sleeps after idling; the first request then waits for a cold start (table above).
* One uvicorn worker by design (the limiters, processing slots and audit ordering assume a single process).
* **Demo day:** do not push to `main` (every push that passes CI redeploys and restarts the service). Open the site about 10
  minutes before presenting so the service and Neon are awake.

## Deferred to Phase 06B

* A visible "LOCAL" badge on the public site (to show which mode the page is in).
* The visitor-mode decision above.

## Stage 2 changes and checks

| File | Purpose |
|---|---|
| `backend/app/settings.py` | `client_ip_header` setting: token validation, lowercase, refuses nonzero hops |
| `backend/app/api.py` | `header_client` and the shared `unidentified` key in the request guard; hop path unchanged |
| `backend/app/auth.py` | one 429 code per login limit |
| `backend/tests/test_client_ip.py` | 39 new tests (parsing, forged headers ignored, shared bucket, startup refusal, no value echo, uvicorn flags, 429 codes, no account enumeration) |
| `scripts/smoke_public.py` | `--spoof-client-ip-headers`, `--expect`, `--wait-seconds`, inconclusive on a non-client 429 |
| `.github/workflows/ci.yml` | image size step inside the existing `container` job (job names unchanged) |
| `docs/deployment.md`, `README.md`, this file | documentation |

Checks run for stage 2 (Windows 11, project venv, SQLite): backend `pytest` **270 passed, 1 skipped, 606 subtests passed**;
agent `pytest` **96 passed, 3 skipped** (unchanged); `scripts/audit_publication.py` 0 findings; `git diff --check` clean; workflow
parsed with PyYAML and `actionlint` 1.7.12 exit 0. A mutation that disables header mode makes two of the new tests fail. The probe
was run end to end against a real local uvicorn server: per-client 429 gives PASS or FAIL as expected, a global 429 gives
INCONCLUSIVE (exit 2). Hosted CI on this branch: runs `42597528426` (`6206b52`), `42598215274` (`5126399`) and `42601238590`
(`fc5aae8`), each 9 of 9 jobs successful.

---

## Stage 1 record (local gates before the first deploy, unchanged)

Stage 1 status at the time: **local gates PASS on Windows. Hosted CI is pending hosted CI. Nothing has been deployed and no deployed measurement
exists** (cold start, memory on the host, login time on the host and the right trusted-proxy hop count are all still to be measured).
Docker is not available on the development machine, so the image was never built locally and the CI `container` job is the first
place it will be built and run.

Baseline: `c0a1669d0e399dd5774d916b5c0d735e6c6a4783` (`main`, Phase 05 published). Work branch: `phase-06a-candidate`.
Feature commit: `809205e3b5e7dd39ce818d438528bd473b030328`. Procedure and the steps only the operator can do:
[deployment.md](../deployment.md). Threat model: [threat-model.md](../threat-model.md).

### Scope and decisions

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

### Checks actually run (Windows 11, Python 3.13.4, SQLite, Node 24.11.0)

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

#### What the new tests prove (hosted configuration, real application, synthetic data)

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

#### Local simulation of the container flow (not Docker, not a deployed measurement)

Using the same steps the entrypoint performs, on this machine: generated key, hash file made with `make_account_hashes.py`,
`alembic upgrade head`, `bootstrap` twice (first `created=1`, `seeded=1`; second `unchanged=1`, `seeded=0 existing=1`), `uvicorn` with
the hosted settings, then `smoke_public.py` against it with the https origin emulated: **14 checks PASS** (warm-up, local mode with
release configured, HSTS, CSP-report-only, docs not published, frontend served, anonymous 401, sign-in, cookie flags, benign ALLOW,
byte-identical release by independent SHA-256, second release refused, protected BLOCK, blocked release delivers nothing),
audit sequence 15, sign-out. The server logged four start-up lines and nothing else. The login probe printed fifteen 401 then 429.
Timings from that run (warm-up 1.6 s, sign-in 0.12 s) are from a local process and say nothing about Render.

### Pending hosted CI, not yet run

* All jobs on the new branch, including the new `container` job (image build, refusal without an https origin, container start,
  smoke test, server uid 10001, restart and idempotent bootstrap) and the new tests on Linux, Python 3.12 and PostgreSQL.
* The Dockerfile, entrypoint and `render.yaml` have never been built or validated by Docker or Render.

### Risks and limitations

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
