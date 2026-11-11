# Local operation and hosted deployment

The gateway runs locally for development and the staging agent, and as a hosted presenter demo
on Render with a Neon PostgreSQL database (see the hosted section below). The hosted demo is an
authenticated-only configuration: there is no anonymous access. `public_demo` remains fail-closed
for all `/api/v1` routes. The authenticated fixture-selection endpoint performs real processing;
it is not anonymous demo isolation. No arbitrary forwarding URL exists. The local staging agent
is a separate client process documented in [staging-spec.md](staging-spec.md), including its
provisioning commands; it does not change this service's configuration.

## Local operation

Keep source in the confirmed project folder. Use the existing external Python environment
and runtime configuration described in [developer guide](developer-guide.md). Keep database,
snapshots, keys, checkpoints, staging payloads and high-volume artifacts outside OneDrive.
Do not use synchronization permissions as a gateway security boundary.

Example PowerShell, from the backend directory with the isolated Python environment active:

```powershell
$env:ROOTSENTINEL_MODE = 'local'
$env:ROOTSENTINEL_ORIGIN = 'http://127.0.0.1:5173'
$env:ROOTSENTINEL_SECURE_COOKIES = 'false' # loopback local mode only
$env:ROOTSENTINEL_RUNTIME_ROOT = Join-Path $env:LOCALAPPDATA 'RootSentinel\runtime'
$env:ROOTSENTINEL_ARTIFACT_ROOT = Join-Path $env:LOCALAPPDATA 'RootSentinel\artifacts'
$env:ROOTSENTINEL_AUDIT_KEY_FILE = Join-Path $env:LOCALAPPDATA 'RootSentinel\audit-secrets\audit-keys.json'
$env:ROOTSENTINEL_CHECKPOINT_ROOT = Join-Path $env:LOCALAPPDATA 'RootSentinel\trusted-checkpoints'
$env:ROOTSENTINEL_TRANSPARENCY_KEY_FILE = Join-Path $env:LOCALAPPDATA 'RootSentinel\audit-secrets\transparency-key.json'
python -m app.audit_keys init $env:ROOTSENTINEL_AUDIT_KEY_FILE
python -m app.audit_keys init-transparency $env:ROOTSENTINEL_TRANSPARENCY_KEY_FILE
python -m alembic upgrade head
python -m app.cli --help
python -m uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log --no-proxy-headers
```

Run both key commands once, not on every restart. The second creates the Ed25519 key that signs audit tree heads; without
it nothing can be submitted for release. Bootstrap an account using the existing CLI's
interactive password prompt; do not embed credentials in commands/history/Git. Use secure
cookies and HTTPS in any non-loopback environment. `.env.example` contains only
configuration names, not operational secrets. Environment variables inject the private
keyring location; the file supplies persistent key material. The hosted demo receives the
same keyring file as a platform secret file without any change to the HMAC format.

Before upgrading an existing database, stop the API, securely back up the database and
retain keys/checkpoints separately. Alembic 0002 adds six tables and immutable-history
triggers, preserving Phase 02 tables/data. Downgrade drops Phase 03 evidence and must only
be used on disposable tests or after explicit operator approval. Do not downgrade production
evidence. New migration/upgrade/round-trip checks run on disposable test databases.

Windows ACLs must grant access only to the current account, SYSTEM and administrators
(owner rights are supported). Broad or unknown access grants fail closed. POSIX directories
must be 0700 and private files 0600. The application does not change existing system-wide
permissions. Resolve unsafe locations by provisioning an approved private application
directory, not by weakening the checks.

The process performs bounded startup recovery and expiry within a minute of the due time. A missing key,
invalid chain or unavailable checkpoint store prevents release; repair dependencies and
restart, inspect uncertain transfers, then request a fresh transfer as needed. Never edit
BLOCK/ERROR/STALE states to ALLOWED. Server send completion is not recipient confirmation.

Free-tier hosting does not provide durable snapshot or checkpoint storage: disk resets erase
them, so do not represent such hosting as durable forensic evidence. A production deployment
would need durable database and snapshot storage, independent checkpoint retention and its own
TLS and proxy review. Running the staging agent under WSL2 is optional; if used, keep its
directories on the native Linux filesystem, not a OneDrive or `/mnt/c` mount.

## Hosted presenter demo (Phase 06A)

Phase 06A adds everything needed to run the gateway on a free host for a live, presenter-driven demonstration. It is deployed at
https://rootsentinel-dlp.onrender.com; the measurements are in the [Phase 06A evidence](evidence/phase-06a.md). This section is the
exact procedure, including the steps only you can do.
It is a demonstration deployment: not production, not a durable evidence store, and **there is no anonymous or visitor access**
(every `/api/v1` route except sign-in and the session check answers 401 without a session; the session check answers 204; the test
suite iterates all routes to prove it).

### Why `ROOTSENTINEL_MODE=local` over an https origin

`mode` gates exactly five things in the code: the blanket `PUBLIC_DEMO_NOT_READY` denial in `RequestGuard`, the account CLI, the
insecure-cookie exemption (loopback only), interactive API documentation (`create_app` in `backend/app/api.py`), and two reporting
fields (`/health`, `/overview`). A new "hosted" mode would have touched all five and the published OpenAPI. Instead the hosted app
runs in `local` mode, which here means only "operational API enabled", and `Settings.hosted` is derived from an `https://` origin.
Being hosted can only add protection: HSTS and no interactive API documentation. The enforced Content-Security-Policy is the same
locally and hosted. `public_demo` is unchanged and still denies every API route (tested). The entrypoint refuses to start without an
https origin or with insecure cookies.

### What is in the image

One container, one `uvicorn` worker, one origin. The built frontend is served by the backend (`backend/app/static_site.py`, GET and
HEAD only, SPA fallback, typed JSON 404 for unknown `/api` paths, no path escapes), so cookies stay SameSite=Strict and Origin and
Host checks are unchanged. The server runs as an unprivileged user (uid 10001). The entrypoint (`docker/entrypoint.sh`) starts as
root only to copy the three secret files to private 0600 paths, then migrates, runs `python -m app.bootstrap`, and starts the server.
`render.yaml` is a Blueprint with no secret values.

The runtime stage applies Debian security updates (`apt-get upgrade`) and removes `pip` after installing the locked requirements, so
the image carries no Python package installer (and none of pip's vendored libraries). `.trivyignore` records three reviewed image-scan findings with their reasons (DS002 no `USER`
instruction, DS031 a file path mistaken for a secret, DS026 no `HEALTHCHECK`). A local build measured 219216151 bytes (about
219 MB) uncompressed; the CI `container` job measures the size on every build and fails above its 258 MiB budget
(`IMAGE_SIZE_BUDGET_MIB`).

| Variable | Meaning | Hosted value |
|---|---|---|
| `ROOTSENTINEL_MODE` | operational API enabled | `local` |
| `ROOTSENTINEL_ORIGIN` | exact public origin, https, no trailing slash | `https://<service>.onrender.com` |
| `ROOTSENTINEL_DATABASE_URL` | Neon connection, driver prefix `postgresql+psycopg://` | set in the dashboard only |
| `ROOTSENTINEL_TRUSTED_PROXY_HOPS` | `X-Forwarded-For` entry taken N from the right; 0 ignores the header | `0` (hop counting did not work on Render, see the Phase 06A evidence) |
| `ROOTSENTINEL_CLIENT_IP_HEADER` | one header holding exactly one client address, set by the edge (for example `True-Client-IP`); empty = off. Cannot be combined with nonzero hops (startup refuses) | **`True-Client-IP`**, set in the dashboard only (not in `render.yaml`). Adopted in Phase 06A after a two-network test; see the Phase 06A evidence |
| `ROOTSENTINEL_EXTRA_HOSTS` | exact additional Host values (for example a custom domain), no wildcards | unset |
| `ROOTSENTINEL_SESSION_SECONDS` | 60 to 86400 | 3600 |
| `ROOTSENTINEL_RETENTION_SECONDS` | 1 to 900 | 900 |
| `ROOTSENTINEL_MAX_UPLOAD_BYTES` | 1024 to 10485760 (default 10 MiB) | 1048576 (1 MiB) |
| `ROOTSENTINEL_TRANSFER_RATE_PER_MINUTE` | per account, 1 to 120 (default 30) | 10 |
| `ROOTSENTINEL_TRANSPARENCY_KEY_FILE` | private Ed25519 key file that signs audit tree heads; a separate file from the audit keyring | set by the image; the entrypoint fills it from the secret file `transparency-key.json` |
| `ROOTSENTINEL_COMMIT` | Docker build argument: the commit `/health` reports. CI passes the Git SHA | not set on Render; the app falls back to Render's `RENDER_GIT_COMMIT` |

The defaults of every new setting reproduce the earlier local behavior exactly. With hops greater than 0 the app trusts the
`X-Forwarded-For` entry that many places from the right; this is only safe when the app is reachable exclusively through that many
proxies that each append their peer's address. A header with too few entries or an unparsable value falls back to the socket peer.
`X-Forwarded-Proto` is ignored (cookies set `Secure` explicitly). `uvicorn` still runs with `--no-proxy-headers`.

With `ROOTSENTINEL_CLIENT_IP_HEADER` set, `X-Forwarded-For` is ignored and the login limiter keys on that one header, but only when
it holds exactly one valid IPv4 or IPv6 address (IPv4-mapped IPv6 is normalised). A missing, repeated, list-valued or invalid header
puts the request in one shared `unidentified` bucket; the raw value is never logged. This is safe only if the edge overwrites that
header on every request that can reach the service. On Render, Cloudflare fronts `<name>.onrender.com` and overwrites
`True-Client-IP`, so a client cannot choose its own key. A probe that is limited does **not** by itself prove per-client keying,
because the shared `unidentified` bucket is limited too. Only a second network inside the same window tells them apart (procedure
below).

The Host check runs first: a request whose Host is not this service is refused with `HOST_REJECTED` before the client header is
read, so it can neither select a bucket nor advance a counter. Only a route that uses the client key advances the counter behind
the log line `client IP header missing or invalid; shared unidentified bucket used (N request(s) so far; method=POST route=api
host_permitted=yes)`. Today that is sign-in alone. The line is logged at N = 1, 10, 100 and so on, starting again at 1 in each new
process. Its last part is a fixed classification: the method (one of seven known methods or `OTHER`), the route class (`health`,
`static`, `api` or `other`) and whether the Host was permitted (`yes` or `no`; always `yes` here because the Host check has
already passed). No header value, address, path or name is ever written. Requests to `/health`, including Render's own health
checks, are counted separately (`health_without_client`); pages, other API calls and rejected requests are not counted at all.
The line therefore means that a sign-in reached the service without a valid header. Phase 06A saw the line caused by health checks
alone and first misread it.

Cloudflare also refuses a client-set `CF-Connecting-IP` at the edge (403, Cloudflare error 1000), so `--spoof-mode
cf-connecting-ip` and `all` need `--expect limited-or-rejected`.

### Health, deployed commit and security headers

`GET /health` returns `status`, `mode`, `release_configured`, `hosted`, `commit` and `max_upload_bytes`. `hosted` is `true` when
the configured origin is https; the interface takes its "Hosted demo" or "Local" badge and its upload cap from this response.
`commit` comes from `ROOTSENTINEL_COMMIT` (a Docker build argument; the CI `container` job builds with
`--build-arg ROOTSENTINEL_COMMIT=$GITHUB_SHA`), else from Render's `RENDER_GIT_COMMIT`, else `unknown`. Only 7 to 40 lowercase hex
characters are accepted; any other value is reported as `unknown` and never echoed.

`scripts/smoke_public.py --expect-commit <sha>` fails unless `/health` reports that commit (full SHA or a prefix of at least 7
characters). The smoke test also checks that the `Content-Security-Policy` header is enforced, not report-only, and has no
`'unsafe-inline'`. Every response, locally and hosted, carries the same enforced policy; HSTS (`max-age=31536000`, no preload, no
subdomains) is added only when hosted. See [frontend](frontend.md#content-security-policy) for the policy text.

### Secrets: files and hashes, never plaintext

* **Audit key file** (`audit-keys.json`): generated on your machine, uploaded as a Render *secret file*, copied by the entrypoint to a
  0600 path. The app reads only files with no group or other permission bits.
* **Tree-head signing key** (`transparency-key.json`): an Ed25519 key generated on your machine with
  `python -m app.audit_keys init-transparency`, uploaded as a second Render *secret file* and copied by the entrypoint to a 0600
  path. It is separate from the audit key file. The container refuses to start without it, because no release is possible without
  a signed tree head. The command prints only the key id and the path. Back it up offline with the audit key file: if it is lost,
  stored tree heads can no longer be verified at startup and the audit refuses everything until a new database is started.
* **Accounts file** (`accounts.json`): usernames, roles and **Argon2id password hashes only**, created locally by
  `scripts/make_account_hashes.py` with hidden prompts. No plaintext password is ever stored on the host. The file is the source of
  truth for the accounts it lists: a changed hash or role is applied and revokes that user's sessions; `"enabled": false` disables
  the account; accounts it does not list are untouched. Re-running bootstrap with an unchanged file changes nothing.
* **Database URL**: an environment variable set in the dashboard. Do not put it in chat, in the repository or in a shell history.
* Nothing in the repository, the image or CI contains a real secret. CI uses throwaway generated secrets.
* Bootstrap seeds two synthetic protected assets through the normal registration and audit path, using a disabled internal ADMIN
  identity that cannot sign in: `synthetic-protected-sample` (the bytes of the smoke test's protected fixture) and
  `synthetic-source-sample` (source-shaped text, the bytes of the interface's `source` fixture, so its shifted and inserted copies
  show the content-defined profile). Register more assets as an ADMIN in the UI if you want.
* Bootstrap also does two things once per database. A seed registered before the content-defined profile existed gets that
  profile's fingerprints (`profiles: seed assets given missing fingerprints=N` in the log), because only seeds have their bytes in
  the image; every other asset needs a new version. And while the migration's own policy 1 is still active, bootstrap activates
  policy rule set `rs-policy-v2` (`policy: rule set rs-policy-v2 activated`). After that the rule set is the administrators' choice
  on the Policies page and no restart changes it. Both steps make database calls only during startup.

### What you must do yourself (checklist)

The dashboards change; where this list and the vendor page disagree, the vendor page wins. Never paste a secret into a chat.

1. **Accounts and 2FA.** Make sure you have a GitHub account, create a Neon account and a Render account (Render can sign in with
   GitHub). Turn on two-factor authentication on all three. Neither Render's nor Neon's free tier asked for a payment card at
   sign-up (operator, 2026-11-09).
2. **Neon.** Create a project and a database. Pick a region geographically near the Render region you will use (the free Render
   regions were not verified). Copy the **direct** (non-pooled) connection string, change the prefix `postgresql://` to
   `postgresql+psycopg://` and keep `sslmode=require`. If the client rejects `channel_binding=require`, remove that parameter. Keep
   the string only in the Render dashboard.
3. **Create the secrets locally** (Windows PowerShell; use the Python environment that has `backend/requirements-dev.lock`; the
   first command creates the folder itself, because a hand-made folder can be rejected by the Windows ACL check):
   ```powershell
   Set-Location '<repository root>\backend'
   $S = Join-Path $env:LOCALAPPDATA 'RootSentinel\hosted-secrets'
   python -B -m app.audit_keys init "$S\audit-keys.json"
   python -B -m app.audit_keys init-transparency "$S\transparency-key.json"
   Set-Location '<repository root>'
   python -B scripts\make_account_hashes.py --out "$S\accounts.json" --account presenter-admin:ADMIN --account presenter-analyst:ANALYST --account class-user-1:EMPLOYEE
   ```
   Back up `audit-keys.json` and `transparency-key.json` **offline** (an encrypted drive or a password manager attachment). If
   either is lost, the audit can never be verified again and you must start a new database. Do not store `$S` in OneDrive. The
   second command prints a `key_id`; note it, it is not secret.
4. **Render service.** In Render choose New > Blueprint, connect the GitHub repository and the `main` branch (`render.yaml` sets
   `branch: main`; deploy from `main` only). Keep or change the name in `render.yaml`; the public URL becomes
   `https://<name>.onrender.com`. When asked, enter `ROOTSENTINEL_ORIGIN` as that exact URL and `ROOTSENTINEL_DATABASE_URL`.
5. **Secret files.** In the service's Environment page add three secret files named `audit-keys.json`, `transparency-key.json`
   and `accounts.json`, pasting the file contents into the dashboard form. Saving redeploys. Deleting `$S\accounts.json` locally
   afterwards is optional. **An existing deployment needs `transparency-key.json` uploaded before the first deploy of a version
   that has the transparency log**: without the file the new container refuses to start and Render keeps serving the previous
   version.
6. **First deploy and the origin check.** Click deploy and read the public URL. If it is not exactly your `ROOTSENTINEL_ORIGIN`
   (for example Render added a suffix), correct the variable and redeploy. A wrong origin shows as HTTP 400 `HOST_REJECTED`.
7. **Health check.** Only now set the Health Check Path to `/health` (Render sends the service's own domain as Host).
8. **Smoke test** from your machine (hidden password prompt; it signs in as the analyst):
   ```powershell
   Set-Location '<repository root>'
   python -B scripts\smoke_public.py --base-url https://<name>.onrender.com --username presenter-analyst --expect-commit <sha>
   ```
   Replace `<sha>` with the commit you expect to be live (`git rev-parse HEAD` on `main`), or omit the option.
9. **Measure and record** (see below), then put the real numbers in `docs/evidence`. Do not quote numbers you did not measure.
10. **Course sheet.** Add the repository link and the hosted URL to the topic selection sheet yourself.

### What to measure after a deploy (Phase 06A values in the evidence record)

* **Cold start.** After more than 15 minutes without traffic, run the smoke test; its first line prints the seconds until `/health`
  answered. Repeat three times; record the median and the maximum. This includes Neon waking up after its own idle suspend. Phase
  06A measured a median of 52.99 s and a maximum of 62.66 s. From the Render logs the time splits into: 27 to 32 s before the
  container prints anything (instance and image start, migrations and bootstrap, both connecting to Neon; the Neon share is not
  separated), 14 to 17 s from the bootstrap result to `Started server process` (checkpoint anchoring and importing the app), 4 to
  5 s until uvicorn is ready, then 1 to 9 s of routing before the first 200.
* **Memory.** The free instance has **512 MB and 0.15 CPU** (Render Metrics page, "Limit"). Memory and CPU usage are shown only on
  paid compute plans, so Phase 06A did not measure peak memory. The application now logs its own peak resident memory: logger
  `rootsentinel.memory` writes `peak resident memory (VmHWM) at startup: N KiB (M MiB)` at INFO, and again every 10 minutes of
  maintenance, wherever `/proc/self/status` exists (Linux, so in the container). Read it from the Render log; no hosted value is
  recorded yet.
* **Argon2 login time.** The smoke test prints the sign-in time. Record it (Phase 06A: 2.47 to 2.67 s live, 0.05 to 0.06 s in CI).
* **Client identification.** Hop counts 1 and 2 did not work on Render. Adopted: `ROOTSENTINEL_CLIENT_IP_HEADER=True-Client-IP` with
  hops 0. Re-verify it with the procedure below after any change to the host, the edge or this setting. The probe uses up the login
  limit for about a minute: never run it during the demo. A classroom behind one NAT shares one address, so up to 15 sign-ins per
  minute per address and 30 per minute overall apply however this is set.

#### Procedure: re-verifying per-client keying (two networks, one window)

Run in Windows PowerShell from the repository root, with the project venv's Python. Set `$U = 'https://rootsentinel-dlp.onrender.com'`.
Only fake user names are sent; no real password is used. Open `$U/health` first so the service is awake.

| Step | Do | Expected (PASS) | FAIL |
|---|---|---|---|
| A | PC on Wi-Fi: `python -B scripts\smoke_public.py --base-url $U --probe-login-throttle --wait-seconds 65 --attempts 16 --expect limited`. Note `first request sent at` (**A_first**) | 15 x `401 app INVALID_CREDENTIALS`, then `429 app LOGIN_RATE_LIMIT_CLIENT`; `PASS`; exit 0 | 16 x 401: the key changes per request, so the header is not trustworthy and must be removed. Exit 2: someone else used the global limit, so redo after 65 s |
| B | A second network (phone on mobile data, Wi-Fi off), **at most 55 s after A_first**: one wrong-password sign-in in the browser with user name `probe-phone`. Alternatively: switch the PC to the phone hotspot and run `... --probe-login-throttle --attempts 12 --expect unlimited` | Browser: "The username or password is incorrect" (401). Script: 12 x 401, `PASS`, exit 0 | Browser: "The request limit was reached" (429). Script: `SHARED-BUCKET` from the first attempt. Either way the networks share one bucket |
| C | Optional, 65 s later: `... --probe-login-throttle --wait-seconds 65 --spoof-mode true-client-ip --expect limited` and `--spoof-mode cf-connecting-ip --expect limited-or-rejected` | limited; `EDGE-REJECTED` | 16 x 401: a forged value picks its own key, so remove the header |

**Why 55 s.** Each limiter window is fixed at 60 s from its first attempt. A takes about 38 s, and a shared bucket is empty again
60 s after A_first, so a later B would pass even with a shared bucket. A per-client 429 still uses a global slot: A's 16 plus B's
12 attempts make 28, under the global 30. The Render log line `unidentified` is **not** a criterion for this test.

### Deploy policy: main only, after checks, no pushes on demo day

* **Deploy from `main`.** `render.yaml` sets `branch: main`. Candidate and feature branches are never deployed.
* **Auto-deploy after checks.** `render.yaml` sets `autoDeployTrigger: checksPass`, which per Render's Blueprint specification
  deploys a new commit on the linked branch only if that branch's CI checks pass. An auto-deploy has run (Phase 06A evidence); that
  it waited for the checks is Render's documented behaviour, not something tested here. Render's older `autoDeploy` key is
  deprecated and is not used.
* **No pushes to `main` on demo day.** Every deploy restarts the service. A restart loses the file checkpoints (they live on the
  container's ephemeral disk; the signed tree heads are in the database and survive) and turns any in-flight transfer into `DELIVERY_UNKNOWN`, which must then be repeated. Merge and push
  well before the demo, wait for the deploy to finish, and run the smoke test afterwards.
* A push to `main` therefore deploys the demo by itself once checks are green: treat every push to `main` as a deploy.

### Day of the demo

Ten minutes before: run the smoke test (the warm-up loop wakes the service and the database). An awake service with no users makes
no database call, so a keep-alive request to `/health` costs Render hours only (see the hosting budget below and the
[demo runbook](demo-runbook.md)). Disable the ADMIN and class accounts afterwards (`"enabled": false` in your local file, upload it
again, redeploy).

### Hosting budget

Both hosts are on free plans. The figures marked "vendor" come from the vendors' plan pages as read in November 2026 and can
change; the figures marked "operator" were read from the dashboards by the operator. Check both before relying on them.

| Resource | Allowance | Use during the grading window | What is left |
|---|---|---|---|
| Render free instance hours | 750 hours per month, shared by every free service in the workspace (vendor) | Always on from 28 November to 20 December: 3 days x 24 h = about 72 h in November, 20 days x 24 h = about 480 h in December | About 270 h in December for the other services in the workspace |
| Neon compute, before this change | 100 CU-hours per project per month (vendor); 1.62 CU-hours used from 8 to 10 November (operator) | The maintenance loop queried the database every 60 s, so an awake service kept the compute awake: 0.25 CU x 24 h = 6 CU-hours per day, about 120 CU-hours over 20 days | Nothing: the allowance would run out and Neon would suspend the database during grading |
| Neon compute, after this change | the same 100 CU-hours | An idle awake service makes no database call, so the compute suspends after Neon's idle delay and runs only while someone uses the application. Two hours of real use per day at 0.25 CU is 0.5 CU-hours per day, about 10 CU-hours over 20 days (an estimate, not a measurement) | About 90 CU-hours |

What makes the "after" row true, and what the tests prove (`backend/tests/test_idle.py`):

* `/health` makes no database call.
* The maintenance loop makes a database call only when a transfer expiry is due or snapshot files exist. After an ALLOWED
  transfer the database is used for at most the retention time (900 s) plus one pass.
* The connection pool (2 idle, 4 at most, recycled after 280 s, checked on checkout) does nothing while idle.
* Signing in, every page of the workspace and every API call do use the database. Only `/health` is free.

Operator steps (dashboards change; where this text and the vendor page disagree, the vendor page wins):

1. **Pin Neon compute to 0.25 CU.** In the Neon console open the project, then the branch's compute settings, and set both the
   minimum and the maximum compute size to 0.25 CU. With autoscaling left on, a busy minute can run at a larger size and use the
   allowance faster.
2. **Read Render usage.** In the Render dashboard open the workspace's billing page; it shows the free instance hours used this
   month across all free services.
3. **Read Neon usage.** In the Neon console open the project's dashboard or the billing page; it shows the compute CU-hours used
   this month.
4. **Keep-alive rule.** The external keep-alive job requests `/health` and nothing else. A keep-alive that loads a page that
   signs in, or calls any `/api/v1` route, wakes the database every time and brings back the "before" row.

The dates, thresholds and the keep-alive job itself are in the [demo runbook](demo-runbook.md).

### Audit integrity on a hosted free tier

* Audit events are chained with an HMAC key held only by the app host, so the database host alone cannot forge or edit them
  undetected: the chain is verified before every release.
* Signed tree heads over the audit events are stored in the database and survive restarts. At startup the gateway rebuilds the
  tree and refuses every audited action if it does not match the latest stored head, so an edit or a truncation that leaves the
  heads in place is detected after a restart.
* The file checkpoints are still written to the container's disk, which is ephemeral: they are lost on every restart, redeploy
  and sleep. A database rollback that also removes the stored heads (for example a Neon restore to an earlier time) is **not**
  detected by the gateway itself. It is detected by anyone who kept an earlier head outside the database: the Audit log tab of
  the Integrity page keeps the last head a browser saw, and `scripts/witness.py` keeps one in a file
  (see the [audit protocol](audit-spec.md#transparency-log-signed-tree-heads-over-the-chain)).
* There is no forensic or compliance claim. Render and Neon account holders can reach the data. Free tiers can restart at any time:
  an in-flight release becomes `DELIVERY_UNKNOWN` and the transfer must be repeated.
* The audit stream is capped at 20000 events; at the cap everything fails closed. Check the sequence number in the smoke output.
  Starting a new stream means a new database, which discards the old evidence on purpose.

### Troubleshooting

* **`could not open certificate file "/root/.postgresql/postgresql.crt": Permission denied`** (alembic fails at start-up against
  Neon). Seen on the first Render deploy of `main` at `6277f0e`. The entrypoint starts as root and then runs everything as uid 10001,
  and that process inherited `HOME=/root` from the root phase. libpq looks for an optional client certificate under
  `$HOME/.postgresql/`: a missing file is skipped, but a permission error on that path is fatal. The fix is in `docker/entrypoint.sh`:
  alembic, bootstrap and uvicorn now run with `HOME=/nonexistent` (the unprivileged account's passwd home, which does not exist), so
  the path is simply absent; no other variable is changed and the privilege drop is unchanged. CI asserts this on every build (the
  server's `HOME`, and that `os.stat` of the expanded path raises `FileNotFoundError` rather than `PermissionError` as uid 10001).
  The fix is live, and the temporary `HOME` variable once set in the Render dashboard as a workaround has been removed (Phase 06A
  evidence).
* **`Network is unreachable` lines with IPv6 addresses** while connecting to Neon. Render's free instances have no IPv6 egress, so
  the driver tries the IPv6 address, fails, and falls back to IPv4. These lines are harmless when the connection then succeeds.

### Rollback and shutdown

Render can roll back to its two most recent earlier deploys (per Render's free-tier page). No migration is added by this phase, so a
code rollback needs no schema change. To stop access immediately, suspend the service in the dashboard, or disable accounts and
redeploy. Neon's free plan keeps six hours of restore history; a restore also invalidates the audit anchor, see above.

### Limitations

Free tiers sleep (Render: after 15 minutes idle, about a minute to wake) and may restart at any time. Retained snapshots and
checkpoints do not survive a restart. Detection limits still apply: encoded, compressed or otherwise re-encoded content is missed by both
detection profiles, and shifted content is found only under policy rule set `rs-policy-v2` and only in content that has cut points. The Content-Security-Policy is enforced, but it cannot stop a malicious script that the build itself
contains. Real uploads are limited to signed-in accounts, at most 1 MiB on the hosted demo, and must be synthetic: the notice in the
interface is a reminder, not a control.
