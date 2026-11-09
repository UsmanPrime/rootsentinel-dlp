# Local Phase 03 operation and future deployment boundary

No public deployment has been performed. `public_demo` remains fail-closed for all `/api/v1`
routes; the hosted presenter demo prepared in Phase 06A (see the hosted section below) is a separate, authenticated-only configuration. The authenticated local fixture-selection endpoint performs real processing;
it is not anonymous demo isolation. No arbitrary forwarding URL exists. The local staging agent
is a separate client process documented in [staging-spec.md](staging-spec.md), including its
provisioning commands; it does not change this service's configuration.

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
python -m app.audit_keys init $env:ROOTSENTINEL_AUDIT_KEY_FILE
python -m alembic upgrade head
python -m app.cli --help
python -m uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log --no-proxy-headers
```

Run key init once, not on every restart. Bootstrap an account using the existing CLI's
interactive password prompt; do not embed credentials in commands/history/Git. Use secure
cookies and HTTPS in any future non-loopback environment. `.env.example` contains only
configuration names, not operational secrets. Environment variables inject the private
keyring location; the file supplies persistent key material. A future secret manager may
mount the same private keyring contract without changing the HMAC format.

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

The process performs bounded startup recovery and minute-based expiry. A missing key,
invalid chain or unavailable checkpoint store prevents release; repair dependencies and
restart, inspect uncertain transfers, then request a fresh transfer as needed. Never edit
BLOCK/ERROR/STALE states to ALLOWED. Server send completion is not recipient confirmation.

Future public hosting requires durable database and snapshot storage, persistent secrets,
independent checkpoint retention, TLS/proxy review, synthetic-only public accounts and
resource limits. Free-tier disk resets can erase snapshots/checkpoints; do not represent
such hosting as providing durable forensic evidence. Later WSL2 admission must use native
Linux filesystem storage, not a OneDrive mount; it is not implemented by this phase.

## Hosted presenter demo (Phase 06A)

Phase 06A adds everything needed to run the gateway on a free host for a live, presenter-driven demonstration. **Nothing has
been deployed**; no deployed measurement exists yet. This section is the exact procedure, including the steps only you can do.
It is a demonstration deployment: not production, not a durable evidence store, and **there is no anonymous or visitor access**
(every `/api/v1` route except sign-in answers 401 without a session; the test suite iterates all routes to prove it).

### Why `ROOTSENTINEL_MODE=local` over an https origin

`mode` gates exactly four things in the code: the blanket `PUBLIC_DEMO_NOT_READY` denial in `RequestGuard`, the account CLI, the
insecure-cookie exemption (loopback only), and two reporting fields (`/health`, `/overview`). A new "hosted" mode would have touched
all four and the published OpenAPI. Instead the hosted app runs in `local` mode, which here means only "operational API enabled", and
`Settings.hosted` is derived from an `https://` origin. Being hosted can only add protection: HSTS, a report-only CSP, and no
interactive API documentation. `public_demo` is unchanged and still denies every API route (tested). The entrypoint refuses to start
without an https origin or with insecure cookies.

### What is in the image

One container, one `uvicorn` worker, one origin. The built frontend is served by the backend (`backend/app/static_site.py`, GET and
HEAD only, SPA fallback, typed JSON 404 for unknown `/api` paths, no path escapes), so cookies stay SameSite=Strict and Origin and
Host checks are unchanged. The server runs as an unprivileged user (uid 10001). The entrypoint (`docker/entrypoint.sh`) starts as
root only to copy the two secret files to private 0600 paths, then migrates, runs `python -m app.bootstrap`, and starts the server.
`render.yaml` is a Blueprint with no secret values.

| Variable | Meaning | Hosted value |
|---|---|---|
| `ROOTSENTINEL_MODE` | operational API enabled | `local` |
| `ROOTSENTINEL_ORIGIN` | exact public origin, https, no trailing slash | `https://<service>.onrender.com` |
| `ROOTSENTINEL_DATABASE_URL` | Neon connection, driver prefix `postgresql+psycopg://` | set in the dashboard only |
| `ROOTSENTINEL_TRUSTED_PROXY_HOPS` | `X-Forwarded-For` entry taken N from the right; 0 ignores the header | `0` (hop counting did not work on Render, see the Phase 06A evidence) |
| `ROOTSENTINEL_CLIENT_IP_HEADER` | one header holding exactly one client address, set by the edge (for example `True-Client-IP`); empty = off. Cannot be combined with nonzero hops (startup refuses) | dashboard only, not in `render.yaml`. `True-Client-IP` does **not** work on Render (absent at the origin, every client in one shared bucket). Under test: `CF-Connecting-IP` (procedure below) |
| `ROOTSENTINEL_EXTRA_HOSTS` | exact additional Host values (for example a custom domain), no wildcards | unset |
| `ROOTSENTINEL_SESSION_SECONDS` / `RETENTION_SECONDS` | 60-86400 / 1-900 | 3600 / 900 |
| `ROOTSENTINEL_MAX_UPLOAD_BYTES` | 1024-10485760 | 1048576 (1 MiB) |
| `ROOTSENTINEL_TRANSFER_RATE_PER_MINUTE` | per account, 1-120 | 10 |

The defaults of every new setting reproduce the earlier local behavior exactly. With hops greater than 0 the app trusts the
`X-Forwarded-For` entry that many places from the right; this is only safe when the app is reachable exclusively through that many
proxies that each append their peer's address. A header with too few entries or an unparsable value falls back to the socket peer.
`X-Forwarded-Proto` is ignored (cookies set `Secure` explicitly). `uvicorn` still runs with `--no-proxy-headers`.

With `ROOTSENTINEL_CLIENT_IP_HEADER` set, `X-Forwarded-For` is ignored and the login limiter keys on that one header, but only when
it holds exactly one valid IPv4 or IPv6 address (IPv4-mapped IPv6 is normalised). A missing, repeated, list-valued or invalid header
puts the request in one shared `unidentified` bucket; the raw value is never logged. This is safe only if the edge overwrites that
header on every request that can reach the service. A probe that is limited does **not** by itself prove per-client keying: the
shared `unidentified` bucket is limited too. Only a second network inside the same window tells them apart (procedure below). Every
request without a valid header (including `/health` and Render's health checks) advances the counter behind the log line
`client IP header missing or invalid; shared unidentified bucket used (N request(s) so far)`, logged at N = 1, 10, 100 and so on,
starting again at 1 in each new process. On Render, Cloudflare refuses a client-set `CF-Connecting-IP` at the edge (403,
Cloudflare error 1000), so `--spoof-mode cf-connecting-ip` and `all` need `--expect limited-or-rejected`.

### Secrets: files and hashes, never plaintext

* **Audit key file** (`audit-keys.json`): generated on your machine, uploaded as a Render *secret file*, copied by the entrypoint to a
  0600 path. The app reads only files with no group or other permission bits.
* **Accounts file** (`accounts.json`): usernames, roles and **Argon2id password hashes only**, created locally by
  `scripts/make_account_hashes.py` with hidden prompts. No plaintext password is ever stored on the host. The file is the source of
  truth for the accounts it lists: a changed hash or role is applied and revokes that user's sessions; `"enabled": false` disables
  the account; accounts it does not list are untouched. Re-running bootstrap with an unchanged file changes nothing.
* **Database URL**: an environment variable set in the dashboard. Do not put it in chat, in the repository or in a shell history.
* Nothing in the repository, the image or CI contains a real secret. CI uses throwaway generated secrets.
* Bootstrap seeds one synthetic protected asset (`synthetic-protected-sample`) through the normal registration and audit path, using
  a disabled internal ADMIN identity that cannot sign in. Register more assets as an ADMIN in the UI if you want.

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
   Set-Location '<repository root>'
   python -B scripts\make_account_hashes.py --out "$S\accounts.json" --account presenter-admin:ADMIN --account presenter-analyst:ANALYST --account class-user-1:EMPLOYEE
   ```
   Back up `audit-keys.json` **offline** (an encrypted drive or a password manager attachment). If it is lost, the audit chain can
   never be verified again and you must start a new database. Do not store `$S` in OneDrive.
4. **Render service.** In Render choose New > Blueprint, connect the GitHub repository and the `main` branch (`render.yaml` sets
   `branch: main`; deploy from `main` only). Keep or change the name in `render.yaml`; the public URL becomes
   `https://<name>.onrender.com`. When asked, enter `ROOTSENTINEL_ORIGIN` as that exact URL and `ROOTSENTINEL_DATABASE_URL`.
5. **Secret files.** In the service's Environment page add two secret files named `audit-keys.json` and `accounts.json`, pasting
   the file contents into the dashboard form. Saving redeploys. Deleting `$S\accounts.json` locally afterwards is optional.
6. **First deploy and the origin check.** Click deploy and read the public URL. If it is not exactly your `ROOTSENTINEL_ORIGIN`
   (for example Render added a suffix), correct the variable and redeploy. A wrong origin shows as HTTP 400 `HOST_REJECTED`.
7. **Health check.** Only now set the Health Check Path to `/health` (Render sends the service's own domain as Host).
8. **Smoke test** from your machine (hidden password prompt; it signs in as the analyst):
   ```powershell
   Set-Location '<repository root>'
   python -B scripts\smoke_public.py --base-url https://<name>.onrender.com --username presenter-analyst
   ```
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
  paid compute plans, so peak memory on the free instance was not measured.
* **Argon2 login time.** The smoke test prints the sign-in time. Record it (Phase 06A: 2.47 to 2.67 s live, 0.05 to 0.06 s in CI).
* **Client identification.** Hop counts 1 and 2 did not work on Render, and `True-Client-IP` is absent at the origin. Under test:
  `ROOTSENTINEL_CLIENT_IP_HEADER=CF-Connecting-IP` with hops 0, using the procedure below. The probe uses up the login limit for
  about a minute: never run it during the demo. A classroom behind one NAT shares one address, so up to 15 sign-ins per minute per
  address and 30 per minute overall apply however this is set.

#### Procedure: testing `ROOTSENTINEL_CLIENT_IP_HEADER=CF-Connecting-IP`

Run everything in Windows PowerShell from the repository root, with the project venv's Python. Set `$U` to the service URL first:
`$U = 'https://rootsentinel-dlp.onrender.com'`. Only fake user names are sent; no password is needed.

**Timing constraint (this decides whether step B means anything).** Every limiter window is fixed: 60 s from its first attempt. A
shared bucket would therefore be empty again 60 s after **A's first request**. A takes about 38 s (16 sign-ins at about 2.4 s
each), so B's first request must be sent at most **55 s after A's first request**. "Within 40 s of A finishing" is not enough: at
22 s or more after A ends, a shared bucket has already expired and B would falsely pass. The probe prints
`first request sent at ...Z` for both runs, so the gap can be checked afterwards. To make the switch fast, turn the phone hotspot on
and pair the PC with it before step A. Do B's ipify check right **after** B's probe, in the same window. It proves which network B
used just as well, provided the PC does not switch networks in between.

| Step | Do | Command | Expected (PASS) | FAIL or INVALID |
|---|---|---|---|---|
| 0 | In the Render dashboard (you, not Claude): set `ROOTSENTINEL_CLIENT_IP_HEADER` to `CF-Connecting-IP`, leave `ROOTSENTINEL_TRUSTED_PROXY_HOPS` at `0`, save (this redeploys). Wait for "Your service is live" and note that time in UTC as **T_live**. Then open `$U/health` once to be sure it is awake | — | live, health `ok` | startup refusal in the log: the name is wrong or hops are not 0 |
| A | Normal Wi-Fi. Note your address, then probe | `irm https://api64.ipify.org` (note **IP_A**), then `python -B scripts\smoke_public.py --base-url $U --probe-login-throttle --wait-seconds 65 --attempts 16 --expect limited` | 15 lines `401 app INVALID_CREDENTIALS`, then `429 app LOGIN_RATE_LIMIT_CLIENT`; `PASS  observed pattern matches --expect limited`; exit 0. Note **A_first** from `first request sent at` | 16 x 401 (exit 1): the key changes per request, so the header is not trustworthy. Exit 2: someone else used the global limit, so redo A after 65 s |
| B | At once: switch the PC to the phone hotspot (mobile data, phone Wi-Fi off), then probe **without** a wait, then check the address | `python -B scripts\smoke_public.py --base-url $U --probe-login-throttle --attempts 12 --expect unlimited`, then `irm https://api64.ipify.org` (**IP_B**) | **Per-client keying:** 12 lines `401 app INVALID_CREDENTIALS`, `PASS  observed pattern matches --expect unlimited`, exit 0, **and** IP_B differs from IP_A, **and** B's `first request sent at` is at most 55 s after A_first | **Shared bucket:** `429 app LOGIN_RATE_LIMIT_CLIENT` from #1, `FAIL ...` plus `SHARED-BUCKET ...`, exit 1. **INVALID** (repeat A and B after 65 s): gap over 55 s, IP_B equals IP_A, or exit 2 |
| C | Hotspot or Wi-Fi | `python -B scripts\smoke_public.py --base-url $U --probe-login-throttle --wait-seconds 65 --spoof-mode cf-connecting-ip --expect limited-or-rejected` | `PASS  EDGE-REJECTED (safe: no login attempts reached the app)`, 16 lines `403 edge ... cloudflare error 1000`, exit 0 | 16 x 401 (exit 1): a client-set `CF-Connecting-IP` reaches the app and picks its own key. Never adopt then |
| D | Render dashboard > Logs (you): search `unidentified` from T_live onward | — | **No lines** | see the decision rules |

Global budget: A's 16 attempts (the 429 included, because a per-client 429 still uses a global slot) plus B's 12 make 28 inside
A's 60 s global window, under 30. Do not sign in anywhere else during A and B.

**Decision rules.**

* **Adopt `CF-Connecting-IP`** when A, B and C all PASS and D shows no line. Record T_live, IP_A and IP_B (or only that they
  differed), the four outputs and the log result in `docs/evidence`.
* **Do not adopt** if B shows `SHARED-BUCKET`, A gives 16 x 401, C gives 16 x 401, or D shows a line caused by the probe traffic.
  Then the header is not delivered, or not per client. Recommendation: unset `ROOTSENTINEL_CLIENT_IP_HEADER` (hops stay 0, so the
  key is the socket peer). That removes the shared-bucket lockout only if Render's proxies reach the app from more than one
  address; this configuration has never been probed. Expect no effective per-client limit; the global 30 per minute, the
  per-account 5 per minute and the two Argon2id slots remain. The design for a temporary diagnostic is in the Phase 06A evidence
  (06B.1).
* **Caveat for D.** Render's own health checks (about every 5 s, user agent `Render/1.0`) also advance the counter. If they do
  not pass through Cloudflare, they carry no `CF-Connecting-IP` and log `(1 request(s) so far)` within seconds of T_live, whatever
  the probes show. Check this first: for the `True-Client-IP` deploy (`b2abe44`), compare its live time with the first logged line,
  12:10:03 UTC. If `b2abe44` went live well before 12:10:03 (with no restart in between), health checks are not counted, and D's
  rule "no lines" applies as written. If lines appear before A_first and keep their pace while no probe runs, they are health
  checks. D is then not decisive, and the decision rests on B (with C). The diagnostic would settle this by logging the path class.

### Deploy policy: main only, after checks, no pushes on demo day

* **Deploy from `main`.** `render.yaml` sets `branch: main`. Candidate and feature branches are never deployed.
* **Auto-deploy after checks.** `render.yaml` sets `autoDeployTrigger: checksPass`, which per Render's Blueprint specification
  deploys a new commit on the linked branch only if that branch's CI checks pass. This is Render's behaviour as documented, not
  something verified here until a real deploy exists. Render's older `autoDeploy` key is deprecated and is not used.
* **No pushes to `main` on demo day.** Every deploy restarts the service. A restart loses the audit checkpoints (they live on the
  container's ephemeral disk) and turns any in-flight transfer into `DELIVERY_UNKNOWN`, which must then be repeated. Merge and push
  well before the demo, wait for the deploy to finish, and run the smoke test afterwards.
* A push to `main` therefore deploys the demo by itself once checks are green: treat every push to `main` as a deploy.

### Day of the demo

Ten minutes before: run the smoke test (the warm-up loop wakes the service and the database). Do not poll afterwards: while the
app is awake it queries Neon once a minute, so Neon's free compute allowance (100 CU-hours per month according to Neon's plan page)
would last only about 17 days at 0.25 CU if you kept the service awake all month. Disable the ADMIN and class accounts afterwards
(`"enabled": false` in your local file, upload it again, redeploy).

### Audit integrity on a hosted free tier

* Audit events are chained with an HMAC key held only by the app host, so the database host alone cannot forge or edit them
  undetected: the chain is verified before every release.
* That is **tamper evidence within one container lifetime**, not durable evidence. Checkpoints are written to the container's
  disk, which is ephemeral: they are lost on every restart, redeploy and sleep. Bootstrap writes a fresh checkpoint at each start,
  so after a restart nothing can detect that the newest events were truncated or that the database was rolled back (for example a
  Neon restore).
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
  **If you set a `HOME=/nonexistent` environment variable in the Render dashboard as a workaround, you can remove it once the
  deploy containing this fix is live.** Removing it before then brings the error back.
* **`Network is unreachable` lines with IPv6 addresses** while connecting to Neon. Render's free instances have no IPv6 egress, so
  the driver tries the IPv6 address, fails, and falls back to IPv4. These lines are harmless when the connection then succeeds.

### Rollback and shutdown

Render can roll back to its two most recent earlier deploys (per Render's free-tier page). No migration is added by this phase, so a
code rollback needs no schema change. To stop access immediately, suspend the service in the dashboard, or disable accounts and
redeploy. Neon's free plan keeps six hours of restore history; a restore also invalidates the audit anchor, see above.

### Limitations

Free tiers sleep (Render: after 15 minutes idle, about a minute to wake) and may restart at any time. Retained snapshots and
checkpoints do not survive a restart. Fixed 1 KiB block matching limits still apply. The CSP is report-only until the deployed
pages have been observed; four React style attributes need `style-src-attr 'unsafe-inline'`. Real uploads are limited to signed-in
accounts, at most 1 MiB by default, and must be synthetic: the notice in the interface is a reminder, not a control.
