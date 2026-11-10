# Demo runbook: the grading window

Graders may open the hosted application at any time from 29 November to 20 December. This page is the short list of what
keeps it reachable in that time. The reasons and the numbers are in [deployment](deployment.md#hosting-budget).

## Keep the service awake

From 28 November until 20 December an external job at cron-job.org requests `https://rootsentinel-dlp.onrender.com/health`
every 10 minutes. Render's free instance sleeps after 15 minutes without traffic, so a request every 10 minutes keeps it awake.

* The job requests `/health` only. That route makes no database call, so the Neon database stays suspended while nobody uses
  the application. Any other URL would wake the database on every request.
* Create the job on 28 November and delete it on 21 December. The job needs no account of ours and no secret: it is a plain
  GET with no headers.
* A failed request in the job's history means the service was restarting or asleep. One failure is normal after a deploy;
  several in a row need a look at the Render log.

## Check the budget every few days

| Where | Read | Act when | Action |
|---|---|---|---|
| Render dashboard, workspace billing page | Free instance hours used this month | Above 650 h | Suspend the other free services in the workspace until the month ends. If that is not enough, pause the keep-alive job at night |
| Neon console, project dashboard or billing page | Compute CU-hours used this month | Above 70 CU-h | Confirm the compute size is pinned to 0.25 CU and that the keep-alive job requests `/health` only. Look in the Render log for traffic that is not ours |

Expected values: about 72 h of Render time in November and about 480 h in December; Neon use that grows only on days when
someone signs in.

## No deploys during the window

Every push to `main` deploys, restarts the service, loses the audit checkpoints and turns an in-flight transfer into
`DELIVERY_UNKNOWN`. From 29 November to 20 December `main` does not move, except for an urgent fix. An urgent fix goes through
the full checks first, and the smoke test runs after the deploy. Finished work waits on the `integration` branch.

## Before a live demo

1. Open `https://rootsentinel-dlp.onrender.com` in a browser and wait for the sign-in page.
2. Run the smoke test from the repository root (hidden password prompt; it signs in as the analyst):
   ```powershell
   python -B scripts\smoke_public.py --base-url https://rootsentinel-dlp.onrender.com --username presenter-analyst
   ```
3. Do not run the login-throttle probe. It uses up the sign-in limit for about a minute.

## If the hosted service is not available

**Local Docker.** The same image runs on the presenter's machine and passes the same smoke test, exactly as the CI `container`
job does it. The image refuses to start without an https origin, so the smoke test connects to the loopback port and sends that
origin with `--origin`. Both scripts ask for the password with a hidden prompt. Run in Windows PowerShell from the repository
root with Docker Desktop running:

```powershell
$S = Join-Path $env:LOCALAPPDATA 'RootSentinel\local-demo-secrets'
Set-Location backend
python -B -m app.audit_keys init "$S\audit-keys.json"
Set-Location ..
python -B scripts\make_account_hashes.py --out "$S\accounts.json" --account demo-analyst:ANALYST
docker build -t rootsentinel-hosted:local .
docker run -d --name rootsentinel -p 127.0.0.1:8000:10000 -e ROOTSENTINEL_ORIGIN=https://rootsentinel-local.example -v "${S}:/etc/secrets:ro" rootsentinel-hosted:local
python -B scripts\smoke_public.py --base-url http://127.0.0.1:8000 --origin https://rootsentinel-local.example --username demo-analyst --warmup-seconds 120
docker rm -f rootsentinel
```

The container uses a throwaway SQLite database inside itself, so nothing from the hosted demo is needed and nothing survives
`docker rm`. This proves the gateway end to end from the command line. A browser cannot sign in to this container, because its
origin is not the loopback address the browser uses. To show the interface in a browser, start the gateway locally as described
in [deployment](deployment.md#local-operation).

**Recorded walkthrough.** Keep a screen recording of the complete flow (sign in, an allowed transfer and its single release, a
blocked transfer and its incident, audit verification) on the presenter's machine and on a second device. Record it against
the hosted service before 28 November and again after any urgent fix, so the recording shows the version being graded.
