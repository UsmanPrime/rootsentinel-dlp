# Developer installation and storage

## Preserve the existing repository

Use the existing `https://github.com/UsmanPrime/rootsentinel-dlp.git` repository. Do not
reinitialize or clone into a nonempty working directory. Preserve local history, inspect
divergence before synchronizing, and stop on unexpected remote content. Do not force push,
force checkout or overwrite unrelated files. Phase history, CI runs, tags and published
commits are indexed in [evidence/README.md](evidence/README.md).

## Repository rules

Never commit original instructor DOCX files, real protected payloads, secrets, runtime databases, or screenshots containing
sensitive machine paths. Dependencies and build output are ignored by Git, but Git-ignore does not stop OneDrive syncing them.

The course requires exactly three students. Named ownership and actual contribution history are recorded by the team in the
final report; neither is invented in this repository. No license has been chosen yet, so no open-source license is implied.

The local workspace and dev server bind to loopback; they are not a production deployment. `main` is protected: CI must pass
before a merge, and a push to `main` deploys the hosted demo once its checks pass ([deployment](deployment.md)).

## Toolchain

- Python 3.12 or 3.13 (`requires-python = ">=3.12,<3.14"`). CI tests both; the hosted image uses `python:3.13-slim`.
- Node 22.12 or later and below 25 (`package.json` engines). CI and the image use Node 22.14.0.
- Cryptographic core: standard library only. Runtime dependencies are pinned in `backend/requirements.lock`, test
  dependencies in `backend/requirements-dev.lock`, and the optional browser tests (Playwright) in
  `backend/requirements-browser.lock`.
- Frontend: exact direct versions plus `package-lock.json`; install with `npm ci`.
- Docker is needed only to build and run the hosted image locally; CI builds it in the `container` job. WSL2 is optional.

The `dev` group in pyproject declares the pytest requirement; the requirements
lock is the canonical installation input including transitive pins. Do not resolve
a different test environment implicitly with `uv sync`. A package-management change
must update both the documentation and reproducibility checks.

## Windows setup

Run from the repository root. These commands create a project-local environment outside the synchronized source tree; they do
not modify global Python.

```powershell
$rsVenv = Join-Path $env:LOCALAPPDATA 'RootSentinel\venvs\backend'
python -m venv $rsVenv
$rsPython = Join-Path $rsVenv 'Scripts\python.exe'
& $rsPython -m pip install -r backend/requirements-dev.lock
Push-Location backend
& $rsPython -m pytest
Pop-Location
```

If the selected Python lacks `venv` or `pip`, use another supported CPython or a container environment. Do not silently
install a system runtime. The cryptographic tests also run without any dependency:

```powershell
Push-Location backend
python -B -m unittest tests.test_crypto tests.test_config -v
Pop-Location
python -B scripts/fixtures.py
```

Frontend setup:

```powershell
Push-Location frontend
npm.cmd ci --ignore-scripts --no-audit --no-fund
npm.cmd run typecheck
npm.cmd run format:check
npm.cmd test
npm.cmd run build
npm.cmd run dev
Pop-Location
```

Stop this project's dev server before `npm ci`: Windows can lock its esbuild
executable while running. Do not kill other projects' processes or delete locked
files blindly. If the default port is busy, use `npm run dev -- --port 5188`.

To avoid unrelated shell-profile execution in npm scripts, optionally set
`npm_config_script_shell` to the system `cmd.exe` in the current PowerShell process
only. Do not change system-wide npm configuration.

## External storage contract

`app.config.StoragePaths.from_environment(source_root)` selects paths without
creating them. Defaults are `%LOCALAPPDATA%/RootSentinel/{runtime,artifacts}` on
Windows and `${XDG_DATA_HOME:-$HOME/.local/share}/RootSentinel/{runtime,artifacts}`
on Linux. Override with absolute `ROOTSENTINEL_RUNTIME_ROOT` and
`ROOTSENTINEL_ARTIFACT_ROOT`.

It rejects source-tree overlap, known OneDrive roots, paths containing OneDrive
components, relative paths, and overlapping artifact/runtime trees. This is path
configuration validation, not a race-safe filesystem admission mechanism. Unknown
third-party sync roots are an operator responsibility until explicitly configured.

Databases go under `runtime/database`; upload snapshots under `runtime/snapshots`.
Secrets live in their own private folders, separate from runtime storage: the local
audit keyring under `%LOCALAPPDATA%\RootSentinel\audit-secrets` with checkpoints in
`%LOCALAPPDATA%\RootSentinel\trusted-checkpoints` ([deployment](deployment.md)), and the
hosted demo's generated secret files under `%LOCALAPPDATA%\RootSentinel\hosted-secrets`
before upload. Do not put secret values into `.env.example`.

Set `ROOTSENTINEL_FRONTEND_DIST` to a dedicated external artifact directory before
building to keep generated bundles outside OneDrive. Without it, Vite uses ignored
`frontend/dist`; it will not automatically empty the chosen directory. Dependencies
remain in ignored `frontend/node_modules`. Git-ignore does not stop OneDrive syncing.

## Local backend

Runtime storage is created only by explicit migration, CLI or application-factory calls.
From the repository root in PowerShell, using the environment created above:

```powershell
$rsPython = Join-Path $env:LOCALAPPDATA 'RootSentinel\venvs\backend\Scripts\python.exe'
$env:ROOTSENTINEL_MODE = 'local'
$env:ROOTSENTINEL_ORIGIN = 'http://127.0.0.1:5173'
$env:ROOTSENTINEL_SECURE_COOKIES = 'false'
Push-Location backend
& $rsPython -m alembic upgrade head
& $rsPython -m app.cli create-user local-admin --role ADMIN
& $rsPython -m uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log --no-proxy-headers
```

Bootstrap prompts for a password privately; no password argument or default exists.
In another terminal, start `npm run dev` from `frontend`. Vite proxies `/api` and
`/health` to loopback port 8000 without changing the browser Host. Sign in, register
the synthetic fixture, run exact, partial and shifted scans, inspect evidence and sign
out. Other roles can be created with the same CLI and their explicit role. Never
reuse real passwords.

`python -m app.cli reset-password local-admin` prompts privately and revokes sessions.
`python -m app.cli revoke-sessions local-admin` revokes all sessions for that user.
Existing users are not silently overwritten by bootstrap.

If ports are occupied, preserve existing services. Choose another frontend port
with `npm run dev -- --port 5189 --strictPort`, update `ROOTSENTINEL_ORIGIN` to match,
and use `ROOTSENTINEL_API_PORT` for the Vite proxy if the backend uses a different
port. The normal Uvicorn command takes its port via `--port`; that variable is not
an automatic Uvicorn configuration. Set the variables in each relevant terminal.

The process reads environment variables directly; `.env.example` is documentation,
not an automatically loaded credential file. With `ROOTSENTINEL_DATABASE_URL` unset,
the application uses SQLite at `<runtime>/database/rootsentinel.sqlite3`. Keep
private PostgreSQL URLs in the process environment or an approved local secret
store. Do not put them in shell history, screenshots, Git or evidence.

Linux/WSL uses the same commands with `python3 -m venv` in native external storage
and environment exports. Runtime directories must be 0700. This is the local API; the
staging agent that consumes it is described in [staging-spec.md](staging-spec.md).

Default mode is `public_demo` and refuses operational requests, so accidental startup
does not expose arbitrary uploads. `local` mode enables the operational API. Expose it
beyond loopback only as the hosted configuration does: an https origin, secure cookies,
operator-provisioned accounts and the checks in [deployment](deployment.md). Secure
cookies are mandatory outside explicit loopback configuration. See
[authentication](authentication.md).

## Audit keys and transfers

Before running mutation APIs, provision a persistent audit key and independent checkpoint
location following [deployment](deployment.md), then `python -m alembic upgrade head`.
Do not automatically create replacement keys on restart. Old verification keys must remain
available after rotation. A missing key makes mandatory operations fail closed. Run one
Uvicorn worker only. The retained snapshot directory is separate from transient intake.

## Browser workspace

The root route opens the role-aware workspace ([frontend](frontend.md)). In development Vite
proxies `/api` and `/health` to the backend. When `ROOTSENTINEL_FRONTEND_DIR` points to a
built interface, the API serves it itself (`backend/app/static_site.py`): GET and HEAD only,
SPA fallback to `index.html` for non-API deep links, and typed JSON 404 for unknown `/api`
paths, never HTML. Run `npm test` before building. After approved API changes, update
`docs/openapi.json` with `python -B scripts/export_openapi.py`, then run
`python -B scripts/frontend_contracts.py`. Node dependencies and build output are
Git-ignored; they may still sync through OneDrive. Set `ROOTSENTINEL_FRONTEND_DIST` to an
external application-owned artifact directory for builds. Runtime databases and keys remain
external.

Test commands, including the real-browser acceptance scripts, are in [testing](testing.md).
No script publishes secrets, runtime data or private filesystem locations.

## Staging agent

The staging gateway agent is implemented in `agent/rootsentinel_agent` (standard library only, a separate process
and a pure client of the REST gateway). Its full specification, provisioning commands, crash-recovery table and
non-coverage statement are in [staging-spec.md](staging-spec.md). Windows is the primary verified platform; the
POSIX code paths are exercised by the Linux CI job. Keep the staging, outbound, quarantine and state directories
outside the source tree and OneDrive, on one native volume; on Linux/WSL2 use the distribution's own filesystem,
never `/mnt/c`, `/mnt/e`, OneDrive, a Windows bind mount or a network share. The hosted server does not access
local staging directories, and the browser workflow does not depend on the agent.

Admission is nonrecursive, no-follow and regular-file only. On POSIX it is descriptor-relative (`dir_fd` with
`O_NOFOLLOW`); Windows has no `dir_fd`, so it uses `lstat`, the reparse-point attribute, link counts and a post-open
identity comparison. Ordinary files are admitted by stability polling; a producer that writes then renames to
`.ready` is admitted at once, which is a supported **hint, not a security control**. Private snapshots, not mutable
producer paths, are what the gateway scans and delivers. Test the agent with `python -m pytest` from `agent`
(it needs the backend test dependencies for the real-gateway tests) and `python -B scripts/demo_agent.py`.

## Troubleshooting and limitations

If pytest errors at setup with `PermissionError: [WinError 5] Access is denied` on `%TEMP%\pytest-of-<user>`, that folder was
left behind with permissions the current account cannot read. The tests themselves are fine: point pytest at another
temporary folder, for example `python -m pytest --basetemp "$env:LOCALAPPDATA\RootSentinel\pytest-tmp"`, or have the account
that owns the folder remove it.

Network-restricted environments may support `npm ci --offline` when every locked
tarball is cached. No custom resolver is needed by normal development.

Local runs cover what the local machine can run. CI covers clean dependency installation from the locks, Linux and Windows
agent runs, PostgreSQL, the real-browser acceptance run and the container image ([testing](testing.md)). Never include raw
terminal profiles or private host paths in public evidence. Use sanitized commands and summarized results.
