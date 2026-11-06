# Developer installation and storage

## Preserve the existing repository

Use the existing `https://github.com/UsmanPrime/rootsentinel-dlp.git` repository.
The owner verified the remote was empty through normal Windows PowerShell
(`git ls-remote`, exit 0), then initialized this local repository on `main` and
configured origin. Source, tests and documentation were preserved. See the Phase 01
report for historical checkpoint evidence. Phase 01 was subsequently published;
Phase 02 has separate conditional publication authorization and evidence.

Do not reinitialize or clone into this nonempty working directory. Preserve local
history, inspect divergence before later synchronization, and stop on unexpected
remote content. Do not force push, force checkout or overwrite unrelated files.
Licensing remains a team decision.

## Toolchain

- Python 3.12 or 3.13; local validation used Python 3.12.12 (unittest) and 3.13.4 (pytest).
- Node >=22.12 and <25; local validation used Node 24.11.0/npm 11.6.1.
- Cryptographic core: standard library only. Phase 02 runtime dependencies are
  pinned in `backend/requirements.lock`, tests in `backend/requirements-dev.lock`.
- Frontend: exact direct versions plus `package-lock.json`; install with `npm ci`.
- Docker/WSL2 are required for later delivery, not to exercise the crypto library.

The `dev` group in pyproject declares the pytest requirement; the requirements
lock is the canonical installation input including transitive pins. Do not resolve
a different test environment implicitly with `uv sync`. A future package-management
change must update both the documentation and reproducibility checks.

## Windows setup (after required path permissions are available)

Run from the authoritative source workspace. These commands create a project-local
environment outside the synchronized source tree; they do not modify global Python.

```powershell
$rsVenv = Join-Path $env:LOCALAPPDATA 'RootSentinel\venvs\backend'
python -m venv $rsVenv
$rsPython = Join-Path $rsVenv 'Scripts\python.exe'
& $rsPython -m pip install -r backend/requirements-dev.lock
Push-Location backend
& $rsPython -m pytest
Pop-Location
```

If the selected Python lacks `venv`/`pip`, use an already available supported
CPython or the agreed WSL/container environment. Do not silently install a system
runtime. During this session the default MSYS Python lacked pip and pytest; the
dependency-free test command worked, and an existing Python 3.13 environment later
provided the exact pinned pytest toolchain. For the dependency-free option:

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
Secrets are stored separately under `%LOCALAPPDATA%/RootSentinel/secrets` or
`$HOME/.config/rootsentinel`, with user-only access. Do not put secret values into
`.env.example`. No application secrets exist in Phase 01.

Set `ROOTSENTINEL_FRONTEND_DIST` to a dedicated external artifact directory before
building to keep generated bundles outside OneDrive. Without it, Vite uses ignored
`frontend/dist`; it will not automatically empty the chosen directory. Dependencies
remain in ignored `frontend/node_modules`. Git-ignore does not stop OneDrive syncing.

## Staging agent (Phase 05)

The staging gateway agent is implemented in `agent/rootsentinel_agent` (standard library only, a separate process
and a pure client of the REST gateway). Its full specification, provisioning commands, crash-recovery table and
non-coverage statement are in [staging-spec.md](staging-spec.md). Windows is the primary verified platform; the
POSIX code paths are exercised by the Linux CI job. Keep the staging, outbound, quarantine and state directories
outside the source tree and OneDrive, on one native volume; on Linux/WSL2 use the distribution's own filesystem,
never `/mnt/c`, `/mnt/e`, OneDrive, a Windows bind mount or a network share. The public server does not access
local staging directories, and the public browser workflow does not depend on the agent.

Admission is nonrecursive, no-follow and regular-file only. On POSIX it is descriptor-relative (`dir_fd` with
`O_NOFOLLOW`); Windows has no `dir_fd`, so it uses `lstat`, the reparse-point attribute, link counts and a post-open
identity comparison. Ordinary files are admitted by stability polling; a producer that writes then renames to
`.ready` is admitted at once, which is a supported **hint, not a security control**. Private snapshots, not mutable
producer paths, are what the gateway scans and delivers. Test the agent with `python -m pytest` from `agent`
(it needs the backend test dependencies for the real-gateway tests) and `python -B scripts/demo_phase05.py`.

## Troubleshooting and limitations

Network-restricted environments may support `npm ci --offline` when every locked
tarball is cached. The implementation session generated the npm lock from cached
registry metadata using npm's bundled resolver, with integrity checking retained;
subsequent standard `npm ci --offline` succeeded. No custom resolver is needed by
normal development. Verify a clean connected installation in CI before release.

Clean Python dependency installation, hosted CI, Docker execution, native Linux
tests, and GitHub connectivity remain separate checks. The existing pinned pytest
environment passed with plugin autoload disabled to exclude unrelated installed
plugins. Never include raw terminal profiles or private host paths in public
evidence. Use sanitized commands and summarized results.

## Phase 02 local backend

The preceding environment-availability notes describe Phase 01. Phase 02 installed
the locked backend into its own external virtual environment. Runtime storage is
created only by explicit migration, CLI or application-factory calls.

From the source root in PowerShell, using an existing supported CPython:

```powershell
$rsVenv = Join-Path $env:LOCALAPPDATA 'RootSentinel\venvs\backend'
python -m venv $rsVenv
$rsPython = Join-Path $rsVenv 'Scripts\python.exe'
& $rsPython -m pip install -r backend/requirements-dev.lock
$env:ROOTSENTINEL_MODE = 'local'
$env:ROOTSENTINEL_ORIGIN = 'http://127.0.0.1:5173'
$env:ROOTSENTINEL_SECURE_COOKIES = 'false'
Push-Location backend
& $rsPython -m alembic upgrade head
& $rsPython -m app.cli create-user local-admin --role ADMIN
& $rsPython -m uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log --no-proxy-headers
```

Bootstrap prompts for a password privately; no password argument or default exists.
In another terminal, start `npm run dev` from `frontend`. Vite proxies `/api` to
loopback port 8000 without changing the browser Host. Sign in, register the synthetic
fixture, run exact/partial/shifted scans, inspect evidence and sign out. Other roles
can be created with the same CLI and their explicit role. Never reuse real passwords.

`python -m app.cli reset-password local-admin` prompts privately and revokes sessions.
`python -m app.cli revoke-sessions local-admin` revokes all sessions for that user.
Existing users are not silently overwritten by bootstrap.

If ports are occupied, preserve existing services. Choose another frontend port
with `npm run dev -- --port 5189 --strictPort`, update `ROOTSENTINEL_ORIGIN` to match,
and use `ROOTSENTINEL_API_PORT` for the Vite proxy if the backend uses a different
port. The normal Uvicorn command takes its port via `--port`; that variable is not
an automatic Uvicorn configuration. Set the variables in each relevant terminal.

The process reads environment variables directly; `.env.example` is documentation,
not an automatically loaded credential file. Unset DATABASE_URL selects external
SQLite. Keep private PostgreSQL URLs in the process environment or an approved local
secret store. Do not put them in shell history, screenshots, Git or evidence.

Linux/WSL uses the same commands with `python3 -m venv` in native external storage
and environment exports. Runtime directories must be 0700. This is the local API; the
staging agent that consumes it is described in [staging-spec.md](staging-spec.md).

Default mode is `public_demo` and refuses operational requests, so accidental startup
does not expose arbitrary uploads. Do not deploy local mode publicly. Secure cookies
are mandatory outside explicit loopback configuration. See [authentication](authentication.md).

## Phase 03 setup

Before running mutation APIs, provision a persistent audit key and independent checkpoint
location following [deployment.md](deployment.md), then `python -m alembic upgrade head`.
Do not automatically create replacement keys on restart. Old verification keys must remain
available after rotation. A missing key makes mandatory operations fail closed. Run one
Uvicorn worker only. The retained snapshot directory is separate from transient intake.

`scripts/verify_phase03.py` records sanitized regression/typecheck/build/fixture results;
`scripts/browser_phase03.py` exercises actual download bytes, denied forged release,
incident resolution/export and audit verification with the existing external browser harness.
`scripts/benchmark_phase03.py` records synthetic SQLite timing/query/allocation samples.
No script publishes secrets, runtime data or private filesystem locations.

## Phase 04 browser workspace

The root route now opens the role-aware SOC workspace; `/legacy` preserves the
earlier workbench. Vite must proxy `/api` to the configured backend. React Router
requires SPA fallback to index.html for non-API deep links in a future static host.
Do not route `/api` failures to HTML. No public deployment was added.
Run `npm test` before building. Update `docs/openapi.json` using the existing export
script, then `python -B scripts/frontend_contracts.py` after approved API changes.
Node dependencies and build output are Git-ignored; they may still sync through
OneDrive. Set `ROOTSENTINEL_FRONTEND_DIST` to an external application-owned artifact
directory for high-volume builds. Runtime databases and keys remain external.
