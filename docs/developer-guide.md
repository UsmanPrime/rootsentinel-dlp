# Developer installation and storage

## Preserve the existing repository

Use the existing `https://github.com/UsmanPrime/rootsentinel-dlp.git` repository.
The owner verified the remote was empty through normal Windows PowerShell
(`git ls-remote`, exit 0), then initialized this local repository on `main` and
configured origin. Source, tests and documentation were preserved. See the Phase 01
report for local checkpoint evidence. No push has been authorized.

Do not reinitialize or clone into this nonempty working directory. Preserve local
history, inspect divergence before later synchronization, and stop on unexpected
remote content. Do not force push, force checkout or overwrite unrelated files.
Licensing remains a team decision.

## Toolchain

- Python 3.12 or 3.13; local validation used Python 3.12.12 (unittest) and 3.13.4 (pytest).
- Node >=22.12 and <25; local validation used Node 24.11.0/npm 11.6.1.
- Backend core: standard library only. Test dependencies: exact versions in
  `backend/requirements-dev.lock`; no installed runtime dependency is required.
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
python -B -m unittest discover -s tests -v
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

## Linux/WSL2 local gateway boundary (later phase)

Keep source in its approved Windows location. Run the supported adapter inside
Linux/WSL2 against `$HOME/.local/share/rootsentinel/runtime/{staging,snapshots,delivered}`
on the distribution's native Linux filesystem. Do not stage on `/mnt/c`, `/mnt/e`,
OneDrive, a Windows bind mount or a network share. Windows can use the service's
loopback browser port; the public server does not access local staging directories.

Admission will be nonrecursive, descriptor-relative, no-follow and regular-file
only. Producers write then rename to `.ready`. Private snapshots—not mutable
producer paths—are scanned and delivered. Linux availability was not verified:
`wsl --list --quiet` returned access denied in this environment. Installing WSL,
altering its settings or changing sync configuration requires explicit approval.

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
