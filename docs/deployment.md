# Local Phase 03 operation and future deployment boundary

No public deployment is implemented. `public_demo` remains fail-closed for all `/api/v1`
routes. The authenticated local fixture-selection endpoint performs real processing;
it is not anonymous demo isolation. No arbitrary forwarding URL or staging agent exists.

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
