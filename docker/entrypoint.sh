#!/bin/sh
# RootSentinel hosted entrypoint (Phase 06A).
#   1. validate the configuration (an https origin is mandatory; insecure cookies are refused)
#   2. copy the secret files to private 0600 paths owned by the unprivileged account
#   3. apply migrations, run the idempotent bootstrap, start ONE uvicorn worker on $PORT
# It prints no secret values. Anything after step 2 runs as the unprivileged account.
set -eu
umask 077

fail() { echo "rootsentinel: $*" >&2; exit 1; }

case "${ROOTSENTINEL_ORIGIN:-}" in
  https://*) ;;
  *) fail "ROOTSENTINEL_ORIGIN must be set to the exact public https origin (for example https://your-service.onrender.com)" ;;
esac
[ "${ROOTSENTINEL_MODE:-}" = "local" ] || fail "ROOTSENTINEL_MODE must be local for the hosted demo"
[ "${ROOTSENTINEL_SECURE_COOKIES:-true}" != "false" ] || fail "secure cookies cannot be disabled when hosted"

PORT="${PORT:-10000}"
BASE=/var/lib/rootsentinel
KEY_SOURCE="${ROOTSENTINEL_AUDIT_KEY_SOURCE:-/etc/secrets/audit-keys.json}"
ACCOUNTS_SOURCE="${ROOTSENTINEL_ACCOUNTS_SOURCE:-/etc/secrets/accounts.json}"
ACCOUNTS_DEST="$BASE/secrets/accounts.json"
# The unprivileged account's home, identical to the passwd entry created in the Dockerfile. It does not exist.
# Everything that runs as uid 10001 gets it explicitly: the root phase leaves HOME=/root in the environment, and
# libpq (psycopg) looks for an optional client certificate under $HOME/.postgresql/. EACCES on /root/.postgresql is
# fatal to libpq while ENOENT is skipped, so the unprivileged server must never inherit root's HOME.
SERVER_HOME=/nonexistent

[ -f "$KEY_SOURCE" ] || fail "the audit key secret file was not found; upload it as a secret file (see docs/deployment.md)"

mkdir -p -m 700 "$BASE/secrets" "$BASE/runtime" "$BASE/artifacts" "$BASE/checkpoints"
if [ "$(id -u)" = "0" ]; then
  install -o 10001 -g 10001 -m 600 "$KEY_SOURCE" "$ROOTSENTINEL_AUDIT_KEY_FILE"
  [ ! -f "$ACCOUNTS_SOURCE" ] || install -o 10001 -g 10001 -m 600 "$ACCOUNTS_SOURCE" "$ACCOUNTS_DEST"
  chown -R 10001:10001 "$BASE"
  # env only sets HOME; every other variable (including ROOTSENTINEL_*) is passed through unchanged.
  run() { setpriv --reuid=10001 --regid=10001 --clear-groups env HOME="$SERVER_HOME" "$@"; }
else
  install -m 600 "$KEY_SOURCE" "$ROOTSENTINEL_AUDIT_KEY_FILE"
  [ ! -f "$ACCOUNTS_SOURCE" ] || install -m 600 "$ACCOUNTS_SOURCE" "$ACCOUNTS_DEST"
  run() { env HOME="$SERVER_HOME" "$@"; }
fi

run python -m alembic -c alembic.ini upgrade head
if [ -f "$ACCOUNTS_DEST" ]; then
  run python -m app.bootstrap --accounts "$ACCOUNTS_DEST"
else
  run python -m app.bootstrap
fi

# One worker: the rate limiters, processing slots and audit ordering assume a single process.
# --no-proxy-headers: client addresses come from ROOTSENTINEL_TRUSTED_PROXY_HOPS inside the app.
if [ "$(id -u)" = "0" ]; then
  exec setpriv --reuid=10001 --regid=10001 --clear-groups env HOME="$SERVER_HOME" python -m uvicorn app.api:create_app --factory \
    --host 0.0.0.0 --port "$PORT" --workers 1 --no-access-log --no-proxy-headers
fi
exec env HOME="$SERVER_HOME" python -m uvicorn app.api:create_app --factory --host 0.0.0.0 --port "$PORT" --workers 1 --no-access-log --no-proxy-headers
