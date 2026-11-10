# RootSentinel hosted presenter demo image (Phase 06A). One process, one worker, one origin.
# Build:  docker build -t rootsentinel-hosted .
# The image contains NO secrets and no data. The audit key and the account hashes arrive as platform
# secret files at run time (see docs/deployment.md); the database is external (PostgreSQL) or, for a
# disposable test, SQLite inside the container. Base images are pinned by tag, not by digest.

FROM node:22.14.0-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN ROOTSENTINEL_FRONTEND_DIST=/dist npm run build

FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# Apply Debian security updates that the base image tag does not include yet (for example zlib1g).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
# An unprivileged account runs the server. The entrypoint starts as root only to copy the secret
# files into a private location owned by that account, then drops privileges for everything else.
RUN groupadd --system --gid 10001 rootsentinel \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin rootsentinel \
 && mkdir -p /var/lib/rootsentinel && chown 10001:10001 /var/lib/rootsentinel && chmod 700 /var/lib/rootsentinel \
 && setpriv --version > /dev/null
COPY backend/requirements.lock /tmp/requirements.lock
# pip is needed only to install the locked requirements; removing it afterwards also removes its vendored
# copies of urllib3, msgpack and setuptools, which nothing at run time uses.
RUN pip install -r /tmp/requirements.lock && rm /tmp/requirements.lock \
 && python -m pip uninstall -y pip
WORKDIR /app/backend
COPY backend/ /app/backend/
COPY --from=frontend /dist /opt/rootsentinel/frontend
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod 755 /usr/local/bin/entrypoint.sh

# ROOTSENTINEL_ORIGIN (the exact public https origin) is deliberately NOT defaulted: the entrypoint
# refuses to start without it. Mode "local" means "operational API enabled"; see docs/deployment.md.
ENV ROOTSENTINEL_MODE=local \
    ROOTSENTINEL_RUNTIME_ROOT=/var/lib/rootsentinel/runtime \
    ROOTSENTINEL_ARTIFACT_ROOT=/var/lib/rootsentinel/artifacts \
    ROOTSENTINEL_AUDIT_KEY_FILE=/var/lib/rootsentinel/secrets/audit-keys.json \
    ROOTSENTINEL_CHECKPOINT_ROOT=/var/lib/rootsentinel/checkpoints \
    ROOTSENTINEL_FRONTEND_DIR=/opt/rootsentinel/frontend \
    ROOTSENTINEL_TRUSTED_PROXY_HOPS=0
EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
