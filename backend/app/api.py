"""Local authenticated registry, detection and controlled transfer API."""
import asyncio
from contextlib import asynccontextmanager, suppress
import ipaddress
import logging
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

import anyio
from fastapi import Depends, FastAPI, Header, Path, Query, Request, Response, Security
from fastapi.security import APIKeyCookie
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import ClientDisconnect

from .auth import AuthService, Principal, csrf_for
from .crypto import create_proof, verify_proof
from .db import Database
from .errors import DomainError
from .intake import receive_snapshot
from .config import VISITOR_ABSOLUTE_SECONDS
from .models import Asset, AssetVersion, PolicyDecision, PolicyVersion, RegistryState, ScanEvaluation
from .visitors import LOG as VISITOR_LOG, VisitorService, visitor_user_ids
from .policy import active_policy, change_policy, policy_view
from .registry import asset_view, manifest_for, register, retire, version_fingerprint, version_view
from .scans import get_scan, run_scan
from .schemas import (
    AssetPage, AssetView, AuthView, ErrorView, IntegrityInput, IntegrityView, Label,
    LoginInput, PolicyInput, PolicyPage, PolicyView, ProfileView, ProofView, ScanPage, ScanSummary,
    ScanView, UserView, VersionView, VersionSummary,
)
from . import profiles
from .settings import Settings
from .transfers import Gateway
from .gateway_api import install_routes
from .presentation import install_presentation
from .static_site import install_static

COOKIE = "rs_session"
RAW_BODY = {"requestBody": {"required": True, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}}


# Enforced on every response, locally and hosted. The interface has no inline scripts, inline style attributes or
# data: URLs; every script, style, image and request is same-origin.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
       "object-src 'none'")
MANAGED_HEADERS = {b"cache-control", b"x-content-type-options", b"referrer-policy", b"x-frame-options",
                   b"strict-transport-security", b"content-security-policy", b"content-security-policy-report-only"}


def error_response(code, status):
    return JSONResponse({"error": {"code": code, "outcome": "INDETERMINATE", "release_authorized": False}}, status_code=status)


def forwarded_client(headers, hops):
    """The address N entries from the right of X-Forwarded-For, or None to keep the socket peer.

    Only meaningful when exactly ``hops`` trusted proxies each append their peer's address, so the
    entry that many places from the right was written by the outermost trusted proxy and cannot be
    chosen by the client. Too few entries or an unparsable value fails closed to the socket peer.
    """
    if hops <= 0:
        return None
    entries = [part.strip() for k, v in headers if k == b"x-forwarded-for" for part in v.decode("latin1").split(",")]
    if len(entries) < hops:
        return None
    try:
        return str(ipaddress.ip_address(entries[-hops]))
    except ValueError:
        return None


# Every request whose configured client IP header is missing or invalid shares this one key, so a forged or
# absent value can never select its own rate-limit bucket. It cannot collide with a real address.
UNIDENTIFIED_CLIENT = "unidentified"
CLIENT_IP_LOG = logging.getLogger("rootsentinel.client_ip")
# Peak resident memory (VmHWM) at startup and every MEMORY_LOG_MINUTES minutes. Uvicorn configures only its own loggers,
# so this logger gets its own stderr handler to make INFO lines visible in the host's log.
MEMORY_LOG = logging.getLogger("rootsentinel.memory")
MEMORY_LOG_MINUTES = 10
# The maintenance loop wakes once a minute (the memory line every MEMORY_LOG_MINUTES wake-ups). It touches the
# database only when an expiry is due or snapshot files exist, so an idle process makes no database call.
MAINTENANCE_SECONDS = 60
if not MEMORY_LOG.handlers:
    _memory_handler = logging.StreamHandler()
    _memory_handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s %(message)s"))
    MEMORY_LOG.addHandler(_memory_handler)
MEMORY_LOG.setLevel(logging.INFO)


def peak_memory_kib(status_path="/proc/self/status"):
    """VmHWM in KiB from /proc (Linux), or None where /proc is unavailable (for example on Windows)."""
    try:
        with open(status_path, encoding="ascii", errors="replace") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    fields = line.split()
                    return int(fields[1]) if len(fields) >= 2 and fields[1].isdigit() else None
    except OSError:
        return None
    return None


def log_peak_memory(when, status_path="/proc/self/status"):
    kib = peak_memory_kib(status_path)
    if kib is not None:
        MEMORY_LOG.info("peak resident memory (VmHWM) %s: %d KiB (%.1f MiB)", when, kib, kib / 1024)
    return kib


def header_client(headers, name):
    """The single IP address in header ``name``, or None when it is missing, repeated or not exactly one address.

    Only meaningful when the edge in front of the host overwrites this header on every request; the
    value is never trusted beyond being parsed as one IPv4 or IPv6 address (IPv4-mapped IPv6 is
    normalised to IPv4, zone identifiers are rejected).
    """
    key = name.encode("latin1")
    values = [v for k, v in headers if k == key]
    if len(values) != 1:
        return None
    try:
        address = ipaddress.ip_address(values[0].decode("latin1").strip())
    except ValueError:
        return None
    if address.version == 6:
        if address.scope_id is not None:
            return None
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped
    return str(address)


# The routes that use the client key. Only these count and log an unidentified client: the login limiter
# today; visitor caps add their routes here.
CLIENT_KEY_ROUTES = frozenset({("POST", "/api/v1/auth/login"), ("POST", "/api/v1/auth/visitor")})
LOGGED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
STATIC_SUFFIXES = (".js", ".css", ".html", ".svg", ".png", ".ico", ".woff2", ".webmanifest", ".map", ".txt", ".json")


def classify_request(method, path, host_permitted):
    """A fixed description of a request for log lines: no part of it is a raw request value.

    The method is one of LOGGED_METHODS or OTHER; the route class is health, api, static or other; the host
    is "yes" when the Host header named this service and "no" otherwise."""
    if path == "/health":
        route = "health"
    elif path == "/api" or path.startswith("/api/"):
        route = "api"
    elif path == "/" or path.startswith("/assets/") or path.endswith(STATIC_SUFFIXES):
        route = "static"
    else:
        route = "other"
    return f"method={method if method in LOGGED_METHODS else 'OTHER'} route={route} host_permitted={'yes' if host_permitted else 'no'}"


class RequestGuard:
    """ASGI byte limits apply before JSON parsing; uploads additionally bound intake."""
    def __init__(self, app, settings):
        self.app, self.settings = app, settings
        self.permitted = frozenset({urlsplit(settings.origin).netloc, "127.0.0.1:8000", "localhost:8000", *settings.extra_hosts})
        # Requests on a route that uses the client key (CLIENT_KEY_ROUTES) without a valid client header.
        self.unidentified = 0
        # Health probes come from the hosting platform itself, not through the edge, so they carry no client
        # header. They never reach the login limiter and are counted on their own.
        self.health_without_client = 0

    def identify(self, scope):
        """The client address for a request whose Host is already accepted, or None to keep the socket peer."""
        name = self.settings.client_ip_header
        if not name:
            return forwarded_client(scope["headers"], self.settings.trusted_proxy_hops)
        client = header_client(scope["headers"], name)
        if client is not None:
            return client
        if scope["path"] == "/health":
            self.health_without_client += 1
            return None
        if (scope["method"], scope["path"]) in CLIENT_KEY_ROUTES:
            # Counted only where the key is used. The line carries a fixed classification, never a raw value,
            # and is written at 1, 10, 100, ... so a flood cannot flood the log.
            self.unidentified += 1
            if self.unidentified in {10 ** k for k in range(10)}:
                CLIENT_IP_LOG.warning("client IP header missing or invalid; shared unidentified bucket used (%d request(s) so far; %s)",
                                      self.unidentified, classify_request(scope["method"], scope["path"], True))
        # Every route gets the shared key, so a route that starts using the client can never fall back to the
        # socket peer; only the routes above count it.
        return UNIDENTIFIED_CLIENT

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        host = headers.get(b"host", b"").decode("latin1")
        failure = None
        # The Host check comes first: a request for another host is refused before any client identification,
        # so it can neither select a bucket nor advance a counter.
        if host not in self.permitted:
            failure = ("HOST_REJECTED", 400)
        else:
            forwarded = self.identify(scope)
            if forwarded is not None:
                scope = {**scope, "client": (forwarded, 0)}
        if failure:
            pass
        elif self.settings.mode != "local" and scope["path"].startswith("/api/v1"):
            failure = ("PUBLIC_DEMO_NOT_READY", 403)
        elif scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            if headers.get(b"origin", b"").decode("latin1") != self.settings.origin:
                failure = ("ORIGIN_REJECTED", 403)
        received = 0
        started = False
        content_type = headers.get(b"content-type", b"").split(b";", 1)[0]
        limit = self.settings.max_upload_bytes if content_type == b"application/octet-stream" else 32768

        async def bounded_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise DomainError("INPUT_TOO_LARGE", 413)
            return message

        async def secured_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                added = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                         (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY"),
                         (b"content-security-policy", CSP.encode("ascii"))]
                if self.settings.hosted:
                    added += [(b"strict-transport-security", b"max-age=31536000")]
                message["headers"] = [(k, v) for k, v in message.get("headers", []) if k.lower() not in MANAGED_HEADERS] + added
            await send(message)
        if failure:
            return await error_response(*failure)(scope, receive, secured_send)
        try:
            await self.app(scope, bounded_receive, secured_send)
        except Exception:
            # Do not let server error logging echo SQL, paths, payloads or secrets.
            # Expected failures use the typed exception handlers below.
            if not started:
                await error_response("INTERNAL_ERROR", 503)(scope, receive, secured_send)


def create_app(settings: Settings | None = None):
    settings = settings or Settings.from_environment()
    settings.prepare_storage()
    db = Database(settings.database_url)
    auth = AuthService(db, settings)
    gateway = Gateway(db, settings)
    visitors = VisitorService(db, settings, gateway.audit)
    auth.visitors, gateway.visitors = visitors, visitors

    @asynccontextmanager
    async def lifespan(app):
        # Refuse to serve with an uninitialized/missing registry or policy.
        with db.transaction() as s:
            state = s.get(RegistryState, 1)
            if state is None:
                raise RuntimeError("Run migrations before starting the API")
            active_policy(s, state)
        # Rebuild the audit tree from the stored events and check it against the latest signed tree head. A
        # mismatch is logged for the operator and leaves the service up with every audited action refused.
        with db.transaction() as s:
            log_usable = gateway.audit.startup(s)
        # Either call ends with the one query that sets the gateway's in-memory next due time.
        if log_usable and settings.audit_key_file is not None and settings.checkpoint_root is not None:
            gateway.recover(restart=True)
        else:
            gateway.load_due()
        log_peak_memory("at startup")

        async def maintenance():
            minutes = 0
            while True:
                await asyncio.sleep(MAINTENANCE_SECONDS)
                minutes += 1
                if minutes % MEMORY_LOG_MINUTES == 0:
                    log_peak_memory(f"after {minutes} minutes")
                try:
                    # No database call unless an expiry is due or snapshot files exist (Gateway.maintain).
                    await run_in_threadpool(gateway.maintain)
                except Exception:
                    # Release still fails closed; retry bounded maintenance next minute.
                    pass
        worker = asyncio.create_task(maintenance())
        try:
            yield
        finally:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker
            db.engine.dispose()

    # Interactive API documentation is a local-development aid; hosted or public_demo deployments do not publish it.
    docs = {} if settings.mode == "local" and not settings.hosted else {"docs_url": None, "redoc_url": None, "openapi_url": None}
    app = FastAPI(title="RootSentinel DLP", version="0.3.0", lifespan=lifespan, **docs,
        description="Local authenticated detection and single-use verified transfer gateway.",
        responses={code: {"model": ErrorView} for code in (400, 401, 403, 404, 409, 413, 415, 422, 429, 503)})
    app.state.db, app.state.auth, app.state.settings = db, auth, settings
    app.state.gateway, app.state.visitors = gateway, visitors
    app.state.intake_slots = anyio.CapacityLimiter(2)
    app.add_middleware(RequestGuard, settings=settings)

    @app.exception_handler(DomainError)
    async def domain_error(_, exc):
        return error_response(exc.code, exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_, exc):
        return error_response("INVALID_REQUEST", 422)

    @app.exception_handler(IntegrityError)
    async def conflict_error(_, exc):
        return error_response("DATA_CONFLICT", 409)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_, exc):
        return error_response("DATABASE_UNAVAILABLE", 503)

    @app.exception_handler(HTTPException)
    async def http_error(_, exc):
        return error_response("HTTP_REQUEST_REJECTED", exc.status_code)

    @app.exception_handler(Exception)
    async def internal_error(_, exc):
        return error_response("INTERNAL_ERROR", 503)

    cookie_auth = APIKeyCookie(name=COOKIE, auto_error=False)

    def principal(request: Request, token: Annotated[str | None, Security(cookie_auth)],
                  x_csrf_token: Annotated[str | None, Header(max_length=64)] = None):
        peer = request.client.host if request.client else "unknown"
        try:
            actor = auth.authenticate(token, x_csrf_token, request.method not in {"GET", "HEAD", "OPTIONS"})
        except DomainError as error:
            if error.code == "VISITOR_SESSION_ENDED":
                VISITOR_LOG.info("visitor session expired ip=%s", peer)
            raise
        if actor.role == "VISITOR":
            route = getattr(request.scope.get("route"), "path", "")
            visitors.guard(actor, request.method, route, peer)  # default deny: only the allowlisted routes
        return actor

    def auth_view(request, actor):
        return AuthView(user=UserView(id=actor.id, username=actor.username, role=actor.role),
                        csrf_token=csrf_for(request.cookies[COOKIE]),
                        visitor=visitors.info(actor) if actor.role == "VISITOR" else None)

    Actor = Annotated[Principal, Depends(principal)]
    PageLimit = Annotated[int, Query(ge=1, le=100)]
    PageOffset = Annotated[int, Query(ge=0, le=100000)]

    @app.get("/health")
    def health():
        # hosted: the server's own view (an https origin), so the interface never guesses from the hostname.
        # commit: the deployed commit id or "unknown"; max_upload_bytes: the upload cap the interface should enforce.
        return {"status": "ok", "mode": settings.mode, "release_configured": settings.mode == "local" and bool(settings.audit_key_file and settings.checkpoint_root and settings.transparency_key_file),
                "hosted": settings.hosted, "commit": settings.commit, "max_upload_bytes": settings.max_upload_bytes,
                "visitor_mode": settings.visitor_mode_enabled, "visitor_upload_bytes": settings.visitor_upload_limit}

    @app.post("/api/v1/auth/visitor", response_model=AuthView)
    def visitor_entry(request: Request, response: Response):
        """Start a sandboxed visitor session. No password and no Argon2 work. The Origin check is the sign-in one
        (RequestGuard); a Sec-Fetch-Site header, when present, must say same-origin (or none)."""
        if not settings.visitor_mode_enabled:
            raise DomainError("NOT_FOUND", 404)
        peer = request.client.host if request.client else "unknown"
        if request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}:
            VISITOR_LOG.warning("visitor entry refused ip=%s code=CROSS_SITE", peer)
            raise DomainError("ORIGIN_REJECTED", 403)
        token, result = visitors.enter(peer)
        response.set_cookie(COOKIE, token, max_age=VISITOR_ABSOLUTE_SECONDS, httponly=True,
                            secure=settings.secure_cookies, samesite="strict", path="/api/v1")
        return result

    @app.post("/api/v1/auth/login", response_model=AuthView)
    def login(body: LoginInput, request: Request, response: Response):
        token, result = auth.login(body.username, body.password, request.client.host if request.client else "unknown", request.cookies.get(COOKIE))
        response.set_cookie(COOKIE, token, max_age=settings.session_seconds, httponly=True,
                            secure=settings.secure_cookies, samesite="strict", path="/api/v1")
        return result

    @app.get("/api/v1/auth/session", response_model=AuthView, responses={204: {"description": "No valid session"}})
    def session_status(request: Request):
        """Public session check for the interface: 200 with the session, or 204 when there is none.

        Unlike /auth/me it never answers 401, so a signed-out page load logs no failed request. It reveals only
        whether the presented cookie is a valid session, which /auth/me already does."""
        try:
            actor = auth.authenticate(request.cookies.get(COOKIE))
        except DomainError:
            return Response(status_code=204)
        return auth_view(request, actor)

    @app.get("/api/v1/auth/me", response_model=AuthView)
    def me(request: Request, actor: Actor):
        return auth_view(request, actor)

    @app.post("/api/v1/auth/logout", status_code=204)
    def logout(response: Response, actor: Actor):
        auth.logout(actor)
        response.delete_cookie(COOKIE, path="/api/v1", httponly=True, secure=settings.secure_cookies, samesite="strict")

    @app.get("/api/v1/assets", response_model=AssetPage)
    def assets(actor: Actor, limit: PageLimit = 25, offset: PageOffset = 0, retired: bool | None = None,
               q: Annotated[str, Query(max_length=120)] = ""):
        actor.require("ADMIN", "ANALYST")
        statement = select(Asset)
        if retired is not None:
            statement = statement.where(Asset.retired == retired)
        if q:
            statement = statement.where(Asset.label.contains(q, autoescape=True))
        with db.transaction() as s:
            return AssetPage(items=[asset_view(a) for a in s.scalars(statement.order_by(Asset.created_at, Asset.id).offset(offset).limit(limit))], offset=offset, limit=limit)

    async def intake(request, action, actor=None):
        if request.headers.get("content-type") != "application/octet-stream":
            raise DomainError("OCTET_STREAM_REQUIRED", 415)
        try:
            app.state.intake_slots.acquire_nowait()
        except anyio.WouldBlock:
            raise DomainError("SCAN_CAPACITY", 503)
        try:
            try:
                snapshot = await asyncio.wait_for(receive_snapshot(request.stream(), settings.paths.snapshots,
                                                                         settings.visitor_upload_limit if actor is not None and actor.role == "VISITOR" else settings.max_upload_bytes), timeout=60)
            except (ClientDisconnect, asyncio.TimeoutError):
                raise DomainError("INCOMPLETE_UPLOAD", 400)
            length = request.headers.get("content-length")
            if length is not None and (not length.isdecimal() or int(length) != len(snapshot.data)):
                raise DomainError("INCOMPLETE_UPLOAD", 400)
            return await run_in_threadpool(action, snapshot)
        finally:
            app.state.intake_slots.release()

    @app.post("/api/v1/assets", response_model=VersionView, status_code=201, openapi_extra=RAW_BODY)
    async def new_asset(request: Request, actor: Actor, label: Label):
        actor.require("ADMIN")
        def action(snapshot):
            with db.transaction() as s:
                result = register(s, actor, label, snapshot.data)
                gateway.audit.append(s, "ASSET_REGISTERED", actor.id, result.asset_id, registry_revision=result.registry_revision)
                return result
        return await intake(request, action, actor)

    @app.post("/api/v1/assets/{asset_id}/versions", response_model=VersionView, status_code=201, openapi_extra=RAW_BODY)
    async def new_version(asset_id: UUID, request: Request, actor: Actor, expected_version: Annotated[int, Query(ge=1)]):
        actor.require("ADMIN")
        def action(snapshot):
            with db.transaction() as s:
                result = register(s, actor, "unused", snapshot.data, str(asset_id), expected_version)
                gateway.audit.append(s, "ASSET_REGISTERED", actor.id, result.asset_id, registry_revision=result.registry_revision)
                return result
        return await intake(request, action)

    @app.get("/api/v1/assets/{asset_id}", response_model=AssetView)
    def asset(asset_id: UUID, actor: Actor):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            asset = s.get(Asset, str(asset_id))
            if asset is None:
                raise DomainError("NOT_FOUND", 404)
            return asset_view(asset)

    @app.get("/api/v1/assets/{asset_id}/versions", response_model=list[VersionSummary])
    def versions(asset_id: UUID, actor: Actor, limit: Annotated[int, Query(ge=1, le=10)] = 5, offset: PageOffset = 0):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            versions = s.scalars(select(AssetVersion).where(AssetVersion.asset_id == str(asset_id)).order_by(AssetVersion.number.desc()).limit(limit).offset(offset)).all()
            carried = profiles.version_profiles(s, versions)
            return [VersionSummary(**{k: getattr(v, k) for k in VersionSummary.model_fields if k not in {"manifest", "profiles"}},
                                   manifest=manifest_for(v).to_dict(), profiles=carried[v.id]) for v in versions]

    @app.get("/api/v1/assets/{asset_id}/versions/{version_id}", response_model=VersionView)
    def version(asset_id: UUID, version_id: UUID, actor: Actor):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            return version_view(s, str(asset_id), str(version_id))

    @app.post("/api/v1/assets/{asset_id}/retire", response_model=AssetView)
    def retire_asset(asset_id: UUID, actor: Actor):
        with db.transaction() as s:
            result = retire(s, actor, str(asset_id))
            gateway.audit.append(s, "ASSET_RETIRED", actor.id, str(asset_id))
            return result

    @app.get("/api/v1/assets/{asset_id}/versions/{version_id}/proofs/{index}", response_model=ProofView)
    def proof(asset_id: UUID, version_id: UUID, index: Annotated[int, Path(ge=0, le=10239)], actor: Actor):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            _, fingerprint = version_fingerprint(s, str(asset_id), str(version_id))
            if index >= len(fingerprint.chunks):
                raise DomainError("NOT_FOUND", 404)
            return create_proof(fingerprint, index).to_dict()

    @app.post("/api/v1/integrity/verify", response_model=IntegrityView)
    def integrity(body: IntegrityInput, actor: Actor):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            _, fingerprint = version_fingerprint(s, body.asset_id, body.version_id)
            return IntegrityView(valid=verify_proof(body.proof, fingerprint.manifest))

    @app.get("/api/v1/detection/profiles", response_model=list[ProfileView])
    def detection_profiles(actor: Actor):
        """The registered detection profiles and their published parameters. Constants: no database call."""
        return [profile.view() for profile in profiles.registered()]

    @app.get("/api/v1/policies/active", response_model=PolicyView)
    def policy(actor: Actor):
        with db.transaction() as s:
            state = s.get(RegistryState, 1)
            if state is None:
                raise DomainError("REGISTRY_UNAVAILABLE", 503)
            return policy_view(active_policy(s, state))

    @app.get("/api/v1/policies/history", response_model=PolicyPage)
    def policies(actor: Actor, limit: PageLimit = 25, offset: PageOffset = 0):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            return PolicyPage(items=[policy_view(p) for p in s.scalars(select(PolicyVersion).order_by(PolicyVersion.number.desc()).offset(offset).limit(limit))], offset=offset, limit=limit)

    @app.post("/api/v1/policies", response_model=PolicyView, status_code=201)
    def update_policy(body: PolicyInput, actor: Actor):
        with db.transaction() as s:
            result = change_policy(s, actor, body)
            gateway.audit.append(s, "POLICY_CHANGED", actor.id, result.id, policy_id=result.id)
            return result

    @app.post("/api/v1/scans", response_model=ScanView, status_code=201, openapi_extra=RAW_BODY)
    async def scan(request: Request, actor: Actor, filename: Label = "candidate.bin"):
        def action(snapshot):
            with db.transaction() as s:
                if actor.role == "VISITOR":
                    visitors.consume_submission(s, actor, audited=False)  # a plain scan writes no audit event
                return run_scan(s, actor, filename, snapshot)
        return await intake(request, action, actor)

    @app.get("/api/v1/scans", response_model=ScanPage)
    def scans(actor: Actor, limit: PageLimit = 25, offset: PageOffset = 0, include_visitors: bool = False):
        stmt = select(ScanEvaluation, PolicyDecision).join(PolicyDecision)
        if include_visitors:
            actor.require("ADMIN")  # visitor sandboxes are hidden from real users unless an administrator asks
        if actor.own_only:
            stmt = stmt.where(ScanEvaluation.actor_id == actor.id)
        elif not include_visitors:
            stmt = stmt.where(ScanEvaluation.actor_id.not_in(visitor_user_ids()))
        with db.transaction() as s:
            rows = s.execute(stmt.order_by(ScanEvaluation.created_at.desc(), ScanEvaluation.id).offset(offset).limit(limit))
            return ScanPage(items=[ScanSummary(id=scan.id, filename=scan.filename, created_at=scan.created_at,
                                              outcome=decision.outcome, reason=decision.reason) for scan, decision in rows], offset=offset, limit=limit)

    @app.get("/api/v1/scans/{scan_id}", response_model=ScanView)
    def scan_detail(scan_id: UUID, actor: Actor):
        with db.transaction() as s:
            return get_scan(s, actor, str(scan_id))

    install_routes(app, principal, intake)
    install_presentation(app, principal)
    if settings.frontend_dir is not None:
        install_static(app, settings.frontend_dir, lambda: error_response("NOT_FOUND", 404))   # last: it is a catch-all
    return app
