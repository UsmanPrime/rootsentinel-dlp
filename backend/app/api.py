"""Local authenticated registry, detection and controlled transfer API."""
import asyncio
from contextlib import asynccontextmanager, suppress
import ipaddress
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
from .models import Asset, AssetVersion, PolicyDecision, PolicyVersion, RegistryState, ScanEvaluation
from .policy import active_policy, change_policy, policy_view
from .registry import asset_view, manifest_for, register, retire, version_fingerprint, version_view
from .scans import get_scan, run_scan
from .schemas import (
    AssetPage, AssetView, AuthView, ErrorView, IntegrityInput, IntegrityView, Label,
    LoginInput, PolicyInput, PolicyPage, PolicyView, ProofView, ScanPage, ScanSummary,
    ScanView, UserView, VersionView, VersionSummary,
)
from .settings import Settings
from .transfers import Gateway
from .gateway_api import install_routes
from .presentation import install_presentation
from .static_site import install_static

COOKIE = "rs_session"
RAW_BODY = {"requestBody": {"required": True, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}}


# Report-only until the deployed pages have been observed. The only inline styles are four React style props.
CSP_REPORT_ONLY = ("default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; "
                   "font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
MANAGED_HEADERS = {b"cache-control", b"x-content-type-options", b"referrer-policy", b"x-frame-options",
                   b"strict-transport-security", b"content-security-policy-report-only"}


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


class RequestGuard:
    """ASGI byte limits apply before JSON parsing; uploads additionally bound intake."""
    def __init__(self, app, settings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        host = headers.get(b"host", b"").decode("latin1")
        permitted = {urlsplit(self.settings.origin).netloc, "127.0.0.1:8000", "localhost:8000", *self.settings.extra_hosts}
        forwarded = forwarded_client(scope["headers"], self.settings.trusted_proxy_hops)
        if forwarded is not None:
            scope = {**scope, "client": (forwarded, 0)}
        failure = None
        if host not in permitted:
            failure = ("HOST_REJECTED", 400)
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
                         (b"referrer-policy", b"no-referrer"), (b"x-frame-options", b"DENY")]
                if self.settings.hosted:
                    added += [(b"strict-transport-security", b"max-age=31536000"),
                              (b"content-security-policy-report-only", CSP_REPORT_ONLY.encode("ascii"))]
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

    @asynccontextmanager
    async def lifespan(app):
        # Refuse to serve with an uninitialized/missing registry or policy.
        with db.transaction() as s:
            state = s.get(RegistryState, 1)
            if state is None:
                raise RuntimeError("Run migrations before starting the API")
            active_policy(s, state)
        if settings.audit_key_file is not None and settings.checkpoint_root is not None:
            gateway.recover(restart=True)
        async def maintenance():
            while True:
                await asyncio.sleep(60)
                try:
                    await run_in_threadpool(gateway.recover)
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
    app.state.gateway = gateway
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
        return auth.authenticate(token, x_csrf_token,
                                 request.method not in {"GET", "HEAD", "OPTIONS"})

    Actor = Annotated[Principal, Depends(principal)]
    PageLimit = Annotated[int, Query(ge=1, le=100)]
    PageOffset = Annotated[int, Query(ge=0, le=100000)]

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": settings.mode, "release_configured": settings.mode == "local" and bool(settings.audit_key_file and settings.checkpoint_root)}

    @app.post("/api/v1/auth/login", response_model=AuthView)
    def login(body: LoginInput, request: Request, response: Response):
        token, result = auth.login(body.username, body.password, request.client.host if request.client else "unknown", request.cookies.get(COOKIE))
        response.set_cookie(COOKIE, token, max_age=settings.session_seconds, httponly=True,
                            secure=settings.secure_cookies, samesite="strict", path="/api/v1")
        return result

    @app.get("/api/v1/auth/me", response_model=AuthView)
    def me(request: Request, actor: Actor):
        return AuthView(user=UserView(id=actor.id, username=actor.username, role=actor.role),
                        csrf_token=csrf_for(request.cookies[COOKIE]))

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

    async def intake(request, action):
        if request.headers.get("content-type") != "application/octet-stream":
            raise DomainError("OCTET_STREAM_REQUIRED", 415)
        try:
            app.state.intake_slots.acquire_nowait()
        except anyio.WouldBlock:
            raise DomainError("SCAN_CAPACITY", 503)
        try:
            try:
                snapshot = await asyncio.wait_for(receive_snapshot(request.stream(), settings.paths.snapshots, settings.max_upload_bytes), timeout=60)
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
        return await intake(request, action)

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
            return [VersionSummary(**{k: getattr(v, k) for k in VersionSummary.model_fields if k != "manifest"},
                                   manifest=manifest_for(v).to_dict()) for v in versions]

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
                return run_scan(s, actor, filename, snapshot)
        return await intake(request, action)

    @app.get("/api/v1/scans", response_model=ScanPage)
    def scans(actor: Actor, limit: PageLimit = 25, offset: PageOffset = 0):
        stmt = select(ScanEvaluation, PolicyDecision).join(PolicyDecision)
        if actor.role == "EMPLOYEE":
            stmt = stmt.where(ScanEvaluation.actor_id == actor.id)
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
