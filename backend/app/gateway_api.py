"""Authenticated controlled downloads and investigation routes."""
import asyncio
import json
from collections import OrderedDict
from threading import Lock
import time
from typing import Annotated
from uuid import UUID, uuid4

import anyio
from fastapi import Depends, Header, Query, Request
from starlette.responses import Response
from starlette.concurrency import run_in_threadpool
from sqlalchemy import select

from .auth import Principal
from .errors import DomainError
from .gateway_models import AuditEvent, Incident, Transfer
from .gateway_schemas import AuditPage, AuditVerification, IncidentPage, IncidentPatch, IncidentView, TransferPage, TransferView, TransferSummary
from .db import now
from .incidents import export_incident, incident_view, update_incident
from .intake import FrozenInput
from .registry import lock_state
from .schemas import Label, Schema
from typing import Literal


class FixtureChoice(Schema):
    fixture: Literal["benign", "protected"]


class TransferLimiter:
    """Single-worker fixed windows; both global and per-account bounds."""
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock, self.buckets = clock, Lock(), OrderedDict()

    def check(self, actor_id):
        with self.lock:
            current = self.clock()
            for key, maximum in (("global", 120), (actor_id, 30)):
                start, count = self.buckets.get(key, (current, 0))
                if current - start >= 60:
                    start, count = current, 0
                if count >= maximum:
                    raise DomainError("TRANSFER_RATE_LIMIT", 429)
                self.buckets[key] = start, count + 1
                self.buckets.move_to_end(key)
            while len(self.buckets) > 2048:
                self.buckets.popitem(last=False)


class VerifiedResponse(Response):
    """Only the immutable preflight buffer is sent. Completion is server-side."""
    def __init__(self, data, gateway, identifier, limiter, borrower):
        super().__init__(data, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="transfer-{identifier}.bin"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        self.gateway, self.identifier, self.limiter, self.borrower = gateway, identifier, limiter, borrower

    async def __call__(self, scope, receive, send):
        completed = False

        async def deliver():
            await send({"type": "http.response.start", "status": 200, "headers": self.raw_headers})
            for offset in range(0, len(self.body), 65536):
                await send({"type": "http.response.body", "body": self.body[offset:offset + 65536], "more_body": True})
            await send({"type": "http.response.body", "body": b"", "more_body": False})

        async def disconnected():
            while True:
                if (await receive())["type"] == "http.disconnect":
                    return

        tasks = [asyncio.create_task(deliver()), asyncio.create_task(disconnected())]
        try:
            done, _ = await asyncio.wait(tasks, timeout=60, return_when=asyncio.FIRST_COMPLETED)
            if tasks[0] in done:
                tasks[0].result()
                completed = True
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            with anyio.CancelScope(shield=True):
                await asyncio.gather(*tasks, return_exceptions=True)
                try:
                    await run_in_threadpool(self.gateway.finish, self.identifier, completed)
                except Exception:
                    # Persisted RELEASE_STARTED remains uncertain; recovery never retries it.
                    pass
                self.limiter.release_on_behalf_of(self.borrower)


def install_routes(app, principal, intake):
    gateway, db = app.state.gateway, app.state.db
    limiter = TransferLimiter()
    Actor = Annotated[Principal, Depends(principal)]
    Limit = Annotated[int, Query(ge=1, le=100)]
    Offset = Annotated[int, Query(ge=0, le=100000)]
    Retry = Annotated[UUID, Header(alias="Idempotency-Key")]

    @app.post("/api/v1/transfers", response_model=TransferView, status_code=201,
        openapi_extra={"requestBody": {"required": True, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}})
    async def submit(request: Request, actor: Actor, idempotency_key: Retry, filename: Label = "candidate.bin"):
        limiter.check(actor.id)
        return await intake(request, lambda snapshot: gateway.submit(actor, filename, snapshot, str(idempotency_key)))

    @app.post("/api/v1/transfers/fixtures", response_model=TransferView, status_code=201)
    async def fixture(body: FixtureChoice, actor: Actor, idempotency_key: Retry):
        limiter.check(actor.id)
        # Local authenticated path only; RequestGuard denies public mode until isolation ships.
        data = b"RootSentinel synthetic benign delivery\n" if body.fixture == "benign" else b"SYNTHETIC-PROTECTED-" * 128
        borrower = object()
        try:
            app.state.intake_slots.acquire_on_behalf_of_nowait(borrower)
        except anyio.WouldBlock:
            raise DomainError("TRANSFER_CAPACITY", 503)
        try:
            return await run_in_threadpool(gateway.submit, actor, body.fixture + ".txt", FrozenInput(str(uuid4()), data), str(idempotency_key))
        finally:
            app.state.intake_slots.release_on_behalf_of(borrower)

    @app.get("/api/v1/transfers", response_model=TransferPage)
    def listing(actor: Actor, limit: Limit = 25, offset: Offset = 0):
        query = select(Transfer)
        if actor.role == "EMPLOYEE":
            query = query.where(Transfer.actor_id == actor.id)
        with db.transaction() as s:
            rows = s.scalars(query.order_by(Transfer.created_at.desc(), Transfer.id).offset(offset).limit(limit)).all()
            return TransferPage(items=[TransferSummary(**{k: getattr(t, k) for k in TransferSummary.model_fields if k != "release_eligible"},
                release_eligible=t.state == "ALLOWED" and t.expires_at > now() and t.actor_id == actor.id) for t in rows], offset=offset, limit=limit)

    @app.get("/api/v1/transfers/{identifier}", response_model=TransferView)
    def detail(identifier: UUID, actor: Actor):
        with db.transaction() as s:
            return gateway.view(s, actor, str(identifier))

    @app.post("/api/v1/transfers/{identifier}/release", response_class=Response,
              responses={200: {"content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}})
    async def release(identifier: UUID, actor: Actor):
        limiter.check(actor.id)
        borrower = object()
        try:
            app.state.intake_slots.acquire_on_behalf_of_nowait(borrower)
        except anyio.WouldBlock:
            raise DomainError("TRANSFER_CAPACITY", 503)
        try:
            data = await run_in_threadpool(gateway.release, actor, str(identifier))
            return VerifiedResponse(data, gateway, str(identifier), app.state.intake_slots, borrower)
        except BaseException:
            app.state.intake_slots.release_on_behalf_of(borrower)
            raise

    @app.get("/api/v1/incidents", response_model=IncidentPage)
    def incidents(actor: Actor, limit: Limit = 25, offset: Offset = 0, status: Literal["OPEN", "INVESTIGATING", "RESOLVED"] | None = None,
                  severity: Literal["HIGH", "MEDIUM"] | None = None, order: Literal["newest", "oldest"] = "newest"):
        actor.require("ADMIN", "ANALYST")
        query = select(Incident)
        if status:
            query = query.where(Incident.status == status)
        if severity:
            query = query.where(Incident.severity == severity)
        with db.transaction() as s:
            rows = s.scalars(query.order_by(Incident.created_at.desc() if order == "newest" else Incident.created_at.asc(), Incident.id).offset(offset).limit(limit))
            return IncidentPage(items=[{k: getattr(row, k) for k in ("id", "transfer_id", "severity", "status", "revision", "created_at")} for row in rows], offset=offset, limit=limit)

    @app.get("/api/v1/incidents/{identifier}", response_model=IncidentView)
    def incident(identifier: UUID, actor: Actor):
        with db.transaction() as s:
            return incident_view(s, actor, str(identifier))

    @app.patch("/api/v1/incidents/{identifier}", response_model=IncidentView)
    def investigate(identifier: UUID, body: IncidentPatch, actor: Actor):
        with db.transaction() as s:
            return update_incident(s, actor, str(identifier), body, gateway.audit)

    @app.get("/api/v1/exports/incidents/{identifier}")
    def export(identifier: UUID, actor: Actor):
        with db.transaction() as s:
            lock_state(s)
            return export_incident(s, actor, str(identifier), gateway.audit)

    @app.get("/api/v1/audit/events", response_model=AuditPage)
    def events(actor: Actor, limit: Limit = 25, after: Annotated[int, Query(ge=0, le=20000)] = 0):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            rows = s.scalars(select(AuditEvent).where(AuditEvent.sequence > after).order_by(AuditEvent.sequence).limit(limit))
            return AuditPage(events=[{"event": json.loads(row.canonical), "mac": row.mac} for row in rows], after=after, limit=limit)

    @app.post("/api/v1/audit/verify", response_model=AuditVerification)
    def verify(actor: Actor):
        actor.require("ADMIN", "ANALYST")
        with db.transaction() as s:
            lock_state(s)
            result = gateway.audit.verify(s)
            if result["valid"]:
                gateway.audit.append(s, "AUDIT_VERIFIED", actor.id, revision=result["through_sequence"])
            return result

    @app.post("/api/v1/audit/checkpoint")
    def checkpoint(actor: Actor):
        actor.require("ADMIN")
        with db.transaction() as s:
            lock_state(s)
            if not gateway.audit.verify(s)["valid"]:
                raise DomainError("AUDIT_VERIFICATION_FAILED", 503)
            gateway.audit.append(s, "CHECKPOINT_CREATED", actor.id)
        with db.transaction() as s:
            return gateway.audit.retain_checkpoint(s)

    @app.post("/api/v1/transfers-maintenance/expire")
    def expire(actor: Actor):
        actor.require("ADMIN")
        return gateway.recover()
