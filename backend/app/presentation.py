"""Read-only, role-scoped dashboard aggregates and crypto-core tree projections."""
from datetime import datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, Query
from sqlalchemy import case, func, select

from .auth import Principal
from .crypto import create_proof
from .crypto.merkle import tree_root
from .db import now
from .errors import DomainError
from .gateway_models import AuditHead, Incident, Transfer
from .models import Asset, PolicyDecision
from .registry import lock_state, version_fingerprint
from .visitors import visitor_user_ids
from .schemas import ChunkView, ManifestView, ProofView, Schema


class DailyCount(Schema):
    date: str
    total: int


class Overview(Schema):
    observed_at: datetime
    scope: Literal["own", "workspace"]
    total_transfers: int
    allowed_decisions: int
    blocked_decisions: int
    undecided_transfers: int
    active_incidents: int | None
    active_assets: int | None
    audit_sequence: int | None
    window_start: datetime
    window_end: datetime
    daily: list[DailyCount]
    severity: dict[str, int] | None
    mode: str
    release_configured: bool


def overview(s, actor, settings, include_visitors=False):
    # Existing mutation lock gives all aggregate statements one coherent observation.
    lock_state(s)
    observed = now()
    filters = [Transfer.created_at <= observed]
    if actor.own_only:
        filters.append(Transfer.actor_id == actor.id)
    elif not include_visitors:
        filters.append(Transfer.actor_id.not_in(visitor_user_ids()))
    grouped = dict(s.execute(select(PolicyDecision.outcome, func.count(Transfer.id))
        .select_from(Transfer).outerjoin(PolicyDecision, PolicyDecision.scan_id == Transfer.scan_id)
        .where(*filters).group_by(PolicyDecision.outcome)).all())
    start = observed.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=6)
    # Seven SQL aggregate expressions; no unbounded transfer/evidence materialization.
    days = [start + timedelta(days=i) for i in range(7)]
    daily_counts = s.execute(select(*[func.count(case((
        (Transfer.created_at >= day) & (Transfer.created_at < day + timedelta(days=1)), 1)))
        for day in days]).select_from(Transfer).where(*filters)).one()
    privileged = actor.role in {"ADMIN", "ANALYST"}
    incident_filters = [Incident.status.in_(["OPEN", "INVESTIGATING"])]
    if not include_visitors:
        incident_filters.append(Incident.transfer_id.not_in(select(Transfer.id).where(Transfer.actor_id.in_(visitor_user_ids()))))
    severity = dict(s.execute(select(Incident.severity, func.count()).where(*incident_filters)
                              .group_by(Incident.severity)).all()) if privileged else None
    return Overview(observed_at=observed, scope="workspace" if privileged else "own",
        total_transfers=sum(grouped.values()), allowed_decisions=grouped.get("ALLOW", 0),
        blocked_decisions=grouped.get("BLOCK", 0),
        undecided_transfers=sum(v for k, v in grouped.items() if k not in {"ALLOW", "BLOCK"}),
        active_incidents=sum(severity.values()) if severity is not None else None,
        active_assets=s.scalar(select(func.count()).select_from(Asset).where(Asset.retired.is_(False))) if privileged else None,
        audit_sequence=s.get(AuditHead, 1).sequence if privileged else None,
        window_start=start, window_end=observed,
        daily=[DailyCount(date=day.date().isoformat(), total=count) for day, count in zip(days, daily_counts)],
        severity=severity, mode=settings.mode,
        release_configured=settings.mode == "local" and bool(settings.audit_key_file and settings.checkpoint_root and settings.transparency_key_file))


class TreeNode(Schema):
    id: str
    start: int
    count: int
    digest: str
    left: str | None
    right: str | None
    selected_path: bool
    sibling: bool


class TreeView(Schema):
    manifest: ManifestView
    mode: Literal["full", "proof_path", "empty"]
    selected_index: int | None
    nodes: list[TreeNode]
    proof: ProofView | None
    chunks: list[ChunkView]
    offset: int
    limit: int


def tree_view(fingerprint, index=0, offset=0, limit=16):
    chunks, manifest = fingerprint.chunks, fingerprint.manifest
    if not chunks:
        return TreeView(manifest=manifest.to_dict(), mode="empty", selected_index=None,
            nodes=[], proof=None, chunks=[], offset=offset, limit=limit)
    if not 0 <= index < len(chunks):
        raise DomainError("NOT_FOUND", 404)
    proof = create_proof(fingerprint, index)  # validates stored root with unchanged core
    full = len(chunks) <= 16
    nodes = []
    def visit(start, end, sibling=False):
        size = end - start
        on_path = start <= index < end
        identifier = f"{start}:{size}"
        left = right = None
        if size > 1 and (full or on_path):
            split = 1 << ((size - 1).bit_length() - 1)
            middle = start + split
            left = visit(start, middle, on_path and not start <= index < middle)
            right = visit(middle, end, on_path and not middle <= index < end)
        nodes.append(TreeNode(id=identifier, start=start, count=size,
            digest=tree_root(chunks[start:end]).hex(), left=left, right=right,
            selected_path=on_path, sibling=sibling))
        return identifier
    visit(0, len(chunks))
    return TreeView(manifest=manifest.to_dict(), mode="full" if full else "proof_path",
        selected_index=index, nodes=nodes, proof=proof.to_dict(),
        chunks=[c.to_dict() for c in chunks[offset:offset + limit]], offset=offset, limit=limit)


def install_presentation(app, principal):
    Actor = Annotated[Principal, Depends(principal)]

    @app.get("/api/v1/overview", response_model=Overview)
    def dashboard(actor: Actor, include_visitors: bool = False):
        if include_visitors:
            actor.require("ADMIN")
        with app.state.db.transaction() as s:
            return overview(s, actor, app.state.settings, include_visitors)

    @app.get("/api/v1/assets/{asset_id}/versions/{version_id}/tree", response_model=TreeView)
    def tree(asset_id: UUID, version_id: UUID, actor: Actor,
             index: Annotated[int, Query(ge=0, le=10239)] = 0,
             offset: Annotated[int, Query(ge=0, le=10240)] = 0,
             limit: Annotated[int, Query(ge=1, le=32)] = 16):
        actor.require("ADMIN", "ANALYST")
        with app.state.db.transaction() as s:
            _, fingerprint = version_fingerprint(s, str(asset_id), str(version_id))
            return tree_view(fingerprint, index, offset, limit)
