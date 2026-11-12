"""Transfer, investigation and audit persistence; migration 0002 owns DDL."""
from datetime import datetime
from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, UTCDateTime, now, uid


class Transfer(Base):
    __tablename__ = "transfers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(36))
    filename: Mapped[str] = mapped_column(String(120))
    snapshot_id: Mapped[str] = mapped_column(String(36), unique=True)
    file_sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(24), index=True)
    reason: Mapped[str] = mapped_column(String(64))
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scan_evaluations.id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    __table_args__ = (
        UniqueConstraint("actor_id", "idempotency_key", name="uq_transfer_retry"),
        CheckConstraint("file_size BETWEEN 0 AND 10485760", name="ck_transfer_size"),
        CheckConstraint("state IN ('SCANNING','ALLOWED','BLOCKED','ERROR','STALE','EXPIRED','RELEASE_STARTED','STREAM_FINISHED','DELIVERY_UNKNOWN')", name="ck_transfer_state"),
    )


class ReleaseAttempt(Base):
    __tablename__ = "release_attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    transfer_id: Mapped[str] = mapped_column(ForeignKey("transfers.id"), unique=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    outcome: Mapped[str] = mapped_column(String(24))


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    transfer_id: Mapped[str] = mapped_column(ForeignKey("transfers.id"), unique=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_evaluations.id"))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    __table_args__ = (
        CheckConstraint("status IN ('OPEN','INVESTIGATING','RESOLVED')", name="ck_incident_status"),
        CheckConstraint("severity IN ('HIGH','MEDIUM')", name="ck_incident_severity"),
    )


class IncidentHistory(Base):
    __tablename__ = "incident_history"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16))
    note: Mapped[str] = mapped_column(String(1000))
    resolution: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    __table_args__ = (UniqueConstraint("incident_id", "revision", name="uq_incident_revision"),)


class AuditHead(Base):
    __tablename__ = "audit_heads"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stream_id: Mapped[str] = mapped_column(String(36), unique=True)
    sequence: Mapped[int] = mapped_column(Integer)
    mac: Mapped[str] = mapped_column(String(64))
    __table_args__ = (CheckConstraint("id = 1 AND sequence >= 0", name="ck_audit_head"),)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    stream_id: Mapped[str] = mapped_column(ForeignKey("audit_heads.stream_id"))
    sequence: Mapped[int] = mapped_column(Integer, unique=True)
    resource_id: Mapped[str | None] = mapped_column(String(36), index=True)
    # Copy of the actor inside the canonical payload, for filtering. Integrity verification checks that it agrees
    # with the payload. NULL on events written before migration 0006. Not part of the HMAC'd bytes.
    actor_id: Mapped[str | None] = mapped_column(String(36), index=True)
    canonical: Mapped[str] = mapped_column(Text)
    mac: Mapped[str] = mapped_column(String(64))


class TransparencyHead(Base):
    """A signed tree head over the first ``tree_size`` audit events. Append-only: migration 0004 adds triggers."""
    __tablename__ = "transparency_heads"
    tree_size: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    log_id: Mapped[str] = mapped_column(ForeignKey("audit_heads.stream_id"))
    root_hash: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[str] = mapped_column(String(27))
    key_id: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(128))
    __table_args__ = (CheckConstraint("tree_size >= 1", name="ck_transparency_head_size"),)
