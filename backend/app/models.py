"""Persistence types only. Response schemas live in schemas.py."""
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, UTCDateTime, now, uid


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    __table_args__ = (CheckConstraint("role IN ('ADMIN','ANALYST','EMPLOYEE','VISITOR')", name="ck_user_role"),)


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Visitor sessions only: the last request, written at most once per VISITOR_SEEN_THROTTLE_SECONDS.
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class VisitorSession(Base):
    """Counters and lifecycle of one visitor sandbox. session_id is not a foreign key: lazy cleanup deletes the
    expired sessions row, and this row stays for the daily cap and the audit trail's meaning."""
    __tablename__ = "visitor_sessions"
    session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    submissions_used: Mapped[int] = mapped_column(Integer, default=0)
    release_attempts_used: Mapped[int] = mapped_column(Integer, default=0)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    number: Mapped[int] = mapped_column(Integer, unique=True)
    threshold: Mapped[int] = mapped_column(Integer)
    block_enabled: Mapped[bool] = mapped_column(Boolean)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    # Which rule set evaluates this policy (policy.RULE_SETS) and, for rs-policy-v2, the matched-byte threshold
    # of the content-defined profile. Both are validated by policy.active_policy, which fails closed.
    rule_set: Mapped[str] = mapped_column(String(16), default="rs-policy-v1", server_default="rs-policy-v1")
    cdc_threshold: Mapped[int | None] = mapped_column(Integer)
    __table_args__ = (CheckConstraint("threshold BETWEEN 1 AND 10485760", name="ck_policy_threshold"),)


class RegistryState(Base):
    __tablename__ = "registry_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policy_versions.id"))
    __table_args__ = (CheckConstraint("id = 1 AND revision >= 0", name="ck_single_state"),)


class Asset(Base):
    __tablename__ = "assets"
    # synthetic has only a server default; a database from before migration 0006 has no such column, and the
    # upgrade test registers on that schema, so the INSERT must neither write nor read it back.
    __mapper_args__ = {"eager_defaults": False}
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    label: Mapped[str] = mapped_column(String(120), unique=True)
    current_version: Mapped[int] = mapped_column(Integer)
    retired: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # True only for the synthetic seed assets. Visitor scans are matched against these and nothing else.
    synthetic: Mapped[bool] = mapped_column(Boolean, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class RegistryRevision(Base):
    __tablename__ = "registry_revisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    number: Mapped[int] = mapped_column(Integer, unique=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class AssetVersion(Base):
    __tablename__ = "asset_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    registry_revision: Mapped[int] = mapped_column(ForeignKey("registry_revisions.number"))
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    profile_id: Mapped[str] = mapped_column(String(32))
    file_size: Mapped[int] = mapped_column(Integer)
    file_sha256: Mapped[str] = mapped_column(String(64))
    merkle_root: Mapped[str] = mapped_column(String(64))
    chunk_count: Mapped[int] = mapped_column(Integer)
    __table_args__ = (
        UniqueConstraint("asset_id", "number", name="uq_asset_version"),
        UniqueConstraint("asset_id", "file_size", "file_sha256", name="uq_asset_content"),
        Index("ix_exact_match", "profile_id", "file_size", "file_sha256"),
        CheckConstraint("file_size BETWEEN 1 AND 10485760", name="ck_asset_size"),
        CheckConstraint("profile_id = 'rs-fixed-sha256-v1'", name="ck_asset_profile"),
    )


class AssetChunk(Base):
    __tablename__ = "asset_chunks"
    version_id: Mapped[str] = mapped_column(ForeignKey("asset_versions.id"), primary_key=True)
    index: Mapped[int] = mapped_column(Integer, primary_key=True)
    length: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    __table_args__ = (
        Index("ix_block_match", "sha256", "length"),
        CheckConstraint('"index" >= 0 AND "index" < 10240 AND length BETWEEN 1 AND 1024', name="ck_chunk_bounds"),
    )


class AssetCdcChunk(Base):
    """Chunks of an asset version under rs-cdc-gear-v1. Versions registered before this profile have none."""
    __tablename__ = "asset_cdc_chunks"
    version_id: Mapped[str] = mapped_column(ForeignKey("asset_versions.id"), primary_key=True)
    offset: Mapped[int] = mapped_column(Integer, primary_key=True)
    length: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    __table_args__ = (
        Index("ix_cdc_match", "sha256"),
        CheckConstraint('"offset" >= 0 AND "offset" < 10485760 AND length BETWEEN 1 AND 8192', name="ck_cdc_chunk_bounds"),
    )


class ScanEvaluation(Base):
    __tablename__ = "scan_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    filename: Mapped[str] = mapped_column(String(120))
    snapshot_id: Mapped[str] = mapped_column(String(36))
    manifest: Mapped[dict] = mapped_column(JSON)
    registry_revision: Mapped[int] = mapped_column(Integer)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policy_versions.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    # Evidence of every evaluated profile other than rs-fixed-sha256-v1 (whose evidence is the matching_evidence
    # rows). NULL when the policy evaluated the fixed profile only, which is every scan before migration 0005.
    profiles: Mapped[list | None] = mapped_column(JSON)


class MatchEvidence(Base):
    __tablename__ = "matching_evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_evaluations.id"), index=True)
    version_id: Mapped[str] = mapped_column(ForeignKey("asset_versions.id"))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    exact: Mapped[bool] = mapped_column(Boolean)
    matched_bytes: Mapped[int] = mapped_column(Integer)
    coverage: Mapped[dict] = mapped_column(JSON)
    intervals: Mapped[list] = mapped_column(JSON)
    blocks: Mapped[list] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("scan_id", "version_id", name="uq_scan_match"),)


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_evaluations.id"), unique=True)
    outcome: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(40))
    qualifying_versions: Mapped[list] = mapped_column(JSON)
    __table_args__ = (CheckConstraint("outcome IN ('ALLOW','BLOCK','INDETERMINATE')", name="ck_outcome"),)
