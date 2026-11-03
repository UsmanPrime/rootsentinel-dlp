"""Strict, allowlisted HTTP and service contracts. No ORM or secret serialization."""
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Label = Annotated[str, StringConstraints(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._()-]*$")]
Username = Annotated[str, StringConstraints(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")]
Role = Literal["ADMIN", "ANALYST", "EMPLOYEE"]


class Schema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginInput(Schema):
    username: Username
    password: str = Field(min_length=1, max_length=128)


class UserView(Schema):
    id: str
    username: str
    role: Role


class AuthView(Schema):
    user: UserView
    csrf_token: str


class PolicyInput(Schema):
    threshold: int = Field(default=1024, ge=1, le=10485760, strict=True)
    block_enabled: bool = Field(default=True, strict=True)
    expected_version: str


class PolicyView(Schema):
    id: str
    number: int
    threshold: int
    block_enabled: bool
    actor_id: str | None
    created_at: datetime


class ManifestView(Schema):
    spec_version: int
    profile_id: str
    file_size: int
    chunk_size: int
    chunk_count: int
    file_sha256: str
    merkle_root: str


class ChunkView(Schema):
    index: int
    length: int
    sha256: str


class AssetView(Schema):
    id: str
    label: str
    current_version: int
    retired: bool
    created_at: datetime


class VersionSummary(Schema):
    id: str
    asset_id: str
    number: int
    registry_revision: int
    actor_id: str
    created_at: datetime
    manifest: ManifestView


class VersionView(VersionSummary):
    chunks: list[ChunkView]


class ProofView(Schema):
    spec_version: int
    profile_id: str
    tree_size: int
    chunk: ChunkView
    siblings: list[str]


class IntegrityInput(Schema):
    asset_id: str
    version_id: str
    proof: dict


class IntegrityView(Schema):
    valid: bool
    verification: Literal["descriptor_inclusion"] = "descriptor_inclusion"


class BlockEvidence(Schema):
    length: int
    sha256: str
    source_indices: list[int]
    outbound_indices: list[int]


class Coverage(Schema):
    numerator: int
    denominator: int


class MatchView(Schema):
    asset_id: str
    version_id: str
    exact: bool
    matched_bytes: int
    coverage: Coverage
    intervals: list[tuple[int, int]]
    blocks: list[BlockEvidence]


class DetectionView(Schema):
    manifest: ManifestView
    registry_revision: int
    matches: list[MatchView]


class DecisionView(Schema):
    outcome: Literal["ALLOW", "BLOCK", "INDETERMINATE"]
    reason: str
    qualifying_versions: list[str]


class ScanView(Schema):
    id: str
    actor_id: str
    filename: str
    snapshot_id: str
    created_at: datetime
    policy_id: str
    detection: DetectionView
    decision: DecisionView
    release_authorized: Literal[False] = False


class AssetPage(Schema):
    items: list[AssetView]
    offset: int
    limit: int


class PolicyPage(Schema):
    items: list[PolicyView]
    offset: int
    limit: int


class ScanSummary(Schema):
    id: str
    filename: str
    created_at: datetime
    outcome: str
    reason: str


class ScanPage(Schema):
    items: list[ScanSummary]
    offset: int
    limit: int


class ErrorDetail(Schema):
    code: str
    outcome: Literal["INDETERMINATE"] = "INDETERMINATE"
    release_authorized: Literal[False] = False


class ErrorView(Schema):
    error: ErrorDetail
