from datetime import datetime
from typing import Literal
from pydantic import Field, field_validator
from .schemas import Schema, ScanView


class TransferView(Schema):
    id: str
    actor_id: str
    filename: str
    state: str
    reason: str
    file_sha256: str
    file_size: int
    created_at: datetime
    expires_at: datetime
    scan: ScanView | None
    incident_id: str | None
    release_eligible: bool


class TransferSummary(Schema):
    id: str
    actor_id: str
    filename: str
    state: str
    reason: str
    file_size: int
    created_at: datetime
    expires_at: datetime
    release_eligible: bool


class TransferPage(Schema):
    items: list[TransferSummary]
    offset: int
    limit: int


class IncidentPatch(Schema):
    expected_revision: int = Field(ge=1, strict=True)
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED"]
    note: str = Field(default="", max_length=1000)
    resolution: str = Field(default="", max_length=500)

    @field_validator("note", "resolution")
    @classmethod
    def safe_text(cls, value):
        if any(ord(c) < 32 or ord(c) == 127 for c in value) or "<" in value or ">" in value:
            raise ValueError("Use plain text without controls or markup")
        return value.strip()


class HistoryView(Schema):
    id: str
    revision: int
    actor_id: str
    status: str
    note: str
    resolution: str
    created_at: datetime


class IncidentView(Schema):
    id: str
    transfer_id: str
    scan_id: str
    severity: str
    status: str
    revision: int
    reviewer_id: str | None
    created_at: datetime
    history: list[HistoryView]
    scan: ScanView


class IncidentPage(Schema):
    items: list[dict]
    offset: int
    limit: int


class AuditVerification(Schema):
    valid: bool
    first_invalid_sequence: int | None
    reason: str
    stream_id: str
    through_sequence: int
    checkpoint_sequence: int | None


class AuditPage(Schema):
    events: list[dict]
    after: int
    limit: int
