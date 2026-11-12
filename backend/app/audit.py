"""Versioned HMAC-SHA-256 audit records and independently retained checkpoints."""
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
import json
from pathlib import Path
import re
import logging
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator
from sqlalchemy import select, update

from .db import now, uid
from .errors import DomainError
from .gateway_models import AuditEvent, AuditHead
from .private_files import private_directory, read_private, sync_directory, write_exclusive
from .transparency import STH_INTERVAL, SigningKeys, TransparencyLog

ZERO = "0" * 64
LOG = logging.getLogger("rootsentinel.transparency")
MAX_EVENTS = 20000
KINDS = {
    "ASSET_REGISTERED", "ASSET_RETIRED", "POLICY_CHANGED", "TRANSFER_SUBMITTED",
    "SCAN_COMPLETED", "DECISION_ALLOWED", "DECISION_BLOCKED", "TRANSFER_ERROR",
    "TRANSFER_EXPIRED", "TRANSFER_STALE", "RELEASE_ATTEMPT", "RELEASE_DENIED",
    "RELEASE_STARTED", "STREAM_FINISHED", "DELIVERY_UNKNOWN", "INCIDENT_CREATED",
    "INCIDENT_UPDATED", "EVIDENCE_EXPORTED", "AUDIT_VERIFIED", "CHECKPOINT_CREATED",
    "ASSET_PROFILE_ADDED", "VISITOR_ENTERED", "VISITOR_ENDED", "VISITOR_EXPIRED",
}
DETAILS = {"expires", "scan_id", "incident_id", "policy_id", "registry_revision", "reason", "state", "digest", "size", "revision", "note_digest", "resolution_digest"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def mac_for(key, payload, domain=b"RootSentinelAudit\x00\x01"):
    raw = payload.encode("ascii")
    return hmac.digest(key, domain + len(raw).to_bytes(4, "big") + raw, "sha256").hex()


class EventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: StrictInt = Field(ge=1, le=1)
    id: str
    stream_id: str
    sequence: StrictInt = Field(ge=1)
    timestamp: str
    kind: str
    actor_id: str | None
    resource_id: str | None
    key_id: str
    previous_mac: str
    details: dict[str, str | StrictInt]

    @field_validator("id", "stream_id", "actor_id", "resource_id")
    @classmethod
    def identifier(cls, value):
        if value is not None and str(UUID(value)) != value:
            raise ValueError("Noncanonical UUID")
        return value

    @field_validator("timestamp")
    @classmethod
    def timestamp_valid(cls, value):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo != timezone.utc or dt.isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
            raise ValueError("Noncanonical timestamp")
        return value

    @field_validator("kind")
    @classmethod
    def kind_valid(cls, value):
        if value not in KINDS:
            raise ValueError("Unknown event")
        return value

    @field_validator("key_id")
    @classmethod
    def key_valid(cls, value):
        if re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", value) is None:
            raise ValueError("Invalid key ID")
        return value

    @field_validator("previous_mac")
    @classmethod
    def mac_valid(cls, value):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("Invalid MAC")
        return value

    @field_validator("details")
    @classmethod
    def details_valid(cls, value):
        if not set(value) <= DETAILS or len(value) > 10:
            raise ValueError("Invalid details")
        if any(isinstance(v, str) and (len(v) > 128 or re.fullmatch(r"[A-Za-z0-9_.:-]*", v) is None) for v in value.values()):
            raise ValueError("Unsafe details")
        return value


@dataclass(frozen=True)
class KeyRing:
    active_id: str
    keys: dict[str, bytes] = field(repr=False)

    def key(self, key_id):
        key = self.keys.get(key_id)
        if type(key) is not bytes or len(key) != 32:
            raise DomainError("AUDIT_KEY_UNAVAILABLE", 503)
        return key

    @classmethod
    def load(cls, path: Path | None):
        if path is None:
            return cls("missing", {})
        try:
            value = json.loads(read_private(path, 16384))
            if set(value) != {"version", "active_id", "keys"} or value["version"] != 1 or not 1 <= len(value["keys"]) <= 32:
                raise ValueError()
            for key_id in value["keys"]:
                EventPayload.key_valid(key_id)
            keys = {k: base64.b64decode(v, validate=True) for k, v in value["keys"].items()}
            ring = cls(value["active_id"], keys)
            for key_id in keys:
                ring.key(key_id)
            ring.key(ring.active_id)
            if path.stat().st_mode & 0o077 and __import__("os").name != "nt":
                raise ValueError()
            return ring
        except Exception:
            raise DomainError("AUDIT_KEY_UNAVAILABLE", 503) from None


def actor_column_matches(row, payload):
    """The filtering column audit_events.actor_id must agree with the actor inside the HMAC'd payload.

    NULL is accepted: events written before migration 0006 have no column value, and an event whose column is
    NULL is simply never returned by a view that filters on the actor."""
    column = getattr(row, "actor_id", None)
    if column is not None and column != payload.actor_id:
        raise ValueError("ACTOR_MISMATCH")


def check_event(row, keys, previous):
    """One stored event: canonical form, identifiers, the link to the previous MAC and its own HMAC.

    Raises ValueError when the event is not what was written, DomainError when its key is unavailable."""
    payload = EventPayload.model_validate_json(row.canonical)
    if canonical(payload.model_dump()) != row.canonical or payload.id != row.id or payload.resource_id != row.resource_id:
        raise ValueError("CANONICAL_MISMATCH")
    if payload.sequence != row.sequence or payload.stream_id != row.stream_id:
        raise ValueError("SEQUENCE_MISMATCH")
    actor_column_matches(row, payload)
    if payload.previous_mac != previous:
        raise ValueError("LINK_MISMATCH")
    if not hmac.compare_digest(mac_for(keys.key(payload.key_id), row.canonical), row.mac):
        raise ValueError("MAC_MISMATCH")


def verify_records(rows, keys, stream_id, sequence, expected_mac, checkpoint=None):
    previous, expected = ZERO, 1
    checkpoint_seen = checkpoint is None or checkpoint["sequence"] == 0
    for row in rows:
        try:
            payload = EventPayload.model_validate_json(row.canonical)
            body = payload.model_dump()
            if canonical(body) != row.canonical or payload.id != row.id or payload.resource_id != row.resource_id:
                raise ValueError("CANONICAL_MISMATCH")
            if payload.sequence != expected or row.sequence != expected or payload.stream_id != stream_id or row.stream_id != stream_id:
                raise ValueError("SEQUENCE_MISMATCH")
            actor_column_matches(row, payload)
            if payload.previous_mac != previous:
                raise ValueError("LINK_MISMATCH")
            computed = mac_for(keys.key(payload.key_id), row.canonical)
            if not hmac.compare_digest(computed, row.mac):
                raise ValueError("MAC_MISMATCH")
            if checkpoint and expected == checkpoint["sequence"]:
                if checkpoint["stream_id"] != stream_id or not hmac.compare_digest(checkpoint["mac"], row.mac):
                    raise ValueError("CHECKPOINT_MISMATCH")
                checkpoint_seen = True
            previous = row.mac
            expected += 1
            if expected > MAX_EVENTS + 1:
                raise ValueError("VERIFICATION_LIMIT")
        except DomainError:
            return {"valid": False, "first_invalid_sequence": expected, "reason": "AUDIT_KEY_UNAVAILABLE"}
        except Exception:
            return {"valid": False, "first_invalid_sequence": expected, "reason": "INVALID_EVENT"}
    valid = expected - 1 == sequence and hmac.compare_digest(previous, expected_mac) and checkpoint_seen
    return {"valid": valid, "first_invalid_sequence": None if valid else expected,
            "reason": "VERIFIED" if valid else "HEAD_OR_CHECKPOINT_MISMATCH"}


class AuditService:
    def __init__(self, keys, checkpoint_root, signing=None):
        self.keys, self.checkpoint_root = keys, checkpoint_root
        # The transparency log over this chain. Without a signing key it still tracks the tree but signs nothing.
        self.log = TransparencyLog(signing if signing is not None else SigningKeys.load(None))

    def head(self, s):
        result = s.execute(update(AuditHead).where(AuditHead.id == 1).values(sequence=AuditHead.sequence))
        if result.rowcount != 1:
            raise DomainError("AUDIT_UNAVAILABLE", 503)
        return s.get(AuditHead, 1, populate_existing=True)

    def append(self, s, kind, actor_id=None, resource_id=None, **details):
        key = self.keys.key(self.keys.active_id)
        head = self.head(s)
        self.log.sync(s, head, self.keys)
        if head.sequence >= MAX_EVENTS:
            raise DomainError("AUDIT_CAPACITY", 503)
        if head.sequence:
            tail = s.scalar(select(AuditEvent).where(AuditEvent.sequence == head.sequence))
            if tail is None or not hmac.compare_digest(tail.mac, head.mac):
                raise DomainError("AUDIT_HEAD_INVALID", 503)
            payload = EventPayload.model_validate_json(tail.canonical)
            if not hmac.compare_digest(tail.mac, mac_for(self.keys.key(payload.key_id), tail.canonical)):
                raise DomainError("AUDIT_HEAD_INVALID", 503)
        payload = EventPayload(schema_version=1, id=uid(), stream_id=head.stream_id, sequence=head.sequence + 1,
            timestamp=now().isoformat(timespec="microseconds").replace("+00:00", "Z"), kind=kind, actor_id=actor_id,
            resource_id=resource_id, key_id=self.keys.active_id, previous_mac=head.mac, details=details)
        encoded = canonical(payload.model_dump())
        mac = mac_for(key, encoded)
        row = AuditEvent(id=payload.id, stream_id=head.stream_id, sequence=payload.sequence,
                         resource_id=resource_id, actor_id=actor_id, canonical=encoded, mac=mac)
        s.add(row)
        head.sequence, head.mac = payload.sequence, mac
        s.flush()
        self.log.extend(s, row)
        if self.log.signing.available and payload.sequence % STH_INTERVAL == 0:
            self.log.sign(s, head.stream_id)
        return row

    # ---- transparency log: signed tree heads over this chain (docs/audit-spec.md) ----
    def synced(self, s):
        """Lock the audit head and bring the tree in memory up to date with the stored events."""
        head = self.head(s)
        self.log.sync(s, head, self.keys)
        return head

    def sign_head(self, s):
        """A stored, signed and verified tree head that covers every event written so far in this transaction."""
        head = self.synced(s)
        return self.log.sign(s, head.stream_id)

    def verify_tail(self, s):
        """The check before a release: the latest signed head and every event after it. Raises when it fails."""
        head = self.synced(s)
        self.log.check_tail(s, head, self.keys, self.checkpoint())

    def startup(self, s):
        """Rebuild the tree from the stored events and check it against the latest stored head.

        Returns False when the log is unusable; the reason is logged for the operator and audited actions are
        refused. When events exist after the latest head and a signing key is configured, a new head is signed."""
        try:
            head = self.synced(s)
            if self.log.signing.available and head.sequence:
                latest = self.log.latest(s)
                if latest is None or latest.tree_size < head.sequence:
                    self.log.sign(s, head.stream_id)
            return True
        except DomainError as error:
            if not self.log.failure:
                LOG.error("audit transparency log is unavailable at startup (%s); releases are refused", error.code)
            return False

    def checkpoint(self):
        if self.checkpoint_root is None:
            raise DomainError("CHECKPOINT_STORAGE_UNAVAILABLE", 503)
        private_directory(self.checkpoint_root)
        files = []
        for inspected, path in enumerate(self.checkpoint_root.iterdir()):
            if inspected >= MAX_EVENTS:
                raise DomainError("CHECKPOINT_CAPACITY", 503)
            if re.fullmatch(r"checkpoint-[0-9]{10}\.json", path.name):
                files.append(path)
                if len(files) > MAX_EVENTS:
                    raise DomainError("CHECKPOINT_CAPACITY", 503)
        if not files:
            return None
        try:
            value = json.loads(read_private(max(files), 2048))
            signature = value.pop("signature")
            if set(value) != {"version", "stream_id", "sequence", "mac", "key_id"} or type(value["sequence"]) is not int or value["sequence"] < 1 or value["version"] != 1:
                raise ValueError()
            UUID(value["stream_id"])
            EventPayload.mac_valid(value["mac"])
            if not hmac.compare_digest(signature, mac_for(self.keys.key(value["key_id"]), canonical(value), b"RootSentinelCheckpoint\x00\x01")):
                raise ValueError()
            return value
        except Exception:
            raise DomainError("CHECKPOINT_INVALID", 503) from None

    def verify(self, s):
        head = self.head(s)
        checkpoint = self.checkpoint()
        if checkpoint and checkpoint["stream_id"] != head.stream_id:
            return {"valid": False, "first_invalid_sequence": 1, "reason": "CHECKPOINT_STREAM_MISMATCH", "stream_id": head.stream_id, "through_sequence": head.sequence, "checkpoint_sequence": checkpoint["sequence"]}
        rows = s.scalars(select(AuditEvent).order_by(AuditEvent.sequence).limit(MAX_EVENTS + 1).execution_options(yield_per=500))
        result = verify_records(rows, self.keys, head.stream_id, head.sequence, head.mac, checkpoint)
        return {**result, "stream_id": head.stream_id, "through_sequence": head.sequence,
                "checkpoint_sequence": checkpoint["sequence"] if checkpoint else None}

    def retain_checkpoint(self, s):
        head = self.head(s)
        if head.sequence == 0:
            raise DomainError("EMPTY_AUDIT_STREAM", 409)
        previous = self.checkpoint()
        if previous and (previous["stream_id"] != head.stream_id or previous["sequence"] > head.sequence):
            raise DomainError("CHECKPOINT_ROLLBACK", 503)
        value = {"version": 1, "stream_id": head.stream_id, "sequence": head.sequence, "mac": head.mac, "key_id": self.keys.active_id}
        value["signature"] = mac_for(self.keys.key(self.keys.active_id), canonical(value), b"RootSentinelCheckpoint\x00\x01")
        target = self.checkpoint_root / f"checkpoint-{head.sequence:010d}.json"
        if not target.exists():
            write_exclusive(target, canonical(value).encode("ascii"))
            sync_directory(self.checkpoint_root)
        elif read_private(target, 2048) != canonical(value).encode("ascii"):
            raise DomainError("CHECKPOINT_CONFLICT", 503)
        return value
