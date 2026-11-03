"""Single-use transfer orchestration. No response bytes are sent by this module."""
from datetime import timedelta
from hashlib import sha256
import hmac
import json
import time
from sqlalchemy import select, func

from .audit import AuditService, KeyRing
from .db import now
from .errors import DomainError
from .gateway_models import AuditEvent, Incident, ReleaseAttempt, Transfer
from .gateway_schemas import TransferView
from .incidents import create_incident
from .models import SessionRecord, User
from .registry import lock_state
from .scans import get_scan, run_scan
from .snapshots import SnapshotStore

TRANSITIONS = {
    "SCANNING": {"ALLOWED", "BLOCKED", "ERROR"},
    "ALLOWED": {"RELEASE_STARTED", "EXPIRED", "STALE", "ERROR"},
    "RELEASE_STARTED": {"STREAM_FINISHED", "DELIVERY_UNKNOWN"},
}


def transition(transfer, target, reason):
    if target not in TRANSITIONS.get(transfer.state, set()):
        raise DomainError("TRANSFER_TRANSITION_DENIED", 409)
    transfer.state, transfer.reason, transfer.updated_at = target, reason, now()


class Gateway:
    def __init__(self, database, settings):
        self.db, self.settings = database, settings
        self.store = SnapshotStore(settings.paths.runtime / "retained")
        self.audit = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root)

    def owned(self, s, actor, identifier, release=False):
        transfer = s.get(Transfer, identifier)
        if transfer is None or ((release or actor.role == "EMPLOYEE") and transfer.actor_id != actor.id):
            raise DomainError("NOT_FOUND", 404)
        return transfer

    def view(self, s, actor, identifier):
        t = self.owned(s, actor, identifier)
        scan = get_scan(s, actor, t.scan_id) if t.scan_id else None
        incident = s.scalar(select(Incident.id).where(Incident.transfer_id == t.id))
        return TransferView(**{k: getattr(t, k) for k in TransferView.model_fields if k not in {"scan", "incident_id", "release_eligible"}},
            scan=scan, incident_id=incident, release_eligible=t.state == "ALLOWED" and t.expires_at > now() and t.actor_id == actor.id)

    def submit(self, actor, filename, snapshot, idempotency_key):
        actor.require("ADMIN", "ANALYST", "EMPLOYEE")
        digest = sha256(snapshot.data).hexdigest()
        created = False
        try:
            with self.db.transaction() as s:
                lock_state(s)
                previous = s.scalar(select(Transfer).where(Transfer.actor_id == actor.id, Transfer.idempotency_key == idempotency_key))
                if previous:
                    if previous.filename != filename or previous.file_sha256 != digest or previous.file_size != len(snapshot.data):
                        raise DomainError("IDEMPOTENCY_CONFLICT", 409)
                    return self.view(s, actor, previous.id)
                pending = select(func.count()).select_from(Transfer).where(Transfer.state.in_(["SCANNING", "ALLOWED", "RELEASE_STARTED"]))
                if s.scalar(pending) >= 20 or s.scalar(pending.where(Transfer.actor_id == actor.id)) >= 10:
                    raise DomainError("PENDING_TRANSFER_CAPACITY", 429)
                self.audit.keys.key(self.audit.keys.active_id)
                self.audit.checkpoint()  # required independent storage available
                self.store.save(snapshot)
                created = True
                t = Transfer(actor_id=actor.id, idempotency_key=idempotency_key, filename=filename,
                    snapshot_id=snapshot.id, file_sha256=digest, file_size=len(snapshot.data), state="SCANNING",
                    reason="EVALUATING", expires_at=now() + timedelta(seconds=self.settings.retention_seconds))
                s.add(t); s.flush()
                identifier = t.id
                self.audit.append(s, "TRANSFER_SUBMITTED", actor.id, t.id, digest=digest, size=len(snapshot.data))
            with self.db.transaction() as s:
                lock_state(s)
                t = self.owned(s, actor, identifier)
                if t.state != "SCANNING":
                    raise DomainError("TRANSFER_TRANSITION_DENIED", 409)
                scan = run_scan(s, actor, filename, snapshot)
                t.scan_id = scan.id
                target = {"ALLOW": "ALLOWED", "BLOCK": "BLOCKED"}.get(scan.decision.outcome, "ERROR")
                transition(t, target, scan.decision.reason)
                self.audit.append(s, "SCAN_COMPLETED", actor.id, t.id, scan_id=scan.id)
                self.audit.append(s, "DECISION_" + target if target != "ERROR" else "TRANSFER_ERROR", actor.id, t.id,
                    scan_id=scan.id, policy_id=scan.policy_id, registry_revision=scan.detection.registry_revision,
                    digest=digest, size=len(snapshot.data), state=target,
                    expires=t.expires_at.isoformat(timespec="microseconds").replace("+00:00", "Z"))
                if target == "BLOCKED":
                    create_incident(s, t, scan, self.audit)
                result = self.view(s, actor, identifier)
            if target != "ALLOWED":
                self.store.remove(snapshot.id)
            return result
        except Exception:
            if created:
                try:
                    with self.db.transaction() as s:
                        lock_state(s)
                        t = s.scalar(select(Transfer).where(Transfer.snapshot_id == snapshot.id))
                        if t and t.state == "SCANNING":
                            transition(t, "ERROR", "EVALUATION_FAILED")
                            self.audit.append(s, "TRANSFER_ERROR", actor.id, t.id, reason="EVALUATION_FAILED")
                finally:
                    self.store.remove(snapshot.id)
            raise

    def release(self, actor, identifier):
        failure, data, snapshot_id = None, None, None
        with self.db.transaction() as s:
            state = lock_state(s)
            t = self.owned(s, actor, identifier, release=True)
            # Lock user before session, matching password-reset/revocation write order.
            # PostgreSQL row locks serialize revocation with acquisition; SQLite's
            # registry UPDATE already holds the writer lock for this transaction.
            user = s.scalar(select(User).where(User.id == actor.id).with_for_update())
            session = s.scalar(select(SessionRecord).where(SessionRecord.id == actor.session_id).with_for_update())
            if not session or session.user_id != actor.id or session.revoked_at or session.expires_at <= now() or not user or not user.enabled:
                raise DomainError("AUTHENTICATION_REQUIRED", 401)
            verified = self.audit.verify(s)
            if not verified["valid"]:
                raise DomainError("AUDIT_VERIFICATION_FAILED", 503)
            self.audit.append(s, "RELEASE_ATTEMPT", actor.id, t.id)
            if t.state != "ALLOWED":
                failure = DomainError("TRANSFER_NOT_ALLOWED", 409)
            elif t.expires_at <= now():
                transition(t, "EXPIRED", "RELEASE_WINDOW_EXPIRED")
                failure = DomainError("TRANSFER_EXPIRED", 410)
            else:
                scan = get_scan(s, actor, t.scan_id)
                if scan.decision.outcome != "ALLOW":
                    transition(t, "ERROR", "DECISION_MISMATCH")
                    failure = DomainError("TRANSFER_NOT_ALLOWED", 409)
                elif state.revision != scan.detection.registry_revision or state.policy_id != scan.policy_id:
                    transition(t, "STALE", "REVISIONS_CHANGED")
                    failure = DomainError("TRANSFER_STALE", 409)
                else:
                    try:
                        # Bind persisted decision metadata to a verified audit event.
                        records = s.scalars(select(AuditEvent).where(AuditEvent.resource_id == t.id).order_by(AuditEvent.sequence).limit(20000)).all()
                        decisions = [json.loads(e.canonical) for e in records if json.loads(e.canonical)["kind"] == "DECISION_ALLOWED"]
                        expected = {"scan_id": scan.id, "policy_id": scan.policy_id, "registry_revision": scan.detection.registry_revision,
                            "digest": t.file_sha256, "size": t.file_size, "state": "ALLOWED", "expires": t.expires_at.isoformat(timespec="microseconds").replace("+00:00", "Z")}
                        if len(decisions) != 1 or decisions[0]["details"] != expected or decisions[0]["actor_id"] != actor.id:
                            raise DomainError("DECISION_INTEGRITY_FAILURE", 503)
                        data = self.store.capture(t.snapshot_id)
                        m = scan.detection.manifest
                        if len(data) != t.file_size or len(data) != m.file_size or not hmac.compare_digest(sha256(data).hexdigest(), t.file_sha256) or not hmac.compare_digest(t.file_sha256, m.file_sha256):
                            raise DomainError("SNAPSHOT_INTEGRITY_FAILURE", 503)
                    except (OSError, ValueError, DomainError):
                        data = None
                        transition(t, "ERROR", "SNAPSHOT_OR_DECISION_INVALID")
                        failure = DomainError("SNAPSHOT_OR_DECISION_INVALID", 503)
            if failure:
                self.audit.append(s, "RELEASE_DENIED", actor.id, t.id, reason=failure.code, state=t.state)
            else:
                transition(t, "RELEASE_STARTED", "SINGLE_USE_CONSUMED")
                s.add(ReleaseAttempt(transfer_id=t.id, actor_id=actor.id, outcome="RELEASE_STARTED"))
                self.audit.append(s, "RELEASE_STARTED", actor.id, t.id, digest=t.file_sha256, size=t.file_size)
            snapshot_id = t.snapshot_id if t.state != "SCANNING" else None
        # The verified immutable buffer is independent of subsequent path changes.
        if snapshot_id:
            self.store.remove(snapshot_id)
        if failure:
            raise failure
        try:
            with self.db.transaction() as s:
                self.audit.retain_checkpoint(s)  # commits no new event; anchors already committed head
        except Exception:
            self.finish(identifier, False)
            raise DomainError("CHECKPOINT_PERSISTENCE_FAILED", 503) from None
        return data

    def finish(self, identifier, completed):
        with self.db.transaction() as s:
            lock_state(s)
            t = s.get(Transfer, identifier)
            if t is None or t.state != "RELEASE_STARTED":
                return
            target = "STREAM_FINISHED" if completed else "DELIVERY_UNKNOWN"
            transition(t, target, "SERVER_SEND_COMPLETED" if completed else "DELIVERY_NOT_CONFIRMED")
            attempt = s.scalar(select(ReleaseAttempt).where(ReleaseAttempt.transfer_id == identifier))
            attempt.outcome, attempt.finished_at = target, now()
            self.audit.append(s, target, t.actor_id, t.id)

    def recover(self, limit=100, restart=False):
        removed = []
        with self.db.transaction() as s:
            lock_state(s)
            query = select(Transfer).where(Transfer.state.in_(["SCANNING", "RELEASE_STARTED"]) if restart else Transfer.state == "ALLOWED")
            if not restart:
                query = query.where(Transfer.expires_at <= now())
            for t in s.scalars(query.order_by(Transfer.created_at).limit(limit)):
                target = {"SCANNING": "ERROR", "RELEASE_STARTED": "DELIVERY_UNKNOWN", "ALLOWED": "EXPIRED"}[t.state]
                transition(t, target, "RESTART_RECOVERY" if restart else "RELEASE_WINDOW_EXPIRED")
                if target == "DELIVERY_UNKNOWN":
                    attempt = s.scalar(select(ReleaseAttempt).where(ReleaseAttempt.transfer_id == t.id))
                    if attempt:
                        attempt.outcome, attempt.finished_at = target, now()
                self.audit.append(s, "TRANSFER_ERROR" if target == "ERROR" else "TRANSFER_EXPIRED" if target == "EXPIRED" else target,
                                  t.actor_id, t.id, reason=t.reason)
                removed.append(t.snapshot_id)
        for identifier in removed:
            self.store.remove(identifier)
        with self.db.transaction() as s:
            for identifier, modified in self.store.candidates(limit):
                t = s.scalar(select(Transfer).where(Transfer.snapshot_id == identifier))
                if (t and t.state not in {"ALLOWED", "SCANNING", "RELEASE_STARTED"}) or (not t and time.time() - modified > 900):
                    self.store.remove(identifier)
        return {"transitioned": len(removed)}
