"""Investigation never changes immutable transfer decisions."""
from hashlib import sha256
from sqlalchemy import select
from .db import now
from .errors import DomainError
from .gateway_models import AuditEvent, Incident, IncidentHistory
from .gateway_schemas import HistoryView, IncidentView
from .registry import lock_state
from .scans import get_scan


def create_incident(s, transfer, scan, audit):
    incident = Incident(transfer_id=transfer.id, scan_id=scan.id,
        severity="HIGH" if scan.decision.reason == "EXACT_PROTECTED_FILE" else "MEDIUM", status="OPEN", revision=1)
    s.add(incident)
    s.flush()
    s.add(IncidentHistory(incident_id=incident.id, revision=1, actor_id=transfer.actor_id,
                         status="OPEN", note="Policy-blocked transfer; intent not established.", resolution=""))
    audit.append(s, "INCIDENT_CREATED", transfer.actor_id, transfer.id, incident_id=incident.id, scan_id=scan.id)
    return incident


def incident_view(s, actor, incident_id):
    actor.require("ADMIN", "ANALYST")
    incident = s.get(Incident, incident_id)
    if incident is None:
        raise DomainError("NOT_FOUND", 404)
    rows = s.scalars(select(IncidentHistory).where(IncidentHistory.incident_id == incident_id).order_by(IncidentHistory.revision).limit(101)).all()
    return IncidentView(**{k: getattr(incident, k) for k in IncidentView.model_fields if k not in {"history", "scan"}},
        history=[HistoryView(**{k: getattr(h, k) for k in HistoryView.model_fields}) for h in rows],
        scan=get_scan(s, actor, incident.scan_id))


def update_incident(s, actor, identifier, change, audit):
    actor.require("ADMIN", "ANALYST")
    lock_state(s)
    incident = s.get(Incident, identifier)
    if incident is None:
        raise DomainError("NOT_FOUND", 404)
    if incident.revision != change.expected_revision:
        raise DomainError("INCIDENT_VERSION_CONFLICT", 409)
    if incident.revision >= 100:
        raise DomainError("INCIDENT_HISTORY_LIMIT", 409)
    if incident.status == "RESOLVED" or (incident.status == "INVESTIGATING" and change.status == "OPEN"):
        raise DomainError("INCIDENT_TRANSITION_DENIED", 409)
    if change.status == "RESOLVED" and not change.resolution:
        raise DomainError("RESOLUTION_REQUIRED", 422)
    incident.status, incident.reviewer_id = change.status, actor.id
    incident.revision += 1
    history = IncidentHistory(incident_id=identifier, revision=incident.revision, actor_id=actor.id,
        status=change.status, note=change.note, resolution=change.resolution)
    s.add(history)
    audit.append(s, "INCIDENT_UPDATED", actor.id, incident.transfer_id, incident_id=identifier,
        revision=incident.revision, state=change.status,
        note_digest=sha256(change.note.encode()).hexdigest(), resolution_digest=sha256(change.resolution.encode()).hexdigest())
    return incident_view(s, actor, identifier)


def export_incident(s, actor, identifier, audit):
    view = incident_view(s, actor, identifier)
    events = s.scalars(select(AuditEvent).where(AuditEvent.resource_id == view.transfer_id).order_by(AuditEvent.sequence).limit(500)).all()
    audit.append(s, "EVIDENCE_EXPORTED", actor.id, view.transfer_id, incident_id=identifier)
    return {"schema_version": 1, "generated_at": now().isoformat(), "generated_by": actor.id,
            "incident": view.model_dump(mode="json"),
            "audit_references": [{"id": e.id, "sequence": e.sequence, "mac": e.mac} for e in events],
            "authentication": "Export itself is not signed. Referenced HMAC events require trusted retained keys and checkpoints. Not a court-certified artifact."}
