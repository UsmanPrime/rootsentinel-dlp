"""Persist a complete evaluation atomically; failures cannot persist ALLOW."""
from sqlalchemy import select

from .crypto import fingerprint_bytes
from .detection import detect
from .errors import DomainError
from .models import MatchEvidence, PolicyDecision, ScanEvaluation
from .policy import active_policy, evaluate, policy_view
from .registry import lock_state
from .schemas import DecisionView, DetectionView, MatchView, ScanView


def run_scan(s, principal, filename, snapshot):
    principal.require("ADMIN", "ANALYST", "EMPLOYEE")
    fp = fingerprint_bytes(snapshot.data)
    state = lock_state(s)
    policy = active_policy(s, state)
    detection = detect(s, fp, state.revision)
    decision = evaluate(detection, policy_view(policy))
    scan = ScanEvaluation(actor_id=principal.id, filename=filename, snapshot_id=snapshot.id,
                          manifest=fp.manifest.to_dict(), registry_revision=state.revision, policy_id=policy.id)
    s.add(scan)
    s.flush()
    for match in detection.matches:
        s.add(MatchEvidence(scan_id=scan.id, **match.model_dump()))
    s.add(PolicyDecision(scan_id=scan.id, **decision.model_dump()))
    s.flush()
    return ScanView(id=scan.id, actor_id=scan.actor_id, filename=filename, snapshot_id=scan.snapshot_id,
                    created_at=scan.created_at, policy_id=policy.id, detection=detection, decision=decision)


def get_scan(s, principal, scan_id):
    scan = s.get(ScanEvaluation, scan_id)
    if scan is None or (principal.role == "EMPLOYEE" and scan.actor_id != principal.id):
        raise DomainError("NOT_FOUND", 404)
    matches = [MatchView(**{k: getattr(m, k) for k in MatchView.model_fields}) for m in s.scalars(
        select(MatchEvidence).where(MatchEvidence.scan_id == scan.id).order_by(MatchEvidence.version_id))]
    decision = s.scalar(select(PolicyDecision).where(PolicyDecision.scan_id == scan.id))
    return ScanView(id=scan.id, actor_id=scan.actor_id, filename=scan.filename, snapshot_id=scan.snapshot_id,
                    created_at=scan.created_at, policy_id=scan.policy_id,
                    detection=DetectionView(manifest=scan.manifest, registry_revision=scan.registry_revision, matches=matches),
                    decision=DecisionView(**{k: getattr(decision, k) for k in DecisionView.model_fields}))
