"""Persist a complete evaluation atomically; failures cannot persist ALLOW."""
from sqlalchemy import select

from . import profiles
from .crypto import fingerprint_bytes
from .detection import detect
from .errors import DomainError
from .models import MatchEvidence, PolicyDecision, ScanEvaluation
from .policy import active_policy, evaluate, policy_view, profiles_for
from .registry import lock_state
from .schemas import DecisionView, DetectionView, MatchView, ProfileEvidence, ScanView


def run_scan(s, principal, filename, snapshot):
    principal.require("ADMIN", "ANALYST", "EMPLOYEE")
    fp = fingerprint_bytes(snapshot.data)
    state = lock_state(s)
    policy = active_policy(s, state)
    # The policy's rule set names the profiles to evaluate. rs-policy-v1 evaluates the fixed profile only.
    detection = detect(s, fp, state.revision)
    detection = profiles.extend(s, snapshot.data, detection, profiles_for(policy.rule_set))
    decision = evaluate(detection, policy_view(policy))
    additional = [e.model_dump(mode="json") for e in detection.profiles if e.profile_id != profiles.FIXED_ID]
    scan = ScanEvaluation(actor_id=principal.id, filename=filename, snapshot_id=snapshot.id,
                          manifest=fp.manifest.to_dict(), registry_revision=state.revision, policy_id=policy.id,
                          profiles=additional or None)
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
    detection = DetectionView(manifest=scan.manifest, registry_revision=scan.registry_revision, matches=matches)
    # The fixed profile's evidence is derived from its stored rows; the other profiles' evidence was stored whole.
    evidence = [profiles.fixed_evidence(detection)] + [ProfileEvidence(**e) for e in scan.profiles or []]
    return ScanView(id=scan.id, actor_id=scan.actor_id, filename=scan.filename, snapshot_id=scan.snapshot_id,
                    created_at=scan.created_at, policy_id=scan.policy_id,
                    detection=detection.model_copy(update={"profiles": evidence}),
                    decision=DecisionView(**{k: getattr(decision, k) for k in DecisionView.model_fields}))
