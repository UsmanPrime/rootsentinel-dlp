"""Deterministic decisions, separate from matching and from future release."""
from .errors import DomainError, Indeterminate
from .models import PolicyVersion
from .registry import lock_state
from .schemas import DecisionView, DetectionView, PolicyInput, PolicyView


def policy_view(policy) -> PolicyView:
    return PolicyView(**{k: getattr(policy, k) for k in PolicyView.model_fields})


def active_policy(s, state):
    policy = s.get(PolicyVersion, state.policy_id)
    if policy is None or type(policy.threshold) is not int or not 1 <= policy.threshold <= 10485760:
        raise Indeterminate("POLICY_UNAVAILABLE")
    return policy


def evaluate(detection: DetectionView | None, policy: PolicyView | None, *, authorized=True) -> DecisionView:
    if not authorized or detection is None or policy is None or not 1 <= policy.threshold <= 10485760:
        return DecisionView(outcome="INDETERMINATE", reason="INVALID_EVALUATION_CONTEXT", qualifying_versions=[])
    exact = sorted(m.version_id for m in detection.matches if m.exact)
    if exact:
        return DecisionView(outcome="BLOCK", reason="EXACT_PROTECTED_FILE", qualifying_versions=exact)
    blocks = sorted(m.version_id for m in detection.matches if m.matched_bytes >= policy.threshold)
    if policy.block_enabled and blocks:
        return DecisionView(outcome="BLOCK", reason="BLOCK_THRESHOLD_MET", qualifying_versions=blocks)
    return DecisionView(outcome="ALLOW", reason="NO_QUALIFYING_MATCH", qualifying_versions=[])


def change_policy(s, principal, request: PolicyInput):
    principal.require("ADMIN")
    state = lock_state(s)
    previous = active_policy(s, state)
    if previous.id != request.expected_version:
        raise DomainError("POLICY_VERSION_CONFLICT", 409)
    new = PolicyVersion(number=previous.number + 1, threshold=request.threshold,
                        block_enabled=request.block_enabled, actor_id=principal.id)
    s.add(new)
    s.flush()
    state.policy_id = new.id
    return policy_view(new)
