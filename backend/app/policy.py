"""Deterministic decisions, separate from matching and from future release."""
from . import profiles
from .errors import DomainError, Indeterminate
from .models import PolicyVersion
from .registry import lock_state
from .schemas import DecisionView, DetectionView, PolicyInput, PolicyView

# A rule set is a versioned evaluator. It names the detection profiles a scan must evaluate. A policy version
# stores the rule set it was written for, so an old policy is always judged by its own rules.
RULE_SET_V1 = "rs-policy-v1"
RULE_SET_V2 = "rs-policy-v2"
RULE_SETS = {RULE_SET_V1: (profiles.FIXED_ID,), RULE_SET_V2: (profiles.FIXED_ID, profiles.CDC_ID)}
# The nominal average chunk size and twice the fixed profile's default threshold: no chunk below the normal
# size blocks on its own. A starting value, to be tuned by the detection evaluation.
DEFAULT_CDC_THRESHOLD = 2048


def policy_view(policy) -> PolicyView:
    return PolicyView(**{k: getattr(policy, k) for k in PolicyView.model_fields})


def valid_threshold(value) -> bool:
    return type(value) is int and 1 <= value <= 10485760


def profiles_for(rule_set) -> tuple[str, ...]:
    if rule_set not in RULE_SETS:
        raise Indeterminate("POLICY_UNAVAILABLE")
    return RULE_SETS[rule_set]


def active_policy(s, state):
    policy = s.get(PolicyVersion, state.policy_id)
    if policy is None or type(policy.threshold) is not int or not 1 <= policy.threshold <= 10485760:
        raise Indeterminate("POLICY_UNAVAILABLE")
    if policy.rule_set not in RULE_SETS or (policy.rule_set == RULE_SET_V2) != (policy.cdc_threshold is not None) \
            or (policy.cdc_threshold is not None and not valid_threshold(policy.cdc_threshold)):
        raise Indeterminate("POLICY_UNAVAILABLE")
    return policy


def evaluate(detection: DetectionView | None, policy: PolicyView | None, *, authorized=True) -> DecisionView:
    if not authorized or detection is None or policy is None or not 1 <= policy.threshold <= 10485760:
        return DecisionView(outcome="INDETERMINATE", reason="INVALID_EVALUATION_CONTEXT", qualifying_versions=[])
    if policy.rule_set != RULE_SET_V1:
        return evaluate_v2(detection, policy)
    exact = sorted(m.version_id for m in detection.matches if m.exact)
    if exact:
        return DecisionView(outcome="BLOCK", reason="EXACT_PROTECTED_FILE", qualifying_versions=exact)
    blocks = sorted(m.version_id for m in detection.matches if m.matched_bytes >= policy.threshold)
    if policy.block_enabled and blocks:
        return DecisionView(outcome="BLOCK", reason="BLOCK_THRESHOLD_MET", qualifying_versions=blocks)
    return DecisionView(outcome="ALLOW", reason="NO_QUALIFYING_MATCH", qualifying_versions=[])


def evaluate_v2(detection: DetectionView, policy: PolicyView) -> DecisionView:
    """rs-policy-v2: the rs-policy-v1 rules in the same order, then the content-defined profile.

    The decision needs evidence of every profile the rule set names. Missing evidence is never read as "no match"."""
    evidence = {e.profile_id: e for e in detection.profiles}
    if policy.rule_set != RULE_SET_V2 or not valid_threshold(policy.cdc_threshold) or set(RULE_SETS[RULE_SET_V2]) - set(evidence):
        return DecisionView(outcome="INDETERMINATE", reason="INVALID_EVALUATION_CONTEXT", qualifying_versions=[])
    exact = sorted(m.version_id for m in detection.matches if m.exact)
    if exact:
        return DecisionView(outcome="BLOCK", reason="EXACT_PROTECTED_FILE", qualifying_versions=exact)
    if policy.block_enabled:
        blocks = sorted(m.version_id for m in detection.matches if m.matched_bytes >= policy.threshold)
        if blocks:
            return DecisionView(outcome="BLOCK", reason="BLOCK_THRESHOLD_MET", qualifying_versions=blocks)
        chunks = sorted(m.version_id for m in evidence[profiles.CDC_ID].matches if m.matched_bytes >= policy.cdc_threshold)
        if chunks:
            return DecisionView(outcome="BLOCK", reason="CDC_THRESHOLD_MET", qualifying_versions=chunks)
    return DecisionView(outcome="ALLOW", reason="NO_QUALIFYING_MATCH", qualifying_versions=[])


def new_policy(s, state, previous, actor_id, *, threshold, block_enabled, rule_set=None, cdc_threshold=None):
    """Append a policy version and make it active. The caller holds the registry lock."""
    rule_set = rule_set or previous.rule_set
    if rule_set == RULE_SET_V2:
        cdc_threshold = cdc_threshold or previous.cdc_threshold or DEFAULT_CDC_THRESHOLD
    elif cdc_threshold is not None:
        raise DomainError("INVALID_REQUEST", 422)  # rs-policy-v1 does not evaluate the content-defined profile
    new = PolicyVersion(number=previous.number + 1, threshold=threshold, block_enabled=block_enabled,
                        actor_id=actor_id, rule_set=rule_set, cdc_threshold=cdc_threshold)
    s.add(new)
    s.flush()
    state.policy_id = new.id
    return new


def change_policy(s, principal, request: PolicyInput):
    principal.require("ADMIN")
    state = lock_state(s)
    previous = active_policy(s, state)
    if previous.id != request.expected_version:
        raise DomainError("POLICY_VERSION_CONFLICT", 409)
    return policy_view(new_policy(s, state, previous, principal.id, threshold=request.threshold,
        block_enabled=request.block_enabled, rule_set=request.rule_set, cdc_threshold=request.cdc_threshold))
