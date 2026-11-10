# Versioned policy evaluation

Each policy version is immutable and contains a UUID, unique increasing number,
threshold, enabled flag, actor and UTC timestamp. The migration creates policy 1
with threshold 1,024 and block matching enabled; its actor is null because it is a
system migration. Later versions identify the authenticated administrator.

Threshold is a strict integer from 1 through 10,485,760 inclusive. Booleans, strings,
fractions and out-of-range values are rejected. Updating requires the current policy
UUID in `expected_version`; stale updates return 409 without overwriting anything.

| Priority | Condition | Result / reason |
|---|---|---|
| 1 | Unauthorized, invalid input, missing registry/policy, infrastructure error, or evidence resource limit | Error HTTP response with INDETERMINATE and `release_authorized: false` |
| 2 | Any exact active protected-file match | BLOCK / `EXACT_PROTECTED_FILE` |
| 3 | Block matching enabled and at least one version meets threshold | BLOCK / `BLOCK_THRESHOLD_MET` |
| 4 | No qualifying evidence | ALLOW / `NO_QUALIFYING_MATCH` |

Exact matches still block when block matching is disabled or the threshold is
larger than the file. Source attribution from different assets is never combined
to reach the threshold. Qualifying version IDs are sorted for deterministic output.
No role has an override. Registry retirement is an explicit administrative change,
not a way to rewrite the outcome of an existing scan.

The pure policy service accepts typed detection and policy values plus an explicit
authorization flag (default true for already-authorized service callers). Missing
values or denied authorization return INDETERMINATE. HTTP input never supplies
trusted evidence or policy definitions directly to this evaluator. The scan unit
of work performs role authorization, reads the policy from the database, and records
the single-workspace actor and file manifest with every evaluation.

All successful evaluations, including ALLOW, have `release_authorized: false`.
This is an evaluation API, not an authorization token for file delivery. Release
reauthorizes the request, verifies the frozen bytes and current revisions, and is
enforced separately ([transfer specification](transfer-spec.md)). A database failure
rolls back the evaluation; the API returns an explicit error, but cannot promise to
persist that failure in an unavailable database. Authenticated audit integrity is
specified in the [audit specification](audit-spec.md).
