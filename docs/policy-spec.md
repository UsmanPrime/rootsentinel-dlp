# Versioned policy evaluation

Each policy version is immutable and contains a UUID, unique increasing number,
threshold, enabled flag, rule set, actor and UTC timestamp. The migration creates policy 1
with threshold 1,024, block matching enabled and rule set `rs-policy-v1`; its actor is null
because it is a system migration. Later versions identify the authenticated administrator.

Threshold is a strict integer from 1 through 10,485,760 inclusive. Booleans, strings,
fractions and out-of-range values are rejected. Updating requires the current policy
UUID in `expected_version`; stale updates return 409 without overwriting anything.

## Rule sets

A rule set is a versioned evaluator. It names the detection profiles a scan must evaluate and the
rules that turn their evidence into a decision. Every policy version stores the rule set it was written
for, so an earlier policy is always judged by its own rules.

| Rule set | Profiles evaluated | Policy fields used |
|---|---|---|
| `rs-policy-v1` | `rs-fixed-sha256-v1` | `threshold`, `block_enabled` |
| `rs-policy-v2` | `rs-fixed-sha256-v1` and `rs-cdc-gear-v1` | `threshold`, `block_enabled`, `cdc_threshold` |

`rs-policy-v1` is the evaluation described below as it always was. Its behaviour, its tests and the
cost of a scan under it are unchanged: the content-defined profile is not computed and its table is not
read.

### rs-policy-v1

| Priority | Condition | Result / reason |
|---|---|---|
| 1 | Unauthorized, invalid input, missing registry/policy, infrastructure error, or evidence resource limit | Error HTTP response with INDETERMINATE and `release_authorized: false` |
| 2 | Any exact active protected-file match | BLOCK / `EXACT_PROTECTED_FILE` |
| 3 | Block matching enabled and at least one version meets threshold | BLOCK / `BLOCK_THRESHOLD_MET` |
| 4 | No qualifying evidence | ALLOW / `NO_QUALIFYING_MATCH` |

### rs-policy-v2

| Priority | Condition | Result / reason |
|---|---|---|
| 1 | As above, and also: evidence of a named profile is missing, or `cdc_threshold` is missing or out of range | INDETERMINATE, `release_authorized: false` |
| 2 | Any exact active protected-file match | BLOCK / `EXACT_PROTECTED_FILE` |
| 3 | Block matching enabled and at least one version has fixed-block matched bytes at or above `threshold` | BLOCK / `BLOCK_THRESHOLD_MET` |
| 4 | Block matching enabled and at least one version has content-defined matched bytes at or above `cdc_threshold` | BLOCK / `CDC_THRESHOLD_MET` |
| 5 | No qualifying evidence | ALLOW / `NO_QUALIFYING_MATCH` |

Rules 2 and 3 are the `rs-policy-v1` rules in the same order, so every file blocked under v1 is blocked
under v2 for the same reason. `qualifying_versions` lists the versions that met the rule that decided.
`block_enabled: false` switches off both partial rules; an exact file still blocks. Missing profile
evidence is never read as "no match".

### Thresholds

| Field | Default | Meaning |
|---|---|---|
| `threshold` | 1,024 | Fixed-block matched bytes per asset version. One whole block |
| `cdc_threshold` | 2,048 | Content-defined matched bytes per asset version. Set only under `rs-policy-v2`; null under `rs-policy-v1` |

The default `cdc_threshold` is deliberately conservative: it equals the profile's normal chunk size and
twice the fixed default, so one chunk below the normal size never blocks on its own. With it, every
shifted and inserted copy in the synthetic corpus blocks (the smallest match is 2,416 bytes) and every
benign corpus file is allowed (no shared chunk). Both thresholds are starting values. They are to be
tuned by the detection evaluation on a larger corpus, and an administrator can set either one in a new
policy version at any time.

### How rs-policy-v2 becomes active

* **By an administrator.** `POST /api/v1/policies` accepts `rule_set` and `cdc_threshold`. The Policies
  page offers both in "Create policy version". An omitted `rule_set` keeps the rule set of the policy
  being replaced, so a client that only knows `threshold` cannot move a workspace back to v1 by
  accident. An omitted `cdc_threshold` keeps the previous value or takes the default. A
  `cdc_threshold` together with `rs-policy-v1` is rejected (422). Switching in either direction is an
  ordinary policy change: a new immutable version, a `POLICY_CHANGED` audit event, and every pending
  approval becomes stale.
* **On the hosted demo.** `python -m app.bootstrap` activates `rs-policy-v2` once, as policy version 2
  with the system identity as its actor and with policy 1's threshold and flag, and appends
  `POLICY_CHANGED`. It does so only while the migration's own policy 1 is still the active one. Any
  later policy was written by an administrator or by an earlier start, and bootstrap never overrides
  it.
* **Everywhere else** (a fresh local database, the test suites, the staging agent's disposable gateway)
  the active policy stays the migration's `rs-policy-v1` until an administrator changes it.

A stored policy whose rule set is unknown, or whose `cdc_threshold` does not fit its rule set, makes
the policy unavailable (`POLICY_UNAVAILABLE`, INDETERMINATE): no scan is evaluated against it.

## Common rules

Exact matches still block when block matching is disabled or the threshold is
larger than the file. Source attribution from different assets is never combined
to reach a threshold, and bytes found by different profiles are never added together.
Qualifying version IDs are sorted for deterministic output.
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
