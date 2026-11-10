# Detection specification

The cryptographic profile remains `rs-fixed-sha256-v1`. No Phase 01 hash,
descriptor, tree rule, fixture or public cryptographic function changed.

`app.detection.detect(session, fingerprint, registry_revision)` returns evidence.
`app.policy.evaluate(...)` returns a separate decision. `app.scans.run_scan(...)`
authorizes the actor, fingerprints frozen input, locks registry state, reads the
active policy, detects, evaluates and persists all records in one transaction.
Detection itself has no delivery, forwarding, download or release capability; release is a
separate gateway step ([transfer specification](transfer-spec.md)).

## Registry lifecycle

Administrators register bytes; callers cannot supply authoritative digests.
Empty protected registrations are rejected. Each version has a UUID, monotonic
asset-local version number, registration actor/time, revision, manifest and ordered
chunk rows. Labels are unique, case-sensitive ASCII display metadata, never paths.
An identical version within the same asset returns 409; separate labels may register
the same bytes, intentionally retaining shared attribution.

Adding a version requires `expected_version` equal to the asset's current version.
Only the current version of each non-retired asset participates in new scans.
Older versions remain retrievable and referenced by earlier scans. Retirement is
idempotent, increments the registry revision once, and retains all historical rows.
Retired assets cannot receive new versions; register a new asset.

## Exact and block evidence

Exact lookup uses `(profile_id, file_size, file_sha256)` and returns all matching
active versions, regardless of filename. Block lookup uses `(sha256, length)` with
the version's profile checked in the join. An index supports each lookup. Unique
outbound keys are queried in batches of 200, rather than iterating over the registry
in Python. For U unique outbound keys, detection uses `1 + ceil(U / 200)` SQL queries;
the empty candidate uses only the exact lookup. This excludes orchestration and
evidence persistence queries. Version listing fetches summaries in one query.

For each matched version, evidence groups a digest/length with its sorted source
indices and outbound indices. It does not expand every source/destination pair.
Each outbound chunk yields the half-open interval `[index * 1024, offset + length)`.
The set of intervals is sorted and counted once per version. Fixed chunks cannot
overlap. Repeated protected source chunks therefore do not inflate matched bytes;
repetition in separate outbound chunks legitimately contributes separate bytes.

Coverage is an exact rational `{numerator: matched_bytes, denominator: file_size}`.
For empty candidates there are no matches. The UI computes a percentage only when
the denominator is nonzero. Multiple assets can explain the same interval; never
sum their matched bytes together to meet a per-asset policy threshold.

Evidence bounds: at most 1,000 matching versions and 100,000 combined source and
outbound references. Query limits are applied before row materialization. Exceeding
either bound returns `EVIDENCE_LIMIT`/503/INDETERMINATE; evidence is not silently
truncated into an ALLOW. The workspace evidence view (`frontend/src/components/Evidence.tsx`)
displays at most 20 matching versions, 20 intervals and 8 block groups per match, with 12
source and outbound indices per group, while the authenticated scan API returns the complete
bounded evidence.

## Testable limitations

| Input after registering the eight-block synthetic protected fixture | Expected |
|---|---|
| Exact or renamed bytes | Exact BLOCK, 8,192 matched bytes |
| First byte modified | Block BLOCK, 7,168 matched bytes |
| Two aligned copied blocks | Block BLOCK, 2,048 matched bytes |
| Whole file embedded after an aligned 1,024-byte prefix | Block BLOCK, 8,192 matched bytes |
| One-byte prefix | No matches, ALLOW for this fixture |
| CRLF or UTF-16LE transformation | No matches, ALLOW for these fixtures |
| zlib-compressed or base64-encoded content | No automatic decoding; fixture misses |
| Short registered tail copied alone | May match but be below threshold |
| Arbitrary snippet cut across chunk boundaries | No sliding window search |

These misses are asserted expected behavior, not failed tests. They are not
universal statements about every transformed file: other unchanged aligned blocks
may still match. SHA-256 equality does not prove intent, provenance or exclusive
ownership. Merkle inclusion commits to integrity and ordering, not DLP similarity.

The registry is one workspace, not a multi-tenant service. Detection receives no
destination context: the gateway and the staging agent decide where released bytes go.
