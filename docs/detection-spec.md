# Detection specification

Detection compares the raw bytes of a submitted file with registered protected assets. It has two
profiles. `rs-fixed-sha256-v1` is the Phase 01 cryptographic profile and is unchanged: no hash,
descriptor, tree rule, fixture or public cryptographic function of it changed. `rs-cdc-gear-v1` is a
second, separate profile that cuts a file at positions chosen by its content.

`app.detection.detect(session, fingerprint, registry_revision)` returns the fixed profile's evidence.
`app.profiles.extend(...)` adds the evidence of every other profile the active policy names.
`app.policy.evaluate(...)` returns a separate decision. `app.scans.run_scan(...)` authorizes the actor,
fingerprints frozen input, locks registry state, reads the active policy, detects, evaluates and
persists all records in one transaction. Detection itself has no delivery, forwarding, download or
release capability; release is a separate gateway step ([transfer specification](transfer-spec.md)).

## Profile registry

`backend/app/profiles.py` is a registry in front of `detection.py`. A profile has an id, a version,
published parameters and three functions: fingerprint bytes, store an asset version's fingerprint, and
match an upload's fingerprint against the current versions of the active assets.

| Profile | Version | Fingerprint | Stored rows | Matcher |
|---|---|---|---|---|
| `rs-fixed-sha256-v1` | 1 | `crypto.fingerprint_bytes` (unchanged) | `asset_chunks` (unchanged) | `detection.detect` (unchanged) |
| `rs-cdc-gear-v1` | 1 | `crypto.cdc.cdc_chunks` | `asset_cdc_chunks` | `profiles._match_cdc` |

Rules of the registry:

* A registered profile is never replaced or altered. A new detection method is a new profile with a new
  id, and registering an id twice is an error.
* The fixed profile is registered as it was. Its code path, its outputs, its stored rows and its test
  vectors (`fixtures/manifest.json`, `backend/tests/test_crypto.py`) are byte-identical.
* An unknown profile id fails closed with `UNSUPPORTED_PROFILE` (INDETERMINATE).
* `GET /api/v1/detection/profiles` lists the profiles and their parameters for every signed-in role. The
  list is built from constants and reads no table.

Which profiles a scan evaluates is decided by the active policy's rule set
([policy specification](policy-spec.md)): `rs-policy-v1` evaluates the fixed profile only,
`rs-policy-v2` evaluates both.

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

### Which versions carry which profile

A new asset version is fingerprinted with every registered profile at registration, in the same
transaction. The raw bytes of an asset are not stored, so a profile cannot be computed later:

* A version registered before `rs-cdc-gear-v1` existed keeps only its fixed-profile rows. Migration
  `0005` adds no fingerprints. Such a version still matches through the fixed profile and is simply
  absent from content-defined lookups until a new version of the asset is registered.
* The asset details page and `GET /assets/{id}/versions` state this per version
  (`profiles[].fingerprinted`).
* The hosted seed assets are the one exception, because their bytes are constants of
  `backend/app/bootstrap.py`. At every container start bootstrap gives a seed's current version the
  missing content-defined rows when its stored size and SHA-256 equal the seed bytes
  (`registry.add_missing_profiles`). Only rows of the missing profile are inserted. The registry
  revision advances by one (action `PROFILE_ADDED`), so approvals issued before the rows existed become
  stale, and the audit chain records `ASSET_PROFILE_ADDED`. A seed that an administrator replaced with
  other content is left alone.

## Exact and block evidence (rs-fixed-sha256-v1)

Exact lookup uses `(profile_id, file_size, file_sha256)` and returns all matching
active versions, regardless of filename. Block lookup uses `(sha256, length)` with
the version's profile checked in the join. An index supports each lookup. Unique
outbound keys are queried in batches of 200, rather than iterating over the registry
in Python. For U unique outbound keys, detection uses `1 + ceil(U / 200)` SQL queries;
the empty candidate uses only the exact lookup. This excludes orchestration and
evidence persistence queries. Version listing fetches summaries in one query and the
per-version profile counts in a second.

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

## Content-defined chunks (rs-cdc-gear-v1)

Fixed blocks start at multiples of 1,024 bytes, so one byte inserted at the front moves every block and
no block hash survives. This profile cuts where the content says so. A boundary depends on a short
window of bytes before it, so after an insertion or a deletion the boundaries fall on the same content
again and the chunks behind the change keep their hashes.

The algorithm is FastCDC with normalized chunking: Xia et al., "FastCDC: a Fast and Efficient
Content-Defined Chunking Approach for Data Deduplication", USENIX ATC 2016, and the extended version,
"The Design of Fast Content-Defined Chunking for Data Deduplication Based Storage Systems", IEEE TPDS
31(9), 2020 (Algorithm 2). The implementation is `backend/app/crypto/cdc.py`. It takes one byte per
step; the paper's optional two-bytes-per-step variant is not used.

| Parameter | Value |
|---|---|
| Minimum chunk size | 512 bytes |
| Normal (expected average) size | 2,048 bytes |
| Maximum chunk size | 8,192 bytes |
| Normalization level | 2: 13 mask bits before the normal size, 9 after |
| `MASK_S` (before the normal size) | `0x0000d93003530000` |
| `MASK_L` (from the normal size on) | `0x0000d90003500000` |
| Gear table | 256 values of 64 bits, derived from SHA-256 ([cryptographic specification](cryptographic-spec.md#content-defined-profile-rs-cdc-gear-v1)) |
| Chunk identifier | SHA-256 of the chunk bytes, 64 lowercase hex characters |
| Maximum input | 10 MiB, as for the fixed profile |

Cut-point rule for one chunk that starts at offset `start` with `n` bytes left in the file:

1. If `n` is at most 512, the rest of the file is the last chunk.
2. Otherwise limit `n` to 8,192 and set `fp = 0`. For `i` from 512 up to `n - 1`, take the byte at
   `start + i` and update `fp = ((fp << 1) + Gear[byte]) mod 2^64`.
3. After each update test `fp & MASK_S == 0` while `i < 2048`, and `fp & MASK_L == 0` from `i = 2048`
   on. The first `i` that passes is the chunk length: the chunk ends before that byte, which becomes
   the first byte of the next chunk.
4. If no position passes, the chunk length is `n`: 8,192 bytes, or the rest of the file.

Consequences: every chunk except the last is 512 to 8,192 bytes long, the chunks concatenate to the
input, an empty input has no chunk, and the result depends on nothing but the bytes. `MASK_L` is a subset
of `MASK_S`, so a position that passes the stricter test also passes the easier one. The highest mask
bit is bit 47, so a boundary depends on at most the 48 bytes before it. On hash-like data the measured
average chunk is about 2.3 KiB.

### Storage, matching and scoring

`asset_cdc_chunks(version_id, offset, length, sha256)` holds one row per chunk of an asset version, with
an index on `sha256` (migration `0005`). Rows are only inserted; triggers reject UPDATE and DELETE.

To match, the upload is cut with the same rule and its unique chunk hashes are looked up in batches of
500, restricted to the current version of non-retired assets. For C unique upload chunks this is
`ceil(C / 500)` queries. A stored chunk counts only when its length also equals the upload chunk's.

Scoring is the same model as the fixed profile. Per matched asset version, the matched bytes are the
size of the union of the byte intervals of the upload's matched chunks. A protected chunk that occurs
several times in the registry counts once; the same content at two places of the upload counts at both.
Assets are judged one by one and their bytes are never added together.

Every scan reports evidence per profile in `detection.profiles`, one entry per evaluated profile with
the fixed profile first:

| Field | Meaning |
|---|---|
| `profile_id` | `rs-fixed-sha256-v1` or `rs-cdc-gear-v1` |
| `chunk_count` | number of chunks the upload has under that profile |
| `matches[].asset_id`, `version_id` | the protected asset version |
| `matches[].matched_bytes` | size of the union of matched intervals |
| `matches[].matched_chunks` | distinct upload chunks that matched |
| `matches[].coverage` | exact rational `{numerator: matched_bytes, denominator: file_size}`, the share of the file |
| `matches[].intervals` | the matched byte runs of the upload, merged and sorted |

`detection.matches` is still the fixed profile's full evidence, with the same fields and values as
before. The fixed entry of `detection.profiles` is derived from it. A profile the policy did not
evaluate has no entry, which is different from an entry without matches. The content-defined evidence
of a scan is stored with the scan (`scan_evaluations.profiles`), so a recorded decision can always be
explained from its own record.

## Evidence bounds

At most 1,000 matching versions and 100,000 combined source and outbound references, for each profile.
Query limits are applied before row materialization. Exceeding either bound returns
`EVIDENCE_LIMIT`/503/INDETERMINATE; evidence is not silently truncated into an ALLOW. The workspace
evidence view (`frontend/src/components/Evidence.tsx`) displays at most 20 matching versions, 20
intervals and 8 block groups per match, with 12 source and outbound indices per group, while the
authenticated scan API returns the complete bounded evidence.

## Scan time

Content-defined chunking is a per-byte loop in Python. It runs only under `rs-policy-v2`, inside the
scan transaction. The loop keeps the table and masks in local variables, iterates a `memoryview` of the
input and does no allocation per byte. Measured for one scan request (upload, both fingerprints,
lookups, decision, persistence) against the hosted image with SQLite, limited with
`docker run --cpus 0.15 --memory 512m`:

| Input size | Unrelated bytes, median of 3 (max) | Shifted copy of the source sample plus filler, median of 3 (max) | Chunking alone, in process |
|---|---|---|---|
| 64 KiB | 0.29 s (0.40 s) | 0.21 s (0.27 s) | 0.10 s |
| 256 KiB | 0.50 s (0.51 s) | 0.48 s (0.53 s) | 0.50 s |
| 1 MiB | 1.66 s (1.67 s) | 1.41 s (1.47 s) | 1.11 s |
| 10 MiB | not measured over HTTP | not measured over HTTP | 10.1 s |

Demonstration-sized inputs, up to 64 KiB, stay well under the 3 second budget. One mebibyte, the upload
limit of the hosted demo, takes about 1.7 seconds, of which chunking is about 1.1. A 10 MiB upload, the
code default limit, would spend about 10 seconds in chunking alone on such a host, during which the scan
holds the registry lock; a deployment that accepts files of that size on so little CPU should stay on
`rs-policy-v1` or lower its upload limit. The fixed profile needs 0.2 seconds for 1 MiB under the same
limits. Peak resident memory of the server after these scans was 148 MiB.

The numbers are from one development machine and say nothing about another host or about network
latency to a remote database. `scripts/benchmark_cdc.py` repeats the measurement against any running
gateway.

## Testable limitations

Results after registering the synthetic protected input, under each rule set. "Miss" means no matched
byte and ALLOW.

| Input | `rs-policy-v1` (fixed blocks) | `rs-policy-v2` (fixed blocks and chunks) |
|---|---|---|
| Exact or renamed bytes | Exact BLOCK | Exact BLOCK |
| First byte modified (eight-block fixture) | BLOCK, 7,168 matched bytes | BLOCK, same fixed evidence |
| Two aligned copied blocks | BLOCK, 2,048 matched bytes | BLOCK, same fixed evidence |
| Whole file embedded after an aligned 1,024-byte prefix | BLOCK, 8,192 matched bytes | BLOCK, same fixed evidence |
| One-byte prefix, source corpus files | Miss | BLOCK, `CDC_THRESHOLD_MET` |
| A line inserted in the first block, source corpus files | Miss | BLOCK, `CDC_THRESHOLD_MET` |
| One-byte prefix, eight-block fixture | Miss | Miss (see below) |
| CRLF or UTF-16LE transformation | Miss | Miss |
| zlib, ZIP or base64 | Miss, no decoding | Miss, no decoding |
| Short registered tail copied alone | May match but be below threshold | Same |
| Snippet shorter than one chunk, or cut inside chunks | No sliding window search | Not found unless it contains whole chunks |

Matched bytes for the five protected files of the synthetic source corpus (`scripts/source_corpus.py`),
fixed profile and content-defined profile, asserted in `backend/tests/test_profiles.py`:

| Protected file | Size | One-byte prefix: fixed / chunks | Inserted line: fixed / chunks |
|---|---|---|---|
| `billing/invoice_engine.py` | 9,025 | 0 / 7,379 | 0 / 7,379 |
| `billing/tax_rules.py` | 6,422 | 0 / 3,542 | 0 / 3,542 |
| `pricing/margin_model.py` | 5,607 | 0 / 2,416 | 0 / 2,416 |
| `auth/token_vault.py` | 8,502 | 0 / 7,216 | 0 / 7,216 |
| `ml/ranking_core.py` | 8,438 | 0 / 7,251 | 0 / 7,251 |

The three benign corpus files share no chunk with any protected file and stay ALLOW under both rule
sets.

What the content-defined profile does not do:

* **Repetitive content has no cut point.** The eight-block fixture repeats one line per block and the
  first hosted seed repeats a 20-byte string. Neither contains a position that passes the mask test, so
  each is cut at the maximum size and is a single chunk. Such chunks are position-defined, exactly like
  fixed blocks, and a shifted copy shares none of them. The tests assert this miss.
* **A change costs the chunk it falls in.** The chunk that contains an inserted or removed byte no
  longer matches, and with normalized chunking the next boundary can move as well, so a small file of
  a few chunks can lose most of its match to one edit in the middle. When the unchanged part before the
  edit is at least one aligned block, the fixed profile still finds it; the two profiles are evaluated
  together for this reason.
* **Re-encoding is still open.** A copy with other line endings, another character encoding,
  compression or base64 has other bytes and therefore other chunks. Closing this needs normalisation and
  a winnowing fingerprint, which is a later profile.
* **Old versions.** A version without content-defined rows is not found by this profile.

These misses are asserted expected behavior, not failed tests. They are not
universal statements about every transformed file: other unchanged aligned blocks
may still match. SHA-256 equality does not prove intent, provenance or exclusive
ownership. Merkle inclusion commits to integrity and ordering, not DLP similarity; the content-defined
chunks are similarity evidence only and are covered by no Merkle root.

The registry is one workspace, not a multi-tenant service. Detection receives no
destination context: the gateway and the staging agent decide where released bytes go.
