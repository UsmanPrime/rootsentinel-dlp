# Authenticated audit protocol, version 1

File fingerprints remain unkeyed SHA-256. Audit integrity is a separate keyed mechanism
implemented with Python `hmac.digest(..., 'sha256')` and `hmac.compare_digest`, using the
[standard HMAC library](https://docs.python.org/3/library/hmac.html).

## Event encoding

The strict `EventPayload` schema contains schema_version=1, canonical UUID event/stream
identifiers, positive integer sequence, UTC timestamp with six fractional digits and Z,
allowlisted event kind, nullable actor/resource UUIDs, key_id, previous_mac, and allowlisted
bounded details. Control characters and arbitrary log text are rejected. Unknown fields
and noncanonical representations fail verification. No source content or credentials
are included. Filenames are not copied into the audit chain.

Let C be `json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
allow_nan=False)` encoded as ASCII. The event MAC is:

```text
HMAC-SHA-256(key[key_id],
  ASCII("RootSentinelAudit") || 00 || 01 || uint32_be(len(C)) || C)
```

The key ID is inside C. previous_mac is 64 lower-case hexadecimal zeros for sequence 1,
otherwise the preceding event MAC. The migration assigns each database a random stable
stream UUID. Sequence begins at 1; one locked head row stores sequence/MAC. Audit append
uses a no-op UPDATE lock, verifies the existing tail, inserts the immutable event and
updates the head in the caller's transaction. Registry lock precedes audit lock in
operations requiring both. There are no independently committed audit appends hidden
inside security-sensitive state mutations.

SQLite and PostgreSQL triggers prohibit ordinary UPDATE/DELETE of audit/history records.
Database administrators can bypass triggers; HMAC verification addresses this distinct
threat. Verification checks canonical schema, IDs, sequence, stream, linkage and MAC,
then head and checkpoint. It reports the first invalid sequence; missing historical
keys are explicit failures. Verification and storage are bounded to 20,000 events for
P0. Reaching the cap fails closed; an archival/stream rollover design is future work.

## Events and semantics

HTTP asset registration/version/retirement and policy mutations append audit records
in their existing transactions. Transfers append submission, completed scan, decision,
failure/expiry, release attempt/denial/start and completion/uncertainty. Incidents append
creation/update; exports and successful verification actions are recorded. Internal
registry unit-of-work calls do not manufacture historical events. The hosted `bootstrap`
command seeds its synthetic assets through the normal path and appends `ASSET_REGISTERED` for each. When it gives
a seed registered earlier the fingerprints of a detection profile it lacks, it appends `ASSET_PROFILE_ADDED` with the
new registry revision, and when it activates policy rule set `rs-policy-v2` it appends `POLICY_CHANGED`. Each happens
at most once per database.
Pre-Phase-03 records are explicitly outside this chain.

Authorized release denials are audited once ownership and chain integrity are known.
Anonymous/CSRF/unknown-object failures are rejected before audit append to avoid revealing
object existence or allowing unauthenticated log flooding. They are not claimed to be
complete audit coverage. Operational error responses contain safe codes, not exception text.

## Key lifecycle

`python -m app.audit_keys init <absolute-external-private-path>` creates a 32-byte random
key using `secrets.token_bytes`, a random key ID and a 0600 JSON keyring. Existing files
are never overwritten by init. Set ROOTSENTINEL_AUDIT_KEY_FILE to this file, never to
a file inside Git/OneDrive/runtime. The CLI prints only the key ID. Missing/unreadable/
unsafe key material causes mandatory audit operations to fail; keys are not regenerated
at application startup. Frontend and API responses never receive them.

Rotate offline: stop the single API worker, securely back up the keyring, run
`python -m app.audit_keys rotate <same-path>`, then restart. Rotation atomically installs
a new active key while retaining old keys for historical events/checkpoints. Up to 32
keys are supported. Preserve old verification keys for the complete retention period.
Do not revoke/delete a historical verification key and then claim the old chain verifies.
If a key is compromised, stop release, revoke operational access, preserve evidence and
establish a new independently trusted stream/checkpoint under an incident procedure.
Rotation cannot restore authenticity to events an attacker could already forge.

## Independent checkpoints

Set ROOTSENTINEL_CHECKPOINT_ROOT to a private absolute directory outside source,
OneDrive and the application runtime/database tree. Files are append-only by application
convention, named `checkpoint-{sequence:010d}.json`; no cleanup deletes them. Each includes
version=1, stream_id, sequence, mac, key_id and signature. Signature uses the same
length-prefixed canonical encoding but domain `RootSentinelCheckpoint || 00 || 01`,
with signature omitted while computing it. New files use exclusive create, fsync and
POSIX directory fsync. Windows does not provide directory fsync here; a power-loss
durability guarantee is not claimed. Existing checkpoints cannot be silently replaced.

Before any payload response, the committed RELEASE_STARTED head is checkpointed.
`POST /api/v1/audit/checkpoint` also lets ADMIN retain a verified head after an audited
checkpoint request. The highest retained filename is consulted; stream changes, rollback,
invalid signatures and a database truncated below that sequence fail verification.
Back up checkpoints independently/off-host for meaningful protection against storage loss.
Local separation protects against database-only replacement, not application-host control.

Not protected: key holders, host administrators, uncheckpointed tail deletion when the
attacker also rewrites the head, or simultaneous compromise/removal of the database and
trusted checkpoints. An empty checkpoint directory cannot prove that no older checkpoint
ever existed. The hosted demo writes checkpoint files to the container's ephemeral disk, so
those files are lost on every restart. The signed tree heads described next are stored in
the database and survive a restart; what they do and do not replace is stated there.

Tests include an independent HMAC reference construction, content/sequence/link/MAC/key/
encoding tampering, middle deletion, reorder, missing keys, rotation, concurrent appends,
database-admin trigger bypass with retained checkpoint detection, and an explicit passing
example of undetectable uncheckpointed tail truncation.

## Transparency log: signed tree heads over the chain

The HMAC chain proves an event to someone who holds the secret key. The transparency log adds a public proof: a
Merkle tree over the same events (RFC 9162) whose root the gateway signs with Ed25519. Anyone with the public key can
check that an event is in the log and that the log only grew, without any secret. Exact encodings, the key file and
its lifecycle are in the [cryptographic specification](cryptographic-spec.md#audit-transparency-log-tree-and-signed-tree-heads).

**What is stored.** Table `transparency_heads` (migration `0004`) holds one signed tree head per tree size: the
five signed fields and the signature. It is append-only: database triggers reject UPDATE and DELETE on SQLite and
PostgreSQL, and the primary key allows one head per size, so a second, different head for the same size cannot be
stored. The application never changes or removes a head.

**When a head is signed.** Inside the transaction that wrote the event, never on a timer:

| Moment | Rule |
|---|---|
| Every 64th event | The append that writes sequence 64, 128, ... also signs a head of that size |
| Every release | After `RELEASE_STARTED` is written, a head covering that event is signed and verified in the same transaction. No head, no delivery |
| On request | `POST /api/v1/transparency/sth` (ADMIN). Asking again at the same size returns the stored head |
| Startup | When events exist after the latest head, they are checked and a head is signed for them |
| Evidence export | The export signs a head that covers the export event itself |

An idle process signs nothing and makes no database call (`test_idle.py`).

**The tree in memory.** The process keeps the leaf hashes and the hash of every complete subtree, so appending one
event costs one hash per tree level and a proof needs no database read of old events. This tree is a cache of the
stored events. It is brought up to date under the audit head lock before every append; a transaction that fails
removes its own leaves again; events written by another process (the account tool, bootstrap) are loaded and checked
before use. If the database holds fewer events than this process has seen committed, every audited action is refused
(`AUDIT_LOG_ROLLBACK`).

**Startup.** The tree is rebuilt from the stored events. The latest stored head must carry a valid signature of a key
in the key file and the root the rebuilt tree has at that size. Events after it are checked one by one (canonical
form, sequence, link, HMAC). If the head and the events disagree, the service still starts but refuses every audited
action and every release with `AUDIT_LOG_INVALID`, and logs for the operator:
`audit transparency log check failed (...)` with the instruction to compare the database with a head kept outside it,
repair or restore, then restart.

**Release.** Before a release the gateway used to verify every stored HMAC, which grew with the log. It now checks
the latest stored head (signature, and root against the tree in memory) and then reads again only the events after
that head: each must equal the leaf in memory, link to its predecessor and carry a valid HMAC. The newest file
checkpoint, when one exists, is compared with the tree as well. Any failure refuses the release. Events under the
latest head are not read again at release; an edit there is caught by `POST /api/v1/audit/verify`, which still
checks every event, and at the next startup. Measured on local SQLite, median of 15 releases
(`scripts/benchmark_release.py`):

| Events already in the log | Before | After |
|---|---|---|
| 0 | 27.6 ms | 26.9 ms |
| 2000 | 98.9 ms | 35.8 ms |
| 10000 | 323.2 ms | 45.7 ms |

These numbers compare two versions of the code on one machine. They are not a hosted latency.

**What a head proves, and to whom.**

* A party that kept an earlier head outside the database (the browser's Audit log tab, `scripts/witness.py`, an
  exported bundle) detects truncation, rollback and any rewrite of events under that head: the consistency proof to
  the current head fails, or the log is smaller than the saved size.
* A party with no earlier head cannot detect a rollback. If the events and the heads are removed together, what
  remains is a shorter log that is consistent with itself. The gateway is in this position after a restart.
* Access to the database can delete heads (after dropping the triggers) but cannot forge one: a head needs the
  signing key, which is not in the database.
* A holder of the signing key can sign anything. The key is on the application host. See the threat model.

**Evidence export.** `GET /api/v1/exports/incidents/{id}` adds a `transparency` section when a signing key is
configured: `format` (`rootsentinel-evidence-v1`), the signed tree head `sth`, `key_id`, `public_key`, and for
every referenced event its `sequence`, `canonical` text, `mac`, `leaf_index`, `tree_size`, `leaf_hash` and inclusion
`path`. `python scripts/witness.py bundle --public-key <pinned keys> <export.json>` verifies it offline. The key
inside the bundle is information only; the verifier uses the key it pinned. The rest of the export is not signed.

**Witness.** `python scripts/witness.py check --base-url <origin> --public-key <pinned keys> --state <file>
--username <ANALYST or ADMIN>` signs in, fetches the latest head, verifies the signature with the pinned key,
verifies a consistency proof from the saved head, and only then replaces the saved head. Exit code 0 means verified,
1 means the log failed a check (the saved head is kept), 2 means the check could not run. Run it on a machine other
than the gateway, on a schedule you choose; it is a request with a session, so it wakes the database.

Tests: `test_transparency_tree.py`, `test_transparency_log.py`, `test_witness.py`, the idle test in `test_idle.py`,
the browser suite's Audit log check, and `frontend/src/lib/transparency.test.ts`.

## Visitor events and the actor column

Three event kinds were added for [visitor mode](visitor-mode.md): `VISITOR_ENTERED`, `VISITOR_ENDED` (sign out) and
`VISITOR_EXPIRED` (written by lazy cleanup). `audit_events.actor_id` (migration 0006) repeats the payload's
`actor_id` so a view can filter on it. It is not part of the canonical payload or the MAC, and the canonical bytes did
not change. Verification (`check_event`, `verify_records`) fails an event whose non-null column differs from the
payload; a null column is accepted because events written before the migration have none. Rejected requests (403, 429
and the 404 of a disabled mode) write no event.
