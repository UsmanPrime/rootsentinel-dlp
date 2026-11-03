# Authenticated audit protocol — version 1

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
creation/update; exports and successful verification actions are recorded. Registry
bootstrap/internal unit-of-work calls do not automatically manufacture historical events.
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
ever existed. Future cloud hosting needs durable independently controlled checkpoint
storage and secret injection; ephemeral free-tier filesystems do not satisfy this contract.

Tests include an independent HMAC reference construction, content/sequence/link/MAC/key/
encoding tampering, middle deletion, reorder, missing keys, rotation, concurrent appends,
database-admin trigger bypass with retained checkpoint detection, and an explicit passing
example of undetectable uncheckpointed tail truncation.
