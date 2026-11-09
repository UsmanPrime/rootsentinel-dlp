# Phase evidence

Each phase ends with a verification record: what was built, which checks ran, the CI result and the commit that was published.
This page indexes those records and keeps the phase history that used to live in the top-level README. Every phase is tagged
in Git (`phase-01` to `phase-06a`).

## Scope at the start

The product was planned around two required parts. P0-A: a public browser workflow with synthetic inputs and real scan,
decision and release processing. P0-B: a local staging gateway agent (Windows primary, Linux CI) that withholds blocked files
and delivers checked snapshot bytes. Both rest on SHA-256 exact file identification, 1 KiB block fingerprints and Merkle
inclusion proofs, with evidence that explains both detections and known misses. Enforcement applies only to the controlled
gateway and, for the agent, only to what reaches its outbound directory. Merkle integrity does not establish authorization.

## Phases

| Phase | Record | Summary |
|---|---|---|
| 01 | [phase-01.md](phase-01.md), [checks](phase-01-final-checks.json) | Cryptographic core |
| 02 | [phase-02.md](phase-02.md), [checks](phase-02-checks.json), [benchmark](phase-02-benchmark.json), [browser](phase-02-browser.json), [checkpoint](phase-02-checkpoint.json) | Registry, detection, policy, authentication |
| 03 | [phase-03.md](phase-03.md), [checks](phase-03-checks.json), [benchmark](phase-03-benchmark.json), [browser](phase-03-browser.json), [checkpoint](phase-03-checkpoint.json), [publication audit](phase-03-publication-audit.json) | Controlled transfer and audit |
| 04 | [phase-04.md](phase-04.md), [browser](phase-04-browser.json), [negative browser](phase-04-negative-browser.json), [publication audit](phase-04-publication-audit.json), [screenshots](phase-04/) | Role-aware workspace |
| 05 | [phase-05.md](phase-05.md), [checks](phase-05-checks.json), [demo](phase-05-demo.json), [hosted CI](phase-05-hosted-ci.json) | Local staging gateway agent |
| 06A | [phase-06a.md](phase-06a.md) | Hosted presenter demo |

### Phase 01: cryptographic core

The cryptographic profile `rs-fixed-sha256-v1` (SHA-256 of the file, of each fixed 1 KiB block, and a Merkle tree over the
blocks) uses only the Python standard library. It was published at `5d6df58a6118a79e8c6b3928a4225c3aebef6b15` and has not
changed since.

### Phase 02: registry, detection, policy and authentication

Phase 02 kept the Phase 01 history and added the protected asset registry, indexed exact and block detection, versioned
policy, and Argon2id sessions with roles. Its completion evidence records validation and publication status; Git history
identifies the exact implementation checkpoint.

### Phase 03: controlled transfer and evidence

Local authenticated transfers retain bounded private snapshots, evaluate the fingerprint and policy engine, and release only
single use verified bytes. Blocks of protected content create incidents to investigate. HMAC event chains and independent
checkpoints give explicitly bounded tamper detection. The browser calls real APIs for download, investigation, export and
verification. No operating system wide interception or public deployment was claimed. Start with
[local setup](../deployment.md), the [transfer protocol](../transfer-spec.md), the [audit protocol and keys](../audit-spec.md)
and the [Phase 03 record](phase-03.md).

### Phase 04: role-aware workspace

A role-aware SOC workspace with an interactive Merkle explorer, incident queue, audit operations, policy administration and a
guided synthetic demonstration, all over the unchanged Phase 01 to 03 backend. Screenshots were captured from the real
application in Chrome against the ephemeral synthetic test backend, with no mocked verdicts; the full set and viewport checks
are in [phase-04/](phase-04/). The [Phase 04 record](phase-04.md) also documents a one-time correction of the Phase 04 commit
messages (identical file contents) and the resulting commit identifiers.

### Phase 05: local staging gateway agent

`agent/rootsentinel_agent` watches an employee's staging directory and acts only as a client of the REST gateway: the server
alone decides. A file reaches the outbound directory only after the gateway persisted ALLOW and the single use release returned
bytes that match the SHA-256 computed from one local read. Blocked files go to a private quarantine with a payload-free report
and a gateway incident. STALE, EXPIRED, ERROR, DELIVERY_UNKNOWN, integrity and transport failures deliver nothing. A journal
flushed with fsync makes crashes neither lose nor silently duplicate a file. Admission is nonrecursive and rejects links,
reparse points, hardlinks, special, empty and oversized files. It is not operating system interception; on Windows the
permission separation between staging and outbound is an operator step. Hosted CI for Phase 05 passed on the candidate head
(run `42268818788`, all 8 jobs at the time). See the [specification](../staging-spec.md), the
[threat model](../threat-model.md) and the [Phase 05 record](phase-05.md).

### Phase 06A: hosted presenter demo

A `Dockerfile`, `render.yaml`, an unprivileged entrypoint, an idempotent `bootstrap` (accounts from a file of password
hashes, one synthetic protected asset) and `scripts/smoke_public.py` deploy the gateway to Render's free tier with PostgreSQL
on Neon, with the frontend served from the same origin. Access is by operator-created accounts only; `public_demo` still
denies every API route. The service runs at https://rootsentinel-dlp.onrender.com. The [Phase 06A record](phase-06a.md) holds
the measurements (cold start, sign-in time, image size), the two deploy failures and their fixes, and the client
identification work. Hop counting failed on the host; `True-Client-IP` header mode was adopted after a two-network test, and
the record keeps the earlier misreadings of that evidence. CI now runs 9 jobs. The final commit is tagged `phase-06a`.
