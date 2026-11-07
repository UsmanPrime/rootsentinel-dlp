# RootSentinel DLP

**Hash-Based Data Loss Prevention and File Integrity Intelligence Platform**

CS-3002 Information Security · Existing repository: [UsmanPrime/rootsentinel-dlp](https://github.com/UsmanPrime/rootsentinel-dlp)

## Current state

Phase 04 adds a complete role-aware browser workspace around the authenticated
registry, versioned policies, controlled single-use transfer gateway, incident
investigation and HMAC audit integrity. It includes a real interactive Merkle
explorer, exact dashboard aggregates and a guided synthetic demonstration.
Phase 05 adds the local staging gateway agent: a separate, standard-library process that
watches a staging directory and delivers a file to its outbound directory only after the
gateway persisted ALLOW and released verified bytes. **Local browser workflow and the
local staging agent are implemented; hosted CI for Phase 05 passed on the candidate head (run 42268818788, all 8 jobs; see the evidence).
Public deployment remains future work.**

The unchanged cryptographic core uses Python `hashlib`. The backend uses FastAPI,
SQLAlchemy/Alembic and Argon2id. Every operational view displays actual backend results.
A scan ALLOW alone never authorizes delivery; the gateway verifies bytes and current
state again before a single-use download.

## Screenshots

Captured from the real application in Chrome against the ephemeral synthetic test
backend (no mocked verdicts). Full set and viewport checks: `docs/evidence/phase-04/`.

![Security overview at 1440 px](docs/evidence/phase-04/overview-1440.png)

![Interactive Merkle explorer at 1440 px](docs/evidence/phase-04/integrity-1440.png)

![Transfer gateway at 375 px](docs/evidence/phase-04/gateway-375.png)

## Intended product

- **P0-A:** public browser workflow with synthetic inputs and actual scan/decision/release processing.
- **P0-B:** local staging gateway agent (Windows primary, Linux CI) that withholds blocked files and delivers checked snapshot bytes.
- SHA-256 exact-file identification, 1 KiB block fingerprints and Merkle inclusion proofs.
- Evidence that explains both successful detections and known misses.

Enforcement applies only to the controlled gateway and, for the staging agent, only to what
reaches its outbound directory. USB, e-mail, clipboard, other applications and direct copying are
not covered. Fixed blocks can miss shifted, encoded or transformed content. Merkle integrity does
not establish authorization.

## Quick validation

Use Python 3.12 or 3.13. From the repository root:

```sh
cd backend
python -B -m unittest tests.test_crypto tests.test_config -v
cd ..
python -B scripts/fixtures.py
```

For the complete backend suite, install `backend/requirements-dev.lock` into an
isolated environment outside source, then run `python -m pytest` from `backend`.
See [local setup and migration instructions](docs/developer-guide.md#phase-02-local-backend).

With Node 22.12+ (below 25):

```sh
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm test
npm run build
npm run dev
```

The workbench binds to loopback. It is not a production deployment. Dependencies and
build output are ignored by Git; Git-ignore does not exclude OneDrive syncing.

Staging agent (needs the backend test dependencies for the real-gateway tests):

```sh
python -B scripts/source_corpus.py        # synthetic corpus manifest check
cd agent
python -m pytest -p no:cacheprovider      # unit, fault-injection, crash-recovery and real-gateway tests
cd ..
python -B scripts/demo_phase05.py         # end-to-end demo on a disposable gateway
```

## Documentation

- [Master-plan implementation baseline](docs/master-plan.md)
- [Instructor requirements and traceability](docs/requirements.md)
- [Cryptographic specification](docs/cryptographic-spec.md)
- [Architecture and threat model](docs/architecture.md)
- [Developer installation and storage boundaries](docs/developer-guide.md)
- [Testing and evidence](docs/testing.md)
- [Research references](docs/research.md)
- [Phase 01 completion report](docs/evidence/phase-01.md)
- [Phase 02 completion report](docs/evidence/phase-02.md)
- [REST contract and OpenAPI](docs/api.md)
- [Detection limitations](docs/detection-spec.md)
- [Database and migrations](docs/database.md)
- [Authentication and authorization](docs/authentication.md)
- [Frontend architecture, design system and guided demonstration](docs/frontend.md)
- [Phase 04 verification evidence](docs/evidence/phase-04.md)
- [Staging agent specification, provisioning and recovery](docs/staging-spec.md)
- [Phase 05 verification evidence](docs/evidence/phase-05.md)

## Repository status and contributions

Phase 01 was published at `5d6df58a6118a79e8c6b3928a4225c3aebef6b15`.
Phase 02 preserves that history. Its completion evidence records validation and
publication status; Git history identifies the exact implementation checkpoint.

The course requires exactly three students. Named ownership and actual contribution
history must be recorded by the team; neither is fabricated here. Licensing remains
unselected pending the team's choice; no open-source license is implied.

Never commit original instructor DOCX files, real protected payloads, secrets,
runtime databases, or screenshots containing sensitive machine paths.

## Phase 03 — controlled transfer and evidence

Local authenticated transfers now retain bounded private snapshots, evaluate the existing
fingerprint/policy engine and release only single-use verified bytes. Protected-content
blocks create investigable incidents. HMAC event chains and independent checkpoints support
explicitly bounded tamper detection. The browser calls real APIs for download, investigation,
export and verification. No operating-system-wide interception or public deployment is claimed.

Start with [local setup](docs/deployment.md), [transfer protocol](docs/transfer-spec.md),
[audit protocol and keys](docs/audit-spec.md), and [Phase 03 verification](docs/evidence/phase-03.md).

## Phase 04 — role-aware workspace

Role-aware SOC workspace with a real interactive Merkle explorer, incident queue, audit operations,
policy administration and a guided synthetic demonstration, all over the unchanged Phase 01–03 backend.
Evidence, including the sanitized browser reports and screenshots, is in
[Phase 04 verification](docs/evidence/phase-04.md), which also records a one-time correction of the
Phase 04 commit messages (identical file contents) and the resulting commit identifiers.

## Phase 05 — local staging gateway agent

`agent/rootsentinel_agent` watches an employee's staging directory and acts only as a client of the
REST gateway: the server alone decides. A file reaches the outbound directory only after the gateway
persisted ALLOW and the single-use release returned bytes that match the SHA-256 computed from one
local read. Blocked files go to a private quarantine with a payload-free report and a gateway incident.
STALE, EXPIRED, ERROR, DELIVERY_UNKNOWN, integrity and transport failures deliver nothing. An fsync'd
journal makes crashes neither lose nor silently duplicate a file. Admission is nonrecursive and rejects
links, reparse points, hardlinks, special, empty and oversized files.

It is **not** operating-system interception: USB, e-mail, clipboard, other applications and direct copying
are not covered, shifted, re-encoded or compressed copies are known misses of fixed 1 KiB block matching,
and on Windows the permission separation between staging and outbound is an operator step. See the
[specification](docs/staging-spec.md) (including exact provisioning commands), the
[threat model](docs/threat-model.md) and the [evidence](docs/evidence/phase-05.md).

## Phase 06A — hosted presenter demo (prepared, not deployed)

A `Dockerfile`, `render.yaml`, an unprivileged entrypoint, an idempotent `bootstrap` (accounts from a file of password hashes, one
synthetic protected asset) and `scripts/smoke_public.py` prepare a free-tier Render plus Neon deployment of the gateway with the
frontend served from the same origin. Access is by operator-created accounts only; there is no anonymous or visitor mode, and
`public_demo` still denies every API route. Nothing has been deployed and there are no deployed measurements yet. On a free tier
the audit chain is tamper evident within one container lifetime only: checkpoints are lost on restart. See
[deployment](docs/deployment.md) (including what you must do yourself) and the [evidence](docs/evidence/phase-06a.md).
