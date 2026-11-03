# RootSentinel DLP

**Hash-Based Data Loss Prevention and File Integrity Intelligence Platform**

CS-3002 Information Security · Existing repository: [UsmanPrime/rootsentinel-dlp](https://github.com/UsmanPrime/rootsentinel-dlp)

## Current state

Phase 01 foundation: a tested SHA-256/Merkle library, deterministic synthetic
fixtures, external-runtime path validation, and a responsive React preview.
**There is no operational DLP gateway or public deployment yet.** Registry,
matching, policy, authentication, incidents and release enforcement are later phases.

The Python core has no third-party runtime dependencies. It uses `hashlib`, not a
custom hash primitive. The preview does not display fabricated scan results.

## Intended product

- **P0-A:** public browser workflow with synthetic inputs and actual scan/decision/release processing.
- **P0-B:** Linux/WSL2 staging gateway that withholds blocked files and delivers checked snapshot bytes.
- SHA-256 exact-file identification, 1 KiB block fingerprints and Merkle inclusion proofs.
- Evidence that explains both successful detections and known misses.

Enforcement applies only to the controlled gateway. Fixed blocks can miss shifted,
encoded or transformed content. Merkle integrity does not establish authorization.

## Quick validation

Use Python 3.12 or 3.13. From the repository root:

```sh
cd backend
python -B -m unittest discover -s tests -v
cd ..
python -B scripts/fixtures.py
```

For the pytest workflow, install `backend/requirements-dev.lock` into an
isolated environment outside the source tree, then run `python -m pytest` from
`backend`. See [installation](docs/developer-guide.md).

With Node 22.12+ (below 25):

```sh
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
npm run dev
```

The preview binds to loopback. It is not a production deployment. Dependencies and
build output are ignored by Git; Git-ignore does not exclude OneDrive syncing.

## Documentation

- [Master-plan implementation baseline](docs/master-plan.md)
- [Instructor requirements and traceability](docs/requirements.md)
- [Cryptographic specification](docs/cryptographic-spec.md)
- [Architecture and threat model](docs/architecture.md)
- [Developer installation and storage boundaries](docs/developer-guide.md)
- [Testing and evidence](docs/testing.md)
- [Research references](docs/research.md)
- [Phase 01 completion report](docs/evidence/phase-01.md)

## Repository status and contributions

The owner verified the existing remote was empty using a successful `git ls-remote`
and initialized this local repository on `main` with the correct origin. Phase 01
validation passes; the audited files are staged, but the sandbox denied the local
commit. See the completion report for verification and the remaining checkpoint
step. Publishing remains a separate authorized action.

The course requires exactly three students. Named ownership and actual contribution
history must be recorded by the team; neither is fabricated here. Licensing remains
unselected pending the team's choice; no open-source license is implied.

Never commit original instructor DOCX files, real protected payloads, secrets,
runtime databases, or screenshots containing sensitive machine paths.
