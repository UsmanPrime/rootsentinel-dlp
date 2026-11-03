# Approved Phase 00 implementation baseline

This repository summary records the governing decisions from the reviewed master
plan and its final configuration amendment. The detailed course traceability,
cryptographic contract and threat assumptions are maintained in adjacent documents.

## Locked configuration

- Existing remote: `https://github.com/UsmanPrime/rootsentinel-dlp.git`.
- Source stays in the user's confirmed Windows/OneDrive workspace; no relocation.
- Instructor DOCX originals are private, unchanged and outside the repository.
- Runtime, secrets, payloads and high-volume artifacts belong outside OneDrive.
- Public mode accepts synthetic fixture IDs only; actual cryptography and matching.
- Local gateway is mandatory to deliver on native Linux/WSL2 filesystem storage.
- Fixed 1 KiB chunks first; CDC is an enhancement.
- Free public hosting is mandatory. No production reliability claim for free tiers.
- Exactly three students academically; execution assumes one primary operator and
  limited Codex availability rather than three full-time developers.
- No deployment, push or system configuration change is authorized by Phase 01.

## Priority and dependency order

**P0:** SHA-256/block/Merkle core; immutable registry; matching and simple policy;
controlled browser release; Linux staging adapter; authentication/authorization;
incident evidence; audit integrity; persistence; basic dashboard/onboarding;
public deployment; required tests, empirical evaluation, report, manual and slides.

**P1:** CDC, WebSockets, scoped exceptions, richer filters/charts and interactive lab.
**P2:** native Windows agent, archives/normalization/semantic matching, enterprise
identity, external audit anchoring, arbitrary forwarding and broader OS controls.

| Phase | Deliverable | Gate |
|---|---|---|
| 01 | Repo/scaffold, crypto contract/tests, preview, fixture manifest | Crypto/build pass; onboarding and pinned test installation verified |
| 02 | Auth, registry, detection, policy and intake | Authorization, immutable versions, deterministic matching |
| 03 | Release, incidents, audit and recovery | Blocked bytes never released; allowed bytes equal scanned snapshot |
| 04 | Integrated product interface | Real backend journeys, accessible evidence and errors |
| 05 | Local gateway and evaluation | Safe admission, idempotent verified delivery, measured scenarios |
| 06 | Free deployment, report and defense | Public smoke test, complete evidence and academic checklist |
| 07 | Optional enhancements | All P0 gates already passing |

Recommended implementation model: available Codex workhorse with high reasoning;
use extra review effort for cryptographic and filesystem/security boundaries.
Subsequent phases are not silently authorized by implementing the foundation.

## Three-day resource strategy

Day 1: verified crypto foundation, then backend scan/policy/release vertical slice
and a connected browser. Day 2: finish core UI/local gateway, then first public
deployment. Day 3: security matrix, fault tests, empirical results and fixes, then
final documents and rehearsal. Write tests/docs during each block, not at the end.
Time is a resource budget, not grounds to lower security gates. Drop P1 first.

## Ownership and integration

Three academic responsibilities: A crypto/detection/threat model; B UI/evidence/
onboarding; C backend/auth/audit/deployment. Actual names and contributions remain
to be supplied. No fabricated histories. Use small reviewed changes and a single
integration line; front-end contracts follow backend types/OpenAPI. Avoid speculative
interfaces or infrastructure not needed for the next verified vertical slice.

Each phase report lists changed files/features, actual commands/results, security
checks, unresolved limitations, Git status/commit if any, produced evidence and
readiness. Failed mandatory acceptance means incomplete, not 'done with caveats'.

## Release and academic package

Public GitHub/README; clean history; technical report/PDF; architecture and threat
diagrams; crypto specification; security tests and raw evaluation; deployment/API/
developer guides; user manual; presentation with speaker notes; live browser and
local demo script; viva preparation; screenshots/evidence; limitations/future work.
CV claims must reflect actual results. Update the designated topic sheet with repo
and hosted URLs; no GCR. Ask targeted questions of the next presenting group and
rehearse without reading slides.

## Highest risks

Remote/network restrictions, unverified WSL access, usage exhaustion, free-tier
sleep/quotas, unsafe snapshot release, misleading fixed-block claims, compromised
audit-key assumptions, OneDrive locks and late academic artifacts. Preserve
recoverable checkpoints and explicit blockers. Never fabricate deployment, tests,
benchmarks, membership or topic reservation.
