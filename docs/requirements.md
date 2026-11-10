# Instructor requirements and traceability

Authority: `Project_Overview_and_Deliverables.docx` (O) and
`Project_Topic_Guide.docx` (T), read directly at project start. Paragraph numbers
are OOXML document-order indices including blank paragraphs, not page numbers.
Original documents remain outside this repository and must not be published
without permission. Their hashes were unchanged at the first intake.

| Document | SHA-256 |
|---|---|
| O | `6ce519febd203a89f5e50632edb678d6161e2aab1bdb1cc61aec0516d1784e47` |
| T | `a60dff190d637b4e5bb780a91ffcb892cc3a06d3e4ea9bfd2174fb8515004aa7` |

## Mandatory administrative rules

- O P5: exactly three members; one- and two-person groups are not allowed.
- O P6 to P8: first-come topic reservation; no duplicate topic within a section;
  changing another group's entry incurs a penalty of two absolute marks.
- O P34: **"Update the Topic Selection Sheet with your GitHub repository link and
  hosted project URL. No submission is required on GCR."**
- O P35: a thorough technical PDF covering architecture, threat model, library
  choices, implementation hurdles and security analysis belongs on GitHub with
  deployable code.
- O P36: PPTX/PDF presentation; direct reading from slides is prohibited and heavily penalized.
- O P37: live demonstration of the deployed web application with real inputs.
- O P38: mandatory Q&A participation and targeted technical questions for the
  group presenting immediately afterward.

[Designated Topic Selection Sheet](https://docs.google.com/spreadsheets/d/1DMW-z8OS7DDUZSGB8PtRbnAUT-8Aa6P75jC5kcHvPU8/edit?usp=sharing).
Its reservation state has not been verified or modified from this repository. Team names, submission
deadline, report length and presentation duration are not established here.

## Traceability

| ID | Source | Requirement | Status and evidence |
|---|---|---|---|
| C01 | O P5 | Three students | Usman Ibrahim, Alishba Inam, Amna Zainab (README). Planned responsibilities: A crypto, detection and threat model; B interface, evidence and onboarding; C backend, authentication, audit and deployment. Actual contributions are documented in the final report, not invented here |
| C02 | O P6 to P8 | Valid reservation | Team checks its sheet entry; pending |
| C03 | T P13 | SHA-256 and block fingerprints | Implemented: `backend/app/crypto`, `backend/app/detection.py`; tests `test_crypto.py`, `test_detection_policy.py` |
| C04 | T P13 | Merkle integrity/proofs | Implemented: [cryptographic spec](cryptographic-spec.md), Merkle explorer in the workspace |
| C05 | T P14 | Detect/block unauthorized source transfers | Implemented: controlled release ([transfer spec](transfer-spec.md), `test_gateway.py`) and staging agent ([staging spec](staging-spec.md)) |
| C06 | T P15 | Staging-directory gateway scenario | Windows-primary agent with Linux CI proof ([staging spec](staging-spec.md), [Phase 05 evidence](evidence/phase-05.md)) |
| C07 | O P13 | Established cryptographic libraries | `hashlib` (SHA-256), `hmac` (HMAC-SHA256 audit chain, `backend/app/audit.py`), `argon2-cffi` (Argon2id passwords) |
| C08 | O P14 | Key generation/distribution/storage/revocation | Audit keyring generation and rotation (`python -m app.audit_keys init` / `rotate`, old verification keys kept), private-file checks, hosted distribution as a platform secret file ([deployment](deployment.md)); session revocation ([authentication](authentication.md)); key compromise handling is a manual procedure ([audit spec](audit-spec.md)) |
| C09 | O P15 | Explicit threat model | [Threat model](threat-model.md) |
| C10 | O P17 | Modular architecture | Detection, policy and enforcement are separate modules (`detection.py`, `policy.py`, `transfers.py`) plus the separate agent ([architecture](architecture.md)) |
| C11 | O P18 | Data/protocol diagrams | TLS and plaintext boundaries, flow and sequence diagrams ([architecture](architecture.md)) |
| C12 | O P19 | Secure integration | Bounded crypto and proof validation; authenticated single-use release gateway ([transfer spec](transfer-spec.md)) |
| C13 | O P21 to P22 | End-to-end responsive full stack | React workspace ([frontend](frontend.md)), deployed at https://rootsentinel-dlp.onrender.com |
| C14 | O P23 | Onboarding/tooltips | Guided synthetic walkthrough at `/guide` and a skippable first-run tour ([frontend](frontend.md)) |
| C15 | O P24 | API, secure sessions, persistence | REST API ([api](api.md), [OpenAPI](openapi.json)), server sessions ([authentication](authentication.md)), SQLite and PostgreSQL persistence ([database](database.md)) |
| C16 | O P26 | GitHub, clean history, README | Published on GitHub `main`; every phase tagged `phase-01` to `phase-06a` ([evidence index](evidence/README.md)) |
| C17 | O P27 | Free public hosting | Deployed on the Render free tier with Neon PostgreSQL: https://rootsentinel-dlp.onrender.com ([Phase 06A evidence](evidence/phase-06a.md)) |
| C18 | O P28 | REST/WebSocket integration | REST implemented; WebSocket (P1) not implemented |
| C19 | O P30 | Attack surface mapping | [Threat model](threat-model.md) tables per boundary |
| C20 | O P31 | Empirical attacks and mitigations | Tested: proof corruption, forged and replayed release, CSRF, Origin and Host, session handling, rate limits, client IP spoofing, audit tampering ([testing](testing.md), [quality review](evidence/quality-review.md)) |
| C21 | O P32 | Security/usability evaluation | Local benchmarks (Phase 02 and 03 evidence), deployed cold start and sign-in time ([Phase 06A](evidence/phase-06a.md)), automated axe and Lighthouse checks ([quality review](evidence/quality-review.md)); no user usability study |
| C22 | O P34 | Sheet submission; no GCR | Team action; pending |
| C23 | O P35 | Technical PDF | Markdown sources in `docs/`; final PDF pending |
| C24 | O P36 | Presentation and no slide reading | Deck, notes and rehearsal pending |
| C25 | O P37 | Deployed live demonstration | Deployed and smoke-tested; classroom demonstration pending |
| C26 | O P38 | Questions for following group | Team preparation; pending |

## Interpretations

Hashes are not ciphertext; TLS provides the relevant transport encryption in protocol diagrams. "Instantly block" means
no delivery before a persisted ALLOW, not zero latency. REST is the baseline interpretation of "REST/WebSocket
endpoints"; any instructor demand for both must be confirmed. The local gateway is mandatory to deliver, though not
required to run with the public server. The three-day plan was an internal time budget, not a university deadline.

C06 (the local staging-directory gateway) is addressed by the staging agent in [staging-spec.md](staging-spec.md). The
Topic Guide text does not require Linux; the earlier "Linux/WSL2 demo" wording was this project's own interpretation.
Because WSL2 was not a usable runtime on the development machine (its only Python was outside the supported range), the
agent is **Windows-primary** with POSIX behavior proven by a Linux CI job, and a Windows CI job. A WSL2 run is optional
and was not performed as evidence. The agent controls only its outbound directory; USB, e-mail, clipboard, other
applications and direct copying are not covered.

## Scope and priorities

**P0 (required):** SHA-256, block and Merkle core; immutable registry; matching and simple policy; controlled browser
release; local staging agent; authentication and authorization; incident evidence; audit integrity; persistence; basic
dashboard and onboarding; public deployment; required tests, empirical evaluation, report, manual and slides.

**P1 (enhancements):** content-defined chunking, WebSockets, scoped exceptions, richer filters and charts, an interactive
lab.

**P2 (out of scope):** a native Windows service or installer, kernel- or driver-level interception, archive
normalization and semantic matching, enterprise identity, external audit anchoring, arbitrary forwarding and broader
operating system controls.

Fixed 1 KiB chunks come first; content-defined chunking is an enhancement. Free hosting is required, with no production
reliability claim for free tiers.

## Release and academic package

Checklist of course deliverables, with C-IDs where the table above tracks them:

- Public GitHub repository with README and clean history (C16).
- Technical report as PDF (C23), with architecture and threat diagrams, the cryptographic specification, security tests
  and raw evaluation, deployment, API and developer guides, and limitations and future work.
- User manual.
- Presentation with speaker notes, rehearsed without reading slides (C24).
- Live browser and local agent demonstration script (C25).
- Viva preparation and questions for the next presenting group (C26).
- Topic sheet updated with the repository and hosted URLs; nothing submitted on GCR (C22).

CV claims must reflect actual results. Never fabricate deployment, tests, benchmarks, membership or topic reservation.
