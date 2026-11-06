# Instructor requirements and traceability

Authority: `Project_Overview_and_Deliverables.docx` (O) and
`Project_Topic_Guide.docx` (T), read directly during Phase 00. Paragraph numbers
are OOXML document-order indices including blank paragraphs, not page numbers.
Original documents remain outside this repository and must not be published
without permission. Their hashes were unchanged at Phase 01 intake.

| Document | SHA-256 |
|---|---|
| O | `6ce519febd203a89f5e50632edb678d6161e2aab1bdb1cc61aec0516d1784e47` |
| T | `a60dff190d637b4e5bb780a91ffcb892cc3a06d3e4ea9bfd2174fb8515004aa7` |

## Mandatory administrative rules

- O P5: exactly three members; one- and two-person groups are not allowed.
- O P6–8: first-come topic reservation; no duplicate topic within a section;
  changing another group's entry incurs a penalty of two absolute marks.
- O P34: **“Update the Topic Selection Sheet with your GitHub repository link and
  hosted project URL. No submission is required on GCR.”**
- O P35: a thorough technical PDF covering architecture, threat model, library
  choices, implementation hurdles and security analysis belongs on GitHub with
  deployable code.
- O P36: PPTX/PDF presentation; direct reading from slides is prohibited and heavily penalized.
- O P37: live demonstration of the deployed web application with real inputs.
- O P38: mandatory Q&A participation and targeted technical questions for the
  group presenting immediately afterward.

[Designated Topic Selection Sheet](https://docs.google.com/spreadsheets/d/1DMW-z8OS7DDUZSGB8PtRbnAUT-8Aa6P75jC5kcHvPU8/edit?usp=sharing).
Its reservation state has not been verified or modified. Team names, submission
deadline, report length and presentation duration are not established here.

## Traceability

| ID | Source | Requirement | Planned evidence / status |
|---|---|---|---|
| C01 | O P5 | Three students | Actual contributor table/history; pending |
| C02 | O P6–8 | Valid reservation | Team checks its sheet entry; pending |
| C03 | T P13 | SHA-256 and block fingerprints | Phase 01 library/tests implemented; matcher later |
| C04 | T P13 | Merkle integrity/proofs | Phase 01 library/tests/spec implemented |
| C05 | T P14 | Detect/block unauthorized source transfers | Phase 02–03 gateway tests; pending |
| C06 | T P15 | Staging-directory gateway scenario | Phase 05: Windows-primary agent, Linux CI proof ([staging-spec](staging-spec.md)); hosted CI pending |
| C07 | O P13 | Established cryptographic libraries | hashlib implemented; hmac planned |
| C08 | O P14 | Key generation/distribution/storage/revocation | Lifecycle design; implementation pending |
| C09 | O P15 | Explicit threat model | Architecture document; evolve with implementation |
| C10 | O P17 | Modular architecture | Detection/policy/enforcement separation planned |
| C11 | O P18 | Data/protocol diagrams | TLS/plaintext boundaries documented |
| C12 | O P19 | Secure integration | Bounded crypto and proof validation now; gateway security later |
| C13 | O P21–22 | End-to-end responsive full stack | Preview only; operational application pending |
| C14 | O P23 | Onboarding/tooltips | Guided workflow pending |
| C15 | O P24 | API, secure sessions, persistence | Later phases |
| C16 | O P26 | GitHub, clean history, README | Correct local origin/main; owner verified empty remote; checkpoint evidence in Phase 01 report; publication pending |
| C17 | O P27 | Free public hosting | Render/Neon planned; not provisioned |
| C18 | O P28 | REST/WebSocket integration | REST P0, WebSocket P1; not implemented |
| C19 | O P30 | Attack surface mapping | Threat model baseline |
| C20 | O P31 | Empirical attacks and mitigations | Proof corruption tested; operational attacks pending |
| C21 | O P32 | Security/usability evaluation | Methodology specified; measurements pending |
| C22 | O P34 | Sheet submission; no GCR | Student submission checklist; pending |
| C23 | O P35 | Technical PDF | Markdown sources started; final PDF pending |
| C24 | O P36 | Presentation and no slide reading | Deck/notes/rehearsal pending |
| C25 | O P37 | Deployed live demonstration | P0-A release gate; pending |
| C26 | O P38 | Questions for following group | Team preparation; pending |

Interpretations are explicit: hashes are not ciphertext; TLS provides the relevant
transport encryption in protocol diagrams. “Instantly block” means no release
before an allowed decision, not zero latency. REST is the baseline interpretation
of “REST/WebSocket endpoints”; any instructor demand for both must be confirmed.
The local gateway is mandatory to deliver, though not required to run with the
public server. Three days is the Codex resource window, not a university deadline.

## Phase 02 traceability update

Source requirements and paragraph references above are unchanged. Their original
status descriptions are the Phase 01 snapshot. Phase 02 advances:

- C03/C10/C12: indexed exact/block detection and separated deterministic policy,
  bounded intake and failure tests; final enforcement remains Phase 03.
- C08/C15: opaque sessions, password hashing, revocation, roles, persistence and
  documented REST endpoints. Authenticated audit keys remain unimplemented.
- C13/C14: minimal responsive real-backend local workbench; full onboarding and
  public hosting remain later work.
- C16: Phase 01 published; Phase 02 checkpoint/publication status is in its evidence.
- C18/C20/C21: REST and reproducible detection/security/browser tests plus measured
  local benchmarks. WebSockets remain P1; no enterprise or universal-DLP claim.
- C09/C19: implemented threat model and remaining boundary assumptions documented.

Three named contributors, topic-sheet confirmation, local staging delivery, public
deployment, final report/PDF, presentation and submission remain overall-project
deliverables. Phase 02 does not claim the entire course project is complete.

## Phase 05 traceability update

C06 (the local staging-directory gateway) is addressed by the staging agent in
[staging-spec.md](staging-spec.md). The Topic Guide text does not require Linux; the earlier "Linux/WSL2 demo"
wording was this project's own interpretation. Because WSL2 was not a usable runtime on the development machine
(its only Python was outside the supported range), the agent is **Windows-primary** with POSIX behavior proven by a
Linux CI job, and a Windows CI job. A WSL2 run is optional and was not performed as evidence. The statement that
"instantly block" means no delivery before a persisted ALLOW is unchanged. The agent controls only its outbound
directory; USB, e-mail, clipboard, other applications and direct copying are not covered.
