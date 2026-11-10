# Quality review: tests, scanners, documents and interface

A repository-wide review on 2026-11-10, starting from `main` at `efa41acc0f7cecdac72cf1aaf8fe92997f73cd10`. Every number below
was measured on the development machine (Windows 11, Python 3.13.4, Node 24.11.0, Docker Desktop 29.6.1, Chrome) or read from
a GitHub Actions log, and says which. The cryptographic core, the detection profile and its test vectors were not changed.

## Before and after

| Measure | Before | After | Source |
|---|---|---|---|
| Backend tests | 311 passed, 1 skipped, 606 subtests | 523 passed, 1 skipped, 606 subtests | local pytest |
| Backend branch coverage | 90% | 93% | local pytest-cov 7.1.0 (coverage 7.17.2) |
| Agent tests | 96 passed, 3 skipped | 104 passed, 3 skipped | local pytest |
| Agent branch coverage | 83% | 86% (`register.py` 62% to 98%) | local pytest-cov |
| Agent end to end demo | 13 of 13 | 13 of 13 | `scripts/demo_agent.py` |
| Frontend unit tests | 19 in 4 files | 37 in 5 files | local vitest |
| Frontend format check | none; Prettier flagged 8 files | `npm run format:check` clean, gated in CI | local, CI `frontend` job |
| Browser suite | Vite dev server, report-only CSP not applied, axe on 17 pages | built interface served by the API, enforced CSP, 32 journey and 8 failure checks, axe on 17 pages, 0 CSP violations, 0 console errors | local run; CI `browser` job |
| axe (96 page and width checks, 3 roles, 375/768/1440 px) | 0 critical, 34 serious, 9 moderate, 0 minor | 0, 0, 0, 0 | local UX audit |
| Console errors during normal use | 12 | 0 | local UX audit |
| CSP | report-only, hosted only, `style-src-attr 'unsafe-inline'` | enforced on every response, no `unsafe-inline`, no `data:` | code, smoke test, browser suite |
| CSP violations | not measured | 0 | local UX audit, browser suites |
| Horizontal overflow at 375 px | 0 pages | 0 pages | local UX audit |
| Focus stops without a visible indicator (6 routes, 40 Tab presses each) | 0 | 0 | local UX audit |
| Hosted image (uncompressed, `du -sxb /`) | 225,147,460 bytes | 219,224,982 bytes (210 MiB; budget 258 MiB) | local Docker build |
| Fixable HIGH or CRITICAL image vulnerabilities | 54 HIGH | 0 | trivy 0.58.1 |
| CI | 9 jobs, actions pinned by tag | 9 jobs, actions pinned by commit SHA, format check added | `.github/workflows/ci.yml` |

### Lighthouse 13.6.0, desktop preset, local server

| Route | Performance before / after | Accessibility before / after | Best practices before / after |
|---|---|---|---|
| Sign in | 100 / 100 | 100 / 100 | 96 / 100 |
| Overview | 94 / 96 | 100 / 100 | 100 / 100 |
| Transfers | 100 / 100 | 100 / 100 | 100 / 100 |
| Blocked transfer | 100 / 100 | 100 / 100 | 100 / 100 |
| Incidents | 100 / 100 | 100 / 100 | 100 / 100 |
| Audit | 96 / 100 | 100 / 100 | 100 / 100 |
| Integrity | 99 / 100 | 100 / 100 | 100 / 100 |
| Policies | 100 / 100 | 100 / 100 | 100 / 100 |

The sign-in score of 96 came from the console error of finding 13. A mid-review build scored 88 on Integrity performance
because of a layout shift (finding 20); the final build scores 100.

### Coverage that stays below 85%

`private_files.py` 69%, `snapshots.py` 75%, `windows_acl.py` 76%, `incidents.py` 83%, `audit.py` 84%, `intake.py` 84%.
The first three are mostly platform branches: this Windows run cannot take their POSIX paths, which the Linux CI jobs exercise,
and Windows symlink creation needs a privilege the account lacks. The remaining gaps are defensive error branches.

## Scanners

| Tool | Version | Scope | Before | After |
|---|---|---|---|---|
| bandit | 1.9.4 | `backend/app`, `agent/rootsentinel_agent`, `scripts` | 2 MEDIUM, 73 LOW | 0 MEDIUM, 66 LOW (2 accepted with `nosec`) |
| semgrep | 1.184.0 | `p/python`, `p/typescript`, `p/react`, `p/secrets` | 1 ERROR | 0 (1 accepted with `nosemgrep`) |
| pip-audit | 2.10.1 | the three backend lock files | 0 | 0 (37 packages) |
| npm audit | npm 11.6.1 | `frontend/package-lock.json` | 0 | 0 |
| gitleaks | 8.21.2 | full Git history, all refs | 1 | 0 (1 reviewed false positive in `.gitleaksignore`) |
| trivy (image) | 0.58.1 | hosted image | 54 HIGH, 0 CRITICAL | 47 HIGH without a Debian fix, 0 fixable, 0 CRITICAL |
| trivy (filesystem) | 0.58.1 | repository, vulnerabilities, secrets, configuration | 1 CRITICAL, 1 HIGH, 1 LOW (Dockerfile) | 0 (3 reviewed in `.trivyignore`) |
| hadolint | 2.12.0 | `Dockerfile` | 0 | 0 |
| actionlint | 1.7.12 | `.github/workflows/ci.yml` | 0 | 0 |
| zizmor | 1.32.0 | `.github/workflows/ci.yml` | 18 high, 7 medium | 0 |

The 66 remaining bandit LOW results are `assert` in test and script code (36), `subprocess` with fixed argument lists and no
shell (11), `subprocess` imports (5), partial executable paths for `git` and `npm` in local scripts (5), `random` for retry
jitter and probe names (3), deliberate `try/except: pass` around best-effort cleanup that must not mask the fail-closed result
(3), two strings flagged as passwords (a private-key regex and the probe's deliberately wrong password) and one
`try/except: continue`. None is reachable from untrusted input in a way that changes a decision.

## Findings

Severity follows the scanner where one reported it; otherwise it is the reviewer's judgement of the impact.

| # | Severity | Location | Finding | Status |
|---|---|---|---|---|
| 1 | High | `.github/workflows/ci.yml` | 18 action references pinned only by tag (zizmor `unpinned-uses`) | Fixed: pinned to commit SHAs, tag kept as a comment |
| 2 | Medium | `.github/workflows/ci.yml` | 7 medium zizmor findings, including checkout credentials persisted in the workspace | Fixed: `persist-credentials: false` on every checkout |
| 3 | High | hosted image | pip's vendored urllib3 2.7.0, msgpack 1.1.2 and setuptools 70.3.0 with known CVEs | Fixed: pip uninstalled after installing the lock |
| 4 | High | hosted image | zlib1g without the Debian security update | Fixed: `apt-get upgrade` layer |
| 5 | High | hosted image | 47 base-OS CVEs (util-linux family, ncurses, libsqlite3, libsystemd, libacl, perl-base) | Accepted: no Debian fix released; the upgrade layer picks fixes up on the next build |
| 6 | Critical (scanner) | `Dockerfile` | trivy DS031 "secret in ENV" on `ROOTSENTINEL_AUDIT_KEY_FILE` | Accepted false positive: the value is a path; the key arrives as a platform secret file |
| 7 | High (scanner) | `Dockerfile` | trivy DS002, no `USER` instruction | Accepted by design: the entrypoint copies two secret files as root, then runs everything as uid 10001; CI asserts the uid |
| 8 | Low | `Dockerfile` | trivy DS026, no `HEALTHCHECK` | Accepted: the platform probes `/health`, and the Host allow-list would need the public origin |
| 9 | Low (scanner) | `docs/evidence/phase-01-final-checks.json` | gitleaks `generic-api-key` | Accepted false positive: a SHA-256 file digest under a key containing "tokens" |
| 10 | Medium (scanner) | `scripts/demo_agent.py` | bandit B310 `urlopen` (2) | Accepted: fixed `http://127.0.0.1:<port>` URL built by the script |
| 11 | Error (scanner) | `scripts/verify_phase05.py` | semgrep tainted environment in `subprocess` | Accepted: fixed argument lists without a shell, the developer's own environment |
| 12 | Medium | `frontend/src/App.tsx` | `/legacy` served the old workbench with its own sign-in form outside the route guards | Fixed: route and its four files removed |
| 13 | Low | `frontend/src/lib/session.tsx` | the session check answered 401 when signed out, logging a console error on every anonymous load | Fixed: `GET /api/v1/auth/session` answers 204; `/auth/me` keeps its 401 contract |
| 14 | Medium | `backend/app/api.py` | CSP report-only and hosted only; four inline style props needed `unsafe-inline` | Fixed: enforced everywhere; charts and bars are SVG attributes |
| 15 | Low | `backend/app/api.py` | health probes advanced the `unidentified` client counter and hid real requests without a client address | Fixed: counted separately |
| 16 | Low | interface | the hosted demo showed "LOCAL" and "local mode" | Fixed: badge from the server's `/health` `hosted` flag |
| 17 | Low | interface | upload limit hard-coded to 10 MiB while the hosted cap is 1 MiB | Fixed: cap read from `/health` |
| 18 | Serious (axe) | brand link | accessible name did not contain the visible text (34 pages) | Fixed |
| 19 | Moderate (axe) | integrity page, access refusal | duplicate landmark names; no level-one heading | Fixed |
| 20 | Low | integrity page | a layout shift introduced mid-review (CLS 0.23) | Fixed: trailing panel renders after the tree; content reserves the viewport |
| 21 | Serious (axe) | toasts | list items outside a list (role on the `ul`) | Fixed before merge |
| 22 | Low | `scripts/browser_phase04*.py` | running the browser suite overwrote recorded evidence in `docs/evidence` | Fixed: output goes to an external folder |
| 23 | Low | `scripts/browser_check.py`, `scripts/browser_phase03.py` | one script failed against the current interface, the other depended on `/legacy` | Removed |
| 24 | Low | documentation | stale or wrong claims in specs, deployment and testing docs (deployment status, caps, CSP, client identification, table counts, commands) | Fixed; see the document table |

No unresolved high or critical finding remains: each one is fixed or accepted above with its reason.

## Interface changes, measured against real data

All screens use the real API with synthetic data; nothing is mocked. The verdict panel explains a decision from the scan's own
fields (rule, matched asset, matched bytes and blocks, share of the file, policy version and threshold). Upload accepts drag
and drop with real progress; release needs a confirmation because it is single use; tables sort and filter the rows on the
current page; the Merkle explorer previews a proof path on hover or keyboard focus; a skippable tour can be replayed and is
remembered only for the browser session (the suite requires `localStorage` to stay empty). Screenshots are in
[docs/screenshots](../screenshots/).

Decisions taken during the review, with the safer option chosen:

* The tour is a non-blocking invitation, not a modal on first sign-in, so it never covers a task or the browser tests.
* Sorting and the audit filter apply to the loaded page and say so; the API returns no totals, so a global sort would mislead.
* `/health` publishes the upload cap and the commit id. Neither is secret, and the hosted flag is the server's own view.
* `img-src` no longer allows `data:`; nothing in the interface uses it.
* Coverage ran in a separate throwaway virtual environment with pytest-cov, so the project environment and the lock files did
  not change.

## New dependencies

None. Prettier, axe-core and Playwright were already project dependencies. pytest-cov and the scanners ran from separate
local environments, `npx` or pinned container images, and are not part of the repository.

## Documents

| File | Decision | Reason |
|---|---|---|
| `README.md` | Keep, rewritten | Entry point; product only |
| `SECURITY.md`, `CONTRIBUTING.md`, `.env.example` | Keep, corrected | Repository hygiene and configuration reference |
| A root-level local instructions file | Untracked | Local working notes, not for readers; kept on disk and excluded locally |
| `docs/master-plan.md` | Removed | Internal plan; priorities and deliverables moved to `requirements.md`, phase gates to the evidence index |
| `docs/architecture.md`, `threat-model.md`, `cryptographic-spec.md`, `detection-spec.md`, `policy-spec.md`, `transfer-spec.md`, `audit-spec.md`, `staging-spec.md`, `authentication.md`, `database.md`, `api.md`, `openapi.json` | Keep, corrected | Course-required specifications |
| `docs/deployment.md`, `developer-guide.md`, `frontend.md`, `testing.md` | Keep, corrected or reorganized | Operation, development, interface and test documentation |
| `docs/requirements.md` | Keep, statuses updated | Course traceability |
| `docs/research.md` | Keep, corrected | Research references |
| `docs/evidence/*` | Keep; punctuation fixes only | Course evidence is never removed or rewritten |
| `docs/screenshots/*` | Added | Current interface for the README |

## Removed references

Development tool names were removed from tracked files without changing the recorded facts: the internal plan's tool lines
(file removed), the requirements' time-budget sentence, two lines in the Phase 01 record (a local browser-automation folder and
a sandboxed command environment), the Phase 04 note on the commit-message correction (now "an automatically added
`Co-Authored-By` attribution trailer"), the Phase 06A source line ("read from the dashboard, read only"), the publication
audit's forbidden folder names (now a generic rule for hidden folders and unlisted root notes), and the ignore files' tool
folder entries (now generic rules). A word-bounded search of every tracked file finds none of the tool or assistant names;
`frontend/package-lock.json` has none either. One commit message body in the Git history names the local notes file and
cannot change without rewriting history, which was not done.
