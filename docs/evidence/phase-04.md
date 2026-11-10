# Phase 04 verification record

Status: **Local gates PASS. Hosted CI and publication are recorded separately after the checkpoint push (see final section).**

Baseline inspected: `46bbe4f143f05d8c066039c1212a7f4a1ceffc13`, branch `main`, existing
origin `https://github.com/UsmanPrime/rootsentinel-dlp.git`. The starting tree was clean
and synchronized. Phase 01–03 source, contracts, evidence and specifications were
inspected before implementation. No cryptographic, authentication, detection,
policy, release or audit algorithm was replaced.

Initial frontend: a functional single-page workbench, no route-based SOC shell and
no frontend unit suite. The previous workbench remains reachable at `/legacy`.

Implemented workspaces: overview, transfer gateway/detail, asset registry/detail,
interactive integrity explorer, incident queue/detail, audit operations, policy
administration, guided demonstration and real session login/logout. Shared native
dialogs, status displays, error/loading/empty states, safe hash copying, keyboard
navigation, mobile navigation and responsive tables are implemented.

Minimal backend additions: role-scoped overview aggregates and a bounded tree
projection computed using the unchanged cryptographic core. No schema migration
or release behavior change. Generated TypeScript contracts derive from OpenAPI.

## Recorded checks so far

- `python -B -m pytest -q -p no:cacheprovider --basetemp <fresh-external-test-directory>`:
  **172 passed, 606 subtests passed**, 210.55 s (final re-run), Python 3.13.4 / SQLite / Windows.
  One existing Starlette/httpx deprecation warning. The default shared pytest temp
  directory was inaccessible; a new application-owned external directory resolved
  the setup failure without altering host permissions.
- `python -B scripts/fixtures.py`: **11 manifests verified**.
- `python -B scripts/frontend_contracts.py --check`: **39 contracts verified**.
- `npm test`: **19 tests passed** (4 files) (HTTP safety/CSRF, session event handling, mutation
  duplication guard, Merkle projection/tamper-copy behavior, independent downloaded-byte hashing).
- `npm run typecheck`: passed after adding pinned Node type definitions for unit tests.
- `npm run build`: passed; harmless dependency `use client` directives are ignored by Vite.

## Browser findings corrected during development

- Native modal focus could move outside on Tab in the tested browser. Added explicit
  first/last focus wrapping. Corrected closed-dialog effect cleanup so Escape restores
  the initiating button instead of prior page focus.
- Corrected incident explanation to recognize `EXACT_PROTECTED_FILE`.
- Removed a visible zero-height chart border and used a nonduplicated integer chart scale.
- Matched analyst-note client limit to the server's 1,000-character maximum.
- GET results are keyed by account, request path and refresh generation to prevent
  a prior record flashing during a route change.

Actual browser results, axe findings, responsive checks and screenshots are recorded
in `phase-04-browser.json` and `phase-04/`. A failed intermediate run is not a passing
gate; the final report must identify the final result explicitly.

## Limits and phase boundary

No public deployment or local staging agent was implemented. Public mode remains
fail-closed. Use synthetic data. HMAC verification is not tamper-proof or independent
forensic certification. Gateway enforcement does not cover other applications.
Automated accessibility scans do not establish complete WCAG conformance.
PostgreSQL is validated in hosted CI, not inferred from SQLite. Publication and
final CI remain pending until all gates pass.

## Final verification run (independent re-run before checkpoint)

All gates below were re-executed against the working tree, not copied from earlier runs.

- Real Chrome 156 journeys, `browser_phase04.py`: **30 checks PASS**, 0 page errors, 0 failed asset
  requests, 0 axe violations across 17 scanned pages/states (axe "incomplete" items are
  contrast-needs-review notices, not failures; they are not claimed as passes).
- `browser_phase04_negative.py` on a fresh disposable backend: **PASS** (expired release denied,
  CSRF rejected, offline recovery, duplicate-submission guard, session expiry, tampered audit chain
  surfaced, mandatory audit failure blocks release).
- 48 route/viewport checks at 320, 375, 768, 1024, 1440 and 1920 px: no page-level horizontal overflow.
  Screenshots are stored at 375 and 1440 px plus desktop state captures.
- Publication audit: 167 candidate files, 0 findings (pattern scan; manual diff review also performed;
  a pattern scan cannot prove absence of every secret). Built bundle contains no browser-storage
  use, no `innerHTML`/`dangerouslySetInnerHTML` in source and no secret values.
- Observed timings (local loopback, SQLite, one run, not a benchmark): renamed-file submit to visible
  verdict ~0.49 s; partial-match ~0.24 s; benign ~0.27 s; release plus independent in-browser hash ~0.84 s.
  Downloaded bytes were independently SHA-256 hashed in the browser and equalled the scanned bytes.

### Defect found and fixed during final visual review

At 375 px the transfer history table clipped the `STREAM FINISHED` badge at the scroll edge.
Cell horizontal padding is now reduced at max-width 480 px. The browser suite and screenshots were
regenerated afterwards; the badge is fully visible and a partially visible further column signals that
the table scrolls horizontally inside its own container. `integrity-desktop.png` shows a displaced
sidebar and visible skip link because it is a full-page capture taken after scroll and keyboard
focus; the deterministic `integrity-1440.png` of the same route is correct.

### Bundle (production build, byte counts; gzip -9 measured separately)

Initial JS `index` 290,982 B (93,538 B gzip); CSS 30,401 B (7,473 B gzip). Routes are lazy chunks:
Gateway 13.5 kB, Legacy 18.2 kB, Integrity 10.5 kB, Guide 8.9 kB, Assets 8.5 kB, Overview 8.3 kB,
Incidents 7.5 kB, Audit 6.3 kB, Policies 5.0 kB. No chart or animation library was added; charts are
accessible SVG/DOM with table alternatives.

### Not done / known limitations

- No Playwright pixel-diff snapshot suite; reproducibility is verified by a same-state screenshot hash
  comparison only. Screenshots are not captured at 320, 768, 1024 or 1920 px (overflow is checked at those widths).
- Contrast and screen-reader behavior were checked with axe and keyboard tests only; no manual
  assistive-technology testing was done and WCAG conformance is not claimed.
- Overview metrics are role-scoped aggregates computed on demand (no streaming or live monitoring).
- Local-mode only; no public deployment. PostgreSQL results come from hosted CI only.

## Publication and hosted CI

> Pointer: the short SHAs, run ids and the "no force push or history rewrite" statement in this
> section are the original, pre-rewrite record. The commit messages were later corrected once;
> see [History correction, 2026-11-06](#history-correction-2026-11-06) for the new SHAs and CI.

Checkpoint `440455f` was first pushed to a candidate branch. Hosted run `42061316687` completed
**success** on all five jobs: backend (3.12), backend (3.13), real-browser acceptance, frontend
(typecheck, unit tests, build) and PostgreSQL. The same commit was then published to `main` as a
normal fast-forward (`46bbe4f..440455f`); no force push or history rewrite. The first candidate push
was rejected once by GitHub with a transient server-side error and succeeded unchanged on retry.
This documentation-only follow-up commit records that result.

## History correction, 2026-11-06

At the repository owner's explicit one-time request, the commit messages of the two Phase 04
commits were rewritten to remove an automatically added `Co-Authored-By` attribution trailer.
Only the messages changed. File contents are identical: each rewritten commit has the same tree
hash as the original, `git diff` between each old and new commit is empty, author and committer
names, emails and dates are unchanged, and no code, test or document content changed. The
evidence text above is left as originally written; the short SHAs it cites are the pre-rewrite
values.

| Item | Before | After |
|---|---|---|
| Phase 04 feature commit | `440455f18bb58b49617149746a6833307366149b` | `157d8be40de2829d65eb44209e681728bdb457e9` |
| Phase 04 evidence commit (`main` tip) | `d24417a394337a6446c4b68b6cecd5805a3d5177` | `2991731ca7933e3964633d81557e8829f8236ecb` |
| `phase-04` annotated tag object | `6fcd878eca313b032abc7ac8c2fc0ca4b8c072f9` | `dc783a16c89acdc199c6a5d6280e1026e609412f` (peels to `2991731`) |

Tree hashes, identical before and after: feature commit `a3870c47597632b0f067c8a3e64e038e93959edf`;
evidence commit `2e4d521cdb3f96158ee68c39aceee7afc0e82680`.

Procedure: `main` was force pushed once, with an exact lease on the old tip
(`--force-with-lease=main:d24417a394337a6446c4b68b6cecd5805a3d5177`), and the `phase-04` tag was
moved once with an exact lease on the old tag object. The Phase 01–03 commits, the `phase-01`,
`phase-02` and `phase-03` tags and the `phase03-gateway-verification` branch were not touched.
A bundle of all refs was taken locally before the rewrite and is not published. A fresh clone of
the remote showed eight linear commits and no merge commits.

CI evidence:

- Hosted runs `42061316687` (candidate branch), `42062807008` and `42062833439` (`main`) ran on
  the pre-rewrite SHAs. They are retained as evidence for identical content (same trees), not as
  CI results for the new SHAs. Their pages still display the old SHAs.
- Run `42244427246` (push to `main`, head `2991731ca7933e3964633d81557e8829f8236ecb`) completed
  **success** on all five jobs: backend (3.12), backend (3.13), browser, frontend and PostgreSQL.
- Run `42244473854` (push of the moved `phase-04` tag, same head SHA) also completed **success**
  on all five jobs.

Limits: clones made before the rewrite hold the old SHAs, GitHub may keep resolving the old
SHAs for a time, and its contributors list may take hours to refresh.
