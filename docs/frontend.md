# Frontend architecture and design system

The interface uses React, TypeScript and Vite. React Router provides deep links and
route-level code splitting. Small Lucide SVG icons are tree-shaken. Plain CSS files
and native HTML components avoid a framework migration or a charting runtime.

## Routes and roles

| Route | Purpose | Access |
|---|---|---|
| `/login` | Real server-managed session | Anonymous |
| `/` | Exact authorized SQL aggregates and recent activity | All roles; employee scope is own transfers |
| `/transfers`, `/transfers/:id` | Intake, evidence, single-use verified download | Authorized records; release remains owner-only |
| `/assets`, `/assets/:id` | Search, pagination, immutable versions, retirement | ADMIN/ANALYST read; ADMIN mutations |
| `/integrity?asset=…&version=…` | Server-projected tree, original/tampered proof verification | ADMIN/ANALYST |
| `/integrity?tab=audit` | Audit log tab: latest signed tree head with its Ed25519 signature verified in the browser (WebCrypto), inclusion proof for a chosen event, consistency with the last head this browser saw (kept in `localStorage`, guarded). Says plainly when the browser has no WebCrypto Ed25519 | ADMIN/ANALYST |
| `/incidents`, `/incidents/:id` | Investigation, history, sanitized JSON export | ADMIN/ANALYST |
| `/audit` | Sequence-based events, verification, checkpoints | ADMIN/ANALYST; ADMIN checkpoint |
| `/policies` | Active policy and immutable history | All read active; ADMIN changes; history privileged |
| `/guide` | Explicit synthetic operations and educational links | Role-aware; full guided setup requires ADMIN |

Any other path inside the workspace shows a "Page not found" state with a link to the
overview. Route protection improves navigation; the backend independently enforces
every permission. No release or policy rule is implemented in React. The hosted demo
runs the same interface with operator-provisioned accounts only; `public_demo` mode
stays closed, and an anonymous visitor mode is an open decision.

## Components and data

`App.tsx` owns the shell, login and route guards. Feature directories own workspace
views. Shared `components/ui.tsx` supplies panels, statuses, dialogs, hashes,
pagination and structured states. `Evidence.tsx` renders actual matching evidence and
`Verdict.tsx` explains each decision. `api.ts` is the HTTP boundary. Safe errors
expose approved messages, never raw backend text. `lib/contracts.ts` is generated
from checked-in OpenAPI by `python -B scripts/frontend_contracts.py`; CI checks drift
with `--check`. Existing untyped audit/incident list fields have explicit frontend
views matching their server serializer. Request schemas and persistence models
remain separate.

Sessions use HttpOnly server-managed cookies. On load the interface calls
`GET /api/v1/auth/session`, which answers 200 with the session or 204 without one
and never 401, so a signed-out page load logs no failed request. CSRF tokens remain
only in memory. 401 responses on other calls clear the current session; logout
unmounts private workspaces. No credential or cached response is placed in
localStorage. GET requests abort on route/account changes and results are keyed by
path/account/revision to avoid showing a prior record while the next one loads.
Mutations use an immediate ref guard in addition to disabled buttons. Transfer
retries preserve the idempotency key until input changes. Other failed mutations
require operator review before retry.

`lib/environment.tsx` reads `GET /health` once. The environment badge shows
"Hosted demo" or "Local" from its `hosted` field, never from the hostname; the
upload cap comes from `max_upload_bytes`, and the footer shows the build commit when
`commit` is known.

Data refresh is explicit. Only an observed SCANNING transfer polls at three-second
intervals, stopping once it leaves that state. This is not streaming telemetry.
The dashboard counts persisted decisions separately from release eligibility.
The seven-day chart uses UTC calendar days including today; other totals cover all
retained authorized records. No incident counts or outcomes are fabricated.

Two read-only presentation endpoints were necessary: exact role-scoped SQL
aggregates and bounded server-generated Merkle projections. The existing singleton
transaction lock makes aggregate queries one coherent observation. This serializes
briefly with mutations and is suitable for the bounded demonstration, not a claim of
large-scale analytics throughput. The tree endpoint calls the unchanged
cryptographic core. Trees with at most 16 leaves render fully; larger trees show
the selected path and collapsed sibling subtrees, with at most 31 nodes and paged
chunk descriptors. React lays out supplied nodes but never recomputes a Merkle hash.

The browser independently SHA-256 hashes the actual allowed response and checks its
length before creating a Blob download. A mismatch saves no file. The backend's
pre-release checks remain the security boundary; browser checks are supplementary.
Server send completion does not prove recipient storage. Download retries require
a new transfer after a consumed release attempt.

## Interaction

* **Upload.** Drag and drop or choose a file. The panel shows the file's name, size
  and type before sending, and real upload progress from `XMLHttpRequest` upload
  events (`lib/files.ts`). The file name is sent as a sanitized display label that
  follows the server's label rule; an unusable name falls back to `candidate.bin`.
  Files above the cap from `/health` are refused before sending.
* **Why this decision.** Each transfer explains its verdict: the rule taken from the
  decision reason, the matched asset label (ANALYST and ADMIN only), matched bytes,
  matched block count, share of the submitted file, the policy version, threshold and
  block-matching flag, and how the largest match compares with the threshold.
* **Single-use release.** "Verified download" opens a confirmation dialog because a
  release can be used once; "Download once" performs it.
* **Feedback.** Completed actions show a toast. Forms validate inline: the asset label
  pattern, a policy threshold from 1 to 10,485,760 bytes, and a required resolution
  reason when an incident is resolved. Loading shows skeleton rows; empty states name
  the next step.
* **Tables.** The incident table sorts by severity, status and observed time; the
  audit table sorts by sequence and time and filters by event type. Sorting and the
  event-type filter apply to the rows on the current page.
* **Merkle explorer.** Hovering over or focusing a chunk button previews that leaf's
  proof path.
* **Charts.** Overview charts are SVG; tooltips show the date and exact count, and a
  table carries the same numbers.
* **Tour.** A skippable first-run tour invitation appears on the overview. The help
  button in the top bar replays it. Only "tour seen" is remembered, in sessionStorage,
  so nothing persists beyond the browser session.

## Design tokens

Styles live in `frontend/src/base.css`, `workspace.css` (design tokens in `:root` and
responsive layout) and `components.css`.

| Token | Value / purpose |
|---|---|
| Surfaces | `--background` `#0c1118`, `--surface-sunken` `#0f1721`, `--surface` `#131c27`, `--surface-raised` `#1d2a39` |
| Text | `--text` `#e9f2fa`, `--text-soft` `#c9d7e5`, `--muted` `#a5b4c6` |
| Borders | `--border` `#2b3a4c`, `--border-strong` `#42556b` |
| Accent / focus | `--accent` `#63dfc9` / `--focus` `#91ecde` |
| Status | `--allow` `#63cbb9`, `--block` `#ffaaaa`, `--warning` `#f0cb88`, `--info` `#9cc5ff` |
| Type scale | 11, 12, 14, 16 and 20 px (`--text-xs` to `--text-xl`) |
| Radius | 6 px controls, 10 px panels |
| Elevation | Two levels (`--elevation-1`, `--elevation-2`) |
| Spacing | 8 px base (`--space`) |
| Motion | 140 ms feedback; `prefers-reduced-motion` honored |
| Layers | Header 20, toast 90, skip link 100; native modal top layer |
| Breakpoints | 480, 600, 900, 1200, 1700 px |

The font stack names locally installed fonts only, so the page makes no external font
request. Status always includes readable text and an icon, never color alone. Charts
have numeric labels and tables. Hashes wrap and have explicitly labeled copy controls.
Tables and tree canvases may scroll inside their labeled regions without expanding the
page. Native modal dialogs include explicit Tab wrapping, Escape dismissal and trigger
focus restoration. Focus is moved to main content on route changes. Loading reflects
pending requests; empty, offline, error and unauthorized states remain distinct.
Upload progress reports real transferred bytes, never an invented percentage.

## Content security policy

The API sends an enforced `Content-Security-Policy` on every response, locally and
hosted (`backend/app/api.py`):

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';
connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self';
frame-ancestors 'none'; object-src 'none'
```

There is no `'unsafe-inline'`. The interface has no inline scripts and no inline style
attributes: chart bars and coverage bars are SVG attributes, and Vite's build adds no
inline script. HSTS is added only when the origin is https.

## Tests

`npm test` runs Vitest:

| File | Covers |
|---|---|
| `src/api.test.ts` | Same-origin cookies, CSRF only in the header, 401 handling, empty logout responses, fixture byte identity |
| `src/lib/hooks.test.tsx` | Same-tick double-submission guard, safe error state and intentional retry |
| `src/lib/quality.test.tsx` | Hosted badge from `/health` (not the hostname), label sanitizer, verdict numbers, incident sorting |
| `src/lib/transparency.test.ts` | Published tree vectors for inclusion and consistency, rejected changes, canonical encoding, signed-bytes encoding, valid and altered heads, the no-Ed25519 answer, guarded storage |
| `src/features/integrity/Integrity.test.tsx` | Tampered copies leave the stored proof unchanged, uneven topology, keyboard leaf selection, empty tree |
| `src/features/transfers/Gateway.test.ts` | Independent hashing of downloaded bytes before saving |

`npm run typecheck`, `npm run format:check` (Prettier) and `npm run build` also run in
CI. Browser acceptance (`scripts/browser_phase04.py` and
`scripts/browser_phase04_negative.py`) runs in CI against the built interface served by
the API under the enforced CSP; see [testing](testing.md).

WCAG 2.2 AA is a quality target. Automated axe checks and keyboard exercises cover
the documented routes; they are not a full accessibility audit or a certification of
conformance. Design references: [WAI dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/),
[React Router routing](https://reactrouter.com/start/declarative/routing),
[Vitest guide](https://vitest.dev/guide/), [axe documentation](https://www.deque.com/axe/core-documentation/).

## Guided demonstration

Provision accounts as described in the [developer guide](developer-guide.md) (local)
or [deployment](deployment.md) (hosted). Start at `/guide`. Explicitly register its
synthetic sample, inspect its commitment, verify the real proof, then verify a
modified copy. Submit a renamed protected copy and open the resulting incident.
Submit a benign sample, open its transfer in another tab and use verified download.
Finish by verifying audit integrity. The guide uses actual operations and adds
labeled evidence; restarting resets only UI progress and never deletes records.
Progress is kept in memory, so reloading starts a new walkthrough. Separate browser
tabs keep the guide open while exploring a record.

Register the three-chunk fixture from Assets to demonstrate the recursive uneven
tree. The empty-input action performs a real scan; empty files cannot become
protected assets. Encodings and compressed data remain documented blind spots, and so do
shifts under policy rule set `rs-policy-v1`; they are not errors disguised as successful detections.

The "Why this decision" panel (`components/Verdict.tsx`) lists the detection profiles the policy evaluated and, for each
matching asset, one row per profile with matched bytes, matched chunks out of the file's chunks and the share of the file.
A profile the policy did not evaluate is named as not evaluated, never shown as zero. Every number is a field of the scan
record (`detection.profiles`). Asset details list per version which profiles it carries, and the Policies page shows and
sets the rule set and the content-defined threshold. The Transfers and Assets pages offer the synthetic source sample and
its shifted and inserted copies as inputs.

Incident listing additionally accepts bounded HIGH/MEDIUM severity and newest/oldest
ordering. These filters apply server-side before pagination; no policy or incident
mutation semantics changed.
