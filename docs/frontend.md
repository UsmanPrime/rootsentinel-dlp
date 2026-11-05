# Frontend architecture and design system

Phase 04 retains React, TypeScript and Vite. React Router provides deep links and
route-level code splitting. Small Lucide SVG icons are tree-shaken. CSS tokens and
native HTML components avoid an unnecessary framework migration or charting runtime.

## Routes and roles

| Route | Purpose | Access |
|---|---|---|
| `/login` | Real server-managed session | Anonymous |
| `/` | Exact authorized SQL aggregates and recent activity | All roles; employee scope is own transfers |
| `/transfers`, `/transfers/:id` | Intake, evidence, single-use verified download | Authorized records; release remains owner-only |
| `/assets`, `/assets/:id` | Search, pagination, immutable versions, retirement | ADMIN/ANALYST read; ADMIN mutations |
| `/integrity?asset=…&version=…` | Server-projected tree, original/tampered proof verification | ADMIN/ANALYST |
| `/incidents`, `/incidents/:id` | Investigation, history, sanitized JSON export | ADMIN/ANALYST |
| `/audit` | Sequence-based events, verification, checkpoints | ADMIN/ANALYST; ADMIN checkpoint |
| `/policies` | Active policy and immutable history | All read active; ADMIN changes; history privileged |
| `/guide` | Explicit synthetic operations and educational links | Role-aware; full guided setup requires ADMIN |
| `/legacy` | Preserved Phase 01–03 workbench | Existing authenticated backend permissions |

Route protection improves navigation; the backend independently enforces every
permission. No release or policy rule is implemented in React. Public mode remains
closed until isolated synthetic demonstration provisioning is implemented later.

## Components and data

`App.tsx` owns the shell, login and route guards. Feature directories own workspace
views. Shared `components/ui.tsx` supplies panels, statuses, dialogs, hashes,
pagination and structured states. `Evidence.tsx` renders actual matching evidence.
The existing `api.ts` is shared with the legacy client. Safe errors expose approved
messages, never raw backend text. `lib/contracts.ts` is generated from checked-in
OpenAPI by `python -B scripts/frontend_contracts.py`; CI checks drift. Existing
untyped audit/incident list fields have explicit frontend views matching their
server serializer. Request schemas and persistence models remain separate.

Sessions use HttpOnly server-managed cookies. CSRF tokens remain only in memory.
401 responses clear the current session; logout unmounts private workspaces. No
credential or cached response is placed in localStorage. GET requests abort on
route/account changes and results are keyed by path/account/revision to avoid
showing a prior record while the next one loads. Mutations use an immediate ref
guard in addition to disabled buttons. Transfer retries preserve the idempotency
key until input changes. Other failed mutations require operator review before retry.

Data refresh is explicit. Only an observed SCANNING transfer polls at three-second
intervals, stopping once it leaves that state. This is not streaming telemetry.
The dashboard counts persisted decisions separately from release eligibility.
The seven-day chart uses UTC calendar days including today; other totals cover all
retained authorized records. No incident counts or outcomes are fabricated.

Two read-only presentation endpoints were necessary: exact role-scoped SQL
aggregates and bounded server-generated Merkle projections. The existing singleton
transaction lock makes aggregate queries one coherent observation. This serializes
briefly with mutations and is suitable for the bounded local demonstration, not a
claim of large-scale analytics throughput. The tree endpoint calls the unchanged
cryptographic core. Trees with at most 16 leaves render fully; larger trees show
the selected path and collapsed sibling subtrees, with at most 31 nodes and paged
chunk descriptors. React lays out supplied nodes but never recomputes a Merkle hash.

The browser independently SHA-256 hashes the actual allowed response and checks its
length before creating a Blob download. A mismatch saves no file. The backend's
pre-release checks remain the security boundary; browser checks are supplementary.
Server send completion does not prove recipient storage. Download retries require
a new transfer after a consumed release attempt.

## Design tokens and interaction

`workspace.css` contains the current design tokens and responsive components;
`styles.css`/`tokens.css` retain legacy workbench compatibility.

| Token | Value / purpose |
|---|---|
| Background / surface | `#0c1118` / `#131c27` |
| Text / secondary text | `#e9f2fa` / `#a5b4c6` |
| Accent / focus | `#63dfc9` / `#91ecde` |
| Danger / caution | `#ffaaaa` / `#f0cb88` |
| Border / radius | `#2b3a4c` / 10 px panels, 6 px controls |
| Spacing | 8 px base, 14–36 px responsive content padding |
| Motion | 140 ms feedback; reduced-motion override |
| Layers | Header 20, skip link 100; native modal top layer |
| Breakpoints | 600, 900, 1200, 1700 px |

System fonts avoid external font requests. Status always includes readable text and
an icon, never color alone. Charts have numeric labels and tables. Hashes wrap and
have explicitly labeled copy controls. Tables and tree canvases may scroll inside
their labeled regions without expanding the page. Native modal dialogs include
explicit Tab wrapping, Escape dismissal and trigger focus restoration. Focus is
moved to main content on route changes. Loading reflects pending requests; empty,
offline, error and unauthorized states remain distinct. No fake progress percentage.

WCAG 2.2 AA is a quality target. Automated axe checks and keyboard exercises cover
the documented routes; they are not a certification of complete conformance.
Design references inspected during this phase: [WAI dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/),
[React Router routing](https://reactrouter.com/start/declarative/routing),
[Vitest guide](https://vitest.dev/guide/), [axe documentation](https://www.deque.com/axe/core-documentation/).

## Guided demonstration

Provision local accounts as described in the developer guide. Start at `/guide`.
Explicitly register its synthetic sample, inspect its commitment, verify the real
proof, then verify a modified copy. Submit a renamed protected copy and open the
resulting incident. Submit a benign sample, open its transfer in another tab and
use verified download. Finish by verifying audit integrity. The guide uses actual
operations and adds labeled evidence; restarting resets only UI progress and never
deletes records. Progress is kept in memory, so reloading starts a new walkthrough.
Separate browser tabs keep the guide open while exploring a record.

Register the three-chunk fixture from Assets to demonstrate the recursive uneven
tree. The empty-input action performs a real scan; empty files cannot become
protected assets. Fixed-size shifts, encodings and compressed data remain documented
blind spots, not errors disguised as successful detections.

Incident listing additionally accepts bounded HIGH/MEDIUM severity and newest/oldest
ordering. These filters apply server-side before pagination; no policy or incident
mutation semantics changed.
