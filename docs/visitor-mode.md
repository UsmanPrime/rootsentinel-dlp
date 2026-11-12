# Visitor mode

Visitor mode lets someone without an account open the hosted demo and run the real flow in a short, sandboxed
session: scan synthetic files, read the decision and its evidence, request one single-use release, and read the
audit events and signed tree head their own session produced. It is off unless `ROOTSENTINEL_VISITOR_MODE_ENABLED`
is `true`. When it is off, the entry route answers 404 and the sign-in page does not show the button.

Every rule below is enforced on the server. The interface only hides what a visitor may not use.

## What a visitor is

Entry is `POST /api/v1/auth/visitor`. It needs no password and does no Argon2 work. It checks the same `Origin`
header as sign-in, and a `Sec-Fetch-Site` header, when the browser sends one, must say `same-origin` (or `none`);
`same-site` and `cross-site` are refused. A missing header is accepted when `Origin` passes.

Entry creates, in one transaction, a `users` row with the role `VISITOR` (a placeholder hash that no password can
match), a session, a `visitor_sessions` counter row, and the audit event `VISITOR_ENTERED`. The sandbox id is the
visitor's user id, so the scoping that already keeps an employee to their own scans and transfers keeps a visitor
to theirs.

| Property | Value |
|---|---|
| Cookie | `rs_session`, `HttpOnly`, `Secure` (hosted), `SameSite=Strict`, path `/api/v1`, `Max-Age` 1800 |
| Absolute lifetime | 1800 s from entry. Never extended by activity |
| Idle lifetime | 600 s without a request |
| Idle tolerance | `last_seen_at` is written at most once per 60 s, so the stored time lags the true last request by less than 60 s. A visitor is ended after between 540 and 600 s without a request |
| Role | Fixed. No route changes a role, and a visitor account refuses every password |
| Kill switch | Turning the mode off also ends live visitor sessions: their next request is a 401 |

The constants live in `backend/app/config.py`.

## Routes a visitor may call

Authorization is a default deny in the shared `principal` dependency: a visitor reaches only the routes in
`VISITOR_ROUTES` (`backend/app/visitors.py`), and every other route answers 403 `FORBIDDEN`. A route added later is
denied until it is added to that list on purpose. A test enumerates the registered routes and fails when one is not
classified.

| Method and path | Scope |
|---|---|
| `GET /auth/session`, `GET /auth/me`, `POST /auth/logout` | own session |
| `GET /detection/profiles`, `GET /policies/active` | read only |
| `GET /overview` | own transfers only |
| `POST /scans`, `GET /scans`, `GET /scans/{id}` | own scans only |
| `POST /transfers`, `POST /transfers/fixtures`, `GET /transfers`, `GET /transfers/{id}`, `POST /transfers/{id}/release` | own transfers only |
| `GET /visitor/audit/events` | own audit events only |
| `GET /visitor/transparency/key`, `GET /visitor/transparency/sth`, `GET /visitor/transparency/proof/inclusion` | the public key, the latest signed head, and inclusion proofs for the visitor's own events (any other index answers 404) |

Everything else is denied: assets and their registration, policy history and changes, incidents, exports, the audit
and transparency routes of the privileged roles, checkpoints, maintenance and signing.

A visitor's scan is matched against the synthetic seed assets only (`assets.synthetic`). A real protected asset
that an administrator registers is never consulted for a visitor, so a visitor cannot probe it.

## Isolation and what real users see

* A visitor sees only their own scans, transfers, releases and audit events. Another visitor's identifier answers
  404, exactly as a missing record does.
* Administrators and analysts do not see visitor activity in their default views: the scan list, the transfer list,
  the incident list and the overview counts exclude visitors. An administrator can add `include_visitors=true` to
  those routes; an analyst who does gets 403. Reason: a BLOCK by a visitor creates an incident like any other, and
  the real queue must not fill with demonstration traffic.
* The audit event list is the exception. It shows the whole chain, with each event labelled `VISITOR`, `ACCOUNT` or
  `SYSTEM`. Reason: the chain is the integrity record, and a view with holes in it would look like tampering.

## Caps

Rejected visitor requests (403 denials, 429 cap hits, the 404 of a disabled mode) are written to the application log
with the resolved client address and never to the audit chain. Password accounts are not affected by any cap.

| Cap | Default | Hard bound | Environment variable (`ROOTSENTINEL_` prefix) |
|---|---|---|---|
| Entries per client address per hour | 6 | 1 to 60 | `VISITOR_ENTRIES_PER_IP_HOUR` |
| Concurrent visitor sessions | 10 | 1 to 50 | `VISITOR_MAX_CONCURRENT` |
| New visitor sessions per UTC day | 30 | 1 to 200 | `VISITOR_SESSIONS_PER_DAY` |
| Scans or transfers per session | 3 | 1 to 10 | `VISITOR_SCANS_PER_SESSION` |
| Release attempts per session | the scan cap | follows the scan cap | |
| Upload per request | 65536 bytes | 1024 to 262144 (never above the general cap) | `VISITOR_UPLOAD_BYTES` |
| Audit ceiling | 14000 events | 1000 to 18000 | `VISITOR_AUDIT_CEILING` |

The per address limit is in memory (one worker; a restart resets it). The other caps are counted in the database.
Release attempts are capped because a denied attempt also writes audit events.

### Why 20,000, and what 14,000 does

The audit chain holds at most 20,000 events (`MAX_EVENTS` in `backend/app/audit.py`). It is a bound on the work
the chain needs: verification re-reads every event, and the Merkle tree is held in memory
(see the [audit protocol](audit-spec.md)). At 20,000 every audited action, for every user, fails closed and only a
new database recovers it. The cap is not changed by visitor mode.

Visitors share that chain, so the ceiling keeps them from using it up:

| Chain position | Visitors | Real users |
|---|---|---|
| Below 14,000 | normal | normal |
| 14,000 or more | entry, submissions and release attempts are refused with 429 `VISITOR_AUDIT_BUDGET`; sessions already open can still read and end | unaffected, at least 6,000 events remain |
| 20,000 | none | every audited action fails closed (existing behaviour) |

### Audit events per session

Every audited visitor event counts: entry 1, each submission 3 (`TRANSFER_SUBMITTED`, `SCAN_COMPLETED`, the decision;
a BLOCK adds `INCIDENT_CREATED`), each release attempt up to 3 (`RELEASE_ATTEMPT`, `RELEASE_STARTED`,
`STREAM_FINISHED`; a denied attempt is 2), and the end of the session 1 (`VISITOR_ENDED` or `VISITOR_EXPIRED`).

| Quantity | Arithmetic | Result |
|---|---|---|
| Worst case per session | 1 + 3 x 3 + 3 x 3 + 1 | 20 (measured: 20 for three allowed and released transfers) |
| Worst case per day | 30 sessions x 20 | 600 |
| Worst case 29 November to 20 December (22 days) | 600 x 22 | 13,200 |
| Against the ceiling | 14,000 - 13,200 | 800 events of room for what the chain already holds |

The 13,200 figure is the product of the caps, not an expectation: it needs 30 sessions every day, each using every
submission and release. Events from real users and from the starting position of the live chain add to it. If the
sum reaches the ceiling, the ceiling stops visitors; it does not stop real users.

### Storage per session

Measured on SQLite with three 64 KiB submissions per session (row bytes plus indexed key bytes, plus an assumed 40
bytes of per row overhead for PostgreSQL):

| Case | Rows | Audit events | About |
|---|---|---|---|
| Three allowed and released | 38 | 20 | 24 KB |
| Three blocked, content-defined heavy | 32 | 14 | 21 KB |
| Three blocked, fixed profile heavy | 35 | 14 | 23 KB |

Worst case 24.5 KB per session. 30 sessions x 22 days x 24.5 KB is about 16 MB, and about 24 MB with a 1.5 factor
for page fill and bloat, against the 512 MB of the free Neon tier. Visitor accounts and every append-only row stay
after a session ends; only the expired session rows (token digests) are deleted.

## Lazy cleanup

Nothing runs on a timer. On visitor entry and after each successful password sign-in, up to 50 finished visitor
sessions are closed: `VISITOR_EXPIRED` is audited and the session row is deleted, in one transaction. A failure is
logged and never blocks the entry or the sign-in. An idle process makes no database call; a test pins this.

## Limits

* The per address limit resets on restart.
* `audit_events.actor_id` is a filtering copy of the actor inside the HMAC'd payload. Verification checks that a
  non-null column agrees with the payload; a null column (every event before migration 0006) is accepted, so a
  post-migration event whose column was cleared would not be flagged, and would simply not appear in a visitor's view.
* A visitor's inclusion proof needs a signed head that covers the event. A head is signed at every release, at every
  64th event and on an administrator's request, so a visitor who has not released anything may see "not covered yet".
* Visitor mode does not claim OS-wide, USB, email or clipboard protection, as nothing else in the product does.
