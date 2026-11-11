# REST API

Version prefix `/api/v1`; same-origin cookie authentication. In local mode over plain
http the application also serves OpenAPI at `/openapi.json` and interactive documentation
at `/docs`; a hosted (https origin) or `public_demo` deployment serves neither. The
checked-in [OpenAPI snapshot](openapi.json) is generated from the application.

All protected endpoints require `rs_session`. Mutations require an exact configured
`Origin`; cookie-authenticated mutations additionally require `X-CSRF-Token`. Login
returns user metadata and CSRF, with the opaque session in an HttpOnly cookie.
`/auth/session` and `/auth/me` support reload without storing tokens in localStorage.

| Method / route | Role / behavior |
|---|---|
| POST `/auth/login` | JSON username/password; generic failures and throttling |
| POST `/auth/logout` | Authenticated; revoke current session; 204 |
| GET `/auth/session` | Public session check: 200 with user and current CSRF value, or 204 when there is no valid session; never 401 |
| GET `/auth/me` | User ID/username/role and current CSRF value; 401 when signed out |
| GET `/assets` | ADMIN/ANALYST; `q`, `retired`, `offset`, `limit` filters |
| POST `/assets?label=...` | ADMIN; raw bytes; new asset/version; 201 |
| GET `/assets/{asset_id}` | ADMIN/ANALYST; display metadata and state |
| POST `/assets/{asset_id}/versions?expected_version=N` | ADMIN; raw bytes, optimistic precondition; 201 |
| GET `/assets/{asset_id}/versions` | ADMIN/ANALYST; paginated manifest summaries; `profiles` states per detection profile whether the version carries its fingerprints and how many chunks |
| GET `/assets/{asset_id}/versions/{version_id}` | ADMIN/ANALYST; manifest and ordered chunks |
| POST `/assets/{asset_id}/retire` | ADMIN; idempotent retirement |
| GET `/assets/{asset_id}/versions/{version_id}/proofs/{index}` | ADMIN/ANALYST; real Phase 01 proof |
| POST `/integrity/verify` | ADMIN/ANALYST; proof, asset_id, version_id; trusted root from registry |
| GET `/detection/profiles` | All authenticated roles; the registered detection profiles with id, version and published parameters; reads no table |
| GET `/policies/active` | All authenticated roles; includes `rule_set` and `cdc_threshold` |
| GET `/policies/history` | ADMIN/ANALYST; paginated immutable versions |
| POST `/policies` | ADMIN; threshold, block_enabled, expected_version UUID, optional `rule_set` (`rs-policy-v1` or `rs-policy-v2`; omitted keeps the current one) and `cdc_threshold` (only with `rs-policy-v2`); 201 |
| POST `/scans?filename=...` | Authenticated; raw bytes; persistent evidence/decision; 201 |
| GET `/scans` | ADMIN/ANALYST all; EMPLOYEE own; paginated summaries |
| GET `/scans/{scan_id}` | Object-authorized complete evidence; `detection.matches` is the fixed profile's evidence and `detection.profiles` lists every evaluated profile with matched bytes, matched chunks, share of the file and matched byte runs |

Pagination defaults to 25, permits limit 1 to 100 and offset 0 to 100,000. Version summaries
default to five with maximum ten. Sorts include stable IDs or unique version numbers.
Resource path IDs are UUIDs. Integrity verification checks descriptor inclusion,
not full-file verification; the caller cannot supply the trusted root.

## Intake protocol

Raw `application/octet-stream` avoids multipart spool locations and hidden parser
limits. Supply `label`/`filename` as display metadata, never storage paths. Labels
allow ASCII alphanumeric plus spaces, periods, underscores, parentheses and hyphens,
beginning with an alphanumeric character, maximum 120. Filenames do not affect hashes.

The server counts received bytes, accepts at most the upload cap
(`ROOTSENTINEL_MAX_UPLOAD_BYTES`, default 10 MiB; `/health` reports it as
`max_upload_bytes`), and checks Content-Length only for consistency after intake. JSON
bodies are limited to 32 KiB. Intake has a 60-second limit. Private temporary bytes
become one immutable memory buffer before evaluation, then the temporary handle is
removed. For scans, snapshot UUIDs are correlation IDs and no payload is kept.
Transfers keep a private retained snapshot until release, BLOCK or expiry
([transfer specification](transfer-spec.md)).

Extensions to the original route plan: version creation/list routes, raw rather than
multipart bodies, and a registry-selected baseline for proof verification. The
cryptographic wire format is unchanged.

## Response and error contract

A scan contains identity/actor/time/filename, snapshot ID, policy UUID,
`detection.manifest`, registry revision, match arrays, and a separate decision.
Match evidence includes asset/version IDs, exact flag, matched bytes, rational
coverage, outbound intervals, and grouped digest/length/source/outbound indices.
Every scan includes `release_authorized: false`.

Errors never echo input or stack traces:

```json
{"error":{"code":"DATABASE_UNAVAILABLE","outcome":"INDETERMINATE","release_authorized":false}}
```

401 authentication; 403 role/CSRF/Origin/public-mode denial; 404 absent or hidden
resource; 409 duplicate/stale/conflicting write; 413 byte limit; 415 wrong media
type; 422 schema/empty protected registration; 429 login limit
(`LOGIN_RATE_LIMIT_ACCOUNT`, `LOGIN_RATE_LIMIT_CLIENT` or `LOGIN_RATE_LIMIT_GLOBAL`);
503 database, capacity or evaluation failure. Interrupted intake returns 400, and a
`Host` header outside the permitted list returns 400 `HOST_REJECTED`. None authorizes release.

Default `public_demo` mode denies every operational `/api/v1` route with 403
`PUBLIC_DEMO_NOT_READY`. There are no anonymous upload, forwarding or download
endpoints. The browser workspace needs `local` mode, which the hosted demo also uses
behind its https origin, and never fabricates verdicts.

References inspected: [FastAPI direct Request support](https://fastapi.tiangolo.com/advanced/using-request-directly/)
and [Starlette streaming requests](https://starlette.dev/requests/). Direct Request
use requires the explicit validation, byte accounting and OpenAPI declarations here.

## Phase 03 additions

All routes retain `/api/v1`, existing cookie/Origin/CSRF checks and public-mode denial.
Mutation requests require `X-CSRF-Token`; raw uploads use `application/octet-stream`.
Transfer creation requires a UUID `Idempotency-Key`. Query pagination: limit 1 to 100,
offset 0 to 100,000. Errors retain the existing safe INDETERMINATE/release_authorized=false envelope.

| Method and route | Permission and behavior |
|---|---|
| POST /transfers?filename=... | Authenticated raw input; bounded intake, persisted evaluation; 201. The interface sends the chosen file name as a sanitized display label, falling back to `candidate.bin` |
| POST /transfers/fixtures | Authenticated local `{fixture: benign or protected}`; same real gateway; 201 |
| GET /transfers | Own transfers for EMPLOYEE, metadata across users for ADMIN/ANALYST |
| GET /transfers/{id} | Same ownership rules; actual evidence/state and release eligibility |
| POST /transfers/{id}/release | Owner only; single-use verified bytes; no administrator BLOCK bypass |
| POST /transfers-maintenance/expire | ADMIN bounded expiry/cleanup |
| GET /incidents | ADMIN/ANALYST; optional OPEN/INVESTIGATING/RESOLVED status, HIGH/MEDIUM severity and newest/oldest order |
| GET /incidents/{id} | ADMIN/ANALYST real scan and bounded investigation history |
| PATCH /incidents/{id} | ADMIN/ANALYST; expected_revision, status, note, resolution |
| GET /exports/incidents/{id} | ADMIN/ANALYST sanitized JSON; audited export. With a signing key configured it carries a `transparency` section: a signed tree head and an inclusion proof for every referenced event |
| GET /audit/events | ADMIN/ANALYST; after sequence 0 to 20,000 and limit 1 to 100 |
| POST /audit/verify | ADMIN/ANALYST; first-invalid-event result and checked head/checkpoint |
| POST /audit/checkpoint | ADMIN; verify and retain independent signed head metadata |
| GET /transparency/key | ADMIN/ANALYST; `algorithm` (`Ed25519`), `active_key_id` and every public key with its key id. Public keys only |
| GET /transparency/sth | ADMIN/ANALYST; the latest signed tree head; 404 when none has been signed |
| POST /transparency/sth | ADMIN; sign and store a head for the current log, or return the stored one for that size; 409 on an empty log |
| GET /transparency/sth/{size} | ADMIN/ANALYST; the stored head of exactly that size, 1 to 20,000; 404 when none |
| GET /transparency/proof/inclusion | ADMIN/ANALYST; `leaf_index` 0 to 19,999 and `tree_size` 1 to 20,000, index below size; 404 when the size exceeds the log |
| GET /transparency/proof/consistency | ADMIN/ANALYST; `first` and `second` 1 to 20,000, first not above second; 404 when a size exceeds the log |

The fixture endpoint's `protected` marker is synthetic; it only BLOCKs if its bytes are
registered. The browser's established eight-block fixtures are a separate deterministic
fixture family and use the raw local upload route. No name creates an automatic verdict.

Release response is octet-stream with generated attachment name, no-store and nosniff.
Denials contain JSON, never file bytes: 401 authentication, 403 role/CSRF/origin, 404 unknown
or unowned object, 409 blocked/stale/consumed/conflict, 410 newly detected expiry, 413 size,
422 invalid schemas/UUIDs, 429 `TRANSFER_RATE_LIMIT` or `PENDING_TRANSFER_CAPACITY`, 503 infrastructure/audit/integrity/capacity.
A prior terminal EXPIRED record returns 409 on subsequent release attempts. See generated
[OpenAPI](openapi.json) for precise schemas and [transfer contract](transfer-spec.md).

## Phase 04 presentation APIs

- `GET /api/v1/overview`: authenticated exact aggregates; EMPLOYEE sees own
  transfers and no registry/incident/audit totals. Seven UTC days include today.
- `GET /api/v1/assets/{asset_id}/versions/{version_id}/tree?index=0&offset=0&limit=16`:
  ADMIN/ANALYST only. Returns registered manifest, real proof, server-computed tree
  nodes and bounded chunk page. Limit 1 to 32; index 0 to 10,239; offset 0 to 10,240. Full tree at <=16 leaves,
  selected proof path otherwise. No bytes or keys are returned.

OpenAPI and generated frontend contracts are checked in. Run
`python -B scripts/frontend_contracts.py --check` to detect type drift.

## Health

`GET /health` (outside `/api/v1`, no authentication) returns:

| Field | Meaning |
|---|---|
| `status` | `ok` when the process answers |
| `mode` | `local` or `public_demo` |
| `release_configured` | `true` in local mode when an audit key file and a checkpoint root are configured |
| `hosted` | `true` when the server's configured origin is https; the interface shows "Hosted demo" or "Local" from this field, never from the hostname |
| `commit` | the deployed commit (7 to 40 lowercase hex characters) from `ROOTSENTINEL_COMMIT`, else `RENDER_GIT_COMMIT`, else `unknown` |
| `max_upload_bytes` | the upload cap the interface enforces before sending |

`/health` makes no database call, so a keep-alive request to it does not wake the database.
With `ROOTSENTINEL_CLIENT_IP_HEADER` set, a `/health` request without a valid header is
counted separately and does not advance the `unidentified` client counter; health probes
never reach the login limiter. The Host check runs before any client identification, and
only a route that uses the client key (sign-in) advances the `unidentified` counter.

## Audit transparency log

The transparency routes are readable by the roles that can read the audit events (ADMIN and ANALYST); EMPLOYEE
gets 403, an anonymous caller 401. Signing on request is ADMIN only and needs the CSRF token like every other
mutation. All values are lowercase hex except `tree_size`, `leaf_index`, `first` and `second`.

| Response | Fields |
|---|---|
| Tree head | `log_id`, `tree_size`, `root_hash`, `timestamp`, `key_id`, `signature` |
| Inclusion proof | `leaf_index`, `tree_size`, `leaf_hash`, `path` |
| Consistency proof | `first`, `second`, `path` |

A parameter outside its range answers 422. A size larger than the log, or a head that was never signed, answers
404. `TRANSPARENCY_KEY_UNAVAILABLE` (503) means no signing key is configured; `AUDIT_LOG_INVALID` and
`AUDIT_LOG_ROLLBACK` (503) mean the stored log failed its own checks and every audited action is refused.
How to verify a head and a proof is in the [cryptographic specification](cryptographic-spec.md#audit-transparency-log-tree-and-signed-tree-heads).
