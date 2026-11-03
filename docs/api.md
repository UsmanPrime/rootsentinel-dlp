# REST API — Phase 02

Version prefix `/api/v1`; local same-origin cookie authentication. The application
generates OpenAPI at `/openapi.json` and interactive documentation at `/docs`.
The checked-in [OpenAPI snapshot](openapi.json) is generated from the application.

All protected endpoints require `rs_session`. Mutations require an exact configured
`Origin`; cookie-authenticated mutations additionally require `X-CSRF-Token`. Login
returns user metadata and CSRF, with the opaque session in an HttpOnly cookie.
`/auth/me` supports reload without storing tokens in localStorage.

| Method / route | Role / behavior |
|---|---|
| POST `/auth/login` | Local-only JSON username/password; generic failures and throttling |
| POST `/auth/logout` | Authenticated; revoke current session; 204 |
| GET `/auth/me` | User ID/username/role and current CSRF value |
| GET `/assets` | ADMIN/ANALYST; `q`, `retired`, `offset`, `limit` filters |
| POST `/assets?label=...` | ADMIN; raw bytes; new asset/version; 201 |
| GET `/assets/{asset_id}` | ADMIN/ANALYST; display metadata and state |
| POST `/assets/{asset_id}/versions?expected_version=N` | ADMIN; raw bytes, optimistic precondition; 201 |
| GET `/assets/{asset_id}/versions` | ADMIN/ANALYST; paginated manifest summaries |
| GET `/assets/{asset_id}/versions/{version_id}` | ADMIN/ANALYST; manifest and ordered chunks |
| POST `/assets/{asset_id}/retire` | ADMIN; idempotent retirement |
| GET `/assets/{asset_id}/versions/{version_id}/proofs/{index}` | ADMIN/ANALYST; real Phase 01 proof |
| POST `/integrity/verify` | ADMIN/ANALYST; proof, asset_id, version_id; trusted root from registry |
| GET `/policies/active` | All authenticated roles |
| GET `/policies/history` | ADMIN/ANALYST; paginated immutable versions |
| POST `/policies` | ADMIN; threshold, block_enabled, expected_version UUID; 201 |
| POST `/scans?filename=...` | Authenticated; raw bytes; persistent evidence/decision; 201 |
| GET `/scans` | ADMIN/ANALYST all; EMPLOYEE own; paginated summaries |
| GET `/scans/{scan_id}` | Object-authorized complete evidence |

Pagination defaults to 25, permits 1–100 and offset 0–100,000. Version summaries
default to five with maximum ten. Sorts include stable IDs or unique version numbers.
Resource path IDs are UUIDs. Integrity verification checks descriptor inclusion,
not full-file verification; the caller cannot supply the trusted root.

## Intake protocol

Raw `application/octet-stream` avoids multipart spool locations and hidden parser
limits. Supply `label`/`filename` as display metadata, never storage paths. Labels
allow ASCII alphanumeric plus spaces, periods, underscores, parentheses and hyphens,
beginning with an alphanumeric character, maximum 120. Filenames do not affect hashes.

The server counts received bytes, accepts at most 10 MiB, and checks Content-Length
only for consistency after intake. JSON bodies are limited to 32 KiB. Intake has a
60-second limit. Private temporary bytes become one immutable memory buffer before
evaluation, then the temporary handle is removed. Snapshot UUIDs are correlation IDs;
there is no retrievable payload store.

Extensions to the master-plan sketch: version creation/list routes, raw rather than
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
type; 422 schema/empty protected registration; 429 login limit; 503 database,
capacity or evaluation failure. Interrupted intake returns 400. None authorizes release.

Default `public_demo` mode denies every operational `/api/v1` route with 403. There
are no anonymous upload, forwarding or download endpoints. The browser workbench
is local-only and never fabricates verdicts.

References inspected: [FastAPI direct Request support](https://fastapi.tiangolo.com/advanced/using-request-directly/)
and [Starlette streaming requests](https://starlette.dev/requests/). Direct Request
use requires the explicit validation, byte accounting and OpenAPI declarations here.
