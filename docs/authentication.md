# Authentication and authorization

Local Phase 02 uses one workspace and three server-enforced roles.

| Operation | ADMIN | ANALYST | EMPLOYEE |
|---|---|---|---|
| Register/version/retire assets | Yes | No | No |
| Registry manifests, versions and proofs | Yes | Yes | No |
| Configure policy | Yes | No | No |
| Read active policy | Yes | Yes | Yes |
| Policy history | Yes | Yes | No |
| Submit scan | Yes | Yes | Yes |
| Inspect scan | All | All | Own only |

Employees may see digest-based evidence for their own scans, including opaque asset
and version IDs and matching indices, but cannot enumerate protected registry
metadata. No endpoint returns registered source bytes. UUID unpredictability does
not replace object authorization; unauthorized scan IDs return the same 404 as
missing IDs.

Passwords use argon2-cffi's Argon2id with 64 MiB memory, three iterations and four
lanes. Operator bootstrap accepts 12 to 128 characters through a hidden prompt, never
argv or committed defaults. Login accepts at most 128 characters and rejects invalid
usernames. Unknown/disabled users and wrong passwords receive the same generic
authentication error; a dummy Argon2 hash avoids skipping verification for unknown
users. This is not a claim of perfect timing indistinguishability.

Login creates 32 random bytes encoded as a URL-safe opaque token. Only its SHA-256
digest is stored. The cookie is HttpOnly, SameSite=Strict, scoped to `/api/v1`, and
Secure by default. Turning off Secure is allowed only in explicit local mode with a
loopback origin. Tokens expire after one hour by default. Logging in rotates the
browser's previous session; logout, password reset and operator revocation invalidate
sessions in the database. Disabling a user invalidates access immediately at the next
authorization check. There are no bearer JWTs or shared signing/session secrets.

The CSRF token is SHA-256 over a fixed domain prefix plus the high-entropy session
token. The database stores only its digest. Authenticated clients receive the CSRF
value at login, from `/auth/me` or from `/auth/session`, and hold it in memory. Mutations require its exact value
in `X-CSRF-Token`, plus an exact configured Origin. Login requires Origin even before
a session exists. There is no cross-origin credential CORS policy. Host allowlisting
reduces DNS-rebinding exposure for loopback development.

Bounded login attempts: five per username, fifteen per client and thirty globally in
each 60-second fixed window. All attempts count. Each limit answers 429 with its own code:
`LOGIN_RATE_LIMIT_ACCOUNT`, `LOGIN_RATE_LIMIT_CLIENT` and `LOGIN_RATE_LIMIT_GLOBAL`. Keys
are hashed in a bounded 2,048-entry in-memory map. A global bucket prevents evasion by
cycling usernames or addresses. Two concurrent Argon2 operations limit memory use. **Run
one application worker**; limits reset at restart and are not a distributed
abuse-prevention service.

The client is the socket peer by default. With `ROOTSENTINEL_CLIENT_IP_HEADER` set (the
hosted demo uses `True-Client-IP`), the client is the single address in that header; a
missing, repeated or invalid value puts the request in one shared `unidentified` bucket.
`ROOTSENTINEL_TRUSTED_PROXY_HOPS` is the alternative `X-Forwarded-For` mode; startup
refuses both together. Unvalidated proxy headers are never trusted. See
[deployment](deployment.md). Public-demo mode denies all operational API routes, even
with an existing session; anonymous visitor access is an open decision and is not
implemented.

No application handler logs request bodies, SQL parameters, credentials or source
content. Structured errors exclude validation input and exception text. Unexpected
request failures are caught before server traceback logging. Uvicorn runs with
`--no-access-log --no-proxy-headers` locally and in the container image; reverse-proxy
and host logs need their own review. Security events are recorded in the HMAC audit
chain ([audit specification](audit-spec.md)).

References inspected for this implementation: [argon2-cffi password hashing](https://argon2-cffi.readthedocs.io/en/stable/howto.html)
and [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

## Phase 03 permissions

All authenticated roles can create local transfers and download only their own eligible
transfer. ADMIN/ANALYST may inspect cross-user metadata, investigate incidents, export
sanitized evidence and verify audit records. Only ADMIN can retain explicit checkpoints
and invoke bounded cleanup. No role can override BLOCK or download another actor's bytes.
Release rechecks session revocation/expiry and enabled account inside its acquisition
transaction. Existing CSRF, Origin, HttpOnly/secure-cookie and login throttling remain.

## Session check

The interface checks for a session with `GET /api/v1/auth/session`. It answers 200 with
the user and CSRF token when the cookie is a valid session, and 204 when there is none;
it never answers 401, so a signed-out page load logs no failed request. It reveals only
what `/auth/me` already reveals. `GET /api/v1/auth/me` is unchanged and answers 401 when
signed out.
