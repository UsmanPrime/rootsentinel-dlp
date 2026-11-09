"""Smoke test for a hosted RootSentinel gateway (the deployed Render site or the CI container).

    python -B scripts/smoke_public.py --base-url https://YOUR-SERVICE.onrender.com --username presenter-analyst

Steps: (1) warm up: poll /health until the service answers (this IS the cold-start measurement),
(2) check the hosted headers and that interactive API docs are not published, (3) sign in and time
the login (Argon2id), (4) submit the server-side benign fixture, expect ALLOW, release it and compare
the SHA-256 of the received bytes with an independently computed digest, expect a second release to
fail (single use), (5) submit the protected fixture, expect BLOCK and that release is refused,
(6) print the audit sequence number (privileged roles only), (7) sign out.

``--probe-login-throttle`` is a separate mode for checking how the deployed app identifies clients
(ROOTSENTINEL_CLIENT_IP_HEADER or ROOTSENTINEL_TRUSTED_PROXY_HOPS): it sends 16 wrong-password sign-ins
with unique user names (no account is touched; ``--attempts N`` changes the count, 1 to 30) and prints only the HTTP status codes
and the UTC time of the first request and the last response.
``--spoof-mode {all,true-client-ip,cf-connecting-ip,xff}`` adds random forged client-address headers to
every request (``--spoof-client-ip-headers`` is the old name for ``all``, ``--spoof-forwarded`` for ``xff``).
Every response is classified as coming from the app (JSON error envelope) or refused at the edge
(Cloudflare text/HTML error, ``Server: cloudflare``, ``cf-ray``); only the status, the source and the app
error code or Cloudflare error number are printed, never a body. ``--expect limited`` (fifteen 401 then a
PER-CLIENT 429, error code LOGIN_RATE_LIMIT_CLIENT), ``--expect unlimited`` (sixteen 401) or ``--expect
limited-or-rejected`` (the limited pattern, or every request refused at the edge: "EDGE-REJECTED (safe: no
login attempts reached the app)") makes the exit status nonzero unless the result matches. A 429 from the
global limit (LOGIN_RATE_LIMIT_GLOBAL) or any other code is INCONCLUSIVE, never a pass (exit 2). When client
identification works: one network gives fifteen 401 then a per-client 429, both normally and with each spoofed
header the edge lets through; a second network gives sixteen 401. The limiter windows are 60 s and there is also a global limit of 30
attempts per minute, so wait at least 65 s before every probe run (``--wait-seconds 65``), otherwise
the earlier run's attempts change the result. It uses up the login limit for about a minute, so never
run it during a demo.

The password comes from a hidden prompt or ``--password-file``; it is never an argument or an
environment variable. Nothing secret is printed: no password, cookie or CSRF token. ``--origin`` lets
the CI container (reached over plain loopback) be tested as if it were the https origin it is
configured for; the cookie is attached manually, so the Secure flag does not matter for the test.
Plain http is only allowed to loopback addresses.
"""
import argparse
from datetime import datetime, timezone
import getpass
import random
import hashlib
import http.client
import json
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit
from uuid import uuid4

BENIGN = b"RootSentinel synthetic benign delivery\n"
FAILURES: list[str] = []


def report(name: str, ok: bool, detail: str = ""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail else ""))
    if not ok:
        FAILURES.append(name)


class Gateway:
    def __init__(self, base_url: str, origin: str):
        self.base, self.origin = urlsplit(base_url), origin
        if self.base.scheme not in {"http", "https"} or not self.base.hostname:
            raise SystemExit("--base-url must be an http(s) URL")
        if self.base.scheme == "http" and self.base.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise SystemExit("Plain http is only allowed to a loopback address; use https for a remote host.")
        self.cookie = self.csrf = None

    def call(self, method, path, body=None, json_body=None, extra=None, timeout=30):
        connection_class = http.client.HTTPSConnection if self.base.scheme == "https" else http.client.HTTPConnection
        connection = connection_class(self.base.hostname, self.base.port, timeout=timeout)
        headers = {"Host": urlsplit(self.origin).netloc, "Accept": "*/*"}
        if method != "GET":
            headers["Origin"] = self.origin
        if self.cookie:
            headers["Cookie"] = "rs_session=" + self.cookie
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        if json_body is not None:
            body, headers["Content-Type"] = json.dumps(json_body).encode(), "application/json"
        headers.update(extra or {})
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()

    def json(self, *args, **kwargs):
        status, headers, data = self.call(*args, **kwargs)
        try:
            return status, headers, json.loads(data)
        except ValueError:
            return status, headers, None


def header(headers, name):
    return next((v for k, v in headers if k.lower() == name), None)


def warm_up(gateway: Gateway, limit: float) -> bool:
    started, attempts = time.monotonic(), 0
    while time.monotonic() - started < limit:
        attempts += 1
        try:
            status, _, body = gateway.json("GET", "/health", timeout=15)
            if status == 200 and body and body.get("status") == "ok":
                elapsed = time.monotonic() - started
                report("warm-up: /health answered", True, f"{elapsed:.1f} s, {attempts} attempt(s); this is the cold-start time if the service was asleep")
                report("gateway reports local mode with release configured", body.get("mode") == "local" and body.get("release_configured") is True)
                return True
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(3)
    report("warm-up: /health answered", False, f"no answer within {limit:.0f} s")
    return False


PER_CLIENT_LIMIT = "LOGIN_RATE_LIMIT_CLIENT"
PER_CLIENT_WINDOW = 15   # backend/app/auth.py: 15 attempts per client key per 60 s
GLOBAL_WINDOW = 30       # 30 attempts for everyone per 60 s; one probe run never exceeds it
DEFAULT_ATTEMPTS = 16


def expected_codes(expect: str, attempts: int) -> list[int]:
    """limited: 401 until the per-client window is full, then 429; unlimited: every attempt 401."""
    if expect == "unlimited":
        return [401] * attempts
    return [401] * min(attempts, PER_CLIENT_WINDOW) + [429] * max(0, attempts - PER_CLIENT_WINDOW)


PROBE_EXPECTATIONS = {name: expected_codes(name, DEFAULT_ATTEMPTS) for name in ("limited", "unlimited")}
# limited-or-rejected: the "limited" pattern, or every request refused at the edge before it reached the app.
EXPECT_CHOICES = sorted([*PROBE_EXPECTATIONS, "limited-or-rejected"])
EDGE_REJECTED = "EDGE-REJECTED (safe: no login attempts reached the app)"
SHARED_BUCKET = ("SHARED-BUCKET  the first attempt was already limited (LOGIN_RATE_LIMIT_CLIENT): this run shares a client key "
                 "with an earlier run inside the same 60 s window")


def attempts_value(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if not 1 <= value <= GLOBAL_WINDOW:
        raise argparse.ArgumentTypeError(f"must be 1 to {GLOBAL_WINDOW}")
    return value

# Which forged client-address headers each --spoof-mode sends (RFC 5737 documentation ranges, new values per request).
SPOOF_HEADERS = {
    "true-client-ip": ("True-Client-IP",),
    "cf-connecting-ip": ("CF-Connecting-IP",),
    "xff": ("X-Forwarded-For",),
    "all": ("True-Client-IP", "CF-Connecting-IP", "X-Forwarded-For"),
}
SPOOF_PREFIX = {"True-Client-IP": "198.51.100", "CF-Connecting-IP": "192.0.2", "X-Forwarded-For": "203.0.113"}
SPOOF_DESCRIPTION = {None: "no forged headers", "true-client-ip": "spoofed True-Client-IP", "cf-connecting-ip": "spoofed CF-Connecting-IP",
                     "xff": "spoofed X-Forwarded-For", "all": "spoofed True-Client-IP, CF-Connecting-IP and X-Forwarded-For"}


def forged_headers(mode: str | None) -> dict | None:
    """Random documentation-range addresses, a new set for every request; None when nothing is forged."""
    if mode is None:
        return None
    return {name: f"{SPOOF_PREFIX[name]}.{random.randint(1, 254)}" for name in SPOOF_HEADERS[mode]}


def classify(headers, body: bytes) -> tuple[str, str | None]:
    """("app", error code) when the RootSentinel API produced the response, otherwise ("edge", detail).

    The app always answers /api/v1 with a JSON error envelope (Render also adds x-render-origin-server, which
    is not relied on here). A non-JSON answer (Cloudflare's text/plain or HTML error page, with Server: cloudflare
    and a cf-ray id) means the request was refused before it reached the app. The detail is only the
    Cloudflare error number, never the body.
    """
    if "json" in (header(headers, "content-type") or "").lower():
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        error = parsed.get("error") if isinstance(parsed, dict) else None
        return "app", error.get("code") if isinstance(error, dict) else None
    match = re.search(rb"error(?: code)?:?\s*(\d{3,5})", body or b"", re.IGNORECASE)
    server = header(headers, "server") or "?"
    ray = "cf-ray" if header(headers, "cf-ray") else "no cf-ray"
    return "edge", f"server={server}, {ray}, cloudflare error {match.group(1).decode() if match else 'unknown'}"


def evaluate_probe(codes: list[int], sources: list[str], errors: list, expect: str | None) -> tuple[int, str]:
    """Exit status and verdict line for one probe run (pure, so it can be unit-tested)."""
    if codes and all(source == "edge" for source in sources):
        if expect == "limited-or-rejected":
            return 0, "PASS  " + EDGE_REJECTED
        return (0 if expect is None else 1), ("" if expect is None else "FAIL  ") + EDGE_REJECTED + (
            f"; does NOT match --expect {expect}" if expect else "")
    if expect is None:
        return 0, ""
    if any(source == "edge" for source in sources):
        return 1, "FAIL  some requests were refused at the edge and others reached the app; rerun after 65 s"
    if any(c == 429 and e != PER_CLIENT_LIMIT for c, e in zip(codes, errors)):
        return 2, "INCONCLUSIVE  a 429 came from a limit other than the per-client one (global or account); wait 65 s and rerun"
    pattern = "limited" if expect == "limited-or-rejected" else expect
    matched = codes == expected_codes(pattern, len(codes))
    verdict = f"{'PASS' if matched else 'FAIL'}  observed pattern {'matches' if matched else 'does NOT match'} --expect {expect}"
    if not matched and codes[0] == 429 and errors[0] == PER_CLIENT_LIMIT:
        verdict += "\n" + SHARED_BUCKET
    return (0 if matched else 1), verdict


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def probe_login_throttle(gateway: Gateway, spoof_mode: str | None, expect: str | None, wait: float,
                         attempts: int = DEFAULT_ATTEMPTS) -> int:
    if wait > 0:
        print(f"waiting {wait:.0f} s so the previous probe's 60 s limiter windows have expired")
        time.sleep(wait)
    codes, sources, errors = [], [], []
    first = last = None
    for index in range(attempts):
        if index == 0:
            first = utc_now()
        status, headers, data = gateway.call("POST", "/api/v1/auth/login", json_body={"username": f"probe-{random.randrange(10**9)}-{index}", "password": "wrong-password-value"}, extra=forged_headers(spoof_mode))
        source, detail = classify(headers, data)
        codes.append(status)
        sources.append(source)
        errors.append(detail if source == "app" else None)
        print(f"  #{index + 1:<2} {status} {source:4} {detail or ''}")
        last = utc_now()
    print(f"first request sent at {first}, last response at {last} (UTC)")
    print(f"login probe ({SPOOF_DESCRIPTION[spoof_mode]}, {attempts} attempts) status codes:", " ".join(str(c) for c in codes))
    print(f"responses from the app: {sources.count('app')}, refused at the edge: {sources.count('edge')}")
    limited = sorted({e for c, e in zip(codes, errors) if c == 429 and e})
    if limited:
        print("429 error codes:", ", ".join(limited))
    print("expected when client identification works: from one network fifteen 401 then a per-client 429 "
          "(LOGIN_RATE_LIMIT_CLIENT), normally AND with every spoofed header the edge lets through; "
          "from a second network inside the first network's 60 s window, 401 for every attempt")
    status, verdict = evaluate_probe(codes, sources, errors, expect)
    if verdict:
        print(verdict)
    return status


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--origin", help="the configured public origin (default: --base-url)")
    parser.add_argument("--username")
    parser.add_argument("--probe-login-throttle", action="store_true", help="probe client identification instead of running the smoke test")
    parser.add_argument("--spoof-mode", choices=sorted(SPOOF_HEADERS),
                        help="with the probe: forge these client-address headers on every request (all = all three)")
    parser.add_argument("--spoof-forwarded", action="store_true", help="with the probe: same as --spoof-mode xff")
    parser.add_argument("--spoof-client-ip-headers", action="store_true", help="with the probe: same as --spoof-mode all")
    parser.add_argument("--expect", choices=EXPECT_CHOICES, help="with the probe: exit 1 unless the codes match "
                        "(limited: fifteen 401 then 429; unlimited: sixteen 401; limited-or-rejected: limited, "
                        "or every request refused at the edge)")
    parser.add_argument("--wait-seconds", type=float, default=0, help="with the probe: wait this long first (use 65 between runs)")
    parser.add_argument("--attempts", type=attempts_value, help=f"with the probe: number of sign-in attempts, 1 to {GLOBAL_WINDOW} "
                        f"(default {DEFAULT_ATTEMPTS}); limited expects 401 for the first {PER_CLIENT_WINDOW}, then 429")
    parser.add_argument("--password-file", type=Path, help="one-line file; otherwise a hidden prompt is used")
    parser.add_argument("--warmup-seconds", type=float, default=240)
    parser.add_argument("--no-frontend", action="store_true", help="do not expect the built frontend at /")
    args = parser.parse_args(argv)
    origin = (args.origin or args.base_url).rstrip("/")
    legacy = [mode for flag, mode in ((args.spoof_client_ip_headers, "all"), (args.spoof_forwarded, "xff")) if flag]
    if len(legacy) + bool(args.spoof_mode) > 1:
        parser.error("use only one of --spoof-mode, --spoof-forwarded and --spoof-client-ip-headers")
    spoof_mode = args.spoof_mode or (legacy[0] if legacy else None)
    if args.probe_login_throttle:
        return probe_login_throttle(Gateway(args.base_url, origin), spoof_mode, args.expect, args.wait_seconds,
                                    args.attempts or DEFAULT_ATTEMPTS)
    if spoof_mode or args.expect or args.attempts:
        parser.error("--spoof-mode, --spoof-forwarded, --spoof-client-ip-headers, --expect and --attempts only apply with --probe-login-throttle")
    if not args.username:
        parser.error("--username is required")
    password = args.password_file.read_text(encoding="utf-8").strip() if args.password_file else getpass.getpass("Password: ")
    gateway = Gateway(args.base_url, origin)

    if not warm_up(gateway, args.warmup_seconds):
        return 1
    if urlsplit(origin).scheme == "https":
        _, headers, _ = gateway.call("GET", "/health")
        report("HSTS header present", (header(headers, "strict-transport-security") or "").startswith("max-age="))
        report("CSP (report-only) header present", "default-src" in (header(headers, "content-security-policy-report-only") or ""))
        report("API documentation is not published", gateway.call("GET", "/openapi.json")[0] == 404)
    if not args.no_frontend:
        status, headers, data = gateway.call("GET", "/")
        report("frontend is served from the same origin", status == 200 and "text/html" in (header(headers, "content-type") or "") and b"<div id=\"root\">" in data)
    report("anonymous API access is denied", gateway.json("GET", "/api/v1/auth/me")[0] == 401)

    started = time.monotonic()
    status, headers, body = gateway.json("POST", "/api/v1/auth/login", json_body={"username": args.username, "password": password})
    seconds = time.monotonic() - started
    if status != 200 or not body:
        report("sign in", False, f"HTTP {status}")
        return 1
    cookie = next((v for k, v in headers if k.lower() == "set-cookie" and v.startswith("rs_session=")), "")
    gateway.cookie, gateway.csrf = cookie.split(";", 1)[0].split("=", 1)[1], body["csrf_token"]
    flags = cookie.lower()
    report("sign in (Argon2id verification time included)", True, f"{seconds:.2f} s, role {body['user']['role']}")
    report("session cookie is HttpOnly, Secure and SameSite=Strict", "httponly" in flags and "secure" in flags and "samesite=strict" in flags)

    def fixture(name):
        status, _, view = gateway.json("POST", "/api/v1/transfers/fixtures", json_body={"fixture": name}, extra={"Idempotency-Key": str(uuid4())})
        return view if status == 201 else None

    benign = fixture("benign")
    report("benign fixture is ALLOWED", bool(benign) and benign["state"] == "ALLOWED")
    if benign:
        status, _, data = gateway.call("POST", f"/api/v1/transfers/{benign['id']}/release")
        expected = hashlib.sha256(BENIGN).hexdigest()
        report("released bytes match an independently computed SHA-256", status == 200 and hashlib.sha256(data).hexdigest() == expected == benign["file_sha256"], f"{len(data)} bytes")
        again = gateway.call("POST", f"/api/v1/transfers/{benign['id']}/release")
        report("a second release is refused (single use)", again[0] == 409 and BENIGN not in again[2])
    protected = fixture("protected")
    report("protected fixture is BLOCKED", bool(protected) and protected["state"] == "BLOCKED", "" if protected and protected["state"] == "BLOCKED" else "was the synthetic asset seeded by app.bootstrap?")
    if protected:
        status, headers, data = gateway.call("POST", f"/api/v1/transfers/{protected['id']}/release")
        report("release of the blocked transfer delivers nothing", status == 409 and "json" in (header(headers, "content-type") or "") and b"SYNTHETIC-PROTECTED-" not in data)

    status, _, overview = gateway.json("GET", "/api/v1/overview")
    sequence = overview.get("audit_sequence") if status == 200 and overview else None
    print(f"INFO  audit sequence number: {sequence if sequence is not None else 'not visible to this role (use an ANALYST or ADMIN account)'}")
    report("sign out", gateway.call("POST", "/api/v1/auth/logout")[0] == 204)
    print(f"\n{'FAILED: ' + ', '.join(FAILURES) if FAILURES else 'All checks passed'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
