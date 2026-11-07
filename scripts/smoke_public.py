"""Smoke test for a hosted RootSentinel gateway (the deployed Render site or the CI container).

    python -B scripts/smoke_public.py --base-url https://YOUR-SERVICE.onrender.com --username presenter-analyst

Steps: (1) warm up: poll /health until the service answers (this IS the cold-start measurement),
(2) check the hosted headers and that interactive API docs are not published, (3) sign in and time
the login (Argon2id), (4) submit the server-side benign fixture, expect ALLOW, release it and compare
the SHA-256 of the received bytes with an independently computed digest, expect a second release to
fail (single use), (5) submit the protected fixture, expect BLOCK and that release is refused,
(6) print the audit sequence number (privileged roles only), (7) sign out.

``--probe-login-throttle`` is a separate mode for choosing ROOTSENTINEL_TRUSTED_PROXY_HOPS: it sends 16
wrong-password sign-ins with unique user names (no account is touched) and prints only the HTTP status
codes. Run it from two different networks (for example laptop Wi-Fi, then a phone on mobile data) and
add ``--spoof-forwarded`` for a third run. With the right hop count the first network ends in 429 on
the 16th attempt, the second network is NOT limited, and the spoofed run is limited exactly like the
first. It uses up the login limit for about a minute, so never run it during a demo.

The password comes from a hidden prompt or ``--password-file``; it is never an argument or an
environment variable. Nothing secret is printed: no password, cookie or CSRF token. ``--origin`` lets
the CI container (reached over plain loopback) be tested as if it were the https origin it is
configured for; the cookie is attached manually, so the Secure flag does not matter for the test.
Plain http is only allowed to loopback addresses.
"""
import argparse
import getpass
import random
import hashlib
import http.client
import json
from pathlib import Path
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


def probe_login_throttle(gateway: Gateway, spoof: bool) -> int:
    codes = []
    for index in range(16):
        extra = {"X-Forwarded-For": f"203.0.113.{random.randint(1, 254)}"} if spoof else None
        codes.append(gateway.json("POST", "/api/v1/auth/login", json_body={"username": f"probe-{random.randrange(10**9)}-{index}", "password": "wrong-password-value"}, extra=extra)[0])
    print("login probe status codes:", " ".join(str(c) for c in codes))
    print("expected with a correct hop count from one network: fifteen 401 then 429; from a second network: all 401")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--origin", help="the configured public origin (default: --base-url)")
    parser.add_argument("--username")
    parser.add_argument("--probe-login-throttle", action="store_true", help="measure proxy hops instead of running the smoke test")
    parser.add_argument("--spoof-forwarded", action="store_true", help="with the probe: send a random X-Forwarded-For each time")
    parser.add_argument("--password-file", type=Path, help="one-line file; otherwise a hidden prompt is used")
    parser.add_argument("--warmup-seconds", type=float, default=240)
    parser.add_argument("--no-frontend", action="store_true", help="do not expect the built frontend at /")
    args = parser.parse_args(argv)
    origin = (args.origin or args.base_url).rstrip("/")
    if args.probe_login_throttle:
        return probe_login_throttle(Gateway(args.base_url, origin), args.spoof_forwarded)
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
