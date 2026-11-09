"""Phase 06A live results: the login-throttle probe in scripts/smoke_public.py, with mocked responses.

No network is used. Each fake response mirrors what was observed live on 2026-11-09: the app answers with a
JSON error envelope, while Cloudflare refuses a client-set CF-Connecting-IP with a text/plain 403
("error code: 1000", Server: cloudflare, cf-ray) before the request reaches the app.
"""
import importlib.util
import ipaddress
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "smoke_public.py"
spec = importlib.util.spec_from_file_location("smoke_public_under_test", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

EDGE_BODY = b"error code: 1000 SECRET-EDGE-BODY-MARKER"
EDGE_HEADERS = [("Server", "cloudflare"), ("CF-RAY", "8f00000000000000-AMS"), ("Content-Type", "text/plain; charset=UTF-8")]


def app_response(status, code):
    headers = [("Server", "cloudflare"), ("CF-RAY", "8f00000000000001-AMS"), ("Content-Type", "application/json"),
               ("x-render-origin-server", "uvicorn")]
    body = json.dumps({"error": {"code": code, "outcome": "INDETERMINATE", "release_authorized": False}}).encode()
    return status, headers, body


def edge_response():
    return 403, EDGE_HEADERS, EDGE_BODY


LIMITED = [app_response(401, "INVALID_CREDENTIALS")] * 15 + [app_response(429, "LOGIN_RATE_LIMIT_CLIENT")]
UNLIMITED = [app_response(401, "INVALID_CREDENTIALS")] * 16
GLOBAL = [app_response(401, "INVALID_CREDENTIALS")] * 15 + [app_response(429, "LOGIN_RATE_LIMIT_GLOBAL")]
EDGE = [edge_response()] * 16
MIXED = [app_response(401, "INVALID_CREDENTIALS")] * 8 + [edge_response()] * 8


class FakeGateway:
    def __init__(self, responses):
        self.responses, self.sent = list(responses), []

    def call(self, method, path, body=None, json_body=None, extra=None, timeout=30):
        self.sent.append((method, path, json_body, extra))
        return self.responses.pop(0)


def run(responses, expect, mode=None, attempts=16):
    gateway = FakeGateway(responses)
    return smoke.probe_login_throttle(gateway, mode, expect, 0, attempts), gateway


def test_classify_app_json_envelope():
    assert smoke.classify(*app_response(401, "INVALID_CREDENTIALS")[1:]) == ("app", "INVALID_CREDENTIALS")
    assert smoke.classify(*app_response(429, "LOGIN_RATE_LIMIT_CLIENT")[1:]) == ("app", "LOGIN_RATE_LIMIT_CLIENT")


def test_classify_cloudflare_plain_text_and_html_errors_as_edge():
    source, detail = smoke.classify(EDGE_HEADERS, EDGE_BODY)
    assert source == "edge" and "cloudflare error 1000" in detail and "server=cloudflare" in detail and "cf-ray" in detail
    assert "SECRET-EDGE-BODY-MARKER" not in detail
    html = b"<html><title>Error 1000</title><body>DNS points to prohibited IP</body></html>"
    source, detail = smoke.classify([("Server", "cloudflare"), ("Content-Type", "text/html")], html)
    assert source == "edge" and "cloudflare error 1000" in detail and "no cf-ray" in detail
    # A non-JSON answer without a recognisable error number is still not counted as the app.
    assert smoke.classify([("Content-Type", "text/html")], b"<html></html>")[0] == "edge"


@pytest.mark.parametrize("expect", ["limited", "limited-or-rejected"])
def test_limited_pattern_passes(expect, capsys):
    status, _ = run(LIMITED, expect)
    out = capsys.readouterr().out
    assert status == 0 and "PASS" in out and "responses from the app: 16, refused at the edge: 0" in out


def test_limited_pattern_fails_unlimited_expectation():
    assert run(LIMITED, "unlimited")[0] == 1


def test_unlimited_pattern():
    assert run(UNLIMITED, "unlimited")[0] == 0
    assert run(UNLIMITED, "limited")[0] == 1
    assert run(UNLIMITED, "limited-or-rejected")[0] == 1


def test_every_request_refused_at_the_edge_is_safe_only_for_limited_or_rejected(capsys):
    status, _ = run(EDGE, "limited-or-rejected", mode="cf-connecting-ip")
    out = capsys.readouterr().out
    assert status == 0
    assert "PASS  EDGE-REJECTED (safe: no login attempts reached the app)" in out
    assert "responses from the app: 0, refused at the edge: 16" in out
    assert "SECRET-EDGE-BODY-MARKER" not in out
    for expect in ("limited", "unlimited"):
        assert run(EDGE, expect)[0] == 1
    assert "FAIL  EDGE-REJECTED" in capsys.readouterr().out


def test_edge_rejected_without_expectation_reports_but_exits_zero(capsys):
    assert run(EDGE, None)[0] == 0
    assert "EDGE-REJECTED" in capsys.readouterr().out


def test_mixed_app_and_edge_is_a_failure():
    for expect in ("limited", "unlimited", "limited-or-rejected"):
        assert run(MIXED, expect)[0] == 1


def test_global_limit_is_inconclusive():
    for expect in ("limited", "limited-or-rejected"):
        assert run(GLOBAL, expect)[0] == 2


@pytest.mark.parametrize("mode,names", [
    ("true-client-ip", {"True-Client-IP"}), ("cf-connecting-ip", {"CF-Connecting-IP"}),
    ("xff", {"X-Forwarded-For"}), ("all", {"True-Client-IP", "CF-Connecting-IP", "X-Forwarded-For"}),
])
def test_each_spoof_mode_forges_only_its_headers_with_documentation_addresses(mode, names):
    _, gateway = run(LIMITED, None, mode=mode)
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for method, path, body, extra in gateway.sent:
        assert (method, path) == ("POST", "/api/v1/auth/login")
        assert body["password"] == "wrong-password-value" and body["username"].startswith("probe-")
        assert set(extra) == names
        assert all(any(ipaddress.ip_address(v) in net for net in documentation) for v in extra.values())
    assert len({b["username"] for _, _, b, _ in gateway.sent}) == 16


def test_no_spoof_mode_sends_no_forged_headers():
    _, gateway = run(LIMITED, None)
    assert all(extra is None for *_, extra in gateway.sent)


@pytest.mark.parametrize("argv,mode", [
    (["--spoof-mode", "xff"], "xff"), (["--spoof-forwarded"], "xff"),
    (["--spoof-client-ip-headers"], "all"), (["--spoof-mode", "cf-connecting-ip"], "cf-connecting-ip"), ([], None),
])
def test_cli_maps_old_and_new_spoof_flags(monkeypatch, argv, mode):
    seen = {}
    monkeypatch.setattr(smoke, "probe_login_throttle",
                        lambda gateway, m, expect, wait, attempts: seen.update(mode=m, expect=expect) or 0)
    assert smoke.main(["--base-url", "https://rs-test.example", "--probe-login-throttle", "--expect", "limited-or-rejected", *argv]) == 0
    assert seen == {"mode": mode, "expect": "limited-or-rejected"}


@pytest.mark.parametrize("argv", [
    ["--probe-login-throttle", "--spoof-mode", "xff", "--spoof-forwarded"],
    ["--probe-login-throttle", "--spoof-forwarded", "--spoof-client-ip-headers"],
    ["--spoof-mode", "all", "--username", "x"],
    ["--expect", "limited-or-rejected", "--username", "x"],
    ["--probe-login-throttle", "--spoof-mode", "forwarded"],
    ["--probe-login-throttle", "--expect", "rejected"],
    ["--attempts", "12", "--username", "x"],
    ["--probe-login-throttle", "--attempts", "0"],
    ["--probe-login-throttle", "--attempts", "31"],
    ["--probe-login-throttle", "--attempts", "-1"],
    ["--probe-login-throttle", "--attempts", "12.5"],
    ["--probe-login-throttle", "--attempts", "many"],
])
def test_cli_rejects_conflicting_or_misplaced_flags(argv):
    with pytest.raises(SystemExit) as exc:
        smoke.main(["--base-url", "https://rs-test.example", *argv])
    assert exc.value.code == 2


@pytest.mark.parametrize("argv,attempts", [([], 16), (["--attempts", "1"], 1), (["--attempts", "12"], 12), (["--attempts", "30"], 30)])
def test_cli_attempts_default_and_bounds(monkeypatch, argv, attempts):
    seen = {}
    monkeypatch.setattr(smoke, "probe_login_throttle",
                        lambda gateway, m, expect, wait, n: seen.update(attempts=n) or 0)
    assert smoke.main(["--base-url", "https://rs-test.example", "--probe-login-throttle", *argv]) == 0
    assert seen == {"attempts": attempts}


def test_attempts_sets_the_number_of_requests_and_scales_expectations(capsys):
    status, gateway = run([app_response(401, "INVALID_CREDENTIALS")] * 12, "unlimited", attempts=12)
    out = capsys.readouterr().out
    assert status == 0 and len(gateway.sent) == 12 and "12 attempts" in out
    assert "first request sent at 20" in out and "Z, last response at 20" in out
    # 30 attempts from one network: fifteen 401, then fifteen per-client 429.
    thirty = [app_response(401, "INVALID_CREDENTIALS")] * 15 + [app_response(429, "LOGIN_RATE_LIMIT_CLIENT")] * 15
    assert run(thirty, "limited", attempts=30)[0] == 0
    assert run(thirty, "unlimited", attempts=30)[0] == 1
    # Fewer than 16 attempts can never show the limit, so "limited" is just all 401.
    assert smoke.expected_codes("limited", 5) == [401] * 5
    assert smoke.expected_codes("limited", 16) == smoke.PROBE_EXPECTATIONS["limited"] == [401] * 15 + [429]


def test_second_network_shared_bucket_is_a_named_failure(capsys):
    """Step B of the CF-Connecting-IP procedure: a shared bucket answers 429 from the first attempt."""
    shared = [app_response(429, "LOGIN_RATE_LIMIT_CLIENT")] * 12
    status, _ = run(shared, "unlimited", attempts=12)
    out = capsys.readouterr().out
    assert status == 1 and "FAIL  observed pattern does NOT match --expect unlimited" in out and "SHARED-BUCKET" in out
    # Per-client keying on the second network: every attempt reaches Argon2id and gets 401.
    status, _ = run([app_response(401, "INVALID_CREDENTIALS")] * 12, "unlimited", attempts=12)
    assert status == 0 and "SHARED-BUCKET" not in capsys.readouterr().out
    # A global-limit 429 stays inconclusive, never SHARED-BUCKET.
    status, _ = run([app_response(429, "LOGIN_RATE_LIMIT_GLOBAL")] * 12, "unlimited", attempts=12)
    assert status == 2 and "SHARED-BUCKET" not in capsys.readouterr().out
