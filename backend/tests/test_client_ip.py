"""Phase 06A stage 2: the optional single-address client IP header (ROOTSENTINEL_CLIENT_IP_HEADER).

With the setting empty nothing changes (the hop-count tests in test_hosted.py still describe that path).
With it set, the login limiter keys on that header's value only when it is exactly one valid address;
anything else shares one "unidentified" bucket, and X-Forwarded-For is ignored completely.
"""
from dataclasses import replace
import logging
from pathlib import Path
import re

from fastapi.testclient import TestClient
import pytest

from app.api import UNIDENTIFIED_CLIENT, create_app, header_client
from app.settings import Settings

ORIGIN = "https://rs-test.example"
HEADER = "true-client-ip"
REPOSITORY = Path(__file__).resolve().parents[2]


def header_settings(system, **override):
    values = dict(origin=ORIGIN, secure_cookies=True, mode="local", client_ip_header="True-Client-IP")
    values.update(override)
    return replace(system[0], **values)


@pytest.fixture
def header_mode(system):
    with TestClient(create_app(header_settings(system)), base_url=ORIGIN, raise_server_exceptions=False) as client:
        client.headers["origin"] = ORIGIN
        yield client


def login(client, index, headers):
    return client.post("/api/v1/auth/login", json={"username": f"nobody-{index}", "password": "wrong-password-value"},
                       headers=headers).status_code


# ---------------------------------------------------------------------------------------------- parsing
@pytest.mark.parametrize("headers,expected", [
    ([(b"true-client-ip", b"198.51.100.7")], "198.51.100.7"),
    ([(b"true-client-ip", b" 198.51.100.7 ")], "198.51.100.7"),
    ([(b"true-client-ip", b"2001:db8::1")], "2001:db8::1"),
    ([(b"true-client-ip", b"2001:DB8:0:0::1")], "2001:db8::1"),
    ([(b"true-client-ip", b"::ffff:198.51.100.7")], "198.51.100.7"),        # IPv4-mapped IPv6 is the same client
    ([], None),                                                               # missing
    ([(b"true-client-ip", b"")], None),
    ([(b"true-client-ip", b"198.51.100.7, 203.0.113.9")], None),            # a list, not one address
    ([(b"true-client-ip", b"198.51.100.7"), (b"true-client-ip", b"198.51.100.7")], None),  # repeated header
    ([(b"true-client-ip", b"198.51.100.7:443")], None),
    ([(b"true-client-ip", b"[2001:db8::1]")], None),
    ([(b"true-client-ip", b"fe80::1%eth0")], None),                          # zone identifiers are rejected
    ([(b"true-client-ip", b"198.051.100.007")], None),
    ([(b"true-client-ip", b"unidentified")], None),
    ([(b"true-client-ip", b"attacker-chosen-key")], None),
    ([(b"x-forwarded-for", b"198.51.100.7")], None),                         # another header is never consulted
])
def test_header_client_accepts_exactly_one_valid_address(headers, expected):
    assert header_client(headers, HEADER) == expected


# ---------------------------------------------------------------------------------------------- the login limiter
def test_login_throttle_keys_on_the_header_and_ignores_forged_forwarded_for(header_mode):
    # The client forges a new X-Forwarded-For (and other edge headers) every time; the header the edge sets is constant.
    codes = [login(header_mode, i, {HEADER: "198.51.100.7", "x-forwarded-for": f"203.0.113.{i}",
                                    "cf-connecting-ip": f"192.0.2.{i}"}) for i in range(16)]
    assert codes[:15] == [401] * 15 and codes[15] == 429
    assert login(header_mode, 99, {HEADER: "198.51.100.8", "x-forwarded-for": "198.51.100.7"}) == 401  # another client


def test_forwarded_for_alone_never_selects_a_bucket_in_header_mode(header_mode):
    # Without the configured header every request is unidentified, whatever X-Forwarded-For claims.
    codes = [login(header_mode, i, {"x-forwarded-for": f"203.0.113.{i}"}) for i in range(16)]
    assert codes[:15] == [401] * 15 and codes[15] == 429


def test_missing_invalid_and_multi_value_headers_share_one_bucket(header_mode, caplog):
    invalid = ["", "not-an-address", "198.51.100.7, 203.0.113.9", "198.51.100.7:443", "unidentified", "fe80::1%eth0"]
    with caplog.at_level(logging.WARNING, logger="rootsentinel.client_ip"):
        codes = [login(header_mode, i, {HEADER: invalid[i % len(invalid)]} if i % 3 else {}) for i in range(16)]
    assert codes[:15] == [401] * 15 and codes[15] == 429                     # one shared bucket of 15 per minute
    assert login(header_mode, 99, {HEADER: "198.51.100.9"}) == 401           # a valid client is not locked out
    messages = [r.getMessage() for r in caplog.records if r.name == "rootsentinel.client_ip"]
    assert messages and all("unidentified" in m for m in messages)
    assert not any(value in m for m in messages for value in invalid if value not in {"", "unidentified"})


def test_unidentified_key_cannot_be_produced_by_a_header_value():
    assert header_client([(b"true-client-ip", UNIDENTIFIED_CLIENT.encode())], HEADER) is None


# ---------------------------------------------------------------------------------------------- settings
def test_header_mode_is_off_by_default(system):
    assert system[0].client_ip_header == ""


def test_header_name_is_normalised(system):
    assert header_settings(system, client_ip_header="  CF-Connecting-IP ").client_ip_header == "cf-connecting-ip"


@pytest.mark.parametrize("name", ["True Client IP", "true_client_ip", "x:y", "-leading", "trailing-", "a--b", "é", "x" * 65,
                                  "true-client-ip\r\nx-injected"])
def test_invalid_header_names_are_rejected(system, name):
    with pytest.raises(ValueError):
        header_settings(system, client_ip_header=name)


@pytest.mark.parametrize("hops", [1, 2, 5])
def test_header_and_proxy_hops_together_refuse_to_start(system, hops):
    with pytest.raises(ValueError, match="not both"):
        header_settings(system, trusted_proxy_hops=hops)
    assert header_settings(system, trusted_proxy_hops=0).client_ip_header == HEADER


def test_environment_parsing_and_startup_refusal_do_not_echo_values(system, monkeypatch):
    settings = system[0]
    for key, value in {"ROOTSENTINEL_RUNTIME_ROOT": settings.paths.runtime, "ROOTSENTINEL_ARTIFACT_ROOT": settings.paths.artifacts,
                       "ROOTSENTINEL_MODE": "local", "ROOTSENTINEL_ORIGIN": ORIGIN,
                       "ROOTSENTINEL_CLIENT_IP_HEADER": "True-Client-IP", "ROOTSENTINEL_TRUSTED_PROXY_HOPS": "0"}.items():
        monkeypatch.setenv(key, str(value))
    assert Settings.from_environment().client_ip_header == HEADER
    monkeypatch.setenv("ROOTSENTINEL_TRUSTED_PROXY_HOPS", "1")
    with pytest.raises(ValueError, match="not both"):
        Settings.from_environment()
    monkeypatch.setenv("ROOTSENTINEL_TRUSTED_PROXY_HOPS", "0")
    monkeypatch.setenv("ROOTSENTINEL_CLIENT_IP_HEADER", "secret-looking value")
    with pytest.raises(ValueError) as error:
        Settings.from_environment()
    assert "secret-looking" not in str(error.value)


# ---------------------------------------------------------------------------------------------- uvicorn
def test_uvicorn_never_rewrites_the_client_address_from_proxy_headers():
    # uvicorn's own --proxy-headers would replace the socket peer from X-Forwarded-For before the app sees it.
    # Both server start lines in the container entrypoint must turn that off, so only the app decides.
    entrypoint = (REPOSITORY / "docker" / "entrypoint.sh").read_text(encoding="utf-8").replace("\r\n", "\n").replace("\\\n", " ")
    starts = re.findall(r"python -m uvicorn[^\n]*", entrypoint)
    assert len(starts) == 2 and all("--no-proxy-headers" in start and "--forwarded-allow-ips" not in start for start in starts)


# ---------------------------------------------------------------------------------------------- 429 codes
def test_each_login_limit_has_its_own_stable_code():
    from app.auth import LoginLimiter
    from app.errors import DomainError

    def tripped(limiter, peer, user):
        with pytest.raises(DomainError) as error:
            limiter.check(peer, user)
        return error.value.code, error.value.status

    clock = [0]
    account = LoginLimiter(lambda: clock[0])
    for i in range(5):
        account.check(f"10.0.0.{i}", "same-user")
    assert tripped(account, "10.0.0.9", "same-user") == ("LOGIN_RATE_LIMIT_ACCOUNT", 429)

    client = LoginLimiter(lambda: clock[0])
    for i in range(15):
        client.check("10.0.0.1", f"user-{i}")
    assert tripped(client, "10.0.0.1", "fresh") == ("LOGIN_RATE_LIMIT_CLIENT", 429)

    everyone = LoginLimiter(lambda: clock[0])
    for i in range(30):
        everyone.check(f"10.0.1.{i}", f"user-{i}")
    assert tripped(everyone, "10.0.2.1", "fresh") == ("LOGIN_RATE_LIMIT_GLOBAL", 429)
    clock[0] = 61
    everyone.check("10.0.2.1", "fresh")                                       # windows still expire after 60 s


def test_the_client_limit_code_reaches_the_response(header_mode):
    responses = [header_mode.post("/api/v1/auth/login", json={"username": f"nobody-{i}", "password": "wrong-password-value"},
                                  headers={HEADER: "198.51.100.7"}) for i in range(16)]
    assert responses[15].status_code == 429
    assert responses[15].json() == {"error": {"code": "LOGIN_RATE_LIMIT_CLIENT", "outcome": "INDETERMINATE", "release_authorized": False}}


def test_account_limit_is_identical_for_existing_and_nonexistent_names(system, credentials):
    # The account bucket is keyed on the submitted name before any database lookup, so its 429 cannot
    # reveal whether the account exists. Distinct client addresses keep the per-client limit out of the way.
    with TestClient(create_app(header_settings(system)), base_url=ORIGIN, raise_server_exceptions=False) as client:
        client.headers["origin"] = ORIGIN
        outcomes = {}
        for offset, name in ((0, "employee"), (10, "no-such-account")):
            codes = [client.post("/api/v1/auth/login", json={"username": name, "password": "wrong-password-value"},
                                 headers={HEADER: f"198.51.100.{offset + i + 1}"}) for i in range(5)]
            assert [r.status_code for r in codes] == [401] * 5
            limited = client.post("/api/v1/auth/login", json={"username": name, "password": "wrong-password-value"},
                                  headers={HEADER: f"198.51.100.{offset + 9}"})
            outcomes[name] = (limited.status_code, limited.json(), "set-cookie" in limited.headers)
        assert outcomes["employee"] == outcomes["no-such-account"] == (
            429, {"error": {"code": "LOGIN_RATE_LIMIT_ACCOUNT", "outcome": "INDETERMINATE", "release_authorized": False}}, False)
        # Even the correct password is refused while the window is full: no oracle for a valid guess.
        correct = client.post("/api/v1/auth/login", json={"username": "employee", "password": credentials[0]}, headers={HEADER: "198.51.100.30"})
        assert correct.status_code == 429 and correct.json()["error"]["code"] == "LOGIN_RATE_LIMIT_ACCOUNT"
        # Non-canonical spellings are rejected before the limiter, so they cannot open a second bucket for the same account.
        assert client.post("/api/v1/auth/login", json={"username": "Employee", "password": "x"}, headers={HEADER: "198.51.100.31"}).status_code == 422


# ---------------------------------------------------------------------------------------------- Phase 06A live-results facts
def unidentified_counts(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "rootsentinel.client_ip"]


LOGIN_CLASS = "method=POST route=api host_permitted=yes"


def guard_of(client):
    guard = client.app.middleware_stack
    while guard is not None and not hasattr(guard, "health_without_client"):
        guard = getattr(guard, "app", None)
    assert guard is not None
    return guard


def test_unidentified_counter_counts_only_requests_that_use_the_client_key(system, caplog):
    """Only a sign-in without a valid header advances the counter (logged at 1, 10, 100...), because sign-in is
    the only route that uses the client key. Health probes, pages, other API calls and rejected requests do not:
    they would fill the warning with noise and hide sign-ins that arrive without a client address."""
    with caplog.at_level(logging.WARNING, logger="rootsentinel.client_ip"):
        with TestClient(create_app(header_settings(system)), base_url=ORIGIN, raise_server_exceptions=False) as client:
            client.headers["origin"] = ORIGIN
            for _ in range(5):
                assert client.get("/health").status_code == 200                                # never counted
            assert client.get("/api/v1/auth/me").status_code == 401                             # the key is not used
            client.post("/api/v1/auth/logout", headers={"origin": "https://elsewhere.example"})   # 403 ORIGIN_REJECTED
            client.get("/missing-page")                                                         # not an API route
            client.get("/api/v1/auth/login")                                                    # not the sign-in method
            assert unidentified_counts(caplog) == [] and guard_of(client).unidentified == 0
            assert login(client, 0, {}) == 401
            assert unidentified_counts(caplog) == [
                f"client IP header missing or invalid; shared unidentified bucket used (1 request(s) so far; {LOGIN_CLASS})"]
            for i in range(3):
                assert login(client, 100 + i, {HEADER: f"198.51.100.{i + 1}"}) == 401           # valid header: not counted
            for i in range(1, 9):
                login(client, i, {})
            assert len(unidentified_counts(caplog)) == 1 and guard_of(client).unidentified == 9
            login(client, 9, {HEADER: "not-an-address"})                                        # the 10th
    assert unidentified_counts(caplog)[-1].endswith(f"(10 request(s) so far; {LOGIN_CLASS})")
    assert len(unidentified_counts(caplog)) == 2


def test_a_route_that_does_not_use_the_key_still_gets_the_shared_key_never_the_socket_peer(system):
    # Fail closed for later routes: without a valid header the client is the shared key on every route except
    # /health, so a route that starts keying on the client cannot be given the proxy's address by mistake.
    from app.api import RequestGuard
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["client"][0])

    async def run(path, headers):
        guard = RequestGuard(inner, header_settings(system))
        scope = {"type": "http", "method": "GET", "path": path, "client": ("10.9.8.7", 1234),
                 "headers": [(b"host", b"rs-test.example"), *headers]}
        await guard(scope, None, None)
        return guard

    import asyncio
    guard = asyncio.run(run("/api/v1/assets", []))
    assert seen == [UNIDENTIFIED_CLIENT] and guard.unidentified == 0
    asyncio.run(run("/api/v1/assets", [(b"true-client-ip", b"198.51.100.7")]))
    asyncio.run(run("/health", []))
    assert seen[1:] == ["198.51.100.7", "10.9.8.7"]


# ---------------------------------------------------------------------------------------------- Host check first
def test_a_foreign_host_is_refused_before_any_client_identification(system, caplog, monkeypatch):
    import app.api as api_module
    parsed = []
    original = api_module.header_client
    monkeypatch.setattr(api_module, "header_client", lambda headers, name: parsed.append(name) or original(headers, name))
    foreign = {"host": "elsewhere.example"}
    with caplog.at_level(logging.WARNING, logger="rootsentinel.client_ip"):
        with TestClient(create_app(header_settings(system)), base_url=ORIGIN, raise_server_exceptions=False) as client:
            client.headers["origin"] = ORIGIN
            for i in range(20):                                       # more than the per-client limit of 15
                response = client.post("/api/v1/auth/login", json={"username": f"nobody-{i}", "password": "wrong-password-value"},
                                       headers={**foreign, **({HEADER: "198.51.100.7"} if i % 2 else {})})
                assert response.status_code == 400 and response.json()["error"]["code"] == "HOST_REJECTED"
            assert client.get("/health", headers=foreign).status_code == 400
            guard = guard_of(client)
            assert parsed == []                                       # the client header was never read
            assert guard.unidentified == 0 and guard.health_without_client == 0
            assert unidentified_counts(caplog) == []
            # None of the 20 reached the limiter: the same address and the shared key both still have a full window.
            assert login(client, 50, {HEADER: "198.51.100.7"}) == 401
            assert login(client, 51, {}) == 401
            assert parsed == [HEADER, HEADER] and guard.unidentified == 1


def test_a_foreign_host_is_refused_first_in_hop_count_mode_too(system, monkeypatch):
    import app.api as api_module
    parsed = []
    original = api_module.forwarded_client
    monkeypatch.setattr(api_module, "forwarded_client", lambda headers, hops: parsed.append(hops) or original(headers, hops))
    settings = replace(system[0], origin=ORIGIN, secure_cookies=True, trusted_proxy_hops=1)
    with TestClient(create_app(settings), base_url=ORIGIN, raise_server_exceptions=False) as client:
        assert client.get("/health", headers={"host": "elsewhere.example", "x-forwarded-for": "198.51.100.7"}).status_code == 400
        assert parsed == []
        assert client.get("/health", headers={"x-forwarded-for": "198.51.100.7"}).status_code == 200
        assert parsed == [1]


# ---------------------------------------------------------------------------------------------- log classification
@pytest.mark.parametrize("method,path,permitted,expected", [
    ("GET", "/health", True, "method=GET route=health host_permitted=yes"),
    ("HEAD", "/health", False, "method=HEAD route=health host_permitted=no"),
    ("POST", "/api/v1/auth/login", True, "method=POST route=api host_permitted=yes"),
    ("DELETE", "/api", True, "method=DELETE route=api host_permitted=yes"),
    ("GET", "/apiary", True, "method=GET route=other host_permitted=yes"),
    ("GET", "/", True, "method=GET route=static host_permitted=yes"),
    ("GET", "/assets/index-3f9a.js", True, "method=GET route=static host_permitted=yes"),
    ("GET", "/favicon.svg", True, "method=GET route=static host_permitted=yes"),
    ("GET", "/transfers", True, "method=GET route=other host_permitted=yes"),
    ("GET", "/health/", True, "method=GET route=other host_permitted=yes"),
    ("PROPFIND", "/x", True, "method=OTHER route=other host_permitted=yes"),
    ("get", "/health", True, "method=OTHER route=health host_permitted=yes"),
    ("GET\r\nX-Injected: 1", "/secret-path?token=abc\r\nINFO forged", False, "method=OTHER route=other host_permitted=no"),
])
def test_log_classification_is_fixed_and_never_echoes_a_request_value(method, path, permitted, expected):
    from app.api import classify_request
    line = classify_request(method, path, permitted)
    assert line == expected
    assert re.fullmatch(r"method=(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|OTHER) route=(health|static|api|other) host_permitted=(yes|no)", line)


def test_the_unidentified_log_line_holds_only_the_count_and_the_classification(header_mode, caplog):
    raw = ["203.0.113.250, 198.51.100.7", "attacker-chosen-key\r\nforged line", "198.51.100.7:443"]
    with caplog.at_level(logging.WARNING, logger="rootsentinel.client_ip"):
        for i in range(10):
            header_mode.post("/api/v1/auth/login", json={"username": f"secret-name-{i}", "password": "wrong-password-value"},
                             headers={HEADER: raw[i % len(raw)], "x-forwarded-for": "192.0.2.99", "user-agent": "probe-agent/9"})
    messages = unidentified_counts(caplog)
    pattern = (r"client IP header missing or invalid; shared unidentified bucket used \((1|10) request\(s\) so far; "
               r"method=POST route=api host_permitted=yes\)")
    assert len(messages) == 2 and all(re.fullmatch(pattern, m) for m in messages)
    assert not any(value in m for m in messages for value in ("203.0.113", "198.51.100", "192.0.2", "attacker", "secret-name", "probe-agent"))


def test_health_probes_are_counted_separately_and_never_select_a_bucket(system):
    app = create_app(header_settings(system))
    with TestClient(app, base_url=ORIGIN, raise_server_exceptions=False) as client:
        for _ in range(3):
            client.get("/health")
        client.get("/health", headers={HEADER: "198.51.100.7"})
        guard = client.app.middleware_stack
        while guard is not None and not hasattr(guard, "health_without_client"):
            guard = getattr(guard, "app", None)
        assert guard is not None
        assert guard.health_without_client == 3 and guard.unidentified == 0


def test_unidentified_counter_starts_again_in_every_new_process(system, caplog):
    with caplog.at_level(logging.WARNING, logger="rootsentinel.client_ip"):
        for _ in range(2):
            with TestClient(create_app(header_settings(system)), base_url=ORIGIN) as client:
                client.headers["origin"] = ORIGIN
                login(client, 0, {})
    assert [m.endswith(f"(1 request(s) so far; {LOGIN_CLASS})") for m in unidentified_counts(caplog)] == [True, True]

def test_a_per_client_429_still_uses_a_global_slot_and_a_global_429_uses_none():
    from app.auth import LoginLimiter
    from app.errors import DomainError

    clock = [0]
    limiter = LoginLimiter(lambda: clock[0])

    def code(peer, name):
        try:
            limiter.check(peer, name)
            return None
        except DomainError as error:
            return error.code

    assert [code("network-a", f"user-{i}") for i in range(16)] == [None] * 15 + ["LOGIN_RATE_LIMIT_CLIENT"]
    # 16 of the global 30 are used, including the per-client 429: a second network has 14 left, not 15.
    assert [code("network-b", f"other-{i}") for i in range(14)] == [None] * 14
    assert code("network-b", "other-14") == "LOGIN_RATE_LIMIT_GLOBAL"
    assert code("network-c", "other-15") == "LOGIN_RATE_LIMIT_GLOBAL"   # a global 429 does not extend anything
    clock[0] = 60
    assert code("network-b", "other-16") is None                        # every window is fixed: 60 s from its first attempt