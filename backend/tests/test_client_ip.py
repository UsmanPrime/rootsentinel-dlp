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
