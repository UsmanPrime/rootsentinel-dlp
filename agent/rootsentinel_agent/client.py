"""Minimal client for the gateway REST API.

Uses ``http.client`` directly: one connection per request, no redirects and no proxy
environment variables, so credentials only ever reach the configured host. The session
cookie is Secure+HttpOnly, so it is read from ``Set-Cookie`` and attached manually. The
client never logs request or response bodies, cookies or CSRF tokens.
"""
from __future__ import annotations

import http.client
from http.cookies import SimpleCookie
import json
import ssl
from urllib.parse import quote, urlsplit

COOKIE_NAME = "rs_session"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
JSON_LIMIT = 1 << 20
BINARY_LIMIT = 10 * 1024 * 1024 + 1024


class ApiError(Exception):
    """The gateway answered with an error. ``code`` is its allowlisted error code."""

    def __init__(self, status: int, code: str):
        super().__init__(f"HTTP {status} {code}")
        self.status, self.code = status, code


class Unavailable(Exception):
    """No complete answer: refused, reset, timed out or truncated."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


class ProtocolViolation(Exception):
    """The answer did not have the documented shape."""


class GatewayClient:
    def __init__(self, base_url: str, origin: str, timeout: float = 30.0, submit_timeout: float = 90.0):
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.path not in {"", "/"} or parts.query or parts.username:
            raise ValueError("base URL must be a bare http(s) origin")
        if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
            raise ValueError("plaintext HTTP is only allowed to a loopback address")
        self.scheme, self.host = parts.scheme, parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.origin, self.timeout, self.submit_timeout = origin, timeout, submit_timeout
        self._cookie: str | None = None
        self._csrf: str | None = None

    def __repr__(self) -> str:
        return f"GatewayClient({self.scheme}://{self.host}:{self.port})"

    @property
    def authenticated(self) -> bool:
        return self._cookie is not None

    def clear_session(self) -> None:
        self._cookie = self._csrf = None

    def _connection(self, timeout: float):
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=ssl.create_default_context())
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def _request(self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None,
                 timeout: float | None = None, limit: int = JSON_LIMIT):
        sent = {"Accept": "application/json, application/octet-stream", "Connection": "close", **(headers or {})}
        if method not in {"GET", "HEAD", "OPTIONS"}:
            sent["Origin"] = self.origin
            if self._csrf:
                sent["X-CSRF-Token"] = self._csrf
        if self._cookie:
            sent["Cookie"] = f"{COOKIE_NAME}={self._cookie}"
        connection = self._connection(timeout or self.timeout)
        try:
            connection.request(method, path, body=body, headers=sent)
            response = connection.getresponse()
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ProtocolViolation("response too large")
            declared = response.getheader("Content-Length")
            if declared is not None and declared.isdecimal() and int(declared) != len(data):
                raise Unavailable("IncompleteRead")
            return response, data
        except (OSError, http.client.HTTPException) as error:
            raise Unavailable(type(error).__name__) from None
        finally:
            connection.close()

    @staticmethod
    def _error(status: int, data: bytes) -> ApiError:
        try:
            code = str(json.loads(data)["error"]["code"])[:64]
        except (ValueError, KeyError, TypeError):
            code = "UNKNOWN"
        return ApiError(status, code)

    def _json(self, response, data: bytes, expected: int):
        if response.status != expected:
            raise self._error(response.status, data)
        try:
            return json.loads(data) if data else None
        except ValueError:
            raise ProtocolViolation("response was not JSON") from None

    def health(self) -> dict:
        response, data = self._request("GET", "/health")
        return self._json(response, data, 200)

    def login(self, username: str, password: str) -> dict:
        payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        self._csrf = None  # a previous cookie (if any) is still sent so the server revokes it
        response, data = self._request("POST", "/api/v1/auth/login", body=payload, headers={"Content-Type": "application/json"})
        if response.status != 200:
            self.clear_session()
            raise self._error(response.status, data)
        token = None
        for header in response.msg.get_all("Set-Cookie") or []:
            jar = SimpleCookie()
            try:
                jar.load(header)
            except Exception:
                continue
            if COOKIE_NAME in jar and jar[COOKIE_NAME].value:
                token = jar[COOKIE_NAME].value
        try:
            body = json.loads(data)
            csrf, user = body["csrf_token"], body["user"]
        except (ValueError, KeyError, TypeError):
            raise ProtocolViolation("login response malformed") from None
        if not token:
            raise ProtocolViolation("login response carried no session cookie")
        self._cookie, self._csrf = token, csrf
        return user

    def me(self) -> dict:
        response, data = self._request("GET", "/api/v1/auth/me")
        return self._json(response, data, 200)

    def logout(self) -> None:
        try:
            response, data = self._request("POST", "/api/v1/auth/logout")
            if response.status not in {204, 401}:
                raise self._error(response.status, data)
        finally:
            self.clear_session()

    def submit(self, label: str, data: bytes, key: str) -> dict:
        response, body = self._request(
            "POST", "/api/v1/transfers?filename=" + quote(label, safe=""), body=data,
            headers={"Content-Type": "application/octet-stream", "Idempotency-Key": key},
            timeout=self.submit_timeout)
        return self._json(response, body, 201)

    def get_transfer(self, transfer_id: str) -> dict:
        response, data = self._request("GET", "/api/v1/transfers/" + quote(transfer_id, safe=""))
        return self._json(response, data, 200)

    def release(self, transfer_id: str) -> bytes:
        response, data = self._request("POST", f"/api/v1/transfers/{quote(transfer_id, safe='')}/release",
                                       limit=BINARY_LIMIT, timeout=self.submit_timeout)
        if response.status != 200:
            raise self._error(response.status, data)
        if response.getheader("Content-Type", "").split(";", 1)[0].strip() != "application/octet-stream":
            raise ProtocolViolation("release did not return a binary body")
        return data

    # Administrative / test helpers (the agent itself never calls these).
    def register_asset(self, label: str, data: bytes) -> dict:
        response, body = self._request("POST", "/api/v1/assets?label=" + quote(label, safe=""), body=data,
                                       headers={"Content-Type": "application/octet-stream"}, timeout=self.submit_timeout)
        return self._json(response, body, 201)

    def get_json(self, path: str):
        response, data = self._request("GET", path)
        return self._json(response, data, 200)

    def post_json(self, path: str, obj=None, expected: int = 200):
        body = json.dumps(obj).encode("utf-8") if obj is not None else None
        response, data = self._request("POST", path, body=body, headers={"Content-Type": "application/json"} if obj is not None else None)
        return self._json(response, data, expected)
