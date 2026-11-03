from dataclasses import replace
from datetime import timedelta
import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError

from app.api import COOKIE, create_app
from app.auth import digest, LoginLimiter
from app.db import now
from app.intake import receive_snapshot
from app.models import ScanEvaluation, SessionRecord


def upload(client, route, data=b"A" * 2048, **params):
    return client.post("/api/v1/" + route, content=data, params=params, headers={"content-type": "application/octet-stream"})


def test_api_complete_journey(client, login):
    login(client)
    registered = upload(client, "assets", label="Synthetic sample")
    assert registered.status_code == 201, registered.text
    version = registered.json()
    asset_id, version_id = version["asset_id"], version["id"]
    assert client.get("/api/v1/assets").json()["items"][0]["id"] == asset_id
    assert client.get(f"/api/v1/assets/{asset_id}").status_code == 200
    assert client.get(f"/api/v1/assets/{asset_id}/versions/{version_id}").json() == version
    assert client.get(f"/api/v1/assets/{asset_id}/versions").json() == [{k: v for k, v in version.items() if k != "chunks"}]
    proof = client.get(f"/api/v1/assets/{asset_id}/versions/{version_id}/proofs/0").json()
    payload = {"asset_id": asset_id, "version_id": version_id, "proof": proof}
    assert client.post("/api/v1/integrity/verify", json=payload).json()["valid"] is True
    proof["siblings"][0] = "0" * 64
    assert client.post("/api/v1/integrity/verify", json=payload).json()["valid"] is False
    scanned = upload(client, "scans", filename="renamed.py")
    assert scanned.status_code == 201, scanned.text
    result = scanned.json()
    assert result["decision"]["reason"] == "EXACT_PROTECTED_FILE"
    assert client.get("/api/v1/scans/" + result["id"]).json() == result
    assert client.get("/api/v1/scans").json()["items"][0]["id"] == result["id"]
    policy = client.get("/api/v1/policies/active").json()
    new = client.post("/api/v1/policies", json={"threshold": 4096, "expected_version": policy["id"]})
    assert new.status_code == 201
    assert client.post("/api/v1/policies", json={"expected_version": policy["id"]}).status_code == 409
    assert len(client.get("/api/v1/policies/history").json()["items"]) == 2
    assert client.post(f"/api/v1/assets/{asset_id}/retire").status_code == 200
    assert upload(client, "scans").json()["decision"]["outcome"] == "ALLOW"
    assert result["release_authorized"] is False
    assert client.get("/api/v1/scans/" + result["id"] + "/release").status_code == 404


@pytest.mark.parametrize("route", ["assets", "policies/active", "policies/history", "scans", "auth/me"])
def test_anonymous_denied(client, route):
    assert client.get("/api/v1/" + route).status_code == 401


@pytest.mark.parametrize("role", ["employee", "analyst"])
def test_role_restrictions(client, login, role):
    login(client, role)
    assert upload(client, "assets", label="Forbidden").status_code == 403
    assert client.post("/api/v1/policies", json={"expected_version": "anything"}).status_code == 403
    assert client.get("/api/v1/assets").status_code == (403 if role == "employee" else 200)


def test_object_access_and_scan_filter(client, login):
    login(client, "employee")
    own = upload(client, "scans").json()
    login(client, "second")
    assert client.get("/api/v1/scans/" + own["id"]).status_code == 404
    assert client.get("/api/v1/scans").json()["items"] == []
    login(client, "analyst")
    assert client.get("/api/v1/scans/" + own["id"]).status_code == 200


def test_sessions_hash_expire_revoke_rotate(client, login, system):
    response = login(client)
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    token = client.cookies.get(COOKIE)
    with system[1].transaction() as s:
        stored = s.scalar(select(SessionRecord))
        assert stored.token_digest == digest(token)
        assert stored.csrf_digest == digest(response.json()["csrf_token"])
        assert token not in repr(stored.__dict__)
        stored.expires_at = now() - timedelta(seconds=1)
    assert client.get("/api/v1/auth/me").status_code == 401
    login(client)
    assert client.cookies.get(COOKIE) != token
    assert client.post("/api/v1/auth/logout").status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401
    login(client)
    token = client.cookies.get(COOKIE)
    login(client)
    client.cookies.set(COOKIE, token, domain="127.0.0.1", path="/api/v1")
    assert client.get("/api/v1/auth/me").status_code == 401


def test_csrf_origin_host_and_no_sensitive_errors(client, login):
    login(client)
    client.headers.pop("x-csrf-token")
    assert upload(client, "scans").json()["error"]["code"] == "CSRF_REJECTED"
    assert client.post("/api/v1/auth/logout", headers={"origin": "https://attacker.invalid"}).status_code == 403
    assert client.get("/api/v1/auth/me", headers={"host": "attacker.invalid"}).status_code == 400
    malformed = client.post("/api/v1/auth/login", json={"username": "admin", "password": "PRIVATE_SENTINEL", "extra": "PRIVATE_SENTINEL"})
    assert malformed.status_code == 422
    assert "PRIVATE_SENTINEL" not in malformed.text
    assert malformed.headers["cache-control"] == "no-store"


def test_authentication_errors_and_throttling(client, credentials):
    unknown = client.post("/api/v1/auth/login", json={"username": "unknown", "password": credentials[0]})
    incorrect = client.post("/api/v1/auth/login", json={"username": "admin", "password": "incorrect"})
    assert unknown.status_code == incorrect.status_code == 401
    assert unknown.json() == incorrect.json()
    for _ in range(4):
        assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "incorrect"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]}).status_code == 429


def test_limiter_expiration_and_global_limit():
    clock = [0]
    limiter = LoginLimiter(lambda: clock[0])
    for i in range(30):
        limiter.check(str(i), str(i))
    with pytest.raises(Exception, match="LOGIN_RATE_LIMIT"):
        limiter.check("fresh", "fresh")
    clock[0] = 61
    limiter.check("fresh", "fresh")


@pytest.mark.parametrize("name", ["../../private", "C:\\secret.txt", "bad\nname", "<script>alert(1)</script>", "/etc/passwd", "a" * 121])
def test_filename_and_label_injection(client, login, name):
    login(client)
    assert upload(client, "scans", filename=name).status_code == 422
    assert upload(client, "assets", label=name).status_code == 422


def test_upload_limits_mime_and_cleanup(client, login, system):
    login(client)
    response = upload(client, "scans", data=b"x" * (10485760 + 1))
    assert response.status_code == 413
    assert list(system[0].paths.snapshots.iterdir()) == []
    assert client.post("/api/v1/scans", content=b"abc", headers={"content-type": "image/png"}).status_code == 415
    assert upload(client, "assets", data=b"", label="Empty").status_code == 422
    assert client.get("/api/v1/assets", params={"limit": 101}).status_code == 422


def test_snapshot_interruption_and_frozen_bytes(system):
    async def broken():
        yield b"part"
        raise ConnectionError("interrupted")
    with pytest.raises(ConnectionError):
        asyncio.run(receive_snapshot(broken(), system[0].paths.snapshots))
    assert list(system[0].paths.snapshots.iterdir()) == []
    source = bytearray(b"original")
    async def stream():
        yield bytes(source)
    frozen = asyncio.run(receive_snapshot(stream(), system[0].paths.snapshots))
    source[:] = b"modified"
    assert frozen.data == b"original"
    assert "original" not in repr(frozen)


def test_infrastructure_failure_never_allows(client, login, system, monkeypatch, caplog):
    login(client)
    def broken(*args):
        raise OperationalError("private query", {}, Exception("PRIVATE_SOURCE_AND_CREDENTIAL"))
    monkeypatch.setattr("app.scans.detect", broken)
    response = upload(client, "scans", data=b"PRIVATE_SOURCE_AND_CREDENTIAL")
    assert response.status_code == 503
    assert response.json()["error"]["outcome"] == "INDETERMINATE"
    assert "PRIVATE_SOURCE" not in response.text + caplog.text
    with system[1].transaction() as s:
        assert not s.scalars(select(ScanEvaluation)).all()


def test_public_demo_denies_even_authenticated_uploads(system, credentials):
    settings = replace(system[0], mode="public_demo", secure_cookies=True)
    with TestClient(create_app(settings), base_url=settings.origin) as c:
        c.headers["origin"] = settings.origin
        for path in ("scans", "assets", "auth/login"):
            r = c.post("/api/v1/" + path, content=b"arbitrary")
            assert r.status_code == 403
            assert r.json()["error"]["code"] == "PUBLIC_DEMO_NOT_READY"


def test_openapi_contract_controlled_release(client):
    schema = client.get("/openapi.json").json()
    assert [p for p in schema["paths"] if "release" in p or "download" in p] == ["/api/v1/transfers/{identifier}/release"]
    assert "application/octet-stream" in schema["paths"]["/api/v1/scans"]["post"]["requestBody"]["content"]
    assert "ScanView" in schema["components"]["schemas"]
